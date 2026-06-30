# OpenMPTCProuter — Decision Engine

`omr_metrics.py` exposes a PyTorch-based decision engine that assigns a routing
weight to each WAN interface for use with `ip route … nexthop … weight N`.
Higher weight = more traffic sent through that gateway.

---

## Pipeline overview

```
Interface metrics (JSON)
        │
        ▼
  [optional] Predictive extrapolation   MLP (torch) or linear regression → future snapshot
        │   (predict=true)
        ▼
  Feature extraction          19 floats in [0, 1], higher = better
        │                     includes trend features and predicted congestion
        ▼
  InterfaceScorer (MLP)       Linear(19→24)→ReLU→Linear(24→8)→ReLU→Linear(8→1)
        │
        ▼
  Offline masking             offline interface → softmax input forced to −∞
        │
        ▼
  Softmax                     proportional values that sum to 1.0
        │
        ▼
  Cost scaling                multiply each weight by 1/cost, renormalise
        │
        ▼
  EMA smoothing               blend(0.3 × new + 0.7 × previous) per interface
        │                     (offline interfaces bypass EMA — immediate reaction)
        ├─► score  = softmax_scaled × 100   (quality %, 0–100, higher = better)
        │
        └─► weight = max(1, round(ema_smoothed × 255))   (ip route weight, 1–255)
```

---

## 1. Feature extraction

Each interface payload is mapped to 19 normalised features.
All values are clamped to their stated range before normalisation so one
outlier cannot distort the others.

### Static features (current snapshot)

| # | Name | Formula | Missing default |
|---|------|----------|-----------------|
| 0 | `inv_latency` | `1 − clip(latency ms, 0, 500) / 500` | 0.5 |
| 1 | `inv_loss` | `1 − clip(loss %, 0, 100) / 100` | 0.5 |
| 2 | `inv_jitter` | `1 − clip(jitter ms, 0, 500) / 500` | 0.5 |
| 3 | `inv_congestion` | `1 − clip(congestion.score, 0, 100) / 100` | 0.5 |
| 4 | `rx_bps` | `clip(bandwidth.rx_bps, 0, 100 MB/s) / 100 MB/s` | 0.0 |
| 5 | `tx_bps` | `clip(bandwidth.tx_bps, 0, 100 MB/s) / 100 MB/s` | 0.0 |
| 6 | `signal` | `clip(signal.quality, 0, 100) / 100` | 0.5 |
| 7 | `bbr_bw` | `clip(bbr.bw, 0, 100 MB/s) / 100 MB/s` | 0.0 |
| 8 | `inv_ecn` | `1 − clip(tc.ecn_mark, 0, 1000) / 1000` | 1.0 |
| 9 | `inv_dropped` | `1 − clip(tc.dropped, 0, 1000) / 1000` | 1.0 |
| 10 | `inv_rtt_spread` | `1 − clip(rtt_max − rtt_min, 0, 500 ms) / 500` — buffer bloat | 0.5 |
| 11 | `signal_rsrp` | `clip(rsrp + 140, 0, 80) / 80` — LTE RSRP (−140…−60 dBm) | 0.5 |
| 12 | `signal_sinr` | `clip(sinr + 20, 0, 50) / 50` — LTE SINR (−20…30 dB) | 0.5 |
| 13 | `inv_bbr_min_rtt` | `1 − clip(bbr.min_rtt ms, 0, 2000) / 2000` | 0.5 |
| 14 | `inv_predicted_congestion` | worst of current and +5 min predicted congestion score | 0.5 |

### Trend features (require InfluxDB history; neutral 0.5 when unavailable)

| # | Name | Description |
|---|------|-------------|
| 15 | `trend_latency` | `>0.5` = improving (falling latency), `<0.5` = degrading |
| 16 | `trend_loss` | `>0.5` = improving (falling loss) |
| 17 | `trend_rx_bps` | `>0.5` = improving (rising throughput) |
| 18 | `trend_jitter` | `>0.5` = improving (falling jitter) |

`inv_*` features are inverted so that higher always means better.  Missing
numeric fields use the default listed above (0.5 = neutral, 0.0 = worst, 1.0 = best).

Trend slopes are computed with **exponential weighting** (half-life 300 s) so
recent samples dominate over older ones.

---

## 2. Neural network (InterfaceScorer)

```
Input  (n_interfaces × 19)
  └─ Linear(19 → 24) + ReLU
       └─ Linear(24 → 8) + ReLU
            └─ Linear(8 → 1)
Output (n_interfaces,)  — unnormalised score per interface
```

The first hidden neuron is pre-seeded with importance priors so the untrained
model already approximates sensible heuristic behaviour:

| Feature | Prior importance |
|---------|-----------------|
| `inv_latency` | 4.0 (highest) |
| `inv_loss` | 2.5 |
| `trend_latency` | 2.0 |
| `inv_predicted_congestion` | 1.5 |
| `inv_rtt_spread` | 1.5 |
| `inv_jitter` | 1.5 |
| `inv_congestion` | 1.2 |
| `trend_loss` | 1.5 |
| `rx_bps` / `tx_bps` | 1.0 each |
| `inv_bbr_min_rtt` | 1.0 |
| `bbr_bw` | 0.8 |
| `trend_rx_bps` / `trend_jitter` | 0.8 each |
| `inv_ecn` / `inv_dropped` | 0.5 each |
| `signal` | 0.5 |
| `signal_rsrp` | 0.6 |
| `signal_sinr` | 0.7 |

The priors are L2-normalised and written into row 0 of the first weight matrix
(`xavier_uniform_` fills the rest).

The model is stored at `/etc/openmptcprouter-vps-admin/omr-decision-model.pt`
and loaded at startup.  If the file is absent a fresh model with the priors
above is initialised automatically.  If the saved model's input dimension does
not match the current feature count (e.g. after a feature-set upgrade), the
file is discarded and the model is reinitialised with a warning log.

---

## 3. Scoring and weight assignment

1. **Run model** — all interfaces are scored in one forward pass (no grad).
2. **Mask down interfaces** — an interface is treated as down (softmax input
   forced to `−∞`, score → 0, weight → 1) when any of the following is true:
   - `status` is set and is not `"online"` (e.g. `"ERROR"` = check failed)
   - `latency` is `null` (ping check did not return a value = unreachable)
3. **Softmax** — converts raw scores to proportional values that sum to 1.0.
   Edge case: if *all* interfaces are offline every softmax output is `nan`
   (0 ÷ 0); the engine falls back to equal proportions (1 / n each).
4. **Cost scaling** — see [§4 Cost per interface](#4-cost-per-interface).
5. **Score** — `score = round(scaled_weight × 100, 2)`.  A quality percentage
   in [0, 100]; always non-negative.  Offline interface → score ≈ 0.
6. **Weight** — `weight = max(1, round(scaled_weight × 255))`.  An integer in
   [1, 255] ready to pass directly to `ip route … nexthop … weight N`.
   The minimum of 1 ensures no interface is completely removed from routing.

### Example

Two interfaces, one with a good connection and one poor:

| Interface | Softmax | Score (%) | ip route weight |
|-----------|---------|-----------|-----------------|
| eth0 | 0.82 | 82.0 | 209 |
| wwan0 | 0.18 | 18.0 | 46 |

All offline fallback (two interfaces): score 50.0 each, weight 128 each.

---

## 4. Cost per interface

The `cost` field on an `InterfaceMetrics` payload applies a routing-cost
penalty **after** softmax and **before** the final score/weight conversion.

```
factor(iface) = 1 / cost   (1.0 when cost is absent or zero)
scaled(iface) = softmax(iface) × factor(iface)
weight(iface) = max(1, round(normalise(scaled(iface)) × 255))
```

Because the scaled values are renormalised before conversion, only the
*relative* cost between interfaces matters:

| wan cost | wan2 cost | Effect |
|----------|-----------|--------|
| absent | absent | No change — standard softmax weights |
| 10 | 10 | No change — equal penalty cancels out |
| 10 | 100 | `wan` gets 10× more weight than `wan2` for identical quality |
| 1 | 10 | `wan` gets 10× more weight than `wan2` |

Cost is intentionally a post-model step so it acts as a hard operator
preference on top of the learned quality signal.  It works identically in
both the PyTorch path and the heuristic fallback.

---

## 5. EMA weight smoothing

To prevent rapid oscillation when two interfaces have similar quality scores, the
final weights are passed through an **Exponential Moving Average** (EMA) before
being returned.

```
smoothed(iface) = 0.3 × new_weight + 0.7 × previous_smoothed
```

| Parameter | Value | Description |
|-----------|-------|-------------|
| `EMA_ALPHA` | 0.3 | Blend fraction for the new observation |
| Half-life | ~60–90 s | At 30 s polling intervals |

The EMA state is kept per user in memory and reset on process restart.
An interface that goes offline **bypasses** EMA entirely — its softmax input is
forced to `−∞` so the weight drops to the minimum immediately without waiting
for the moving average to decay.

---

## 6. Predictive congestion handling

The engine has two complementary mechanisms for acting on congestion trends
*before* they fully manifest.

### 6a. `inv_predicted_congestion` feature (ML model)

Feature #14 is the **worst of the current and +5 min predicted congestion
score**, converted to `[0, 1]` (higher = less congestion).  When the current
score is still low but rising fast, this feature already reflects the future
degradation, causing the model to reduce the interface's weight preemptively.

It requires at least 2 timestamped history points for the interface.  Without
history it falls back to the current `congestion.score`.

### 6b. Heuristic preemptive penalty

The heuristic scorer (used when PyTorch is absent) now accepts history data
and substitutes `max(current_congestion, predicted_congestion)` as the
effective score.  This mirrors what the ML model does via the feature above.

### 6c. `preemptive` query parameter

Both scorers receive history data when `?preemptive=true` (the default) is
passed to `GET /metrics/decision`.  The engine fetches the last hour of
history per interface from InfluxDB and uses it for both predictive congestion
and trend features.  This is a no-op with the JSON backend (no history).

```
GET /metrics/decision                    → preemptive on (default)
GET /metrics/decision?preemptive=false   → current snapshot only, no history fetch
```

### 6d. Full payload extrapolation (`predict=true`)

When `?predict=true` is passed, the engine replaces **all** metric fields with
forward extrapolations before scoring (not just congestion).  This is the more
aggressive mode: latency, loss, jitter, bandwidth, signal quality, and
congestion are all projected to `now + horizon`.

The following fields are extrapolated:

| Field | Path |
|-------|------|
| Latency | `latency` |
| Packet loss | `loss` |
| Jitter | `jitter` |
| Congestion score | `congestion.score` |
| RX throughput | `bandwidth.rx_bps` |
| TX throughput | `bandwidth.tx_bps` |
| BBR bandwidth | `bbr.bw` |
| Signal quality | `signal.quality` |

Non-numeric and non-listed fields (status, device, IP…) are preserved from
the latest snapshot.  If fewer than 2 timestamped points exist for an
interface, its current snapshot is used unchanged.

When PyTorch is installed and at least 5 timestamped history points are
available for an interface, extrapolations use a small neural network
(MLP: Linear(1→16)→Tanh→Linear(16→8)→Tanh→Linear(8→1)) trained online on the
history window with exponential sample weighting (half-life per metric).
This path can capture non-linear trends that linear regression misses.

When PyTorch is absent, or for interfaces with fewer than 5 points, extrapolations
fall back to **exponentially weighted linear regression** (half-life 300 s).

All extrapolated values are clamped to physically valid ranges (e.g. loss stays
in [0, 100]).

| Parameter | Default | Range | Description |
|-----------|---------|-------|-------------|
| `predict` | `false` | — | Enable full payload extrapolation |
| `horizon` | `300` | 1–86400 | Seconds into the future to predict |

---

## 7. Quality forecast endpoint

`GET /metrics/quality/forecast` returns a combined quality forecast for every
WAN interface covering four metrics: **congestion**, **loss**, **jitter**, and
**RTT**, independent of the weight decision.

### Forecast backend

| Condition | Method |
|-----------|--------|
| PyTorch installed, ≥ 5 history points | MLP trained online on the history window (can capture curves) |
| PyTorch installed, < 5 history points | Exponentially weighted linear regression (fallback) |
| PyTorch not installed | Exponentially weighted linear regression |

The MLP is a fresh 1→16→8→1 network trained for 100 Adam steps each call, with
exponential sample weighting (half-life per metric) and L2 regularisation to
prevent wild extrapolation.  Predictions from both methods are clamped to
physically valid ranges and labelled with a `confidence` level.

| Parameter | Default | Range | Description |
|-----------|---------|-------|-------------|
| `horizon` | `300` | 30–3600 | Prediction horizon in seconds |
| `since` | `1h` | — | History window: `15m` `30m` `1h` `6h` `12h` `24h` or seconds |
| `limit` | `100` | 10–1000 | Maximum history points per interface |

Each interface entry contains four sub-objects (`congestion`, `loss`, `jitter`,
`rtt`), each with the same set of fields:

| Field | Description |
|-------|-------------|
| `current` / `current_level` | Latest measured value and severity level |
| `predicted` / `predicted_level` | Extrapolated value and level at +horizon seconds |
| `trend` | `rising` \| `stable` \| `falling` |
| `slope_per_min` | Change per minute in native units (positive = worsening) |
| `eta_moderate_s` | Seconds to reach moderate severity; `null` if not trending there |
| `eta_high_s` | Seconds to reach high severity; `null` if not trending there |
| `eta_severe_s` | Seconds to reach severe; `null` if not trending there |
| `confidence` | `high` (≥5 points, ≥2 min window) \| `medium` \| `low` \| `none` |

Severity levels per metric:

| Metric | none | low | moderate | high | severe |
|--------|------|-----|----------|------|--------|
| Congestion (score) | 0–24 | 25–49 | 50–74 | 75–89 | ≥90 |
| Loss (%) | <0.1 | 0.1–1 | 1–5 | 5–15 | ≥15 |
| Jitter (ms) | <5 | 5–10 | 10–30 | 30–60 | ≥60 |
| RTT (ms) | <50 | 50–100 | 100–200 | 200–500 | ≥500 |

Example response:

```jsonc
{
  "wwan0": {
    "congestion": {
      "current": 28.0, "current_level": "low",
      "predicted": 62.0, "predicted_level": "moderate",
      "trend": "rising", "slope_per_min": 5.6,
      "eta_moderate_s": 389, "eta_high_s": 836, "eta_severe_s": null,
      "confidence": "high"
    },
    "loss": {
      "current": 0.4, "current_level": "low",
      "predicted": 0.6, "predicted_level": "low",
      "trend": "stable", "slope_per_min": 0.02,
      "eta_moderate_s": null, "eta_high_s": null, "eta_severe_s": null,
      "confidence": "high"
    },
    "jitter": { ... },
    "rtt":    { ... }
  }
}
```

With the JSON backend (no history), all ETAs are `null` and
`confidence` is `"none"` for every metric.

---

## 8. Prometheus scrape endpoint

`GET /metrics/prometheus` returns all users' latest WAN metrics in
[Prometheus text format 0.0.4](https://prometheus.io/docs/instrumenting/exposition_formats/).
Admin authentication is required (pass the bearer token in the `Authorization` header).

Prometheus scrape config example:

```yaml
scrape_configs:
  - job_name: openmptcprouter
    scheme: https
    authorization:
      credentials: <admin-token>
    static_configs:
      - targets: ['your-vps:443']
    metrics_path: /metrics/prometheus
```

Exposed metrics (all gauges, labelled `username` and `interface`):

| Metric | Description |
|--------|-------------|
| `omr_interface_online` | 1 = online, 0 = offline/error |
| `omr_latency_ms` | Latency in ms |
| `omr_loss_percent` | Packet loss in % |
| `omr_jitter_ms` | Jitter in ms |
| `omr_rtt_min_ms` / `omr_rtt_max_ms` | Min/max RTT in ms |
| `omr_rx_bps` / `omr_tx_bps` | Throughput in bytes/s |
| `omr_congestion_score` | Congestion score 0–100 |
| `omr_signal_quality` | Signal quality in % (cellular/wifi) |
| `omr_bbr_bw_bps` | BBR bandwidth estimate in bytes/s |
| `omr_data_age_seconds` | Age of the latest sample in seconds |

Example output:

```
# HELP omr_interface_online 1 if the WAN interface is online 0 otherwise
# TYPE omr_interface_online gauge
omr_interface_online{username="alice",interface="wan"} 1
omr_interface_online{username="alice",interface="wwan0"} 1
# HELP omr_latency_ms WAN interface latency in milliseconds
# TYPE omr_latency_ms gauge
omr_latency_ms{username="alice",interface="wan"} 18.4
omr_latency_ms{username="alice",interface="wwan0"} 42.1
```

Fields absent from a payload (e.g. `signal_quality` on a wired interface) are
silently omitted — no `NaN` lines are emitted.

---

## 9. Online learning (fine-tuning)

`POST /metrics/decision/train` runs one SGD step minimising the MSE between
the model's current softmax output and a caller-supplied target distribution.

```jsonc
// Tell the engine that eth0 is the best interface
{ "best_interface": "eth0", "learning_rate": 0.01 }

// Or supply explicit target weights (they are L1-normalised internally)
{ "weights": { "eth0": 0.7, "wwan0": 0.3 }, "learning_rate": 0.005 }
```

The model is saved to disk after every training step.  At least two interfaces
must be present; the call is a no-op otherwise.

---

## 10. API endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/metrics/prometheus` | admin | All users' WAN metrics in Prometheus text format |
| `GET` | `/metrics/decision` | user | Current weights |
| `GET` | `/metrics/decision?explain=true` | user | Weights + raw scores + per-feature breakdown |
| `GET` | `/metrics/decision?predict=true` | user | Weights based on extrapolated future metrics |
| `GET` | `/metrics/decision?predict=true&horizon=600` | user | Predict 10 minutes ahead |
| `GET` | `/metrics/decision?preemptive=false` | user | Skip history fetch; current snapshot only |
| `GET` | `/metrics/decision?username=X` | admin | Decision for another user |
| `GET` | `/metrics/quality/forecast` | user | Per-interface forecast: congestion, loss, jitter, RTT |
| `GET` | `/metrics/quality/forecast?horizon=600&since=6h` | user | Longer window / horizon |
| `GET` | `/metrics/user` | user | Metrics DB stats: entry count, first/last seen, interfaces |
| `GET` | `/metrics/user?username=X` | admin | Stats for another user |
| `POST` | `/metrics/decision/train` | user | Submit quality feedback |
| `POST` | `/metrics/decision/reset` | admin | Reset model to heuristic init |

### GET /metrics/decision

```jsonc
{
  "weights": { "eth0": 209, "wwan0": 46 },
  "scores":  { "eth0": 82.0, "wwan0": 18.0 }
}
```

`weights` are passed directly to `ip route … nexthop dev eth0 weight 209 nexthop dev wwan0 weight 46`.

`scores` are quality percentages in [0, 100]; an offline interface scores ≈ 0.

### GET /metrics/decision?explain=true

Adds a `"features"` block with the 19 normalised values used as model input:

```jsonc
{
  "weights":  { "eth0": 209, "wwan0": 46 },
  "scores":   { "eth0": 82.0, "wwan0": 18.0 },
  "features": {
    "eth0":  { "inv_latency": 0.95, "inv_loss": 1.0, "inv_predicted_congestion": 0.91, ... },
    "wwan0": { "inv_latency": 0.61, "inv_loss": 0.87, "inv_predicted_congestion": 0.38, ... }
  }
}
```

---

## 11. Fallback behaviour

| Condition | Behaviour |
|-----------|-----------|
| PyTorch not installed | Heuristic engine used (predicted congestion → latency → loss proxy) |
| Model file missing | Fresh model initialised with heuristic priors |
| Model file corrupt | Warning logged, fresh model used |
| Model input size mismatch | Warning logged, fresh model used (feature set changed) |
| No metrics stored for user | `GET /metrics/decision` returns `{}` |
| All interfaces offline | Equal weights (128 each for 2 interfaces, min 1) |
| EMA cold start (first call) | EMA initialised at current weights — no jump |
| InfluxDB unavailable | Falls back to JSON file backend transparently |
| `preemptive=true` with JSON backend | History fetch skipped; current snapshot only |
| `predict=true` with JSON backend | Current snapshot used (no history available) |
| `predict=true`, < 2 history points | Current snapshot used for that interface |
| `quality/forecast` with JSON backend | `confidence: "none"`, ETAs all `null` for every metric |
| `quality/forecast`, < 2 history points | `confidence: "none"` or `"low"` for that interface |
| `quality/forecast`, PyTorch not installed | Linear regression used for all extrapolations |
| `quality/forecast`, < 5 history points per interface | MLP path bypassed; linear regression used |
| InfluxDB retention push fails | Warning logged; installer-set retention remains as hard floor |

---

## 12. InfluxDB configuration reference

The `influxdb` block in `omr-admin-config.json` accepts:

| Key | Default | Description |
|-----|---------|-------------|
| `url` | — | InfluxDB 3 host URL (required to enable InfluxDB backend) |
| `token` | — | Authentication token |
| `org` | `"omr"` | Organisation (not used by InfluxDB 3 Core; kept for compatibility) |
| `bucket` | `"omr_metrics"` | Database / bucket name |
| `retention_days` | `60` | Data retention period pushed to InfluxDB at startup via `/api/v3/configure/database` |

The latest-snapshot query window is fixed at **1 day** (much smaller than the
retention period) to stay within InfluxDB 3 Core's Parquet file scan limits.

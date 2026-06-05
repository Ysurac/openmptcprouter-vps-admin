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
  [optional] Predictive extrapolation   linear regression → future snapshot
        │
        ▼
  Feature extraction          10 floats in [0, 1], higher = better
        │
        ▼
  InterfaceScorer (MLP)       Linear(10→16)→ReLU→Linear(16→8)→ReLU→Linear(8→1)
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
        ├─► score  = softmax_scaled × 100   (quality %, 0–100, higher = better)
        │
        └─► weight = max(1, round(softmax_scaled × 255))   (ip route weight, 1–255)
```

---

## 1. Feature extraction

Each interface payload is mapped to 10 normalised features.
All values are clamped to their stated range before normalisation so one
outlier cannot distort the others.

| # | Name | Formula | Missing default |
|---|------|----------|-----------------|
| 0 | `inv_latency` | `1 − clip(latency ms, 0, 2000) / 2000` | 0.5 |
| 1 | `inv_loss` | `1 − clip(loss %, 0, 100) / 100` | 0.5 |
| 2 | `inv_jitter` | `1 − clip(jitter ms, 0, 500) / 500` | 0.5 |
| 3 | `inv_congestion` | `1 − clip(congestion.score, 0, 100) / 100` | 0.5 |
| 4 | `rx_bps` | `clip(bandwidth.rx_bps, 0, 100 MB/s) / 100 MB/s` | 0.0 |
| 5 | `tx_bps` | `clip(bandwidth.tx_bps, 0, 100 MB/s) / 100 MB/s` | 0.0 |
| 6 | `signal` | `clip(signal.quality, 0, 100) / 100` | 0.5 |
| 7 | `bbr_bw` | `clip(bbr.bw, 0, 100 MB/s) / 100 MB/s` | 0.0 |
| 8 | `inv_ecn` | `1 − clip(tc.ecn_mark, 0, 1000) / 1000` | 1.0 |
| 9 | `inv_dropped` | `1 − clip(tc.dropped, 0, 1000) / 1000` | 1.0 |

`inv_*` features are inverted so that higher always means better across the
board.  Missing numeric fields use the default listed above (0.5 = neutral,
0.0 = worst, 1.0 = best).

---

## 2. Neural network (InterfaceScorer)

```
Input  (n_interfaces × 10)
  └─ Linear(10 → 16) + ReLU
       └─ Linear(16 → 8) + ReLU
            └─ Linear(8 → 1)
Output (n_interfaces,)  — unnormalised score per interface
```

The first hidden neuron is pre-seeded with importance priors so the untrained
model already approximates sensible heuristic behaviour:

| Feature | Prior importance |
|---------|-----------------|
| `inv_loss` | 3.0 (highest) |
| `inv_latency` | 2.0 |
| `inv_jitter` | 1.5 |
| `inv_congestion` | 1.5 |
| `rx_bps` / `tx_bps` | 1.0 each |
| `bbr_bw` | 0.8 |
| `inv_ecn` / `inv_dropped` | 0.5 each |
| `signal` | 0.5 |

The priors are L2-normalised and written into row 0 of the first weight matrix
(`xavier_uniform_` fills the rest).

The model is stored at `/etc/openmptcprouter-vps-admin/omr-decision-model.pt`
and loaded at startup.  If the file is absent a fresh model with the priors
above is initialised automatically.

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

## 5. Predictive mode

When `?predict=true` is passed to `GET /metrics/decision`, the engine
replaces each interface's current snapshot with a forward extrapolation
before scoring.

### How it works

For each interface, the engine fetches recent history from the storage
backend (InfluxDB required — see [§8 Fallback behaviour](#8-fallback-behaviour))
and fits a linear regression on each metric independently:

```
predicted_value(t_now + horizon) = slope × t_target + intercept
```

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

Non-numeric and non-listed fields (status, device, IP…) are preserved
unchanged from the latest snapshot.

If fewer than 2 timestamped data points exist for an interface, its current
snapshot is used as-is (no extrapolation).

### Query parameters

| Parameter | Default | Range | Description |
|-----------|---------|-------|-------------|
| `predict` | `false` | — | Enable predictive mode |
| `horizon` | `300` | 1–86400 | Seconds into the future to predict |

### Example

```
GET /metrics/decision?predict=true&horizon=600
```

Returns weights based on where each interface's metrics are projected to be
in 10 minutes, allowing the router to proactively shift traffic away from a
degrading link before it becomes unusable.

---

## 6. Online learning (fine-tuning)

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

## 7. API endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/metrics/decision` | user | Current weights |
| `GET` | `/metrics/decision?explain=true` | user | Weights + raw scores + per-feature breakdown |
| `GET` | `/metrics/decision?predict=true` | user | Weights based on extrapolated future metrics |
| `GET` | `/metrics/decision?predict=true&horizon=600` | user | Predict 10 minutes ahead |
| `GET` | `/metrics/decision?username=X` | admin | Decision for another user |
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

Adds a `"features"` block with the 10 normalised values used as model input:

```jsonc
{
  "weights":  { "eth0": 209, "wwan0": 46 },
  "scores":   { "eth0": 82.0, "wwan0": 18.0 },
  "features": {
    "eth0":  { "inv_latency": 0.95, "inv_loss": 1.0, "inv_jitter": 0.92, ... },
    "wwan0": { "inv_latency": 0.61, "inv_loss": 0.87, "inv_jitter": 0.74, ... }
  }
}
```

---

## 8. Fallback behaviour

| Condition | Behaviour |
|-----------|-----------|
| PyTorch not installed | Heuristic engine used (congestion → latency → loss proxy) |
| Model file missing | Fresh model initialised with heuristic priors |
| Model file corrupt | Warning logged, fresh model used |
| No metrics stored for user | `GET /metrics/decision` returns `{}` |
| All interfaces offline | Equal weights (128 each for 2 interfaces, min 1) |
| InfluxDB unavailable | Falls back to JSON file backend transparently |
| `predict=true` with JSON backend | Current snapshot used (no history available) |
| `predict=true`, < 2 history points | Current snapshot used for that interface |

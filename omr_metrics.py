# Copyright (C) 2026 Ycarus (Yannick Chabanois) <ycarus@zugaina.org> for OpenMPTCProuter
# SPDX-License-Identifier: AGPL-3.0
#
# Optional module: router metrics endpoints + PyTorch decision engine.
# The router posts one interface payload per call (via omr-tracker post-tracking hooks).
# Loaded by omradmin.py when present; safe to remove to disable the feature entirely.
#
# Storage backends
# ----------------
# JSON (default): /etc/openmptcprouter-vps-admin/omr-metrics.json
# InfluxDB 3.x:   enabled by adding an "influxdb" block to omr-admin-config.json:
#
#   "influxdb": {
#     "url":    "http://localhost:8181",
#     "token":  "<your-token>",
#     "org":    "omr",          (ignored by v3, kept for config compatibility)
#     "bucket": "omr_metrics"   (optional, default: "omr_metrics")
#   }
#
# Requires:  pip install influxdb3-python
# Falls back silently to JSON if the package is absent or the server is unreachable.
#
# Metrics endpoints
# -----------------
# GET  /metrics                  — latest snapshot for the current user's WAN interfaces
# POST /metrics                  — store one interface payload (called by omr-tracker)
# GET  /metrics/all              — all users' snapshots (admin only)
# GET  /metrics/history          — time-series history (InfluxDB only)
#                                  ?interface=wwan0 &since=1h &limit=500
#
# Decision engine
# ---------------
# GET  /metrics/decision         — model-assigned nexthop weight per WAN interface
#   ?explain=true                  include per-interface feature breakdown
#   ?predict=true &horizon=300     replace current metrics with forward extrapolations
#                                  before scoring (horizon in seconds, default 300)
#   ?preemptive=true (default)     fetch history to penalise interfaces whose congestion
#                                  is rising even when current reading is still low;
#                                  no-op with JSON backend (history unavailable)
# POST /metrics/decision/train   — submit quality feedback to fine-tune the model
# POST /metrics/decision/reset   — reset model to heuristic initialisation (admin only)
#
# Requires: pip install torch
# Falls back to a hand-crafted heuristic scorer when PyTorch is not installed.
# The heuristic also benefits from preemptive congestion prediction when InfluxDB
# history is available.
#
# Predictive quality handling
# ----------------------------
# GET  /metrics/quality/forecast
#   ?horizon=300  prediction horizon in seconds (30–3600, default 300 = 5 min)
#   ?since=1h     history window used for regression (default 1 h)
#   ?limit=100    maximum history points fetched per interface
#
# Returns one entry per WAN interface with three sub-objects (congestion, loss, jitter)
# each with a uniform set of keys:
#   current / current_level     — latest measured value and severity level
#   predicted / predicted_level — extrapolated value at +horizon seconds
#   trend                       — "rising" | "stable" | "falling"
#   slope_per_min               — change per minute in native units
#   eta_severe_s / eta_high_s / eta_moderate_s — seconds to reach that severity (null if never)
#   confidence                  — "high" | "medium" | "low" | "none"
#
# Loss levels:   none (<0.1%) | low (0.1–1%) | moderate (1–5%) | high (5–15%) | severe (15%+)
# Jitter levels: none (<5 ms) | low (5–10 ms) | moderate (10–30 ms) | high (30–60 ms) | severe (60 ms+)
#
# Engine diagnostics
# ------------------
# GET  /metrics/engine           — inference/training stats + storage info (admin only)

import asyncio
import json
import math
import os
import logging
import threading
import time
import urllib.request
import urllib.error
from typing import Optional, Dict

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from starlette.responses import JSONResponse

LOG = logging.getLogger('uvicorn.error')

try:
    import torch
    import torch.nn as nn
    _TORCH_AVAILABLE = True
except ImportError:
    _TORCH_AVAILABLE = False

METRICS_FILE = '/etc/openmptcprouter-vps-admin/omr-metrics.json'
OMR_CONFIG_FILE = '/etc/openmptcprouter-vps-admin/omr-admin-config.json'
DECISION_MODEL_FILE = '/etc/openmptcprouter-vps-admin/omr-decision-model.pt'

# ---------------------------------------------------------------------------
# Engine runtime stats (thread-safe counters, reset only on process restart)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# EMA weight smoothing (prevents rapid oscillation between similar WANs)
# ---------------------------------------------------------------------------

# Blend fraction for the new observation: 0.3 = 30 % new, 70 % previous.
# At 30-second polling intervals this gives ~60-90 s for a sustained quality
# change to fully propagate, while a hard offline event still fires immediately
# (the offline mask sets score to −∞, bypassing EMA for that interface).
EMA_ALPHA: float = 0.3

_weight_ema: dict = {}   # {username: {interface: float}}
_ema_lock = threading.Lock()


def _apply_ema(username: str, probs: dict) -> dict:
    """Blend float probabilities *probs* {iface: [0,1]} with the per-user EMA history.

    Operates on raw probabilities before integer conversion so that rounding
    noise does not accumulate across iterations.  Returns a dict of floats.
    First call initialises the EMA at the current probabilities (no cold-start
    jump).  Interfaces that disappear are evicted automatically.
    """
    if not probs:
        return probs
    with _ema_lock:
        prev = _weight_ema.get(username, {})
        new_ema: dict = {}
        for iface, p_new in probs.items():
            p_prev = prev.get(iface, float(p_new))   # no prior → start at current
            new_ema[iface] = EMA_ALPHA * float(p_new) + (1.0 - EMA_ALPHA) * p_prev
        _weight_ema[username] = new_ema
    return new_ema


_stats_lock = threading.Lock()
_engine_stats: dict = {
    # torch inference (full model)
    "inference_count": 0,
    "inference_total_ms": 0.0,
    "last_inference_ms": None,
    # heuristic fallback (no torch)
    "heuristic_count": 0,
    "heuristic_total_ms": 0.0,
    "last_heuristic_ms": None,
    # training
    "training_count": 0,
    "training_total_ms": 0.0,
    "last_training_ms": None,
    "last_training_loss": None,
    "cumulative_loss": 0.0,
    # model lifecycle
    "model_resets": 0,
    "model_loaded_at": None,   # Unix timestamp of last load/init
}


def _stats_update(**kw):
    with _stats_lock:
        for k, v in kw.items():
            _engine_stats[k] = v


def _stats_inc(count_key: str, ms_key: str, elapsed_ms: float):
    with _stats_lock:
        _engine_stats[count_key] += 1
        _engine_stats[ms_key] += elapsed_ms


# ---------------------------------------------------------------------------
# Pydantic models — mirror the JSON produced by 040-metrics on the router
# ---------------------------------------------------------------------------

class SignalMetrics(BaseModel):
    quality: Optional[float] = None
    operator: Optional[str] = None
    state: Optional[str] = None
    type: Optional[str] = None      # 'wifi' | 'modemmanager' | 'qmi'
    rssi: Optional[float] = None
    rsrp: Optional[float] = None
    rsrq: Optional[float] = None
    sinr: Optional[float] = None


class WifiMetrics(BaseModel):
    ssid: Optional[str] = None
    bssid: Optional[str] = None
    mode: Optional[str] = None
    channel: Optional[int] = None
    signal: Optional[int] = None    # dBm
    noise: Optional[int] = None     # dBm
    bitrate: Optional[str] = None
    quality: Optional[int] = None
    quality_max: Optional[int] = None


class TCMetrics(BaseModel):
    qdisc: Optional[str] = None
    sent_bytes: Optional[int] = None
    sent_pkts: Optional[int] = None
    dropped: Optional[int] = None
    overlimits: Optional[int] = None
    requeues: Optional[int] = None
    backlog_bytes: Optional[int] = None
    backlog_pkts: Optional[int] = None
    ecn_mark: Optional[int] = None
    drop_overlimit: Optional[int] = None
    flows: Optional[int] = None
    throttled: Optional[int] = None
    flows_plimit: Optional[int] = None
    new_flow_count: Optional[int] = None


class BBRMetrics(BaseModel):
    bw: Optional[int] = None             # bytes/s
    pacing_rate: Optional[int] = None    # bytes/s
    delivery_rate: Optional[int] = None  # bytes/s
    cwnd: Optional[int] = None           # packets
    min_rtt: Optional[float] = None      # ms
    retrans: Optional[int] = None


class CongestionMetrics(BaseModel):
    score: Optional[int] = None          # 0-100
    level: Optional[str] = None          # none | low | moderate | high | severe


class BandwidthMetrics(BaseModel):
    rx_bytes: Optional[int] = None
    tx_bytes: Optional[int] = None
    rx_bps: Optional[int] = None         # bytes/s
    tx_bps: Optional[int] = None         # bytes/s


class InterfaceMetrics(BaseModel):
    """Mirrors the JSON written by 040-metrics for one WAN interface."""
    interface: str
    device: Optional[str] = None
    status: Optional[str] = None
    status_msg: Optional[str] = None
    device_ip: Optional[str] = None
    device_ip6: Optional[str] = None
    gateway: Optional[str] = None
    gateway6: Optional[str] = None
    weight: Optional[int] = 100           # nexthop weight (1-255, default 100)
    cost: Optional[int] = None           # interface routing cost (lower = preferred)
    asn: Optional[str] = None            # ASN of the WAN (e.g. "AS1234")
    latency: Optional[float] = None      # ms
    rtt_min: Optional[float] = None      # ms
    rtt_max: Optional[float] = None      # ms
    loss: Optional[float] = None         # percent
    jitter: Optional[float] = None       # ms
    signal: Optional[SignalMetrics] = None
    wifi: Optional[WifiMetrics] = None
    tc: Optional[TCMetrics] = None
    bbr: Optional[BBRMetrics] = None
    congestion: Optional[CongestionMetrics] = None
    bandwidth: Optional[BandwidthMetrics] = None
    timestamp: Optional[int] = None      # Unix epoch


class DecisionFeedback(BaseModel):
    """Feedback used to fine-tune the interface scorer."""
    best_interface: Optional[str] = None   # shorthand: 1.0 for this iface, 0.0 rest
    weights: Optional[Dict[str, float]] = None  # free-form {iface: weight}
    learning_rate: float = 0.01


# ---------------------------------------------------------------------------
# Storage backends
# ---------------------------------------------------------------------------

class JSONBackend:
    """Stores the latest interface metrics per user in a single JSON file."""

    def read_all(self) -> dict:
        if not os.path.isfile(METRICS_FILE):
            return {}
        try:
            with open(METRICS_FILE) as f:
                return json.load(f)
        except Exception as exc:
            LOG.debug("omr_metrics JSON: read error: %s", exc)
            return {}

    def read_user(self, username: str) -> dict:
        return self.read_all().get(username, {})

    def read_history(self, username: str, interface: Optional[str],
                     since_seconds: int, limit: int):
        return [] if interface is not None else {}  # JSON backend: latest snapshot only

    def user_stats(self, username: str) -> dict:
        """Return entry count and first/last seen timestamps for a user.

        JSON backend stores only the latest snapshot per interface, so
        entry_count equals the number of known interfaces.
        """
        user_data = self.read_user(username)
        if not user_data:
            return {"entry_count": 0, "first_seen": None, "last_seen": None, "interfaces": []}
        timestamps = [
            p["timestamp"] for p in user_data.values()
            if isinstance(p, dict) and p.get("timestamp") is not None
        ]
        return {
            "entry_count": len(user_data),
            "first_seen": min(timestamps) if timestamps else None,
            "last_seen":  max(timestamps) if timestamps else None,
            "interfaces": sorted(user_data.keys()),
        }

    def write_interface(self, username: str, payload: dict):
        data = self.read_all()
        data.setdefault(username, {})[payload["interface"]] = payload
        tmp = METRICS_FILE + '.tmp'
        try:
            with open(tmp, 'w') as f:
                json.dump(data, f, indent=4)
            os.replace(tmp, METRICS_FILE)
        except Exception as exc:
            LOG.error("omr_metrics JSON: write error: %s", exc)


class InfluxBackend:
    """Stores metrics in InfluxDB 3.x.

    Each interface write creates one InfluxDB point with:
      - tags:   username, interface, device, status
      - fields: individual numeric metrics (latency, loss, …) for time-series
                queries, plus a 'json_payload' string field for full retrieval.

    Reads fetch the latest json_payload per interface via a SQL query.
    """

    _MEASUREMENT = "interface_metrics"

    def __init__(self, url: str, token: str, org: str, bucket: str,
                 retention_days: int = 60):
        from influxdb_client_3 import InfluxDBClient3  # noqa: PLC0415
        # org is not used in InfluxDB 3; bucket becomes the database name
        self._client = InfluxDBClient3(host=url, token=token, database=bucket)
        self._bucket = bucket
        self._url = url
        self._token = token
        self._retention_days = max(1, int(retention_days))
        threading.Thread(target=self._apply_retention, daemon=True,
                         name="omr-influx-retention").start()

    def _apply_retention(self):
        """Push the configured retention period to the InfluxDB 3 management API.

        Tries POST (create) first; on 409 Conflict (database already exists)
        falls back to PATCH (update).  Logs a warning and continues on any
        other error; the DB-level retention set by the installer remains as
        the hard floor.
        """
        body = json.dumps({
            "db": self._bucket,
            "retention_period": f"{self._retention_days}d",
        }).encode()
        base_url = self._url.rstrip("/") + "/api/v3/configure/database"
        headers = {
            "Authorization": f"Token {self._token}",
            "Content-Type": "application/json",
        }

        def _do_request(method: str):
            req = urllib.request.Request(base_url, data=body, method=method)
            for k, v in headers.items():
                req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status

        try:
            try:
                status = _do_request("POST")
            except urllib.error.HTTPError as exc:
                if exc.code != 409:
                    raise
                status = _do_request("PATCH")
            LOG.info("omr_metrics: InfluxDB retention set to %d days (HTTP %s)",
                     self._retention_days, status)
        except Exception as exc:
            LOG.warning("omr_metrics: could not apply InfluxDB retention policy: %s", exc)

    # Window used for latest-snapshot queries (_query). Much smaller than the
    # retention period so InfluxDB3 Core stays within its Parquet file scan limit.
    _LATEST_WINDOW = "1 day"

    def _query(self, username: Optional[str] = None) -> dict:
        """Return {username: {interface: payload}} for the latest data point."""
        if username:
            sql = (
                f"SELECT username, interface, json_payload FROM {self._MEASUREMENT} "
                f"WHERE time >= now() - interval '{self._LATEST_WINDOW}' AND username = $username "
                f"ORDER BY time DESC"
            )
            params: dict = {"username": username}
        else:
            sql = (
                f"SELECT username, interface, json_payload FROM {self._MEASUREMENT} "
                f"WHERE time >= now() - interval '{self._LATEST_WINDOW}' "
                f"ORDER BY time DESC"
            )
            params = {}
        try:
            table = self._client.query(sql, query_parameters=params or None)
        except Exception as exc:
            LOG.error("omr_metrics InfluxDB: query error: %s", exc)
            return {}

        result: dict = {}
        seen: set = set()
        try:
            d = table.to_pydict()
            for uname, iface, payload_str in zip(
                d.get("username", []),
                d.get("interface", []),
                d.get("json_payload", []),
            ):
                key = (uname, iface)
                if key in seen:
                    continue  # ORDER BY time DESC — first occurrence is latest
                seen.add(key)
                try:
                    result.setdefault(uname, {})[iface] = json.loads(payload_str)
                except Exception:
                    pass
        except Exception as exc:
            LOG.error("omr_metrics InfluxDB: result parse error: %s", exc)
        return result

    def read_all(self) -> dict:
        return self._query()

    def read_user(self, username: str) -> dict:
        return self._query(username).get(username, {})

    def read_history(self, username: str, interface: Optional[str],
                     since_seconds: int, limit: int):
        """Return history for one interface (list) or all interfaces (dict).

        When *interface* is None every interface for the user is returned as
        ``{interface_name: [payload, ...]}`` ordered oldest-first per interface.
        When *interface* is given a plain list is returned (backward-compatible).
        """
        if interface is not None:
            return self._read_history_iface(username, interface, since_seconds, limit)
        return self._read_history_all(username, since_seconds, limit)

    def _parse_history_rows(self, table) -> list:
        result = []
        try:
            d = table.to_pydict()
            for ts, payload_str in zip(d.get("time", []), d.get("json_payload", [])):
                try:
                    entry = json.loads(payload_str)
                    if "timestamp" not in entry and ts is not None:
                        entry["timestamp"] = int(ts.timestamp()) if hasattr(ts, "timestamp") else int(ts)
                    result.append(entry)
                except Exception:
                    pass
        except Exception as exc:
            LOG.debug("omr_metrics InfluxDB history: result parse error: %s", exc)
        return result

    def _read_history_iface(self, username: str, interface: str,
                            since_seconds: int, limit: int) -> list:
        sql = (
            f"SELECT time, json_payload FROM {self._MEASUREMENT} "
            f"WHERE username = $username AND interface = $interface "
            f"AND time >= now() - interval '{since_seconds} seconds' "
            f"ORDER BY time ASC "
            f"LIMIT {int(limit)}"
        )
        try:
            table = self._client.query(
                sql, query_parameters={"username": username, "interface": interface}
            )
        except Exception as exc:
            LOG.debug("omr_metrics InfluxDB history: query error: %s", exc)
            return []
        return self._parse_history_rows(table)

    def _read_history_all(self, username: str, since_seconds: int, limit: int) -> dict:
        sql = (
            f"SELECT time, interface, json_payload FROM {self._MEASUREMENT} "
            f"WHERE username = $username "
            f"AND time >= now() - interval '{since_seconds} seconds' "
                f"ORDER BY time ASC"
        )
        try:
            table = self._client.query(sql, query_parameters={"username": username})
        except Exception as exc:
            LOG.debug("omr_metrics InfluxDB history: query error: %s", exc)
            return {}

        result: dict = {}
        try:
            d = table.to_pydict()
            for ts, iface, payload_str in zip(
                d.get("time", []),
                d.get("interface", []),
                d.get("json_payload", []),
            ):
                try:
                    entry = json.loads(payload_str)
                    if "timestamp" not in entry and ts is not None:
                        entry["timestamp"] = int(ts.timestamp()) if hasattr(ts, "timestamp") else int(ts)
                    entries = result.setdefault(iface, [])
                    if len(entries) < int(limit):
                        entries.append(entry)
                except Exception:
                    pass
        except Exception as exc:
            LOG.debug("omr_metrics InfluxDB history: result parse error: %s", exc)
        return result

    def user_stats(self, username: str) -> dict:
        """Return total entry count, first/last seen and interface list for a user."""
        sql = (
            f"SELECT COUNT(*) as entry_count, MIN(time) as first_seen, "
            f"MAX(time) as last_seen FROM {self._MEASUREMENT} "
            f"WHERE username = $username "
            f"AND time >= now() - interval '{self._LATEST_WINDOW}'"
        )
        iface_sql = (
            f"SELECT DISTINCT interface FROM {self._MEASUREMENT} "
            f"WHERE username = $username "
            f"AND time >= now() - interval '{self._LATEST_WINDOW}'"
        )
        params = {"username": username}
        try:
            table = self._client.query(sql, query_parameters=params)
            d = table.to_pydict()
            counts = d.get("entry_count", [None])
            entry_count = int(counts[0]) if counts and counts[0] is not None else 0

            def _ts(v):
                if v is None:
                    return None
                return int(v.timestamp()) if hasattr(v, "timestamp") else int(v)

            firsts = d.get("first_seen", [None])
            lasts  = d.get("last_seen",  [None])
            first_seen = _ts(firsts[0]) if firsts else None
            last_seen  = _ts(lasts[0])  if lasts  else None
        except Exception as exc:
            LOG.error("omr_metrics InfluxDB user_stats: %s", exc)
            entry_count, first_seen, last_seen = 0, None, None

        try:
            itable = self._client.query(iface_sql, query_parameters=params)
            id_ = itable.to_pydict()
            interfaces = sorted(id_.get("interface", []))
        except Exception as exc:
            LOG.error("omr_metrics InfluxDB user_stats interfaces: %s", exc)
            interfaces = []

        return {
            "entry_count": entry_count,
            "first_seen":  first_seen,
            "last_seen":   last_seen,
            "interfaces":  interfaces,
        }

    def write_interface(self, username: str, payload: dict):
        from influxdb_client_3 import Point  # noqa: PLC0415
        iface = payload["interface"]
        ts = payload.get("timestamp") or int(time.time())

        p = (Point(self._MEASUREMENT)
             .tag("username", username)
             .tag("interface", iface)
             .tag("device", payload.get("device") or "")
             .tag("status", payload.get("status") or "")
             .field("json_payload", json.dumps(payload)))

        # Top-level string fields
        for f in ("status_msg", "device_ip", "device_ip6", "gateway", "gateway6", "asn"):
            v = payload.get(f)
            if v:
                p = p.field(f, str(v))

        # Top-level numeric fields
        for f in ("latency", "rtt_min", "rtt_max", "loss", "jitter", "weight", "cost"):
            v = payload.get(f)
            if v is not None:
                p = p.field(f, float(v))

        # Bandwidth and BBR (all numeric)
        for section, fields in (
            ("bandwidth", ("rx_bytes", "tx_bytes", "rx_bps", "tx_bps")),
            ("bbr",       ("bw", "pacing_rate", "delivery_rate", "cwnd", "min_rtt", "retrans")),
        ):
            sec = payload.get(section) or {}
            for f in fields:
                v = sec.get(f)
                if v is not None:
                    p = p.field(f"{section}_{f}", float(v))

        # Congestion
        cong = payload.get("congestion") or {}
        if cong.get("score") is not None:
            p = p.field("congestion_score", float(cong["score"]))
        if cong.get("level"):
            p = p.field("congestion_level", str(cong["level"]))

        # Signal
        sig = payload.get("signal") or {}
        for f in ("quality", "rssi", "rsrp", "rsrq", "sinr"):
            v = sig.get(f)
            if v is not None:
                p = p.field(f"signal_{f}", float(v))
        for f in ("operator", "state", "type"):
            v = sig.get(f)
            if v:
                p = p.field(f"signal_{f}", str(v))

        # Wifi
        wifi = payload.get("wifi") or {}
        for f in ("signal", "noise", "channel", "quality", "quality_max"):
            v = wifi.get(f)
            if v is not None:
                p = p.field(f"wifi_{f}", float(v))
        for f in ("ssid", "bssid", "mode", "bitrate"):
            v = wifi.get(f)
            if v:
                p = p.field(f"wifi_{f}", str(v))

        # TC
        tc = payload.get("tc") or {}
        for f in ("sent_bytes", "sent_pkts", "dropped", "overlimits", "requeues",
                  "ecn_mark", "drop_overlimit", "backlog_bytes", "backlog_pkts",
                  "flows", "throttled", "flows_plimit", "new_flow_count"):
            v = tc.get(f)
            if v is not None:
                p = p.field(f"tc_{f}", float(v))
        if tc.get("qdisc"):
            p = p.field("tc_qdisc", str(tc["qdisc"]))

        p = p.time(ts, write_precision="s")
        try:
            self._client.write(record=p)
        except Exception as exc:
            LOG.debug("omr_metrics InfluxDB: write error: %s", exc)


# ---------------------------------------------------------------------------
# Backend singleton
# ---------------------------------------------------------------------------

_backend: Optional[object] = None
_backend_lock = threading.Lock()


def _init_backend():
    """Read omr-admin-config.json and return the appropriate backend."""
    global EMA_ALPHA
    try:
        with open(OMR_CONFIG_FILE) as f:
            config = json.load(f)
        ema_alpha = config.get("ema_alpha")
        if ema_alpha is not None:
            try:
                EMA_ALPHA = max(0.01, min(1.0, float(ema_alpha)))
                LOG.info("omr_metrics: EMA_ALPHA=%.2f (from config)", EMA_ALPHA)
            except (TypeError, ValueError):
                pass
        influx_cfg = config.get("influxdb") or {}
        if influx_cfg.get("url") and influx_cfg.get("token"):
            try:
                retention_days = int(influx_cfg.get("retention_days", 60))
                backend = InfluxBackend(
                    url=influx_cfg["url"],
                    token=influx_cfg["token"],
                    org=influx_cfg.get("org", "omr"),
                    bucket=influx_cfg.get("bucket", "omr_metrics"),
                    retention_days=retention_days,
                )
                LOG.info("omr_metrics: InfluxDB backend at %s bucket=%s retention=%dd",
                         influx_cfg["url"], influx_cfg.get("bucket", "omr_metrics"),
                         retention_days)
                return backend
            except ImportError:
                LOG.warning("omr_metrics: influxdb3-python not installed – falling back to JSON")
            except Exception as exc:
                LOG.warning("omr_metrics: InfluxDB init failed (%s) – falling back to JSON", exc)
    except Exception as exc:
        LOG.debug("omr_metrics: config read: %s", exc)

    LOG.info("omr_metrics: JSON backend at %s", METRICS_FILE)
    return JSONBackend()


def _get_backend():
    global _backend
    if _backend is None:
        with _backend_lock:
            if _backend is None:
                _backend = _init_backend()
    return _backend


def _read_all() -> dict:
    return _get_backend().read_all()


def _read_user(username: str) -> dict:
    return _get_backend().read_user(username)


def _write_interface(username: str, payload: dict):
    _get_backend().write_interface(username, payload)


# Accepted shorthands for the ?since= query parameter → seconds.
_SINCE_PRESETS: dict = {
    "15m": 900,    "30m": 1800,
    "1h":  3600,   "6h":  21600,  "12h": 43200,
    "1d":  86400,  "24h": 86400,  "2d":  172800, "7d":  604800,
    "30d": 2592000,
}


def _parse_since(since: str) -> int:
    """Return seconds for a shorthand like '1h', '7d', or a raw integer string."""
    s = since.strip().lower()
    if s in _SINCE_PRESETS:
        return _SINCE_PRESETS[s]
    try:
        return max(60, int(s))
    except ValueError:
        return 3600  # default: 1 h


def _read_history(username: str, interface: Optional[str], since_seconds: int, limit: int):
    return _get_backend().read_history(username, interface, since_seconds, limit)


def _user_stats(username: str) -> dict:
    return _get_backend().user_stats(username)


# ---------------------------------------------------------------------------
# Decision engine — predictive extrapolation (pure Python, no torch required)
# ---------------------------------------------------------------------------

# Half-life for exponential weighting: a point this many seconds old gets
# half the weight of the most recent point.  300 s = 5 min is a good default
# for WAN metrics that are sampled every ~30 s.
PREDICT_HALFLIFE_S: float = 300.0

# (path, lo_clamp, hi_clamp, halflife_s) — path is a 1- or 2-tuple into the payload.
# Clamping keeps extrapolated values inside physically meaningful bounds.
# halflife_s: exponential decay half-life for this metric — shorter for fast-changing
# metrics (congestion), longer for slow-changing ones (bandwidth, signal).
_PREDICTABLE: list = [
    (("latency",),             0.0,   None,  180.0),   # ms ≥ 0
    (("loss",),                0.0,  100.0,  180.0),   # % in [0, 100]
    (("jitter",),              0.0,   None,  180.0),   # ms ≥ 0
    (("rtt_min",),             0.0,   None,  180.0),   # ms ≥ 0
    (("rtt_max",),             0.0,   None,  180.0),   # ms ≥ 0
    (("congestion", "score"),  0.0,  100.0,  120.0),   # reacts quickly
    (("bandwidth",  "rx_bps"), 0.0,   None,  600.0),   # slow trend
    (("bandwidth",  "tx_bps"), 0.0,   None,  600.0),
    (("bbr",        "bw"),     0.0,   None,  600.0),
    (("signal",     "quality"),0.0,  100.0,  600.0),   # very slow
]

# Public name kept for backward compatibility (used in tests and the doc).
PREDICTABLE_FIELDS: list = [path for path, _, _, _ in _PREDICTABLE]


# ---------------------------------------------------------------------------
# Congestion levels and predictive forecast
# ---------------------------------------------------------------------------

_CONGESTION_LEVELS = [
    (90.0, "severe"),
    (75.0, "high"),
    (50.0, "moderate"),
    (25.0, "low"),
    (0.0,  "none"),
]


def _congestion_level(score: float) -> str:
    for threshold, level in _CONGESTION_LEVELS:
        if score >= threshold:
            return level
    return "none"


def _predict_congestion(history: list, horizon_s: int = 300,
                        halflife_s: float = 120.0) -> dict:
    """Return a congestion forecast dict for one interface.

    Keys: current_score, current_level, predicted_score, predicted_level,
          trend (rising|stable|falling), slope_per_min,
          eta_moderate_s, eta_high_s, eta_severe_s (seconds to threshold, None if never),
          confidence (high|medium|low|none).
    halflife_s: EWL decay half-life (default 120 s — congestion is fast-changing).
    """
    timestamps: list = []
    scores: list = []
    for p in history:
        ts = p.get("timestamp")
        cong = (p.get("congestion") or {}).get("score")
        if ts is not None and cong is not None:
            timestamps.append(float(ts))
            scores.append(float(cong))

    now = timestamps[-1] if timestamps else time.time()
    current_score = round(scores[-1], 1) if scores else None
    current_level = _congestion_level(current_score) if current_score is not None else "unknown"

    if len(timestamps) < 2:
        return {
            "current_score": current_score,
            "current_level": current_level,
            "predicted_score": current_score,
            "predicted_level": current_level,
            "trend": "stable",
            "slope_per_min": 0.0,
            "eta_moderate_s": None,
            "eta_high_s": None,
            "eta_severe_s": None,
            "confidence": "none",
        }

    predicted_raw = _predict_at(timestamps, scores, now + horizon_s,
                                halflife_s=halflife_s)
    predicted_score = round(max(0.0, min(100.0, predicted_raw)), 1)
    predicted_level = _congestion_level(predicted_score)

    slope = _weighted_slope(timestamps, scores, halflife_s=halflife_s)   # score / second
    slope_per_min = round((slope or 0.0) * 60.0, 3)

    if abs(slope_per_min) < 0.5:
        trend = "stable"
    elif slope_per_min > 0:
        trend = "rising"
    else:
        trend = "falling"

    def _eta(threshold: float) -> Optional[int]:
        if not slope or slope <= 0 or current_score is None:
            return None
        if current_score >= threshold:
            return 0
        secs = (threshold - current_score) / slope
        return round(secs) if secs <= 86400 else None

    n = len(timestamps)
    age_s = now - min(timestamps)
    if n >= 5 and age_s >= 120:
        confidence = "high"
    elif n >= 3:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "current_score": current_score,
        "current_level": current_level,
        "predicted_score": predicted_score,
        "predicted_level": predicted_level,
        "trend": trend,
        "slope_per_min": slope_per_min,
        "eta_moderate_s": _eta(50.0),
        "eta_high_s": _eta(75.0),
        "eta_severe_s": _eta(90.0),
        "confidence": confidence,
    }


def _wls_params(ts_seq: tuple, vs_seq: tuple,
                halflife_s: float = PREDICT_HALFLIFE_S) -> tuple:
    """Exponentially weighted OLS on pre-validated sequences (len >= 2).

    Returns (slope, t_mean, v_mean).  Internal helper; callers must filter
    None values and ensure at least 2 points before calling.
    """
    t_max = max(ts_seq)
    decay = math.log(2) / halflife_s if halflife_s > 0 else 0.0
    ws = [math.exp(-decay * (t_max - ti)) for ti in ts_seq]
    w_sum = sum(ws)
    t_mean = sum(w * t for w, t in zip(ws, ts_seq)) / w_sum
    v_mean = sum(w * v for w, v in zip(ws, vs_seq)) / w_sum
    num = sum(ws[i] * (ts_seq[i] - t_mean) * (vs_seq[i] - v_mean) for i in range(len(ts_seq)))
    den = sum(ws[i] * (ts_seq[i] - t_mean) ** 2 for i in range(len(ts_seq)))
    slope = num / den if den != 0.0 else 0.0
    return slope, t_mean, v_mean


def _linear_predict_at(timestamps: list, values: list, target_ts: float,
                       halflife_s: float = PREDICT_HALFLIFE_S) -> Optional[float]:
    """Exponentially weighted linear regression on (Unix-seconds, value) pairs.

    Points decay with half-life *halflife_s*: a point that is halflife_s seconds
    older than the most recent one carries half the weight.  This makes the
    extrapolation much more responsive to recent behaviour than plain OLS.

    Returns None when fewer than 2 valid points are available.
    """
    pairs = [
        (float(t), float(v))
        for t, v in zip(timestamps, values)
        if t is not None and v is not None
    ]
    if len(pairs) < 2:
        return pairs[-1][1] if pairs else None
    ts_seq, vs_seq = zip(*pairs)
    slope, t_mean, v_mean = _wls_params(ts_seq, vs_seq, halflife_s)
    return slope * (target_ts - t_mean) + v_mean


# Minimum history length to engage the neural-network forecast path.
_FORECAST_TORCH_MIN_POINTS: int = 5


def _torch_predict_at(timestamps: list, values: list, target_ts: float,
                      halflife_s: float = PREDICT_HALFLIFE_S) -> Optional[float]:
    """Neural-network forecast using a small MLP with exponential sample weighting.

    Trains a tiny 1→16→8→1 MLP on the (timestamp, value) history for 100 Adam
    steps, then evaluates at *target_ts*.  Returns None when fewer than
    _FORECAST_TORCH_MIN_POINTS valid samples are available so the caller can
    fall back to the linear estimator.

    Timestamps are normalised relative to the latest sample and *halflife_s* so
    the optimiser operates on well-conditioned inputs regardless of metric scale.
    The MLP can capture non-linear trends (e.g. exponential growth) that WLS
    misses; L2 regularisation prevents wild extrapolation with short histories.
    """
    pairs = [
        (float(t), float(v))
        for t, v in zip(timestamps, values)
        if t is not None and v is not None
    ]
    if len(pairs) < _FORECAST_TORCH_MIN_POINTS:
        return None

    ts_arr = [p[0] for p in pairs]
    vs_arr = [p[1] for p in pairs]

    t_ref = ts_arr[-1]
    hl = halflife_s if halflife_s > 0 else 1.0
    v_scale = max(abs(sum(vs_arr) / len(vs_arr)), 1e-9)

    decay = math.log(2) / hl
    t_norm = torch.tensor(
        [(t - t_ref) / hl for t in ts_arr], dtype=torch.float32
    ).unsqueeze(1)
    v_norm = torch.tensor([v / v_scale for v in vs_arr], dtype=torch.float32)
    weights = torch.tensor(
        [math.exp(-decay * (t_ref - t)) for t in ts_arr], dtype=torch.float32
    )

    model = nn.Sequential(
        nn.Linear(1, 16), nn.Tanh(),
        nn.Linear(16, 8), nn.Tanh(),
        nn.Linear(8, 1),
    )
    optimizer = torch.optim.Adam(model.parameters(), lr=0.05)

    for _ in range(100):
        optimizer.zero_grad()
        pred = model(t_norm).squeeze(1)
        l2 = sum(p.pow(2).sum() for p in model.parameters()) * 1e-4
        loss = (weights * (pred - v_norm).pow(2)).mean() + l2
        loss.backward()
        optimizer.step()

    t_target = torch.tensor([[(target_ts - t_ref) / hl]], dtype=torch.float32)
    with torch.no_grad():
        result = model(t_target).item() * v_scale
    return result


def _predict_at(timestamps: list, values: list, target_ts: float,
                halflife_s: float = PREDICT_HALFLIFE_S) -> Optional[float]:
    """Forecast dispatcher: uses torch when available and history is sufficient,
    otherwise falls back to exponentially weighted linear regression."""
    if _TORCH_AVAILABLE:
        result = _torch_predict_at(timestamps, values, target_ts, halflife_s)
        if result is not None:
            return result
    return _linear_predict_at(timestamps, values, target_ts, halflife_s)


def _weighted_slope(timestamps: list, values: list,
                    halflife_s: float = PREDICT_HALFLIFE_S) -> Optional[float]:
    """Exponentially weighted OLS slope (value/second) over (timestamp, value) pairs.

    Uses the same decay logic as _linear_predict_at so recent points dominate.
    Returns None when fewer than 2 valid pairs exist.
    """
    pairs = [
        (float(t), float(v))
        for t, v in zip(timestamps, values)
        if t is not None and v is not None
    ]
    if len(pairs) < 2:
        return None
    ts_seq, vs_seq = zip(*pairs)
    slope, _, _ = _wls_params(ts_seq, vs_seq, halflife_s)
    return slope


_LOSS_THRESHOLDS = [
    (15.0, "severe"),
    (5.0,  "high"),
    (1.0,  "moderate"),
    (0.1,  "low"),
    (0.0,  "none"),
]

_JITTER_THRESHOLDS = [
    (60.0, "severe"),
    (30.0, "high"),
    (10.0, "moderate"),
    (5.0,  "low"),
    (0.0,  "none"),
]

_RTT_THRESHOLDS = [
    (500.0, "severe"),
    (200.0, "high"),
    (100.0, "moderate"),
    (50.0,  "low"),
    (0.0,   "none"),
]


def _metric_level(value: float, thresholds: list) -> str:
    for threshold, level in thresholds:
        if value >= threshold:
            return level
    return thresholds[-1][1]


def _forecast_metric(history: list, path: tuple, thresholds: list,
                     hi_clamp: Optional[float] = None,
                     stable_slope_per_min: float = 0.1,
                     horizon_s: int = 300,
                     halflife_s: Optional[float] = None) -> dict:
    """Exponentially weighted linear forecast for any scalar metric.

    path: tuple of keys to extract from each payload, e.g. ("loss",) or ("congestion", "score").
    thresholds: [(threshold, level_name), ...] sorted descending.
    hi_clamp: optional upper bound for the predicted value.
    stable_slope_per_min: abs(slope) below this is considered "stable".
    halflife_s: EWL decay half-life; defaults to PREDICT_HALFLIFE_S when None.

    Returns current/predicted/trend/slope_per_min/eta_severe_s/eta_high_s/eta_moderate_s/confidence.
    """
    hl = halflife_s if halflife_s is not None else PREDICT_HALFLIFE_S

    timestamps: list = []
    values: list = []
    for p in history:
        ts = p.get("timestamp")
        v: object = p
        for key in path:
            v = (v or {}).get(key) if isinstance(v, dict) else None
        if ts is not None and v is not None:
            timestamps.append(float(ts))
            values.append(float(v))

    now = timestamps[-1] if timestamps else time.time()
    current = round(values[-1], 2) if values else None
    current_level = _metric_level(current, thresholds) if current is not None else "unknown"

    # ETA for severe / high / moderate levels only
    eta_levels = [(t, n) for t, n in thresholds if n in ("severe", "high", "moderate")]

    def _eta(threshold: float) -> Optional[int]:
        if len(timestamps) < 2 or current is None:
            return None
        slope = _weighted_slope(timestamps, values, halflife_s=hl)
        if not slope or slope <= 0:
            return None
        if current >= threshold:
            return 0
        secs = (threshold - current) / slope
        return round(secs) if secs <= 86400 else None

    base: dict = {
        "current":         current,
        "current_level":   current_level,
        "predicted":       current,
        "predicted_level": current_level,
        "trend":           "stable",
        "slope_per_min":   0.0,
        "confidence":      "none",
    }
    for _, n in eta_levels:
        base[f"eta_{n}_s"] = None

    if len(timestamps) < 2:
        return base

    predicted_raw = _predict_at(timestamps, values, now + horizon_s, halflife_s=hl)
    if predicted_raw is not None:
        pred = max(0.0, predicted_raw)
        if hi_clamp is not None:
            pred = min(hi_clamp, pred)
        base["predicted"] = round(pred, 2)
    base["predicted_level"] = _metric_level(base["predicted"], thresholds) \
        if base["predicted"] is not None else "unknown"

    slope = _weighted_slope(timestamps, values, halflife_s=hl)
    slope_per_min = round((slope or 0.0) * 60.0, 4)
    base["slope_per_min"] = slope_per_min

    if abs(slope_per_min) < stable_slope_per_min:
        base["trend"] = "stable"
    elif slope_per_min > 0:
        base["trend"] = "rising"
    else:
        base["trend"] = "falling"

    n_pts = len(timestamps)
    age_s = now - min(timestamps)
    if n_pts >= 5 and age_s >= 120:
        base["confidence"] = "high"
    elif n_pts >= 3:
        base["confidence"] = "medium"
    else:
        base["confidence"] = "low"

    for t, n in eta_levels:
        base[f"eta_{n}_s"] = _eta(t)

    return base


def _extract_trend_features(history: list) -> list:
    """Return 4 trend features in [0, 1]: 0.5 = stable, >0.5 = improving, <0.5 = degrading.

    Falls back to 0.5 (neutral) when history has fewer than 2 timestamped points.
    Slope is computed with exponential weighting so recent samples dominate.
    """
    def _slope(path: tuple) -> Optional[float]:
        ts_list: list = []
        val_list: list = []
        for p in history:
            ts = p.get("timestamp")
            v: object = p
            for key in path:
                v = (v or {}).get(key) if isinstance(v, dict) else None
            if ts is not None and v is not None:
                ts_list.append(float(ts))
                val_list.append(float(v))
        return _weighted_slope(ts_list, val_list)

    def _trend(path: tuple, scale: float, inv: bool) -> float:
        """slope/s → [0,1]; inv=True means lower values are better."""
        s = _slope(path)
        if s is None:
            return 0.5
        t = max(-1.0, min(1.0, s / scale))
        return 0.5 + (-t if inv else t) * 0.5

    return [
        _trend(("latency",),             scale=0.10, inv=True),   # ms/s, lower=better
        _trend(("loss",),                scale=0.01, inv=True),   # %/s,  lower=better
        _trend(("bandwidth", "rx_bps"),  scale=1e4,  inv=False),  # B/s², higher=better
        _trend(("jitter",),              scale=0.05, inv=True),   # ms/s, lower=better
    ]


def _predict_payload(history: list, horizon_seconds: int = 300) -> dict:
    """Return a copy of the latest payload with PREDICTABLE_FIELDS replaced by
    exponentially weighted linear extrapolations *horizon_seconds* into the future.

    Each history entry must carry a 'timestamp' (Unix seconds) field; entries
    without one are skipped for regression.  Predicted values are blended with
    the current snapshot according to confidence (fewer history points → lean
    toward current value) so that a 2-point history does not produce wild
    extrapolations.  Clamped to physically valid ranges.
    """
    if not history:
        return {}
    payload = dict(history[-1])
    latest_ts = payload.get("timestamp") or time.time()
    target_ts = float(latest_ts) + horizon_seconds

    for path, lo, hi, halflife in _PREDICTABLE:
        timestamps: list = []
        values: list = []
        for p in history:
            ts = p.get("timestamp")
            v: object = p
            for key in path:
                v = (v or {}).get(key) if isinstance(v, dict) else None
            if ts is not None and v is not None:
                timestamps.append(float(ts))
                values.append(float(v))

        predicted = _predict_at(timestamps, values, target_ts, halflife_s=halflife)
        if predicted is None:
            continue

        # Confidence blend: fewer points → lean toward current snapshot value.
        n_pts = len(timestamps)
        alpha = 1.0 if n_pts >= 5 else 0.7 if n_pts >= 3 else 0.4
        predicted = alpha * predicted + (1.0 - alpha) * values[-1]

        if lo is not None:
            predicted = max(lo, predicted)
        if hi is not None:
            predicted = min(hi, predicted)

        if len(path) == 1:
            payload[path[0]] = predicted
        else:
            nested = dict(payload.get(path[0]) or {})
            nested[path[1]] = predicted
            payload[path[0]] = nested

    return payload


# ---------------------------------------------------------------------------
# Decision engine — feature extraction (pure Python, no torch required)
# ---------------------------------------------------------------------------

# Each feature is in [0, 1] with higher = better.
FEATURE_NAMES = [
    # --- static features (current snapshot) ---
    "inv_latency",     # 1 - clip(latency ms,          0,   500) / 500
    "inv_loss",        # 1 - clip(loss %,              0,   100) / 100
    "inv_jitter",      # 1 - clip(jitter ms,           0,   500) / 500
    "inv_congestion",  # 1 - clip(congestion.score,    0,   100) / 100
    "rx_bps",          # log1p(rx_bps) / log1p(100 MB/s)  — log scale
    "tx_bps",          # log1p(tx_bps) / log1p(100 MB/s)
    "signal",          # clip(signal.quality,          0,   100) / 100
    "bbr_bw",          # log1p(bbr.bw)  / log1p(100 MB/s)
    "inv_ecn",         # 1 - clip(tc.ecn_mark,         0,  1000) / 1000
    "inv_dropped",     # 1 - clip(tc.dropped,          0,  1000) / 1000
    "inv_rtt_spread",  # 1 - clip(rtt_max-rtt_min ms,  0,   500) / 500  (buffer bloat)
    "signal_rsrp",     # clip(rsrp + 140,              0,    80) / 80   (cellular)
    "signal_sinr",     # clip(sinr  + 20,              0,    50) / 50   (cellular)
    "inv_bbr_min_rtt", # 1 - clip(bbr.min_rtt ms,      0,  2000) / 2000 (clean RTT)
    "inv_predicted_congestion",  # predicted congestion score at +5 min horizon
    "staleness",       # 1.0=fresh (<5 min old), 0.0=stale (≥5 min)
    "inv_latency_std", # 1 - clip(latency std over history, 0, 500 ms) / 500
    # --- trend features (neutral 0.5 when history unavailable) ---
    "trend_latency",   # 0.5=stable, >0.5=improving, <0.5=degrading
    "trend_loss",
    "trend_rx_bps",
    "trend_jitter",
]
N_FEATURES = len(FEATURE_NAMES)

# Per-feature importance priors used to seed all first-layer neurons.
_FEATURE_IMPORTANCES = [
    4.0, 2.5, 1.5, 1.2, 1.0, 1.0, 0.5, 0.8, 0.5, 0.5,  # original 10  (inv_latency raised to 4.0)
    1.5, 0.6, 0.7, 1.0,                                   # new static 4
    1.5,                                                    # inv_predicted_congestion
    1.8, 1.0,                                              # staleness, inv_latency_std
    2.0, 1.5, 0.8, 0.8,                                   # trend 4  (trend_latency raised to 2.0)
]


def _predicted_congestion_feat(cong: dict, history: list) -> float:
    """Return inv_predicted_congestion in [0, 1]: extrapolated score at +5 min.

    Falls back to the current congestion score when history is too sparse.
    Uses the worst (highest) of current and predicted so the penalty is conservative.
    """
    current_score = cong.get("score") if cong else None
    ts_list: list = []
    sc_list: list = []
    for p in history:
        ts = p.get("timestamp")
        s = (p.get("congestion") or {}).get("score")
        if ts is not None and s is not None:
            ts_list.append(float(ts))
            sc_list.append(float(s))

    if len(ts_list) >= 2:
        pred_raw = _linear_predict_at(ts_list, sc_list, ts_list[-1] + PREDICT_HALFLIFE_S,
                                      halflife_s=120.0)
        if pred_raw is not None:
            pred_score = max(0.0, min(100.0, pred_raw))
            # Conservative: use worst of current vs predicted
            if current_score is not None:
                worst = max(float(current_score), pred_score)
            else:
                worst = pred_score
            return max(0.0, 1.0 - worst / 100.0)

    # No history — fall back to current congestion score
    if current_score is not None:
        return max(0.0, 1.0 - min(float(current_score), 100.0) / 100.0)
    return 0.5   # neutral when no congestion data at all


_LOG_BW_MAX = math.log1p(100e6)   # log1p(100 MB/s) — denominator for log-bw features


def _log_bw(bps) -> float:
    """Log-normalize bytes/s: log1p(bps) / log1p(100 MB/s) → [0, 1].

    Provides good discrimination across the full range from 1 Mbps to 100 Mbps,
    unlike linear normalization which compresses slow links near 0.
    """
    if bps is None:
        return 0.0
    return math.log1p(max(0.0, float(bps))) / _LOG_BW_MAX


def _staleness_feat(payload: dict, max_age_s: float = 300.0) -> float:
    """Return 1.0 when the snapshot is fresh, decaying to 0.0 at max_age_s."""
    ts = payload.get("timestamp")
    if ts is None:
        return 0.5   # unknown age — neutral
    age_s = max(0.0, time.time() - float(ts))
    return max(0.0, 1.0 - age_s / max_age_s)


def _latency_std_feat(history: list) -> float:
    """Return inv_latency_std: 1 - clip(population std of latency, 0, 500 ms) / 500.

    A stable-latency link (low std) scores near 1.0; a jittery link (high std)
    scores near 0.0.  Falls back to 0.5 (neutral) when history is too sparse.
    """
    vals = [float(p["latency"]) for p in history if p.get("latency") is not None]
    if len(vals) < 2:
        return 0.5
    mean = sum(vals) / len(vals)
    std = math.sqrt(sum((v - mean) ** 2 for v in vals) / len(vals))
    return max(0.0, 1.0 - min(std, 500.0) / 500.0)


def _extract_features(payload: dict, history: Optional[list] = None) -> list:
    """Return an N_FEATURES list of floats in [0, 1] where higher = better.

    Missing values fall back to a neutral 0.5 (or 0.0 / 1.0 where noted).
    Bandwidth features use log normalization (better discrimination for slow links).
    Trend/std features (last 6) are computed from *history* when provided; else 0.5.
    """
    def _n(v, lo, hi, inv=False, default=0.5):
        if v is None:
            return default
        v = max(lo, min(hi, float(v)))
        t = (v - lo) / (hi - lo) if hi != lo else 0.0
        return 1.0 - t if inv else t

    bw   = payload.get("bandwidth")  or {}
    sig  = payload.get("signal")     or {}
    bbr  = payload.get("bbr")        or {}
    tc   = payload.get("tc")         or {}
    cong = payload.get("congestion") or {}

    rtt_min = payload.get("rtt_min")
    rtt_max = payload.get("rtt_max")
    rtt_spread = (
        max(0.0, float(rtt_max) - float(rtt_min))
        if rtt_min is not None and rtt_max is not None
        else None
    )

    static = [
        _n(payload.get("latency"),  0,    500, inv=True),
        _n(payload.get("loss"),     0,    100, inv=True),
        _n(payload.get("jitter"),   0,    500, inv=True),
        _n(cong.get("score"),       0,    100, inv=True),
        _log_bw(bw.get("rx_bps")),           # log-scale, 0.0 when missing
        _log_bw(bw.get("tx_bps")),
        _n(sig.get("quality"),      0,    100, default=0.5),
        _log_bw(bbr.get("bw")),
        _n(tc.get("ecn_mark"),      0,   1000, inv=True, default=1.0),
        _n(tc.get("dropped"),       0,   1000, inv=True, default=1.0),
        # buffer bloat: rtt_max - rtt_min, lower spread = better
        _n(rtt_spread,              0,    500, inv=True),
        # cellular signal: RSRP -140 dBm (worst) … -60 dBm (best)
        _n(sig.get("rsrp"),      -140,   -60),
        # cellular signal: SINR -20 dB (worst) … 30 dB (best)
        _n(sig.get("sinr"),       -20,    30),
        # clean baseline RTT from BBR
        _n(bbr.get("min_rtt"),      0,   2000, inv=True),
        # predicted congestion at +5 min: use extrapolated score when history available
        _predicted_congestion_feat(cong, history or []),
        # metric freshness: stale data should not drive routing decisions
        _staleness_feat(payload),
        # latency stability: low std = predictable link quality
        _latency_std_feat(history or []),
    ]
    return static + _extract_trend_features(history or [])


# ---------------------------------------------------------------------------
# Decision engine — PyTorch model (optional, graceful 501 when absent)
# ---------------------------------------------------------------------------

if _TORCH_AVAILABLE:
    class InterfaceScorer(nn.Module):
        """2-hidden-layer MLP scoring WAN interfaces from their feature vectors.

        Input:  (n_interfaces, N_FEATURES) — all features in [0, 1], higher = better
        Output: (n_interfaces,) unnormalized scores
        Apply softmax externally across the interface dimension to get weights.
        Dropout(0.1) regularizes against overfitting on sparse user feedback.
        """
        def __init__(self):
            super().__init__()
            self.net = nn.Sequential(
                nn.Linear(N_FEATURES, 32), nn.ReLU(), nn.Dropout(0.1),
                nn.Linear(32, 16),         nn.ReLU(), nn.Dropout(0.1),
                nn.Linear(16, 1),
            )

        def forward(self, x: "torch.Tensor") -> "torch.Tensor":
            return self.net(x).squeeze(-1)

_decision_model = None
_model_lock = threading.RLock()
_optimizer = None   # persistent Adam; reset when model is reset


def _make_model():
    """Create a fresh InterfaceScorer with heuristic-informed initial weights.

    All 32 neurons of the first layer are seeded with noisy variants of the
    feature-importance vector so that multiple neurons start near the prior
    rather than only the first one.
    """
    model = InterfaceScorer()
    imp = torch.tensor(_FEATURE_IMPORTANCES, dtype=torch.float32)
    imp = imp / imp.norm()
    with torch.no_grad():
        n_hidden = model.net[0].weight.shape[0]
        for i in range(n_hidden):
            noise = torch.randn_like(imp) * 0.15
            row = imp + noise
            model.net[0].weight.data[i] = row / row.norm().clamp(min=1e-6)
        model.net[0].bias.data.zero_()
        # net[1]=ReLU net[2]=Dropout net[3]=Linear(32,16) net[4]=ReLU net[5]=Dropout net[6]=Linear(16,1)
        nn.init.xavier_uniform_(model.net[3].weight)
        model.net[3].bias.data.zero_()
        nn.init.xavier_uniform_(model.net[6].weight)
        model.net[6].bias.data.zero_()
    model.eval()
    return model


def _get_model():
    global _decision_model
    with _model_lock:
        if _decision_model is not None:
            return _decision_model
        if os.path.isfile(DECISION_MODEL_FILE):
            try:
                state = torch.load(DECISION_MODEL_FILE, map_location="cpu", weights_only=True)
                saved_in = state.get("net.0.weight", torch.empty(0, 0)).shape[1]
                if saved_in != N_FEATURES:
                    LOG.warning(
                        "omr_decision: saved model has %d input features but N_FEATURES=%d"
                        " – reinitializing (feature set changed)",
                        saved_in, N_FEATURES,
                    )
                    raise ValueError("feature dimension mismatch")
                m = InterfaceScorer()
                m.load_state_dict(state)
                m.eval()
                _decision_model = m
                _stats_update(model_loaded_at=time.time())
                LOG.info("omr_decision: loaded model from %s", DECISION_MODEL_FILE)
                return _decision_model
            except Exception as exc:
                LOG.warning("omr_decision: cannot load model (%s) – reinitializing", exc)
        _decision_model = _make_model()
        _stats_update(model_loaded_at=time.time())
        return _decision_model


def _save_model(model):
    tmp = DECISION_MODEL_FILE + '.tmp'
    try:
        torch.save(model.state_dict(), tmp)
        os.replace(tmp, DECISION_MODEL_FILE)
    except Exception as exc:
        LOG.debug("omr_decision: save error: %s", exc)


def _safe_float(v: float, default: float = 0.0) -> float:
    """Return v rounded to 4 decimal places, or default when v is nan or ±inf."""
    if math.isnan(v) or math.isinf(v):
        return default
    return round(v, 4)


def _cost_factor(payload: dict) -> float:
    """Return 1/cost so that lower cost → higher score. Neutral (1.0) when absent."""
    c = payload.get("cost")
    return 1.0 / float(c) if c and c > 0 else 1.0


def _apply_cost(raw: list, interfaces: list, user_data: dict) -> list:
    """Scale raw scores by each interface's cost factor and renormalise."""
    scaled = [raw[i] * _cost_factor(user_data[interfaces[i]]) for i in range(len(interfaces))]
    total = sum(scaled)
    if total == 0.0:
        eq = 1.0 / len(interfaces) if interfaces else 1.0
        return [eq] * len(interfaces)
    return [v / total for v in scaled]


def _compute_weights_heuristic(user_data: dict,
                               history_data: Optional[dict] = None) -> dict:
    """Compute interface weights without PyTorch using all available signals.

    Scoring (when online): weighted blend of congestion, latency, loss, jitter,
    signal quality, and ECN marks.  When congestion is available it dominates
    (60 %); otherwise latency + loss carry more weight.  Offline interfaces
    score 0.  Congestion is replaced with the worst of current vs predicted
    (+5 min) when history is available.

    Returns {"probs": {...floats...}, "scores": {...}} for consistency with
    _compute_weights so the route applies EMA and int conversion uniformly.
    """
    _t0 = time.perf_counter()
    interfaces = list(user_data.keys())
    raw: list = []
    for iface in interfaces:
        p = user_data[iface]
        status  = p.get("status")
        latency = p.get("latency")
        if (status and status != "online") or latency is None:
            raw.append(0.0)
            continue

        lat   = float(latency)
        loss  = p.get("loss")
        jitter = p.get("jitter")
        sig_q = (p.get("signal") or {}).get("quality")
        ecn   = (p.get("tc") or {}).get("ecn_mark")
        cong  = (p.get("congestion") or {}).get("score")

        lat_q    = max(0.0, 1.0 - min(lat, 500.0) / 500.0)
        loss_q   = max(0.0, 1.0 - min(float(loss),   100.0) / 100.0) if loss   is not None else 0.5
        jitter_q = max(0.0, 1.0 - min(float(jitter), 500.0) / 500.0) if jitter is not None else 0.5
        signal_q = min(float(sig_q), 100.0) / 100.0                   if sig_q  is not None else 0.5
        ecn_q    = max(0.0, 1.0 - min(float(ecn), 1000.0) / 1000.0)  if ecn    is not None else 1.0

        if cong is not None:
            effective_cong = float(cong)
            hist = (history_data or {}).get(iface, [])
            if len(hist) >= 2:
                fc = _predict_congestion(hist, horizon_s=300)
                pred = fc.get("predicted_score")
                if pred is not None:
                    effective_cong = max(effective_cong, pred)
            cong_q = max(0.0, 100.0 - effective_cong) / 100.0
            quality = (0.35 * lat_q + 0.30 * cong_q + 0.15 * loss_q
                       + 0.10 * jitter_q + 0.05 * signal_q + 0.05 * ecn_q)
        else:
            quality = (0.50 * lat_q + 0.22 * loss_q + 0.15 * jitter_q
                       + 0.07 * signal_q + 0.06 * ecn_q)

        raw.append(quality)

    raw = _apply_cost(raw, interfaces, user_data)

    elapsed_ms = (time.perf_counter() - _t0) * 1000.0
    _stats_inc("heuristic_count", "heuristic_total_ms", elapsed_ms)
    _stats_update(last_heuristic_ms=round(elapsed_ms, 3))

    return {
        "probs":  {iface: raw[i]               for i, iface in enumerate(interfaces)},
        "scores": {iface: round(raw[i] * 100, 2) for i, iface in enumerate(interfaces)},
    }


def _compute_weights(user_data: dict, explain: bool = False,
                     history_data: Optional[dict] = None) -> dict:
    """Run the scorer against current interface metrics and return weights.

    Interfaces with status != 'online' are masked (score = -inf → weight ≈ 0).
    When all interfaces are offline softmax produces nan; we fall back to equal
    weights so the result is always finite and JSON-serializable.
    Returns {'weights': {...}, 'scores': {...}, optionally 'features': {...}}.

    *history_data* is {interface: [payload, ...]} used to compute trend features.
    When absent or for JSON backend, trend features default to neutral (0.5).
    """
    _t0 = time.perf_counter()
    interfaces = list(user_data.keys())
    hist = history_data or {}
    features = {
        iface: _extract_features(payload, history=hist.get(iface))
        for iface, payload in user_data.items()
    }

    with _model_lock:
        model = _get_model()
        feat_tensor = torch.tensor(
            [features[iface] for iface in interfaces], dtype=torch.float32
        )
        with torch.no_grad():
            scores = model(feat_tensor)
            for idx, iface in enumerate(interfaces):
                p      = user_data[iface]
                status  = p.get("status")
                latency = p.get("latency")
                # Treat as down when: status is not "online", status is "ERROR",
                # or latency is null (check failed / interface unreachable).
                if (status and status != "online") or latency is None:
                    scores[idx] = float("-inf")
            weights = torch.softmax(scores, dim=0)
        raw_weights = [float(weights[i]) for i in range(len(interfaces))]

    # All-offline edge case: softmax(-inf, …) → 0/0 → nan; use equal fallback.
    if any(math.isnan(w) for w in raw_weights):
        eq = 1.0 / len(interfaces) if interfaces else 1.0
        raw_weights = [eq] * len(interfaces)

    raw_weights = _apply_cost(raw_weights, interfaces, user_data)

    scores_pct = [round(w * 100, 2) for w in raw_weights]

    elapsed_ms = (time.perf_counter() - _t0) * 1000.0
    _stats_inc("inference_count", "inference_total_ms", elapsed_ms)
    _stats_update(last_inference_ms=round(elapsed_ms, 3))

    # Return raw probabilities so the route can EMA them before int conversion.
    result: dict = {
        "probs":  {iface: raw_weights[i]  for i, iface in enumerate(interfaces)},
        "scores": {iface: scores_pct[i]   for i, iface in enumerate(interfaces)},
    }
    if explain:
        result["features"] = {
            iface: dict(zip(FEATURE_NAMES, [round(v, 4) for v in features[iface]]))
            for iface in interfaces
        }
    return result


def _train_step(user_data: dict, target_weights: dict, lr: float,
                history_data: Optional[dict] = None) -> float:
    """One Adam step minimising KL-divergence between predicted and target distributions.

    KL-divergence is the correct loss for softmax outputs against a probability
    target.  The optimizer is persistent across calls so Adam's moment estimates
    accumulate over multiple feedback rounds.  Returns the scalar loss value.
    At least two interfaces are required; returns 0.0 otherwise.
    """
    global _optimizer
    interfaces = list(user_data.keys())
    if len(interfaces) < 2:
        return 0.0

    _t0 = time.perf_counter()
    hist = history_data or {}
    features = {
        iface: _extract_features(payload, history=hist.get(iface))
        for iface, payload in user_data.items()
    }
    feat_tensor_data = [features[iface] for iface in interfaces]
    target_data = [float(target_weights.get(iface, 0.0)) for iface in interfaces]
    if any((not math.isfinite(v)) or v < 0.0 for v in target_data):
        raise ValueError("Target weights must be finite and non-negative")

    with _model_lock:
        model = _get_model()
        if _optimizer is None:
            _optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
        # Apply user-supplied lr as a clipped one-shot override.
        for pg in _optimizer.param_groups:
            pg["lr"] = max(1e-5, min(0.05, float(lr)))
        feat_tensor = torch.tensor(feat_tensor_data, dtype=torch.float32)
        target = torch.tensor(target_data, dtype=torch.float32)
        total = target.sum()
        if total <= 0:
            raise ValueError("Target weights must assign positive mass to at least one interface")
        target = target / total
        model.train()
        _optimizer.zero_grad()
        log_pred = torch.log_softmax(model(feat_tensor), dim=0)
        loss = torch.nn.functional.kl_div(log_pred, target, reduction="batchmean")
        loss.backward()
        _optimizer.step()
        model.eval()
        loss_val = float(loss)

    elapsed_ms = (time.perf_counter() - _t0) * 1000.0
    with _stats_lock:
        _engine_stats["training_count"] += 1
        _engine_stats["training_total_ms"] += elapsed_ms
        _engine_stats["last_training_ms"] = round(elapsed_ms, 3)
        _engine_stats["last_training_loss"] = round(loss_val, 6)
        _engine_stats["cumulative_loss"] += loss_val
    return loss_val


# ---------------------------------------------------------------------------
# Engine diagnostics helpers
# ---------------------------------------------------------------------------

def _model_meta() -> dict:
    """Return static metadata about the decision model (no inference)."""
    meta: dict = {"torch_available": _TORCH_AVAILABLE}
    if not _TORCH_AVAILABLE:
        return meta

    file_bytes: Optional[int] = None
    if os.path.isfile(DECISION_MODEL_FILE):
        try:
            file_bytes = os.path.getsize(DECISION_MODEL_FILE)
        except OSError:
            pass
    meta["model_file_bytes"] = file_bytes

    param_count: Optional[int] = None
    try:
        m = _get_model()
        param_count = sum(p.numel() for p in m.parameters())
    except Exception:
        pass
    meta["model_parameters"] = param_count
    meta["model_loaded_at"] = _engine_stats.get("model_loaded_at")
    return meta


_INFLUX_METRIC_PREFIXES = (
    # InfluxDB 3.x (IOx / Rust) process metrics exposed via /metrics
    "process_resident_memory_bytes",
    "process_virtual_memory_bytes",
    "process_cpu_seconds_total",
    "iox_catalog_",
    "iox_ingester_",
    "iox_querier_",
    "iox_write_",
    "iox_read_",
    "iox_wal_",
    # InfluxDB 2.x (Go) equivalents
    "influxdb_",
    "go_memstats_",
    "go_gc_",
    "storage_",
    "queryd_",
    "http_api_",
)


def _parse_prometheus_metrics(text: str) -> dict:
    """Parse a Prometheus /metrics text payload into {metric_name: value}.

    Only lines that start with a known prefix and are not comments are kept.
    Label sets are collapsed by keeping only the first occurrence of each base name.
    """
    result: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not any(line.startswith(p) for p in _INFLUX_METRIC_PREFIXES):
            continue
        # metric_name{labels} value [timestamp]  OR  metric_name value [timestamp]
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        name_labels, value_str = parts[0], parts[1]
        base = name_labels.split("{")[0]
        if base in result:
            continue
        try:
            result[base] = float(value_str)
        except ValueError:
            pass
    return result


def _fetch_influx_metrics(influx_url: str, token: str, timeout: int = 5) -> dict:
    """Fetch Prometheus metrics from InfluxDB's /metrics endpoint.

    Returns a filtered dict of metric_name → float, or an error key on failure.
    """
    url = influx_url.rstrip("/") + "/metrics"
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Token {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return {"error": f"HTTP {resp.status}"}
            return _parse_prometheus_metrics(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.URLError as exc:
        return {"error": str(exc)}
    except Exception as exc:
        return {"error": str(exc)}


_INFLUX_CONFIG_PATHS = [
    # InfluxDB 3.x
    "/etc/influxdb3/config.toml",
    "/etc/influxdb3.toml",
    # InfluxDB 2.x
    "/etc/influxdb/config.toml",
    "/etc/influxdb/influxdb.conf",
]

_INFLUX_DATA_DIRS = [
    # InfluxDB 3.x defaults
    "/var/lib/influxdb3",
    # InfluxDB 2.x default
    "/var/lib/influxdb",
]


def _find_influx_data_dir() -> Optional[str]:
    """Return the InfluxDB data directory by reading config or trying defaults."""
    # Try to extract from config files (TOML key  data-dir  or  path)
    for cfg_path in _INFLUX_CONFIG_PATHS:
        if not os.path.isfile(cfg_path):
            continue
        try:
            with open(cfg_path) as f:
                for line in f:
                    line = line.strip()
                    # Match:  data-dir = "/some/path"  or  path = "/some/path"
                    for key in ("data-dir", "data_dir", "path"):
                        if line.startswith(key):
                            parts = line.split("=", 1)
                            if len(parts) == 2:
                                val = parts[1].strip().strip('"').strip("'")
                                if val and os.path.isdir(val):
                                    return val
        except OSError:
            pass

    for d in _INFLUX_DATA_DIRS:
        if os.path.isdir(d):
            return d
    return None


def _dir_size_bytes(path: str) -> int:
    """Return total bytes of all regular files under *path* (follows no symlinks)."""
    total = 0
    try:
        for dirpath, _, filenames in os.walk(path):
            for fname in filenames:
                try:
                    total += os.path.getsize(os.path.join(dirpath, fname))
                except OSError:
                    pass
    except OSError:
        pass
    return total


def _backend_meta() -> dict:
    """Return storage backend stats."""
    backend = _get_backend()
    if isinstance(backend, JSONBackend):
        size: Optional[int] = None
        try:
            size = os.path.getsize(METRICS_FILE) if os.path.isfile(METRICS_FILE) else 0
        except OSError:
            pass
        return {"backend": "json", "file_bytes": size, "file_path": METRICS_FILE}

    # InfluxDB backend — read config to get URL + token, then fetch /metrics
    influx_cfg: dict = {}
    try:
        with open(OMR_CONFIG_FILE) as f:
            influx_cfg = json.load(f).get("influxdb") or {}
    except Exception:
        pass
    url   = influx_cfg.get("url", "")
    token = influx_cfg.get("token", "")
    bucket = influx_cfg.get("bucket", "omr_metrics")
    result: dict = {"backend": "influxdb", "url": url, "bucket": bucket}

    data_dir = _find_influx_data_dir()
    result["data_dir"] = data_dir
    result["data_dir_bytes"] = _dir_size_bytes(data_dir) if data_dir else None

    if url:
        result["influxdb_metrics"] = _fetch_influx_metrics(url, token)
    return result


def _engine_diagnostics() -> dict:
    """Assemble the full engine diagnostics snapshot."""
    with _stats_lock:
        stats = dict(_engine_stats)

    # Derived averages (avoid ZeroDivision)
    ic = stats["inference_count"]
    hc = stats["heuristic_count"]
    tc = stats["training_count"]
    stats["avg_inference_ms"]  = round(stats["inference_total_ms"]  / ic, 3) if ic else None
    stats["avg_heuristic_ms"]  = round(stats["heuristic_total_ms"]  / hc, 3) if hc else None
    stats["avg_training_ms"]   = round(stats["training_total_ms"]   / tc, 3) if tc else None
    stats["avg_training_loss"] = round(stats["cumulative_loss"]      / tc, 6) if tc else None

    return {
        "model":   _model_meta(),
        "runtime": stats,
        "storage": _backend_meta(),
    }


def _validate_feedback_weights(user_data: dict, weights: Dict[str, float]) -> dict:
    """Validate free-form training weights against known interfaces.

    Accepts partial mappings but requires at least one known interface to carry
    a strictly positive finite weight.
    """
    target_weights: dict = {}
    total = 0.0
    for iface in user_data:
        value = float(weights.get(iface, 0.0))
        if not math.isfinite(value):
            raise ValueError(f"Invalid weight for interface: {iface}")
        if value < 0.0:
            raise ValueError(f"Negative weight not allowed for interface: {iface}")
        target_weights[iface] = value
        total += value
    if total <= 0.0:
        raise ValueError("Provide at least one positive weight for a known interface")
    return target_weights


# ---------------------------------------------------------------------------
# Router factory — avoids circular imports with omradmin.py
# ---------------------------------------------------------------------------

def create_router(get_current_user, get_current_active_user, User) -> APIRouter:
    """Return an APIRouter with /metrics and /metrics/decision endpoints."""
    router = APIRouter()

    # ---- metrics storage endpoints ----------------------------------------

    @router.get('/metrics', summary="Get stored router metrics for the current user")
    async def get_metrics(
        username: Optional[str] = Query(None),
        interface: Optional[str] = Query(None),
        current_user: User = Depends(get_current_user),
    ):
        target = username if current_user.permissions == "admin" and username else current_user.username
        user_data = _read_user(target)
        if interface:
            return user_data.get(interface, {})
        return user_data

    @router.post('/metrics', summary="Store router metrics for one WAN interface")
    async def set_metrics(
        metrics: InterfaceMetrics,
        username: Optional[str] = Query(None),
        current_user: User = Depends(get_current_active_user),
    ):
        target = username if current_user.permissions == "admin" and username else current_user.username
        payload = metrics.model_dump()
        if payload.get('timestamp') is None:
            payload['timestamp'] = int(time.time())
        _write_interface(target, payload)
        return {'result': 'ok'}

    @router.get('/metrics/all', summary="Get stored metrics for all users (admin only)")
    async def get_all_metrics(current_user: User = Depends(get_current_user)):
        if current_user.permissions != "admin":
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail="Admin only")
        return _read_all()

    @router.get('/metrics/user', summary="Get current user profile and metrics DB stats")
    async def get_user_info(
        username: Optional[str] = Query(None),
        current_user: User = Depends(get_current_user),
    ):
        """Return metrics DB statistics for the user: entry count, first/last seen
        timestamps and known WAN interfaces.
        With the JSON backend entry_count equals the number of interfaces
        (only the latest snapshot per interface is stored).
        """
        target = username if current_user.permissions == "admin" and username else current_user.username
        import asyncio
        stats = await asyncio.to_thread(_user_stats, target)
        return {"username": target, **stats}

    _501_history = JSONResponse(
        status_code=501,
        content={"error": "History not available with JSON backend", "hint": "Configure InfluxDB in omr-admin-config.json"},
    )

    @router.get('/metrics/history', summary="Get historical metrics for WAN interfaces (InfluxDB only)")
    async def get_metrics_history(
        interface: Optional[str] = Query(None, description="WAN interface name; omit to get all interfaces"),
        since: str = Query("1h", description="How far back to look: 15m 30m 1h 6h 12h 24h 2d 7d 30d or seconds"),
        limit: int = Query(1000, ge=1, le=10000, description="Maximum number of data points"),
        username: Optional[str] = Query(None),
        current_user: User = Depends(get_current_user),
    ):
        if isinstance(_get_backend(), JSONBackend):
            return _501_history
        target = username if current_user.permissions == "admin" and username else current_user.username
        since_seconds = _parse_since(since)
        return _read_history(target, interface, since_seconds, limit)

    # ---- decision endpoints -----------------------------------------------

    _501 = JSONResponse(
        status_code=501,
        content={"error": "PyTorch not installed", "hint": "pip install torch"},
    )

    @router.get('/metrics/decision', summary="Get model-assigned weight for each WAN interface")
    async def get_decision(
        username: Optional[str] = Query(None),
        explain: bool = Query(False, description="Include per-interface feature breakdown"),
        predict: bool = Query(False, description="Extrapolate metrics forward in time before scoring"),
        horizon: int = Query(300, ge=1, le=86400, description="Prediction horizon in seconds (default 300 = 5 min)"),
        preemptive: bool = Query(True, description="Fetch history to penalise rising congestion before it peaks"),
        current_user: User = Depends(get_current_user),
    ):
        target = username if current_user.permissions == "admin" and username else current_user.username
        user_data = _read_user(target)
        if not user_data:
            return {}

        history_data: dict = {}
        has_history_backend = not isinstance(_get_backend(), JSONBackend)

        if predict:
            async def _pfetch(iface):
                h = await asyncio.to_thread(_read_history, target, iface,
                                            max(horizon * 10, 3600), 50)
                return iface, h

            predicted_data = {}
            for iface, hist in await asyncio.gather(*[_pfetch(i) for i in user_data]):
                if len(hist) >= 2:
                    predicted_data[iface] = _predict_payload(hist, horizon_seconds=horizon)
                    history_data[iface] = hist   # reuse for trend and congestion features
                else:
                    predicted_data[iface] = user_data[iface]
            user_data = predicted_data
        elif preemptive and has_history_backend:
            async def _hfetch(iface):
                return iface, await asyncio.to_thread(_read_history, target, iface, 3600, 60)

            for iface, hist in await asyncio.gather(*[_hfetch(i) for i in user_data]):
                if hist:
                    history_data[iface] = hist

        if not _TORCH_AVAILABLE:
            result = _compute_weights_heuristic(user_data, history_data=history_data)
        else:
            result = _compute_weights(user_data, explain=explain, history_data=history_data)

        # EMA on raw probabilities (floats) then convert to [1, 255] integers.
        smoothed_probs = _apply_ema(target, result.get("probs", {}))
        int_weights = {iface: max(1, round(p * 255)) for iface, p in smoothed_probs.items()}
        output = {k: v for k, v in result.items() if k != "probs"}
        return {**output, "weights": int_weights}

    @router.get('/metrics/quality/forecast',
                summary="Combined quality forecast: congestion, loss, jitter and RTT per WAN interface")
    async def get_quality_forecast(
        horizon: int = Query(300, ge=30, le=3600,
                             description="Prediction horizon in seconds (default 300 = 5 min)"),
        since: str = Query("1h", description="History window: 15m 30m 1h 6h 12h 24h or seconds"),
        limit: int = Query(100, ge=10, le=1000,
                           description="Maximum history points per interface"),
        username: Optional[str] = Query(None),
        current_user: User = Depends(get_current_user),
    ):
        """Return a combined quality forecast for every WAN interface.

        Each interface entry contains four sub-objects — congestion, loss, jitter, rtt —
        each with: current / current_level / predicted / predicted_level /
        trend / slope_per_min / eta_severe_s / eta_high_s / eta_moderate_s / confidence.
        RTT levels: none (<50 ms), low (<100 ms), moderate (<200 ms), high (<500 ms), severe (≥500 ms).

        Works with the JSON backend but returns confidence="none" for all metrics
        (only a single snapshot is available).
        """
        target = username if current_user.permissions == "admin" and username else current_user.username
        user_data = _read_user(target)
        if not user_data:
            return {}

        since_seconds = _parse_since(since)

        async def _qfetch(iface):
            h = await asyncio.to_thread(_read_history, target, iface, since_seconds, limit)
            if not h:
                snap = user_data[iface]
                h = [snap] if snap.get("timestamp") is not None else []
            return iface, h

        result: dict = {}
        for iface, hist in await asyncio.gather(*[_qfetch(i) for i in user_data]):
            result[iface] = {
                "congestion": _forecast_metric(
                    hist, ("congestion", "score"), _CONGESTION_LEVELS,
                    hi_clamp=100.0, stable_slope_per_min=0.5, horizon_s=horizon,
                    halflife_s=120.0,   # congestion reacts quickly
                ),
                "loss": _forecast_metric(
                    hist, ("loss",), _LOSS_THRESHOLDS,
                    hi_clamp=100.0, stable_slope_per_min=0.1, horizon_s=horizon,
                    halflife_s=180.0,
                ),
                "jitter": _forecast_metric(
                    hist, ("jitter",), _JITTER_THRESHOLDS,
                    hi_clamp=None, stable_slope_per_min=0.5, horizon_s=horizon,
                    halflife_s=180.0,
                ),
                "rtt": _forecast_metric(
                    hist, ("rtt_min",), _RTT_THRESHOLDS,
                    hi_clamp=None, stable_slope_per_min=2.0, horizon_s=horizon,
                    halflife_s=180.0,
                ),
            }

        return result

    @router.post('/metrics/decision/train',
                 summary="Submit interface quality feedback to fine-tune the scorer")
    async def train_decision(
        feedback: DecisionFeedback,
        username: Optional[str] = Query(None),
        current_user: User = Depends(get_current_active_user),
    ):
        if not _TORCH_AVAILABLE:
            return _501
        from fastapi import HTTPException
        if current_user.permissions != "admin":
            raise HTTPException(status_code=403, detail="Admin only")
        target = username if username else current_user.username
        user_data = _read_user(target)
        if not user_data:
            raise HTTPException(status_code=404, detail="No metrics stored for this user")

        if feedback.best_interface:
            if feedback.best_interface not in user_data:
                raise HTTPException(
                    status_code=422,
                    detail=f"Unknown interface: {feedback.best_interface}",
                )
            target_weights = {
                iface: (1.0 if iface == feedback.best_interface else 0.0)
                for iface in user_data
            }
        elif feedback.weights:
            try:
                target_weights = _validate_feedback_weights(user_data, feedback.weights)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
        else:
            raise HTTPException(status_code=422, detail="Provide 'best_interface' or 'weights'")

        history_data: dict = {}
        if not isinstance(_get_backend(), JSONBackend):
            async def _hfetch(iface):
                return iface, await asyncio.to_thread(_read_history, target, iface, 3600, 60)

            for iface, hist in await asyncio.gather(*[_hfetch(i) for i in user_data]):
                if hist:
                    history_data[iface] = hist

        loss = _train_step(
            user_data,
            target_weights,
            feedback.learning_rate,
            history_data=history_data,
        )
        _save_model(_get_model())
        return {"result": "ok", "loss": round(loss, 6)}

    @router.post('/metrics/decision/reset',
                 summary="Reset the scorer to heuristic initialization (admin only)")
    async def reset_decision(current_user: User = Depends(get_current_user)):
        if not _TORCH_AVAILABLE:
            return _501
        from fastapi import HTTPException
        if current_user.permissions != "admin":
            raise HTTPException(status_code=403, detail="Admin only")
        global _decision_model, _optimizer
        with _model_lock:
            _decision_model = _make_model()
            _optimizer = None   # force a fresh Adam for the new model
            _save_model(_decision_model)
        with _stats_lock:
            _engine_stats["model_resets"] += 1
            _engine_stats["model_loaded_at"] = time.time()
        return {"result": "ok"}

    # ---- engine diagnostics endpoint ----------------------------------------

    @router.get('/metrics/engine',
                summary="Decision engine and storage backend diagnostics (admin only)")
    async def get_engine_diagnostics(current_user: User = Depends(get_current_user)):
        from fastapi import HTTPException
        if current_user.permissions != "admin":
            raise HTTPException(status_code=403, detail="Admin only")
        import asyncio
        return await asyncio.to_thread(_engine_diagnostics)

    return router

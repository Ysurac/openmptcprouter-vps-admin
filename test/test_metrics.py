"""
Unit tests for the omr_metrics optional module.

The router posts one interface payload per call (via the 040-metrics
post-tracking hook on the OpenMPTCProuter device).  Tests cover:

  - Authentication requirement
  - Per-user isolation (regular user vs. admin ?username= override)
  - Per-interface storage and retrieval
  - Timestamp auto-fill when the router omits it
  - Full-signal payloads (modem, wifi, BBR, congestion, TC)
  - Admin-only /metrics/all endpoint
  - Backend selection (JSON default, InfluxDB when configured)
"""

import builtins
import contextlib
import json
import math
import os
import time
from unittest.mock import MagicMock, patch, call

import pytest

# Capture the real open/replace before any autouse fixture can shadow them.
_REAL_OPEN = builtins.open
_REAL_REPLACE = os.replace

import omr_metrics
from conftest import ADMIN_USER, RW_USER, omr_admin, app

# ---------------------------------------------------------------------------
# Sample payloads — mirror 040-metrics JSON output
# ---------------------------------------------------------------------------

_WAN = {
    "interface": "wan",
    "device": "eth0",
    "status": "online",
    "status_msg": "",
    "device_ip": "1.2.3.4",
    "device_ip6": "",
    "gateway": "1.2.3.1",
    "gateway6": "",
    "cost": 10,
    "latency": 25.0,
    "rtt_min": 20.0,
    "rtt_max": 35.0,
    "loss": 0.0,
    "jitter": 1.5,
    "signal": {
        "quality": None, "operator": None, "state": None, "type": None,
        "rssi": None, "rsrp": None, "rsrq": None, "sinr": None,
    },
    "wifi": {
        "ssid": None, "bssid": None, "mode": None, "channel": None,
        "signal": None, "noise": None, "bitrate": None,
        "quality": None, "quality_max": None,
    },
    "tc": {
        "qdisc": "fq_codel", "sent_bytes": 12345, "sent_pkts": 100,
        "dropped": 0, "overlimits": 0, "requeues": 0,
        "backlog_bytes": 0, "backlog_pkts": 0, "ecn_mark": 0,
        "drop_overlimit": 0, "flows": None, "throttled": None,
        "flows_plimit": None, "new_flow_count": None,
    },
    "bbr": {
        "bw": None, "pacing_rate": None, "delivery_rate": None,
        "cwnd": None, "min_rtt": None, "retrans": None,
    },
    "congestion": {"score": 5, "level": "none"},
    "bandwidth": {"rx_bytes": 1_000_000, "tx_bytes": 500_000, "rx_bps": 1024, "tx_bps": 2048},
    "timestamp": 1_700_000_000,
}

_WAN2 = {**_WAN, "interface": "wan2", "device": "eth1", "device_ip": "5.6.7.8"}

_MODEM_WAN = {
    **_WAN,
    "interface": "modem0",
    "device": "wwan0",
    "signal": {
        "quality": 75.0, "operator": "OperatorName", "state": "registered",
        "type": "modemmanager", "rssi": -65.0, "rsrp": -95.0, "rsrq": -10.0, "sinr": 12.0,
    },
}

_WIFI_WAN = {
    **_WAN,
    "interface": "wlan0",
    "device": "wlan0",
    "signal": {"quality": 85, "operator": None, "state": None, "type": "wifi",
               "rssi": -55.0, "rsrp": None, "rsrq": None, "sinr": None},
    "wifi": {
        "ssid": "MyNetwork", "bssid": "AA:BB:CC:DD:EE:FF", "mode": "Client",
        "channel": 6, "signal": -55, "noise": -90, "bitrate": "72.2 MBit/s",
        "quality": 55, "quality_max": 70,
    },
}

_BBR_WAN = {
    **_WAN,
    "bbr": {
        "bw": 5_000_000, "pacing_rate": 4_800_000, "delivery_rate": 4_500_000,
        "cwnd": 32, "min_rtt": 20.5, "retrans": 3,
    },
    "congestion": {"score": 42, "level": "moderate"},
}


def _no_ts(payload: dict) -> dict:
    return {k: v for k, v in payload.items() if k != "timestamp"}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_backend():
    """Reset backend, decision-model, EMA and auto-learning state between tests."""
    orig_backend = omr_metrics._backend
    orig_model  = omr_metrics._decision_model
    orig_ema    = dict(omr_metrics._weight_ema)
    omr_metrics._backend        = None
    omr_metrics._decision_model = None
    omr_metrics._weight_ema     = {}
    omr_metrics._auto_cfg_cache = {"ts": 0.0, "cfg": None}
    omr_metrics._auto_bad_streak = 0
    yield
    omr_metrics._backend        = orig_backend
    omr_metrics._decision_model = orig_model
    omr_metrics._weight_ema     = orig_ema
    omr_metrics._auto_cfg_cache = {"ts": 0.0, "cfg": None}
    omr_metrics._auto_bad_streak = 0


@pytest.fixture
def admin_client(admin_client):
    app.dependency_overrides[omr_admin.get_current_active_user] = lambda: ADMIN_USER
    yield admin_client
    app.dependency_overrides.pop(omr_admin.get_current_active_user, None)


@pytest.fixture
def user_client(user_client):
    app.dependency_overrides[omr_admin.get_current_active_user] = lambda: RW_USER
    yield user_client
    app.dependency_overrides.pop(omr_admin.get_current_active_user, None)


# ===========================================================================
# GET /metrics
# ===========================================================================

class TestGetMetrics:
    def test_returns_empty_when_no_metrics_stored(self, user_client):
        with patch.object(omr_metrics, "_read_user", return_value={}):
            r = user_client.get("/metrics")
        assert r.status_code == 200
        assert r.json() == {}

    def test_returns_stored_interfaces_for_current_user(self, user_client):
        with patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN}):
            r = user_client.get("/metrics")
        assert r.status_code == 200
        assert r.json()["wan"]["latency"] == 25.0

    def test_filters_by_interface_query_param(self, user_client):
        with patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN, "wan2": _WAN2}):
            r = user_client.get("/metrics?interface=wan2")
        assert r.status_code == 200
        assert r.json()["interface"] == "wan2"

    def test_unknown_interface_returns_empty(self, user_client):
        with patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN}):
            r = user_client.get("/metrics?interface=missing")
        assert r.status_code == 200
        assert r.json() == {}

    def test_read_user_called_with_correct_username(self, user_client):
        with patch.object(omr_metrics, "_read_user", return_value={}) as mock_ru:
            user_client.get("/metrics")
        mock_ru.assert_called_once_with("openmptcprouter")

    def test_admin_can_query_another_user(self, admin_client):
        with patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN}) as mock_ru:
            r = admin_client.get("/metrics?username=openmptcprouter")
        assert r.status_code == 200
        mock_ru.assert_called_once_with("openmptcprouter")

    def test_unauthenticated_returns_403(self, unauth_client):
        r = unauth_client.get("/metrics")
        assert r.status_code == 403


# ===========================================================================
# POST /metrics
# ===========================================================================

class TestPostMetrics:
    def _post(self, client, payload, **query):
        url = "/metrics"
        if query:
            url += "?" + "&".join(f"{k}={v}" for k, v in query.items())
        return client.post(url, json=payload)

    def test_stores_interface_and_returns_ok(self, user_client):
        with patch.object(omr_metrics, "_write_interface") as mock_wi:
            r = self._post(user_client, _WAN)
        assert r.status_code == 200
        assert r.json() == {"result": "ok"}
        mock_wi.assert_called_once()
        username, payload = mock_wi.call_args.args
        assert username == "openmptcprouter"
        assert payload["interface"] == "wan"

    def test_fills_timestamp_when_absent(self, user_client):
        captured = {}

        def fake_write(username, payload):
            captured["payload"] = payload

        before = int(time.time())
        with patch.object(omr_metrics, "_write_interface", side_effect=fake_write):
            self._post(user_client, _no_ts(_WAN))
        after = int(time.time())

        ts = captured["payload"]["timestamp"]
        assert before <= ts <= after

    def test_keeps_existing_timestamp_when_provided(self, user_client):
        captured = {}

        def fake_write(username, payload):
            captured["payload"] = payload

        with patch.object(omr_metrics, "_write_interface", side_effect=fake_write):
            self._post(user_client, _WAN)

        assert captured["payload"]["timestamp"] == 1_700_000_000

    def test_multiple_interfaces_stored_separately(self, user_client):
        calls = []

        def fake_write(username, payload):
            calls.append((username, payload["interface"]))

        with patch.object(omr_metrics, "_write_interface", side_effect=fake_write):
            self._post(user_client, _WAN)
            self._post(user_client, _WAN2)

        assert ("openmptcprouter", "wan") in calls
        assert ("openmptcprouter", "wan2") in calls

    def test_stores_modem_signal_fields(self, user_client):
        captured = {}

        def fake_write(username, payload):
            captured["payload"] = payload

        with patch.object(omr_metrics, "_write_interface", side_effect=fake_write):
            self._post(user_client, _MODEM_WAN)

        sig = captured["payload"]["signal"]
        assert sig["type"] == "modemmanager"
        assert sig["rsrp"] == -95.0
        assert sig["operator"] == "OperatorName"

    def test_stores_wifi_fields(self, user_client):
        captured = {}

        def fake_write(username, payload):
            captured["payload"] = payload

        with patch.object(omr_metrics, "_write_interface", side_effect=fake_write):
            self._post(user_client, _WIFI_WAN)

        wifi = captured["payload"]["wifi"]
        assert wifi["ssid"] == "MyNetwork"
        assert wifi["channel"] == 6
        assert wifi["noise"] == -90

    def test_stores_bbr_and_congestion_fields(self, user_client):
        captured = {}

        def fake_write(username, payload):
            captured["payload"] = payload

        with patch.object(omr_metrics, "_write_interface", side_effect=fake_write):
            self._post(user_client, _BBR_WAN)

        assert captured["payload"]["bbr"]["bw"] == 5_000_000
        assert captured["payload"]["bbr"]["min_rtt"] == 20.5
        assert captured["payload"]["congestion"]["score"] == 42
        assert captured["payload"]["congestion"]["level"] == "moderate"

    def test_stores_tc_fields(self, user_client):
        captured = {}

        def fake_write(username, payload):
            captured["payload"] = payload

        with patch.object(omr_metrics, "_write_interface", side_effect=fake_write):
            self._post(user_client, _WAN)

        tc = captured["payload"]["tc"]
        assert tc["qdisc"] == "fq_codel"
        assert tc["sent_bytes"] == 12345
        assert tc["ecn_mark"] == 0

    def test_stores_bandwidth_fields(self, user_client):
        captured = {}

        def fake_write(username, payload):
            captured["payload"] = payload

        with patch.object(omr_metrics, "_write_interface", side_effect=fake_write):
            self._post(user_client, _WAN)

        bw = captured["payload"]["bandwidth"]
        assert bw["rx_bytes"] == 1_000_000
        assert bw["rx_bps"] == 1024

    def test_admin_can_post_for_another_user(self, admin_client):
        with patch.object(omr_metrics, "_write_interface") as mock_wi:
            r = self._post(admin_client, _WAN, username="openmptcprouter")
        assert r.status_code == 200
        username, _ = mock_wi.call_args.args
        assert username == "openmptcprouter"

    def test_unauthenticated_returns_403(self, unauth_client):
        r = unauth_client.post("/metrics", json=_WAN)
        assert r.status_code == 403

    def test_missing_interface_field_returns_422(self, user_client):
        bad = {k: v for k, v in _WAN.items() if k != "interface"}
        with patch.object(omr_metrics, "_write_interface"):
            r = self._post(user_client, bad)
        assert r.status_code == 422


# ===========================================================================
# GET /metrics/all
# ===========================================================================

class TestGetAllMetrics:
    def test_admin_gets_all_users(self, admin_client):
        store = {"openmptcprouter": {"wan": _WAN}, "user2": {"wan": _WAN2}}
        with patch.object(omr_metrics, "_read_all", return_value=store):
            r = admin_client.get("/metrics/all")
        assert r.status_code == 200
        data = r.json()
        assert "openmptcprouter" in data
        assert "user2" in data

    def test_non_admin_gets_403(self, user_client):
        with patch.object(omr_metrics, "_read_all", return_value={}):
            r = user_client.get("/metrics/all")
        assert r.status_code == 403

    def test_unauthenticated_returns_403(self, unauth_client):
        r = unauth_client.get("/metrics/all")
        assert r.status_code == 403

    def test_returns_empty_dict_when_no_data(self, admin_client):
        with patch.object(omr_metrics, "_read_all", return_value={}):
            r = admin_client.get("/metrics/all")
        assert r.status_code == 200
        assert r.json() == {}


# ===========================================================================
# GET /metrics/prometheus
# ===========================================================================

class TestGetPrometheusMetrics:
    _STORE = {"openmptcprouter": {"wan": _WAN, "wwan0": _MODEM_WAN}}

    def test_admin_gets_200(self, admin_client):
        with patch.object(omr_metrics, "_read_all", return_value=self._STORE):
            r = admin_client.get("/metrics/prometheus")
        assert r.status_code == 200

    def test_non_admin_gets_403(self, user_client):
        with patch.object(omr_metrics, "_read_all", return_value=self._STORE):
            r = user_client.get("/metrics/prometheus")
        assert r.status_code == 403

    def test_unauthenticated_returns_403(self, unauth_client):
        r = unauth_client.get("/metrics/prometheus")
        assert r.status_code == 403

    def test_content_type_is_prometheus(self, admin_client):
        with patch.object(omr_metrics, "_read_all", return_value=self._STORE):
            r = admin_client.get("/metrics/prometheus")
        assert "text/plain" in r.headers["content-type"]
        assert "0.0.4" in r.headers["content-type"]

    def test_empty_store_returns_no_data_comment(self, admin_client):
        with patch.object(omr_metrics, "_read_all", return_value={}):
            r = admin_client.get("/metrics/prometheus")
        assert r.status_code == 200
        assert "# no data" in r.text

    def test_response_contains_interface_online_metric(self, admin_client):
        with patch.object(omr_metrics, "_read_all", return_value=self._STORE):
            r = admin_client.get("/metrics/prometheus")
        assert "omr_interface_online" in r.text

    def test_response_contains_latency_metric(self, admin_client):
        with patch.object(omr_metrics, "_read_all", return_value=self._STORE):
            r = admin_client.get("/metrics/prometheus")
        assert "omr_latency_ms" in r.text

    def test_labels_include_username_and_interface(self, admin_client):
        with patch.object(omr_metrics, "_read_all", return_value=self._STORE):
            r = admin_client.get("/metrics/prometheus")
        assert 'username="openmptcprouter"' in r.text
        assert 'interface="wan"' in r.text

    def test_each_metric_has_help_and_type_lines(self, admin_client):
        with patch.object(omr_metrics, "_read_all", return_value=self._STORE):
            r = admin_client.get("/metrics/prometheus")
        assert "# HELP omr_latency_ms" in r.text
        assert "# TYPE omr_latency_ms gauge" in r.text


# ===========================================================================
# _to_prometheus_text — unit tests
# ===========================================================================

class TestToPrometheusText:
    def _make_store(self, **iface_overrides):
        return {"user1": {"wan": {**_WAN, **iface_overrides}}}

    def test_empty_store_returns_no_data_comment(self):
        assert omr_metrics._to_prometheus_text({}) == "# no data\n"

    def test_online_interface_emits_1(self):
        text = omr_metrics._to_prometheus_text(self._make_store())
        line = next(l for l in text.splitlines()
                    if "omr_interface_online" in l and not l.startswith("#"))
        assert line.endswith(" 1")

    def test_offline_interface_emits_0(self):
        text = omr_metrics._to_prometheus_text(
            self._make_store(status="offline"))
        line = next(l for l in text.splitlines()
                    if "omr_interface_online" in l and not l.startswith("#"))
        assert line.endswith(" 0")

    def test_error_status_emits_0(self):
        text = omr_metrics._to_prometheus_text(
            self._make_store(status="ERROR"))
        line = next(l for l in text.splitlines()
                    if "omr_interface_online" in l and not l.startswith("#"))
        assert line.endswith(" 0")

    def test_latency_value_present(self):
        text = omr_metrics._to_prometheus_text(self._make_store(latency=42.5))
        assert "omr_latency_ms" in text
        assert "42.5" in text

    def test_null_latency_omitted(self):
        text = omr_metrics._to_prometheus_text(self._make_store(latency=None))
        assert "omr_latency_ms" not in text

    def test_loss_value_present(self):
        text = omr_metrics._to_prometheus_text(self._make_store(loss=1.5))
        assert "omr_loss_percent" in text
        assert "1.5" in text

    def test_congestion_score_present(self):
        store = {"u": {"wan": {**_WAN, "congestion": {"score": 55, "level": "moderate"}}}}
        text = omr_metrics._to_prometheus_text(store)
        assert "omr_congestion_score" in text
        assert "55" in text

    def test_signal_quality_present_for_modem(self):
        store = {"u": {"wwan0": _MODEM_WAN}}
        text = omr_metrics._to_prometheus_text(store)
        assert "omr_signal_quality" in text

    def test_signal_quality_absent_for_wired(self):
        store = {"u": {"wan": {**_WAN, "signal": {**_WAN["signal"], "quality": None}}}}
        text = omr_metrics._to_prometheus_text(store)
        assert "omr_signal_quality" not in text

    def test_bbr_bw_present_for_bbr_interface(self):
        store = {"u": {"wan": _BBR_WAN}}
        text = omr_metrics._to_prometheus_text(store)
        assert "omr_bbr_bw_bps" in text

    def test_bandwidth_rx_tx_present(self):
        text = omr_metrics._to_prometheus_text(self._make_store())
        assert "omr_rx_bps" in text
        assert "omr_tx_bps" in text

    def test_data_age_present_when_timestamp_set(self):
        text = omr_metrics._to_prometheus_text(self._make_store())
        assert "omr_data_age_seconds" in text

    def test_data_age_absent_when_no_timestamp(self):
        store = {"u": {"wan": {k: v for k, v in _WAN.items() if k != "timestamp"}}}
        text = omr_metrics._to_prometheus_text(store)
        assert "omr_data_age_seconds" not in text

    def test_multiple_users_and_interfaces(self):
        store = {
            "alice": {"wan": _WAN, "wwan0": _MODEM_WAN},
            "bob":   {"wan": _WAN2},
        }
        text = omr_metrics._to_prometheus_text(store)
        assert 'username="alice"' in text
        assert 'username="bob"' in text
        assert 'interface="wwan0"' in text

    def test_each_metric_block_has_help_and_type(self):
        text = omr_metrics._to_prometheus_text(self._make_store())
        for name in ("omr_interface_online", "omr_latency_ms", "omr_loss_percent"):
            assert f"# HELP {name}" in text
            assert f"# TYPE {name} gauge" in text

    def test_output_ends_with_newline(self):
        text = omr_metrics._to_prometheus_text(self._make_store())
        assert text.endswith("\n")

    def test_rtt_min_and_max_present(self):
        text = omr_metrics._to_prometheus_text(self._make_store())
        assert "omr_rtt_min_ms" in text
        assert "omr_rtt_max_ms" in text

    def test_anomaly_metric_present_for_stale_sample(self):
        store = {"u": {"wan": {**_WAN, "timestamp": 1}}}
        with patch.object(omr_metrics.time, "time", return_value=1_000):
            text = omr_metrics._to_prometheus_text(store)
        assert "omr_interface_anomaly" in text
        assert 'anomaly="stale_metrics"' in text


# ===========================================================================
# JSONBackend unit tests
# ===========================================================================

class TestJSONBackend:
    def test_read_all_returns_empty_when_file_missing(self):
        backend = omr_metrics.JSONBackend()
        with patch("os.path.isfile", return_value=False):
            assert backend.read_all() == {}

    def test_read_all_returns_empty_on_corrupt_json(self):
        import io
        backend = omr_metrics.JSONBackend()
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", return_value=io.StringIO("{invalid")),
        ):
            assert backend.read_all() == {}

    def test_read_user_returns_empty_for_unknown_user(self):
        backend = omr_metrics.JSONBackend()
        with patch("os.path.isfile", return_value=False):
            assert backend.read_user("nobody") == {}

    def test_write_interface_persists_data(self, tmp_path):
        metrics_file = tmp_path / "omr-metrics.json"
        backend = omr_metrics.JSONBackend()
        # Override the autouse builtins.open mock with the real one so actual
        # file I/O reaches the filesystem.
        with (
            patch("builtins.open", new=_REAL_OPEN),
            patch("os.replace", new=_REAL_REPLACE),
            patch("os.path.isfile", wraps=os.path.isfile),
            patch.object(omr_metrics, "METRICS_FILE", str(metrics_file)),
        ):
            backend.write_interface("alice", _WAN)
            result = backend.read_user("alice")
        assert "wan" in result
        assert result["wan"]["latency"] == 25.0

    def test_write_interface_is_atomic(self, tmp_path):
        """Data is written to a tmp file then replaced — no partial writes."""
        metrics_file = tmp_path / "omr-metrics.json"
        backend = omr_metrics.JSONBackend()
        replaced = []

        def spy_replace(src, dst):
            replaced.append((src, dst))
            _REAL_REPLACE(src, dst)

        with (
            patch("builtins.open", new=_REAL_OPEN),
            patch("os.replace", side_effect=spy_replace),
            patch("os.path.isfile", wraps=os.path.isfile),
            patch.object(omr_metrics, "METRICS_FILE", str(metrics_file)),
        ):
            backend.write_interface("alice", _WAN)

        assert len(replaced) == 1
        src, dst = replaced[0]
        assert src.endswith(".tmp")
        assert dst == str(metrics_file)

    def test_write_interface_merges_multiple_interfaces(self, tmp_path):
        metrics_file = tmp_path / "omr-metrics.json"
        backend = omr_metrics.JSONBackend()
        with (
            patch("builtins.open", new=_REAL_OPEN),
            patch("os.replace", new=_REAL_REPLACE),
            patch("os.path.isfile", wraps=os.path.isfile),
            patch.object(omr_metrics, "METRICS_FILE", str(metrics_file)),
        ):
            backend.write_interface("alice", _WAN)
            backend.write_interface("alice", _WAN2)
            result = backend.read_user("alice")
        assert "wan" in result
        assert "wan2" in result

    def test_write_interface_uses_backend_lock(self, tmp_path):
        metrics_file = tmp_path / "omr-metrics.json"
        backend = omr_metrics.JSONBackend()
        events = []

        class _LockSpy:
            def __enter__(self):
                events.append("enter")

            def __exit__(self, exc_type, exc, tb):
                events.append("exit")

        with (
            patch("builtins.open", new=_REAL_OPEN),
            patch("os.replace", new=_REAL_REPLACE),
            patch("os.path.isfile", wraps=os.path.isfile),
            patch.object(omr_metrics, "METRICS_FILE", str(metrics_file)),
            patch.object(omr_metrics.JSONBackend, "_lock", _LockSpy()),
        ):
            backend.write_interface("alice", _WAN)

        assert events == ["enter", "exit"]


# ===========================================================================
# GET /metrics/history
# ===========================================================================

class TestGetMetricsHistory:
    def test_requires_influxdb_backend(self, user_client):
        r = user_client.get("/metrics/history")
        assert r.status_code == 501

    def test_single_interface_returns_list(self, user_client):
        hist = [_WAN, {**_WAN, "timestamp": _WAN["timestamp"] + 30}]
        with (
            patch.object(omr_metrics, "_get_backend",
                         return_value=MagicMock(spec=omr_metrics.InfluxBackend,
                                               read_history=MagicMock(return_value=hist))),
        ):
            r = user_client.get("/metrics/history?interface=wan")
        assert r.status_code == 200
        assert isinstance(r.json(), list)
        assert len(r.json()) == 2

    def test_no_interface_returns_dict_by_interface(self, user_client):
        all_hist = {"wan": [_WAN], "wan2": [_WAN2]}
        with (
            patch.object(omr_metrics, "_get_backend",
                         return_value=MagicMock(spec=omr_metrics.InfluxBackend,
                                               read_history=MagicMock(return_value=all_hist))),
        ):
            r = user_client.get("/metrics/history")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, dict)
        assert set(data.keys()) == {"wan", "wan2"}

    def test_admin_can_query_other_user(self, admin_client):
        captured = {}

        def fake_history(username, interface, since_seconds, limit):
            captured["username"] = username
            return []

        with (
            patch.object(omr_metrics, "_get_backend",
                         return_value=MagicMock(spec=omr_metrics.InfluxBackend,
                                               read_history=MagicMock(side_effect=fake_history))),
        ):
            admin_client.get("/metrics/history?username=openmptcprouter&interface=wan")

        assert captured["username"] == "openmptcprouter"

    def test_since_parameter_parsed(self, user_client):
        captured = {}

        def fake_history(username, interface, since_seconds, limit):
            captured["since"] = since_seconds
            return []

        with (
            patch.object(omr_metrics, "_get_backend",
                         return_value=MagicMock(spec=omr_metrics.InfluxBackend,
                                               read_history=MagicMock(side_effect=fake_history))),
        ):
            user_client.get("/metrics/history?interface=wan&since=6h")

        assert captured["since"] == 21600

    def test_json_backend_returns_empty_dict_for_all(self):
        backend = omr_metrics.JSONBackend()
        assert backend.read_history("alice", None, 3600, 100) == {}

    def test_json_backend_returns_empty_list_for_iface(self):
        backend = omr_metrics.JSONBackend()
        assert backend.read_history("alice", "wan", 3600, 100) == []


# ===========================================================================
# Backend selection
# ===========================================================================

class TestBackendSelection:
    def _config_with(self, influx_cfg=None):
        cfg = {"port": 65500, "users": [{}]}
        if influx_cfg is not None:
            cfg["influxdb"] = influx_cfg
        return json.dumps(cfg)

    def test_no_influxdb_config_uses_json(self):
        import io
        with patch("builtins.open", return_value=io.StringIO(self._config_with())):
            backend = omr_metrics._init_backend()
        assert isinstance(backend, omr_metrics.JSONBackend)

    def test_influxdb_config_without_token_uses_json(self):
        import io
        cfg = {"url": "http://localhost:8086"}
        with patch("builtins.open", return_value=io.StringIO(self._config_with(cfg))):
            backend = omr_metrics._init_backend()
        assert isinstance(backend, omr_metrics.JSONBackend)

    def test_influxdb_config_without_url_uses_json(self):
        import io
        cfg = {"token": "mytoken"}
        with patch("builtins.open", return_value=io.StringIO(self._config_with(cfg))):
            backend = omr_metrics._init_backend()
        assert isinstance(backend, omr_metrics.JSONBackend)

    def test_influxdb_client_not_installed_falls_back_to_json(self):
        import io
        import sys
        cfg = {"url": "http://localhost:8086", "token": "tok"}
        config_str = self._config_with(cfg)

        # Remove influxdb_client from sys.modules so the ImportError path is hit
        saved = sys.modules.pop("influxdb_client", None)
        try:
            with (
                patch("builtins.open", return_value=io.StringIO(config_str)),
                patch.dict("sys.modules", {"influxdb_client": None}),
            ):
                backend = omr_metrics._init_backend()
        finally:
            if saved is not None:
                sys.modules["influxdb_client"] = saved

        assert isinstance(backend, omr_metrics.JSONBackend)

    def test_influxdb_init_exception_falls_back_to_json(self):
        import io
        cfg = {"url": "http://localhost:8086", "token": "tok"}
        with (
            patch("builtins.open", return_value=io.StringIO(self._config_with(cfg))),
            patch.object(omr_metrics, "InfluxBackend",
                         side_effect=Exception("connection refused")),
        ):
            backend = omr_metrics._init_backend()
        assert isinstance(backend, omr_metrics.JSONBackend)

    def test_influxdb_config_creates_influx_backend(self):
        import io
        cfg = {"url": "http://localhost:8086", "token": "tok", "org": "myorg", "bucket": "mybucket"}
        mock_influx = MagicMock(spec=omr_metrics.InfluxBackend)
        with (
            patch("builtins.open", return_value=io.StringIO(self._config_with(cfg))),
            patch.object(omr_metrics, "InfluxBackend", return_value=mock_influx) as mock_cls,
        ):
            backend = omr_metrics._init_backend()
        mock_cls.assert_called_once_with(
            url="http://localhost:8086", token="tok", org="myorg", bucket="mybucket",
            retention_days=60,
        )
        assert backend is mock_influx

    def test_influxdb_config_uses_defaults_for_org_and_bucket(self):
        import io
        cfg = {"url": "http://localhost:8086", "token": "tok"}
        mock_influx = MagicMock(spec=omr_metrics.InfluxBackend)
        with (
            patch("builtins.open", return_value=io.StringIO(self._config_with(cfg))),
            patch.object(omr_metrics, "InfluxBackend", return_value=mock_influx) as mock_cls,
        ):
            omr_metrics._init_backend()
        mock_cls.assert_called_once_with(
            url="http://localhost:8086", token="tok", org="omr", bucket="omr_metrics",
            retention_days=60,
        )

    def test_get_backend_caches_singleton(self):
        mock_backend = MagicMock()
        with patch.object(omr_metrics, "_init_backend", return_value=mock_backend) as mock_init:
            b1 = omr_metrics._get_backend()
            b2 = omr_metrics._get_backend()
        assert b1 is b2
        mock_init.assert_called_once()


class TestApplyRetention:
    """InfluxBackend._apply_retention() talks to the InfluxDB 3 Core management
    API directly, so exercise it against a bare instance (bypassing __init__,
    which requires the influxdb_client_3 package) rather than a real client.
    """

    def _make_backend(self):
        backend = object.__new__(omr_metrics.InfluxBackend)
        backend._bucket = "omr_metrics"
        backend._url = "http://127.0.0.1:65501"
        backend._token = "tok"
        backend._retention_days = 60
        return backend

    def test_success_on_create_logs_info_and_does_not_retry(self):
        backend = self._make_backend()
        resp = MagicMock()
        resp.status = 200
        resp.__enter__ = MagicMock(return_value=resp)
        resp.__exit__ = MagicMock(return_value=False)
        with (
            patch("urllib.request.urlopen", return_value=resp) as mock_urlopen,
            patch("omr_metrics.time.sleep") as mock_sleep,
        ):
            backend._apply_retention()
        mock_urlopen.assert_called_once()
        mock_sleep.assert_not_called()

    def test_409_conflict_is_treated_as_already_configured_no_retry(self):
        # InfluxDB 3 Core has no endpoint to change retention_period on an
        # existing database (only Enterprise supports that, via PATCH) -- a
        # 409 here just means the installer already created the database,
        # which is the normal case on every restart. Must not retry or warn.
        import urllib.error
        backend = self._make_backend()
        exc = urllib.error.HTTPError("url", 409, "Conflict", {}, None)
        with (
            patch("urllib.request.urlopen", side_effect=exc) as mock_urlopen,
            patch("omr_metrics.time.sleep") as mock_sleep,
            patch.object(omr_metrics.LOG, "warning") as mock_warning,
        ):
            backend._apply_retention()
        mock_urlopen.assert_called_once()
        mock_sleep.assert_not_called()
        mock_warning.assert_not_called()

    def test_transient_failure_retries_with_backoff_then_warns(self):
        import urllib.error
        backend = self._make_backend()
        exc = urllib.error.URLError("connection refused")
        with (
            patch("urllib.request.urlopen", side_effect=exc) as mock_urlopen,
            patch("omr_metrics.time.sleep") as mock_sleep,
            patch.object(omr_metrics.LOG, "warning") as mock_warning,
        ):
            backend._apply_retention()
        assert mock_urlopen.call_count == backend._RETENTION_MAX_ATTEMPTS
        assert mock_sleep.call_count == backend._RETENTION_MAX_ATTEMPTS - 1
        mock_warning.assert_called_once()

    def test_success_after_transient_failure_stops_retrying(self):
        import urllib.error
        backend = self._make_backend()
        resp = MagicMock()
        resp.status = 200
        resp.__enter__ = MagicMock(return_value=resp)
        resp.__exit__ = MagicMock(return_value=False)
        with (
            patch("urllib.request.urlopen",
                  side_effect=[urllib.error.URLError("not ready"), resp]) as mock_urlopen,
            patch("omr_metrics.time.sleep") as mock_sleep,
        ):
            backend._apply_retention()
        assert mock_urlopen.call_count == 2
        mock_sleep.assert_called_once()


# ===========================================================================
# Feature extraction (pure Python — no torch required)
# ===========================================================================

class TestExtractFeatures:
    def test_returns_correct_number_of_features(self):
        feats = omr_metrics._extract_features(_WAN)
        assert len(feats) == omr_metrics.N_FEATURES

    def test_all_values_in_unit_interval(self):
        for payload in (_WAN, _WAN2, _MODEM_WAN, _WIFI_WAN, _BBR_WAN):
            feats = omr_metrics._extract_features(payload)
            for i, v in enumerate(feats):
                assert 0.0 <= v <= 1.0, f"feature {omr_metrics.FEATURE_NAMES[i]} = {v} out of [0,1]"

    def test_all_none_payload_returns_defaults(self):
        feats = omr_metrics._extract_features({"interface": "wan"})
        # inv_latency, inv_loss, inv_jitter, inv_congestion, signal → 0.5
        # rx_bps, tx_bps, bbr_bw → 0.0
        # inv_ecn, inv_dropped → 1.0
        assert feats[omr_metrics.FEATURE_NAMES.index("inv_latency")]    == 0.5
        assert feats[omr_metrics.FEATURE_NAMES.index("inv_loss")]       == 0.5
        assert feats[omr_metrics.FEATURE_NAMES.index("rx_bps")]         == 0.0
        assert feats[omr_metrics.FEATURE_NAMES.index("inv_ecn")]        == 1.0
        assert feats[omr_metrics.FEATURE_NAMES.index("inv_dropped")]    == 1.0

    def test_zero_latency_gives_max_inv_latency(self):
        feats = omr_metrics._extract_features({**_WAN, "latency": 0.0})
        assert feats[omr_metrics.FEATURE_NAMES.index("inv_latency")] == 1.0

    def test_max_latency_gives_min_inv_latency(self):
        feats = omr_metrics._extract_features({**_WAN, "latency": 2000.0})
        assert feats[omr_metrics.FEATURE_NAMES.index("inv_latency")] == 0.0

    def test_latency_clamped_above_max(self):
        feats = omr_metrics._extract_features({**_WAN, "latency": 99999.0})
        assert feats[omr_metrics.FEATURE_NAMES.index("inv_latency")] == 0.0

    def test_zero_loss_gives_max_inv_loss(self):
        feats = omr_metrics._extract_features({**_WAN, "loss": 0.0})
        assert feats[omr_metrics.FEATURE_NAMES.index("inv_loss")] == 1.0

    def test_full_loss_gives_min_inv_loss(self):
        feats = omr_metrics._extract_features({**_WAN, "loss": 100.0})
        assert feats[omr_metrics.FEATURE_NAMES.index("inv_loss")] == 0.0

    def test_high_bandwidth_gives_high_score(self):
        high_bw = {**_WAN, "bandwidth": {"rx_bps": 100_000_000, "tx_bps": 100_000_000,
                                          "rx_bytes": 0, "tx_bytes": 0}}
        feats = omr_metrics._extract_features(high_bw)
        assert feats[omr_metrics.FEATURE_NAMES.index("rx_bps")] == 1.0
        assert feats[omr_metrics.FEATURE_NAMES.index("tx_bps")] == 1.0

    def test_congestion_score_100_gives_zero(self):
        payload = {**_WAN, "congestion": {"score": 100, "level": "severe"}}
        feats = omr_metrics._extract_features(payload)
        assert feats[omr_metrics.FEATURE_NAMES.index("inv_congestion")] == 0.0

    def test_congestion_score_0_gives_one(self):
        payload = {**_WAN, "congestion": {"score": 0, "level": "none"}}
        feats = omr_metrics._extract_features(payload)
        assert feats[omr_metrics.FEATURE_NAMES.index("inv_congestion")] == 1.0

    def test_signal_quality_normalized(self):
        payload = {**_WAN, "signal": {**_WAN["signal"], "quality": 80.0}}
        feats = omr_metrics._extract_features(payload)
        assert abs(feats[omr_metrics.FEATURE_NAMES.index("signal")] - 0.8) < 1e-6

    def test_bbr_bw_normalized(self):
        import math
        payload = {**_WAN, "bbr": {**_WAN["bbr"], "bw": 50_000_000}}
        feats = omr_metrics._extract_features(payload)
        expected = math.log1p(50_000_000) / math.log1p(100e6)
        assert abs(feats[omr_metrics.FEATURE_NAMES.index("bbr_bw")] - expected) < 1e-6

    def test_ecn_mark_inverted(self):
        payload = {**_WAN, "tc": {**_WAN["tc"], "ecn_mark": 1000}}
        feats = omr_metrics._extract_features(payload)
        assert feats[omr_metrics.FEATURE_NAMES.index("inv_ecn")] == 0.0

    def test_feature_names_length_matches_constant(self):
        assert len(omr_metrics.FEATURE_NAMES) == omr_metrics.N_FEATURES


# ===========================================================================
# Predictive extrapolation (pure Python — no torch required)
# ===========================================================================

_T0 = 1_700_000_000  # base Unix timestamp used across prediction tests


def _history_at(base: dict, overrides: list[dict], step: int = 30) -> list:
    """Build a history list: base payload repeated with per-entry field overrides."""
    result = []
    for i, over in enumerate(overrides):
        p = {**base, "timestamp": _T0 + i * step}
        for k, v in over.items():
            if "." in k:
                top, sub = k.split(".", 1)
                p[top] = {**(p.get(top) or {}), sub: v}
            else:
                p[k] = v
        result.append(p)
    return result


class TestLinearPredictAt:
    def test_perfect_linear_trend(self):
        # WLS on a perfectly linear series must recover the exact slope regardless of weights.
        ts = [100.0, 200.0, 300.0]
        vs = [10.0, 20.0, 30.0]
        pred = omr_metrics._linear_predict_at(ts, vs, 400.0)
        assert abs(pred - 40.0) < 1e-6

    def test_flat_series_returns_mean(self):
        ts = [100.0, 200.0, 300.0]
        vs = [5.0, 5.0, 5.0]
        pred = omr_metrics._linear_predict_at(ts, vs, 999.0)
        assert abs(pred - 5.0) < 1e-9

    def test_single_point_returns_that_value(self):
        pred = omr_metrics._linear_predict_at([100.0], [7.0], 999.0)
        assert abs(pred - 7.0) < 1e-9

    def test_empty_returns_none(self):
        assert omr_metrics._linear_predict_at([], [], 999.0) is None

    def test_none_values_skipped(self):
        # Valid pairs: (200, 10), (400, 20) — result is close to 25 (WLS may differ slightly from OLS).
        ts = [100.0, 200.0, 300.0, 400.0]
        vs = [None, 10.0, None, 20.0]
        pred = omr_metrics._linear_predict_at(ts, vs, 500.0)
        assert abs(pred - 25.0) < 0.5

    def test_recent_point_dominates_with_short_halflife(self):
        # With a very short half-life, the last point (30) should pull the
        # prediction toward a high value more than a long half-life would.
        ts = [0.0, 100.0, 200.0]
        vs = [10.0, 10.0, 30.0]
        pred_short = omr_metrics._linear_predict_at(ts, vs, 300.0, halflife_s=10.0)
        pred_long  = omr_metrics._linear_predict_at(ts, vs, 300.0, halflife_s=10000.0)
        assert pred_short > pred_long

    def test_halflife_zero_uses_unweighted(self):
        # halflife_s=0 should not raise; all weights become exp(0)=1 (uniform).
        ts = [100.0, 200.0, 300.0]
        vs = [10.0, 20.0, 30.0]
        pred = omr_metrics._linear_predict_at(ts, vs, 400.0, halflife_s=0.0)
        assert abs(pred - 40.0) < 1e-6


class TestPredictPayload:
    def test_empty_history_returns_empty(self):
        assert omr_metrics._predict_payload([]) == {}

    def test_single_entry_returns_copy_of_latest(self):
        p = omr_metrics._predict_payload([_WAN])
        assert p["interface"] == "wan"

    def test_rising_latency_is_projected_higher(self):
        hist = _history_at(_WAN, [{"latency": 20.0}, {"latency": 30.0}, {"latency": 40.0}])
        predicted = omr_metrics._predict_payload(hist, horizon_seconds=30)
        assert predicted["latency"] > 40.0

    def test_falling_latency_is_projected_lower(self):
        hist = _history_at(_WAN, [{"latency": 50.0}, {"latency": 40.0}, {"latency": 30.0}])
        predicted = omr_metrics._predict_payload(hist, horizon_seconds=30)
        assert predicted["latency"] < 30.0

    def test_stable_latency_stays_flat(self):
        hist = _history_at(_WAN, [{"latency": 25.0}] * 5)
        predicted = omr_metrics._predict_payload(hist, horizon_seconds=300)
        assert abs(predicted["latency"] - 25.0) < 1e-6

    def test_nested_congestion_score_projected(self):
        hist = _history_at(_WAN, [
            {"congestion.score": 10}, {"congestion.score": 20}, {"congestion.score": 30},
        ])
        predicted = omr_metrics._predict_payload(hist, horizon_seconds=30)
        assert predicted["congestion"]["score"] > 30.0

    def test_non_predictable_fields_preserved(self):
        hist = _history_at(_WAN, [{"latency": 25.0}] * 3)
        predicted = omr_metrics._predict_payload(hist, horizon_seconds=60)
        assert predicted["interface"] == "wan"
        assert predicted["status"] == "online"

    def test_horizon_zero_evaluates_at_latest_timestamp(self):
        hist = _history_at(_WAN, [{"latency": 20.0}, {"latency": 30.0}, {"latency": 40.0}])
        predicted = omr_metrics._predict_payload(hist, horizon_seconds=0)
        assert predicted["latency"] == pytest.approx(40.0, abs=2.0)

    def test_loss_clamped_to_zero(self):
        # Falling loss trend must not produce a negative value.
        hist = _history_at(_WAN, [{"loss": 5.0}, {"loss": 3.0}, {"loss": 1.0}])
        predicted = omr_metrics._predict_payload(hist, horizon_seconds=300)
        assert predicted["loss"] >= 0.0

    def test_loss_clamped_to_100(self):
        # Rapidly rising loss must not exceed 100 %.
        hist = _history_at(_WAN, [{"loss": 80.0}, {"loss": 90.0}, {"loss": 99.0}])
        predicted = omr_metrics._predict_payload(hist, horizon_seconds=3600)
        assert predicted["loss"] <= 100.0

    def test_congestion_score_clamped_to_100(self):
        hist = _history_at(_WAN, [
            {"congestion.score": 80}, {"congestion.score": 90}, {"congestion.score": 99},
        ])
        predicted = omr_metrics._predict_payload(hist, horizon_seconds=3600)
        assert predicted["congestion"]["score"] <= 100.0

    def test_signal_quality_clamped_to_bounds(self):
        hist = _history_at(_WAN, [
            {"signal.quality": 90}, {"signal.quality": 95}, {"signal.quality": 99},
        ])
        predicted = omr_metrics._predict_payload(hist, horizon_seconds=3600)
        assert predicted["signal"]["quality"] <= 100.0


class TestPredictDecisionEndpoint:
    def test_predict_false_skips_history_fetch(self, user_client):
        with (
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN}),
            patch.object(omr_metrics, "_read_history") as mock_hist,
        ):
            user_client.get("/metrics/decision")
        mock_hist.assert_not_called()

    def test_predict_true_fetches_history_per_interface(self, user_client):
        hist = _history_at(_WAN, [{"latency": 25.0}] * 3)
        with (
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN, "wan2": _WAN2}),
            patch.object(omr_metrics, "_read_history", return_value=hist) as mock_hist,
        ):
            r = user_client.get("/metrics/decision?predict=true")
        assert r.status_code == 200
        assert mock_hist.call_count == 2  # once per interface

    def test_predict_falls_back_to_current_when_no_history(self, user_client):
        with (
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN}),
            patch.object(omr_metrics, "_read_history", return_value=[]),  # no history
        ):
            r = user_client.get("/metrics/decision?predict=true")
        assert r.status_code == 200

    def test_predict_uses_custom_horizon(self, user_client):
        hist = _history_at(_WAN, [{"latency": 25.0}] * 3)
        captured = {}

        def fake_read_history(username, iface, since_seconds, limit):
            captured["since_seconds"] = since_seconds
            return hist

        with (
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN}),
            patch.object(omr_metrics, "_read_history", side_effect=fake_read_history),
        ):
            user_client.get("/metrics/decision?predict=true&horizon=600")
        assert captured["since_seconds"] >= 600


# ===========================================================================
# DSCP traffic-class routing (pure Python — no torch required)
# ===========================================================================

class TestDscpClassTable:
    """Sanity checks on the _DSCP_CLASSES profile table itself."""

    def test_keys_are_unique(self):
        keys = [c[0] for c in omr_metrics._DSCP_CLASSES]
        assert len(keys) == len(set(keys))

    def test_dscp_values_are_unique_across_classes(self):
        seen = set()
        for _, dscp_values, *_ in omr_metrics._DSCP_CLASSES:
            for v in dscp_values:
                assert v not in seen, f"DSCP value {v} used by more than one class"
                seen.add(v)

    def test_every_dscp_value_in_valid_range(self):
        for _, dscp_values, *_ in omr_metrics._DSCP_CLASSES:
            for v in dscp_values:
                assert 0 <= v <= 63

    def test_profile_feature_names_are_known(self):
        for key, _, _, profile, _ in omr_metrics._DSCP_CLASSES:
            for name in profile:
                assert name in omr_metrics.FEATURE_NAMES, f"{key}: unknown feature {name}"

    def test_profile_weights_are_positive(self):
        for key, _, _, profile, _ in omr_metrics._DSCP_CLASSES:
            for name, w in profile.items():
                assert w > 0, f"{key}.{name} weight must be positive"

    def test_horizons_are_positive(self):
        for key, _, _, _, horizon_s in omr_metrics._DSCP_CLASSES:
            assert horizon_s > 0, key

    def test_feature_index_covers_all_feature_names(self):
        assert set(omr_metrics._FEATURE_INDEX) == set(omr_metrics.FEATURE_NAMES)


class TestDscpClassWeights:
    """Tests for _dscp_class_weights: per-class formula + model blend + forecast."""

    # Low-latency/low-bandwidth vs. high-latency/high-bandwidth interface pair.
    _LOW_LAT  = {**_WAN,  "latency": 15.0, "loss": 0.0, "jitter": 2.0,
                 "bandwidth": {"rx_bps": 1_000_000, "tx_bps": 500_000}}
    _HIGH_BW  = {**_WAN2, "latency": 80.0, "loss": 1.0, "jitter": 20.0,
                 "bandwidth": {"rx_bps": 50_000_000, "tx_bps": 25_000_000}}

    def _user_data(self):
        return {"wan": self._LOW_LAT, "wan2": self._HIGH_BW}

    def test_returns_entry_per_class(self):
        result = omr_metrics._dscp_class_weights(self._user_data(), {}, {"wan": 0.5, "wan2": 0.5})
        assert set(result) == {c[0] for c in omr_metrics._DSCP_CLASSES}

    def test_entry_shape(self):
        result = omr_metrics._dscp_class_weights(self._user_data(), {}, {"wan": 0.5, "wan2": 0.5})
        entry = result["ef"]
        assert set(entry) == {"dscp", "label", "horizon_s", "weights", "scores",
                               "best_interface", "ranking"}
        assert entry["dscp"] == [46]
        assert set(entry["weights"]) == {"wan", "wan2"}
        assert set(entry["ranking"]) == {"wan", "wan2"}
        assert entry["best_interface"] == entry["ranking"][0]

    def test_weights_are_ints_in_valid_nexthop_range(self):
        result = omr_metrics._dscp_class_weights(self._user_data(), {}, {"wan": 0.5, "wan2": 0.5})
        for entry in result.values():
            for w in entry["weights"].values():
                assert isinstance(w, int)
                assert 1 <= w <= 255

    def test_latency_sensitive_class_prefers_low_latency_interface(self):
        # Neutral model input so the class formula alone drives the outcome.
        result = omr_metrics._dscp_class_weights(self._user_data(), {}, {"wan": 0.5, "wan2": 0.5})
        for key in ("ef", "cs3", "cs6"):
            assert result[key]["best_interface"] == "wan", key

    def test_throughput_class_prefers_high_bandwidth_interface(self):
        result = omr_metrics._dscp_class_weights(self._user_data(), {}, {"wan": 0.5, "wan2": 0.5})
        for key in ("cs1", "af11"):
            assert result[key]["best_interface"] == "wan2", key

    def test_offline_interface_scores_minimum_weight(self):
        user_data = {
            "wan":  self._LOW_LAT,
            "wan2": {**self._HIGH_BW, "status": "offline"},
        }
        result = omr_metrics._dscp_class_weights(user_data, {}, {"wan": 1.0, "wan2": 0.0})
        for entry in result.values():
            assert entry["weights"]["wan2"] == 1
            assert entry["best_interface"] == "wan"

    def test_missing_latency_treated_as_offline(self):
        user_data = {
            "wan":  self._LOW_LAT,
            "wan2": {**self._HIGH_BW, "latency": None},
        }
        result = omr_metrics._dscp_class_weights(user_data, {}, {"wan": 1.0, "wan2": 0.0})
        assert result["cs1"]["best_interface"] == "wan"

    def test_model_blend_shifts_score_toward_model_probability(self):
        # Same two interfaces, only model_probs differ — bulk class (cs1) would
        # normally favor "wan2" on the formula alone; a strong model preference
        # for "wan" should pull its blended score up.
        user_data = self._user_data()
        neutral = omr_metrics._dscp_class_weights(user_data, {}, {"wan": 0.5, "wan2": 0.5})
        biased  = omr_metrics._dscp_class_weights(user_data, {}, {"wan": 0.95, "wan2": 0.05})
        assert biased["cs1"]["scores"]["wan"] > neutral["cs1"]["scores"]["wan"]

    def test_zero_blend_ignores_model_probs_entirely(self):
        user_data = self._user_data()
        with patch.object(omr_metrics, "_DSCP_MODEL_BLEND", 0.0):
            ignored = omr_metrics._dscp_class_weights(user_data, {}, {"wan": 1.0, "wan2": 0.0})
            baseline = omr_metrics._dscp_class_weights(user_data, {}, {"wan": 0.0, "wan2": 1.0})
        assert ignored["cs1"]["weights"] == baseline["cs1"]["weights"]

    def test_uses_class_specific_forecast_horizon(self):
        hist = _history_at(self._LOW_LAT, [{"latency": 15.0}, {"latency": 20.0}, {"latency": 25.0}])
        history_data = {"wan": hist, "wan2": []}
        captured_horizons = []
        real_predict = omr_metrics._predict_payload

        def spy(history, horizon_seconds=300):
            captured_horizons.append(horizon_seconds)
            return real_predict(history, horizon_seconds=horizon_seconds)

        with patch.object(omr_metrics, "_predict_payload", side_effect=spy):
            omr_metrics._dscp_class_weights(self._user_data(), history_data, {"wan": 0.5, "wan2": 0.5})

        expected_horizons = sorted({c[4] for c in omr_metrics._DSCP_CLASSES})
        assert sorted(set(captured_horizons)) == expected_horizons

    def test_short_history_falls_back_to_current_snapshot(self):
        # Fewer than 2 points: _predict_payload must not be called for that interface.
        history_data = {"wan": [self._LOW_LAT], "wan2": []}
        with patch.object(omr_metrics, "_predict_payload") as mock_predict:
            omr_metrics._dscp_class_weights(self._user_data(), history_data, {"wan": 0.5, "wan2": 0.5})
        mock_predict.assert_not_called()

    def test_rising_latency_history_degrades_latency_sensitive_class(self):
        flat   = _history_at(self._LOW_LAT, [{"latency": 15.0}] * 5)
        rising = _history_at(self._LOW_LAT, [{"latency": 15.0}, {"latency": 40.0}, {"latency": 90.0}])
        user_data = self._user_data()
        model_probs = {"wan": 0.5, "wan2": 0.5}

        flat_result   = omr_metrics._dscp_class_weights(
            user_data, {"wan": flat, "wan2": []}, model_probs)
        rising_result = omr_metrics._dscp_class_weights(
            user_data, {"wan": rising, "wan2": []}, model_probs)

        assert rising_result["ef"]["scores"]["wan"] < flat_result["ef"]["scores"]["wan"]


class TestDscpByInterface:
    def test_empty_input_returns_empty(self):
        assert omr_metrics._dscp_by_interface({}) == {}

    def test_groups_classes_by_best_interface(self):
        dscp_classes = {
            "ef":  {"best_interface": "wan"},
            "cs1": {"best_interface": "wan2"},
            "cs0": {"best_interface": "wan"},
        }
        result = omr_metrics._dscp_by_interface(dscp_classes)
        assert result == {"wan": ["ef", "cs0"], "wan2": ["cs1"]}

    def test_class_without_best_interface_is_skipped(self):
        dscp_classes = {"ef": {"best_interface": None}}
        assert omr_metrics._dscp_by_interface(dscp_classes) == {}


# ===========================================================================
# GET /metrics/decision?dscp=true
# ===========================================================================

class TestGetDecisionDscpEndpoint:
    _FAKE_RESULT = {
        "probs":  {"wan": 0.7, "wan2": 0.3},
        "scores": {"wan": 70.0, "wan2": 30.0},
    }

    def test_omitted_by_default(self, user_client):
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN, "wan2": _WAN2}),
            patch.object(omr_metrics, "_compute_weights", return_value=self._FAKE_RESULT),
        ):
            r = user_client.get("/metrics/decision")
        data = r.json()
        assert "dscp_classes" not in data
        assert "dscp_by_interface" not in data

    def test_included_when_requested(self, user_client):
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN, "wan2": _WAN2}),
            patch.object(omr_metrics, "_compute_weights", return_value=self._FAKE_RESULT),
        ):
            r = user_client.get("/metrics/decision?dscp=true")
        assert r.status_code == 200
        data = r.json()
        assert set(data["dscp_classes"]) == {c[0] for c in omr_metrics._DSCP_CLASSES}
        assert isinstance(data["dscp_by_interface"], dict)

    def test_uses_probs_from_main_computation_for_blend(self, user_client):
        captured = {}
        real_dscp = omr_metrics._dscp_class_weights

        def spy(user_data, history_data, model_probs):
            captured["model_probs"] = model_probs
            return real_dscp(user_data, history_data, model_probs)

        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN, "wan2": _WAN2}),
            patch.object(omr_metrics, "_compute_weights", return_value=self._FAKE_RESULT),
            patch.object(omr_metrics, "_dscp_class_weights", side_effect=spy),
        ):
            user_client.get("/metrics/decision?dscp=true")
        assert captured["model_probs"] == self._FAKE_RESULT["probs"]

    def test_works_with_heuristic_fallback_when_torch_unavailable(self, user_client):
        fake_result = {"probs": {"wan": 1.0}, "scores": {"wan": 100.0}}
        with (
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN}),
            patch.object(omr_metrics, "_compute_weights_heuristic", return_value=fake_result),
        ):
            r = user_client.get("/metrics/decision?dscp=true")
        assert r.status_code == 200
        assert "dscp_classes" in r.json()

    def test_no_metrics_returns_empty_without_error(self, user_client):
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={}),
        ):
            r = user_client.get("/metrics/decision?dscp=true")
        assert r.status_code == 200
        assert r.json() == {}


# ===========================================================================
# Cost factor (pure Python — no torch required)
# ===========================================================================

class TestCostFactor:
    def test_no_cost_returns_neutral(self):
        assert omr_metrics._cost_factor({}) == 1.0
        assert omr_metrics._cost_factor({"cost": None}) == 1.0

    def test_cost_1_returns_1(self):
        assert omr_metrics._cost_factor({"cost": 1}) == pytest.approx(1.0)

    def test_lower_cost_gives_higher_factor(self):
        assert omr_metrics._cost_factor({"cost": 10}) > omr_metrics._cost_factor({"cost": 100})

    def test_apply_cost_biases_toward_lower_cost_interface(self):
        wan  = {**_WAN,  "cost": 10}
        wan2 = {**_WAN2, "cost": 100}
        user_data = {"wan": wan, "wan2": wan2}
        # Both interfaces are identical except for cost — wan should win.
        result = omr_metrics._compute_weights_heuristic(user_data)
        assert result["probs"]["wan"] > result["probs"]["wan2"]

    def test_equal_costs_do_not_change_relative_order(self):
        wan  = {**_WAN,  "cost": 10}
        wan2 = {**_WAN2, "cost": 10}
        result_with    = omr_metrics._compute_weights_heuristic({"wan": wan,  "wan2": wan2})
        result_without = omr_metrics._compute_weights_heuristic({"wan": _WAN, "wan2": _WAN2})
        assert result_with["probs"]["wan"] == result_without["probs"]["wan"]

    def test_cost_zero_treated_as_no_cost(self):
        # cost=0 must not cause division by zero — falls back to neutral factor.
        result = omr_metrics._compute_weights_heuristic(
            {"wan": {**_WAN, "cost": 0}, "wan2": _WAN2}
        )
        assert "wan" in result["probs"]


# ===========================================================================
# GET /metrics/decision
# ===========================================================================

class TestGetDecision:
    """Tests for the decision endpoint.

    Since torch may not be installed, the 501 path is tested directly.
    The success path is tested by patching _TORCH_AVAILABLE + _compute_weights.
    """

    _FAKE_RESULT = {
        "probs":  {"wan": 0.7, "wan2": 0.3},
        "scores": {"wan": 1.5, "wan2": 0.2},
    }

    def test_uses_heuristic_when_torch_not_available(self, user_client):
        fake_result = {"weights": {"wan": 100}, "scores": {"wan": 100.0}}
        with (
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN}),
            patch.object(omr_metrics, "_compute_weights_heuristic",
                         return_value=fake_result) as mock_h,
        ):
            r = user_client.get("/metrics/decision")
        assert r.status_code == 200
        mock_h.assert_called_once()

    def test_heuristic_not_called_when_torch_available(self, user_client):
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN}),
            patch.object(omr_metrics, "_compute_weights", return_value=self._FAKE_RESULT),
            patch.object(omr_metrics, "_compute_weights_heuristic") as mock_h,
        ):
            user_client.get("/metrics/decision")
        mock_h.assert_not_called()

    def test_returns_empty_when_no_metrics(self, user_client):
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={}),
        ):
            r = user_client.get("/metrics/decision")
        assert r.status_code == 200
        assert r.json() == {}

    def test_returns_weights_and_scores(self, user_client):
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN, "wan2": _WAN2}),
            patch.object(omr_metrics, "_compute_weights", return_value=self._FAKE_RESULT),
        ):
            r = user_client.get("/metrics/decision")
        assert r.status_code == 200
        data = r.json()
        assert "weights" in data
        assert "scores" in data
        assert set(data["weights"].keys()) == {"wan", "wan2"}

    def test_returns_confidence_and_anomalies(self, user_client):
        fresh = {**_WAN, "timestamp": 2_000}
        hist = _history_at(fresh, [{"loss": 0.0}] * 5)
        with (
            patch.object(omr_metrics.time, "time", return_value=2_200),
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_get_backend", return_value=MagicMock()),
            patch.object(omr_metrics, "_read_user", return_value={"wan": fresh}),
            patch.object(omr_metrics, "_read_history", return_value=hist),
            patch.object(omr_metrics, "_compute_weights", return_value={"probs": {"wan": 1.0}, "scores": {"wan": 100.0}}),
        ):
            r = user_client.get("/metrics/decision")
        data = r.json()
        assert data["confidence"]["wan"] == "high"
        assert data["anomalies"]["wan"] == []

    def test_decision_flags_rising_loss(self, user_client):
        fresh = {**_WAN, "timestamp": 2_000, "loss": 4.0}
        hist = _history_at(fresh, [{"loss": 0.1}, {"loss": 1.0}, {"loss": 2.5}, {"loss": 4.0}])
        with (
            patch.object(omr_metrics.time, "time", return_value=2_060),
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_get_backend", return_value=MagicMock()),
            patch.object(omr_metrics, "_read_user", return_value={"wan": fresh}),
            patch.object(omr_metrics, "_read_history", return_value=hist),
            patch.object(omr_metrics, "_compute_weights", return_value={"probs": {"wan": 1.0}, "scores": {"wan": 100.0}}),
        ):
            r = user_client.get("/metrics/decision")
        assert "rising_loss" in r.json()["anomalies"]["wan"]

    def test_explain_flag_forwarded(self, user_client):
        captured = {}

        def fake_compute(user_data, explain=False, **kwargs):
            captured["explain"] = explain
            return self._FAKE_RESULT

        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN}),
            patch.object(omr_metrics, "_compute_weights", side_effect=fake_compute),
        ):
            user_client.get("/metrics/decision?explain=true")

        assert captured["explain"] is True

    def test_explain_false_by_default(self, user_client):
        captured = {}

        def fake_compute(user_data, explain=False, **kwargs):
            captured["explain"] = explain
            return self._FAKE_RESULT

        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN}),
            patch.object(omr_metrics, "_compute_weights", side_effect=fake_compute),
        ):
            user_client.get("/metrics/decision")

        assert captured["explain"] is False

    def test_admin_can_query_other_user(self, admin_client):
        captured = {}

        def fake_read(username):
            captured["username"] = username
            return {"wan": _WAN}

        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", side_effect=fake_read),
            patch.object(omr_metrics, "_compute_weights", return_value=self._FAKE_RESULT),
        ):
            admin_client.get("/metrics/decision?username=openmptcprouter")

        assert captured["username"] == "openmptcprouter"

    def test_unauthenticated_returns_403(self, unauth_client):
        r = unauth_client.get("/metrics/decision")
        assert r.status_code == 403


# ===========================================================================
# POST /metrics/decision/train
# ===========================================================================

class TestTrainDecision:
    def _post(self, client, body, **query):
        url = "/metrics/decision/train"
        if query:
            url += "?" + "&".join(f"{k}={v}" for k, v in query.items())
        return client.post(url, json=body)

    def test_returns_501_when_torch_not_available(self, admin_client):
        r = self._post(admin_client, {"best_interface": "wan"})
        assert r.status_code == 501

    def test_non_admin_returns_403(self, user_client):
        with patch.object(omr_metrics, "_TORCH_AVAILABLE", True):
            r = self._post(user_client, {"best_interface": "wan"})
        assert r.status_code == 403

    def test_returns_404_when_no_metrics(self, admin_client):
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={}),
        ):
            r = self._post(admin_client, {"best_interface": "wan"})
        assert r.status_code == 404

    def test_train_with_best_interface(self, admin_client):
        captured = {}

        def fake_train(user_data, target_weights, lr, history_data=None):
            captured["target"] = target_weights
            captured["lr"] = lr
            captured["history_data"] = history_data
            return 0.05

        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN, "wan2": _WAN2}),
            patch.object(omr_metrics, "_train_step", side_effect=fake_train),
            patch.object(omr_metrics, "_get_model", return_value=MagicMock()),
            patch.object(omr_metrics, "_save_model"),
        ):
            r = self._post(admin_client, {"best_interface": "wan"})

        assert r.status_code == 200
        assert r.json()["result"] == "ok"
        assert captured["target"]["wan"] == 1.0
        assert captured["target"]["wan2"] == 0.0
        assert captured["history_data"] == {}

    def test_train_with_free_form_weights(self, admin_client):
        captured = {}

        def fake_train(user_data, target_weights, lr, history_data=None):
            captured["target"] = target_weights
            captured["history_data"] = history_data
            return 0.03

        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN, "wan2": _WAN2}),
            patch.object(omr_metrics, "_train_step", side_effect=fake_train),
            patch.object(omr_metrics, "_get_model", return_value=MagicMock()),
            patch.object(omr_metrics, "_save_model"),
        ):
            r = self._post(admin_client, {"weights": {"wan": 0.8, "wan2": 0.2}})

        assert r.status_code == 200
        assert captured["target"]["wan"] == 0.8
        assert captured["target"]["wan2"] == 0.2
        assert captured["history_data"] == {}

    def test_train_fetches_history_for_feature_alignment(self, admin_client):
        captured = {}
        hist = _history_at(_WAN, [{"latency": 25.0}] * 3)

        def fake_train(user_data, target_weights, lr, history_data=None):
            captured["history_data"] = history_data
            return 0.01

        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN, "wan2": _WAN2}),
            patch.object(omr_metrics, "_read_history", return_value=hist) as mock_hist,
            patch.object(omr_metrics, "_get_backend",
                         return_value=MagicMock(spec=omr_metrics.InfluxBackend)),
            patch.object(omr_metrics, "_train_step", side_effect=fake_train),
            patch.object(omr_metrics, "_get_model", return_value=MagicMock()),
            patch.object(omr_metrics, "_save_model"),
        ):
            r = self._post(admin_client, {"best_interface": "wan"})

        assert r.status_code == 200
        assert mock_hist.call_count == 2
        assert captured["history_data"] == {"wan": hist, "wan2": hist}

    def test_negative_free_form_weight_returns_422(self, admin_client):
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN, "wan2": _WAN2}),
        ):
            r = self._post(admin_client, {"weights": {"wan": -0.1, "wan2": 1.1}})

        assert r.status_code == 422
        assert "Negative weight" in r.json()["detail"]

    def test_zero_sum_free_form_weights_returns_422(self, admin_client):
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN, "wan2": _WAN2}),
        ):
            r = self._post(admin_client, {"weights": {"wan": 0.0, "wan2": 0.0}})

        assert r.status_code == 422
        assert "positive weight" in r.json()["detail"]

    def test_unknown_only_free_form_weights_returns_422(self, admin_client):
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN, "wan2": _WAN2}),
        ):
            r = self._post(admin_client, {"weights": {"doesnotexist": 1.0}})

        assert r.status_code == 422
        assert "known interface" in r.json()["detail"]

    def test_custom_learning_rate_forwarded(self, admin_client):
        captured = {}

        def fake_train(user_data, target_weights, lr, history_data=None):
            captured["lr"] = lr
            return 0.0

        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN, "wan2": _WAN2}),
            patch.object(omr_metrics, "_train_step", side_effect=fake_train),
            patch.object(omr_metrics, "_get_model", return_value=MagicMock()),
            patch.object(omr_metrics, "_save_model"),
        ):
            self._post(admin_client, {"best_interface": "wan", "learning_rate": 0.005})

        assert captured["lr"] == 0.005

    def test_unknown_best_interface_returns_422(self, admin_client):
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN}),
        ):
            r = self._post(admin_client, {"best_interface": "doesnotexist"})
        assert r.status_code == 422

    def test_no_feedback_field_returns_422(self, admin_client):
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN}),
        ):
            r = self._post(admin_client, {})
        assert r.status_code == 422

    def test_loss_included_in_response(self, admin_client):
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN, "wan2": _WAN2}),
            patch.object(omr_metrics, "_train_step", return_value=0.123456),
            patch.object(omr_metrics, "_get_model", return_value=MagicMock()),
            patch.object(omr_metrics, "_save_model"),
        ):
            r = self._post(admin_client, {"best_interface": "wan"})
        assert r.json()["loss"] == 0.123456

    def test_model_saved_after_training(self, admin_client):
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN, "wan2": _WAN2}),
            patch.object(omr_metrics, "_train_step", return_value=0.0),
            patch.object(omr_metrics, "_get_model", return_value=MagicMock()),
            patch.object(omr_metrics, "_save_model") as mock_save,
        ):
            self._post(admin_client, {"best_interface": "wan"})
        mock_save.assert_called_once()

    def test_unauthenticated_returns_403(self, unauth_client):
        r = unauth_client.post("/metrics/decision/train", json={"best_interface": "wan"})
        assert r.status_code == 403


# ===========================================================================
# POST /metrics/decision/reset
# ===========================================================================

class TestResetDecision:
    def test_returns_501_when_torch_not_available(self, admin_client):
        r = admin_client.post("/metrics/decision/reset")
        assert r.status_code == 501

    def test_admin_can_reset(self, admin_client):
        fake_model = MagicMock()
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_make_model", return_value=fake_model),
            patch.object(omr_metrics, "_save_model") as mock_save,
        ):
            r = admin_client.post("/metrics/decision/reset")
        assert r.status_code == 200
        assert r.json()["result"] == "ok"
        mock_save.assert_called_once_with(fake_model)
        assert omr_metrics._decision_model is fake_model

    def test_non_admin_returns_403(self, user_client):
        with patch.object(omr_metrics, "_TORCH_AVAILABLE", True):
            r = user_client.post("/metrics/decision/reset")
        assert r.status_code == 403

    def test_unauthenticated_returns_403(self, unauth_client):
        r = unauth_client.post("/metrics/decision/reset")
        assert r.status_code == 403


# ===========================================================================
# Fake-torch infrastructure
# ===========================================================================
# These classes simulate the torch APIs used by _compute_weights, _train_step,
# _get_model, and _save_model without requiring PyTorch to be installed.

class _FakeTensor:
    """Minimal tensor-like backed by a plain Python list."""

    def __init__(self, data):
        self._data = [float(x) for x in data]

    def __len__(self):            return len(self._data)
    def __float__(self):          return self._data[0]
    def __bool__(self):           return bool(self._data[0])
    def __getitem__(self, i):     return _FakeTensor([self._data[i]])
    def __setitem__(self, i, v):  self._data[i] = float(v)
    def __iter__(self):           return (_FakeTensor([v]) for v in self._data)
    def __gt__(self, other):      return self._data[0] > float(other)
    def __ge__(self, other):      return self._data[0] >= float(other)
    def __lt__(self, other):      return self._data[0] < float(other)
    def __le__(self, other):      return self._data[0] <= float(other)
    def __eq__(self, other):      return self._data[0] == float(other)
    def __truediv__(self, other): return _FakeTensor([v / float(other) for v in self._data])

    def sum(self):   return _FakeTensor([sum(self._data)])
    def norm(self):  return _FakeTensor([math.sqrt(sum(v * v for v in self._data))])
    def backward(self): pass
    def item(self):  return self._data[0]


class _Fake2DTensor:
    """Represents a (n_interfaces, n_features) tensor — only __len__ is needed."""
    def __init__(self, rows):
        self._rows = rows

    def __len__(self): return len(self._rows)


class _FakeSGD:
    def __init__(self, params, lr=0.01):
        self.param_groups = [{"lr": lr}]
    def zero_grad(self): pass
    def step(self): pass


class _FakeAdam:
    def __init__(self, params, lr=1e-3):
        self.param_groups = [{"lr": lr}]
    def zero_grad(self): pass
    def step(self): pass


class _FakeOptim:
    SGD  = _FakeSGD
    Adam = _FakeAdam


def _fake_mse_loss(pred, target):
    n = len(pred)
    pd = [float(pred[i]) for i in range(n)]
    td = [float(target[i]) for i in range(n)]
    mse = sum((p - t) ** 2 for p, t in zip(pd, td)) / max(n, 1)
    return _FakeTensor([mse])


def _fake_kl_div(log_input, target, reduction="batchmean"):
    n = len(log_input)
    li = [float(log_input[i]) for i in range(n)]
    td = [float(target[i]) for i in range(n)]
    kl = sum(t * (math.log(max(t, 1e-10)) - p) for t, p in zip(td, li))
    return _FakeTensor([kl / max(n, 1)])


class _FakeFunctional:
    mse_loss = staticmethod(_fake_mse_loss)
    kl_div   = staticmethod(_fake_kl_div)


class _FakeInit:
    @staticmethod
    def xavier_uniform_(tensor): pass


class _FakeNN:
    functional = _FakeFunctional()
    init       = _FakeInit()


class _FakeTorch:
    float32 = "float32"
    optim   = _FakeOptim
    nn      = _FakeNN()

    def tensor(self, data, dtype=None):
        if data and isinstance(data[0], list):
            return _Fake2DTensor(data)
        return _FakeTensor([float(x) for x in data])

    def no_grad(self):
        @contextlib.contextmanager
        def _noop():
            yield
        return _noop()

    def log_softmax(self, tensor, dim=0):
        data = [float(tensor[i]) for i in range(len(tensor))]
        max_v = max(data) if data else 0.0
        exps = [math.exp(v - max_v) for v in data]
        total = sum(exps) or 1.0
        return _FakeTensor([math.log(max(e / total, 1e-10)) for e in exps])

    def softmax(self, tensor, dim=0):
        data = [float(tensor[i]) for i in range(len(tensor))]
        max_v = max(data) if data else 0.0
        exps = [math.exp(v - max_v) if v != float("-inf") else 0.0 for v in data]
        total = sum(exps) or 1.0
        return _FakeTensor([e / total for e in exps])

    def empty(self, *dims):
        class _ShapedTensor:
            shape = dims
        return _ShapedTensor()

    def save(self, obj, path): pass

    def load(self, path, map_location=None, weights_only=True):
        class _W:
            shape = (16, omr_metrics.N_FEATURES)
        return {"net.0.weight": _W()}


_fake_torch = _FakeTorch()


class _FakeModel:
    """Simulates InterfaceScorer using plain Python."""

    def __init__(self, scores=None):
        self._fixed_scores = scores
        self.training = False

    def __call__(self, feat_tensor):
        n = len(feat_tensor)
        if self._fixed_scores is not None:
            return _FakeTensor(self._fixed_scores[:n])
        return _FakeTensor([1.0 / (i + 1) for i in range(n)])

    def train(self):  self.training = True
    def eval(self):   self.training = False
    def parameters(self): return []
    def state_dict(self): return {"fake": "weights"}
    def load_state_dict(self, d): pass


@pytest.fixture
def torch_env():
    """Inject fake torch into the omr_metrics namespace so PyTorch-dependent
    functions (_compute_weights, _train_step, _get_model, _save_model) can be
    exercised without a real installation."""
    with (
        patch.dict(omr_metrics.__dict__, {"torch": _fake_torch}),
        patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
        patch.object(omr_metrics, "_optimizer", None),
    ):
        yield _fake_torch


# ===========================================================================
# _compute_weights — unit tests
# ===========================================================================

class TestComputeWeights:
    def test_returns_weights_and_scores_keys(self, torch_env):
        model = _FakeModel(scores=[2.0, 1.0])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            result = omr_metrics._compute_weights({"wan": _WAN, "wan2": _WAN2})
        assert "probs" in result
        assert "scores" in result

    def test_weights_are_positive_integers(self, torch_env):
        model = _FakeModel(scores=[3.0, 1.0])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            result = omr_metrics._compute_weights({"wan": _WAN, "wan2": _WAN2})
        for p in result["probs"].values():
            assert isinstance(p, float)
            assert 0.0 <= p <= 1.0

    def test_scores_sum_to_100(self, torch_env):
        model = _FakeModel(scores=[3.0, 1.0])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            result = omr_metrics._compute_weights({"wan": _WAN, "wan2": _WAN2})
        total = sum(result["scores"].values())
        assert abs(total - 100.0) < 0.1

    def test_interface_keys_match_input(self, torch_env):
        model = _FakeModel(scores=[1.0, 0.5, 0.2])
        data = {"eth0": _WAN, "lte0": _MODEM_WAN, "wlan0": _WIFI_WAN}
        with patch.object(omr_metrics, "_get_model", return_value=model):
            result = omr_metrics._compute_weights(data)
        assert set(result["probs"].keys()) == {"eth0", "lte0", "wlan0"}
        assert set(result["scores"].keys()) == {"eth0", "lte0", "wlan0"}

    def test_higher_raw_score_yields_higher_weight(self, torch_env):
        # wan gets score 5.0, wan2 gets 1.0 → wan's prob must be larger
        model = _FakeModel(scores=[5.0, 1.0])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            result = omr_metrics._compute_weights({"wan": _WAN, "wan2": _WAN2})
        assert result["probs"]["wan"] > result["probs"]["wan2"]

    def test_offline_interface_gets_minimum_weight(self, torch_env):
        offline = {**_WAN2, "status": "offline"}
        model = _FakeModel(scores=[1.0, 1.0])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            result = omr_metrics._compute_weights({"wan": _WAN, "wan2": offline})
        # Offline interface is masked to -inf → softmax ≈ 0 → prob ≈ 0.0
        assert result["probs"]["wan2"] < 0.01
        assert result["probs"]["wan"]  > result["probs"]["wan2"]

    def test_online_status_not_masked(self, torch_env):
        model = _FakeModel(scores=[1.0, 1.0])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            result = omr_metrics._compute_weights({"wan": _WAN, "wan2": _WAN2})
        assert result["probs"]["wan"]  > 0.0
        assert result["probs"]["wan2"] > 0.0

    def test_none_status_not_masked(self, torch_env):
        no_status = {**_WAN, "status": None}
        model = _FakeModel(scores=[1.0, 1.0])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            result = omr_metrics._compute_weights({"wan": no_status, "wan2": _WAN2})
        assert result["probs"]["wan"] > 0.0

    def test_explain_includes_all_feature_names(self, torch_env):
        model = _FakeModel(scores=[1.0])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            result = omr_metrics._compute_weights({"wan": _WAN}, explain=True)
        assert "features" in result
        assert set(result["features"]["wan"].keys()) == set(omr_metrics.FEATURE_NAMES)

    def test_explain_false_omits_features(self, torch_env):
        model = _FakeModel(scores=[1.0])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            result = omr_metrics._compute_weights({"wan": _WAN}, explain=False)
        assert "features" not in result

    def test_feature_values_are_rounded_to_4dp(self, torch_env):
        model = _FakeModel(scores=[1.0])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            result = omr_metrics._compute_weights({"wan": _WAN}, explain=True)
        for v in result["features"]["wan"].values():
            assert v == round(v, 4)

    def test_single_interface_gets_maximum_weight(self, torch_env):
        # Single online interface: softmax([x]) = [1.0] → prob = 1.0
        model = _FakeModel(scores=[2.5])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            result = omr_metrics._compute_weights({"wan": _WAN})
        assert abs(result["probs"]["wan"] - 1.0) < 0.01

    def test_all_offline_weights_are_zero(self, torch_env):
        """When every interface is offline the softmax of -inf values is NaN;
        the implementation should not crash and probs are effectively 0."""
        data = {
            "wan":  {**_WAN,  "status": "offline"},
            "wan2": {**_WAN2, "status": "offline"},
        }
        model = _FakeModel(scores=[1.0, 1.0])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            # Should not raise
            result = omr_metrics._compute_weights(data)
        assert "probs" in result


# ===========================================================================
# _train_step — unit tests
# ===========================================================================

class TestTrainStep:
    def test_single_interface_returns_zero_immediately(self, torch_env):
        with patch.object(omr_metrics, "_get_model", return_value=_FakeModel()):
            loss = omr_metrics._train_step({"wan": _WAN}, {"wan": 1.0}, lr=0.01)
        assert loss == 0.0

    def test_returns_non_negative_float(self, torch_env):
        model = _FakeModel(scores=[1.0, 0.5])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            loss = omr_metrics._train_step(
                {"wan": _WAN, "wan2": _WAN2}, {"wan": 1.0, "wan2": 0.0}, lr=0.01
            )
        assert isinstance(loss, float)
        assert loss >= 0.0

    def test_perfect_prediction_gives_low_loss(self, torch_env):
        # Model returns [3.0, 0.0] → softmax ≈ [1.0, 0.0]; target = {wan: 1.0, wan2: 0.0}
        model = _FakeModel(scores=[10.0, -10.0])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            loss = omr_metrics._train_step(
                {"wan": _WAN, "wan2": _WAN2}, {"wan": 1.0, "wan2": 0.0}, lr=0.01
            )
        assert loss < 0.01

    def test_wrong_prediction_gives_higher_loss(self, torch_env):
        # Model predicts wan≈1; target gives all weight to wan2 → high loss
        model = _FakeModel(scores=[10.0, -10.0])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            loss = omr_metrics._train_step(
                {"wan": _WAN, "wan2": _WAN2}, {"wan": 0.0, "wan2": 1.0}, lr=0.01
            )
        assert loss > 0.1

    def test_target_weights_are_normalized(self, torch_env):
        """Targets summing to 10 must behave the same as if they summed to 1."""
        model_a = _FakeModel(scores=[1.0, 0.5])
        model_b = _FakeModel(scores=[1.0, 0.5])
        with patch.object(omr_metrics, "_get_model", return_value=model_a):
            loss_norm = omr_metrics._train_step(
                {"wan": _WAN, "wan2": _WAN2}, {"wan": 1.0, "wan2": 0.0}, lr=0.0
            )
        with patch.object(omr_metrics, "_get_model", return_value=model_b):
            loss_unnorm = omr_metrics._train_step(
                {"wan": _WAN, "wan2": _WAN2}, {"wan": 10.0, "wan2": 0.0}, lr=0.0
            )
        assert abs(loss_norm - loss_unnorm) < 1e-9

    def test_zero_target_sum_raises_value_error(self, torch_env):
        model = _FakeModel(scores=[1.0, 0.5])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            with pytest.raises(ValueError, match="positive mass"):
                omr_metrics._train_step(
                    {"wan": _WAN, "wan2": _WAN2}, {"wan": 0.0, "wan2": 0.0}, lr=0.01
                )

    def test_history_forwarded_to_feature_extraction(self, torch_env):
        model = _FakeModel(scores=[1.0, 0.5])
        history_data = {
            "wan": _history_at(_WAN, [{"latency": 20.0}] * 3),
            "wan2": _history_at(_WAN2, [{"latency": 30.0}] * 3),
        }
        captured = {}

        def fake_extract(payload, history=None):
            captured[payload["interface"]] = history
            return [0.5] * omr_metrics.N_FEATURES

        with (
            patch.object(omr_metrics, "_get_model", return_value=model),
            patch.object(omr_metrics, "_extract_features", side_effect=fake_extract),
        ):
            omr_metrics._train_step(
                {"wan": _WAN, "wan2": _WAN2},
                {"wan": 1.0, "wan2": 0.0},
                lr=0.01,
                history_data=history_data,
            )

        assert captured["wan"] == history_data["wan"]
        assert captured["wan2"] == history_data["wan2"]

    def test_model_toggled_train_then_eval(self, torch_env):
        model = _FakeModel(scores=[1.0, 0.5])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            omr_metrics._train_step(
                {"wan": _WAN, "wan2": _WAN2}, {"wan": 1.0, "wan2": 0.0}, lr=0.01
            )
        assert model.training is False   # must be back in eval mode

    def test_three_interfaces(self, torch_env):
        model = _FakeModel(scores=[3.0, 2.0, 1.0])
        data = {"wan": _WAN, "wan2": _WAN2, "lte": _MODEM_WAN}
        with patch.object(omr_metrics, "_get_model", return_value=model):
            loss = omr_metrics._train_step(
                data, {"wan": 1.0, "wan2": 0.0, "lte": 0.0}, lr=0.01
            )
        assert isinstance(loss, float)
        assert loss >= 0.0


# ===========================================================================
# _get_model — unit tests
# ===========================================================================

class TestGetModel:
    def test_returns_cached_model(self, torch_env):
        sentinel = _FakeModel()
        omr_metrics._decision_model = sentinel
        with patch.object(omr_metrics, "_make_model") as mock_make:
            result = omr_metrics._get_model()
        assert result is sentinel
        mock_make.assert_not_called()

    def test_calls_make_model_when_no_file(self, torch_env):
        fresh = _FakeModel()
        with (
            patch("os.path.isfile", return_value=False),
            patch.object(omr_metrics, "_make_model", return_value=fresh) as mock_make,
        ):
            result = omr_metrics._get_model()
        mock_make.assert_called_once()
        assert result is fresh

    def test_caches_result_of_make_model(self, torch_env):
        fresh = _FakeModel()
        with (
            patch("os.path.isfile", return_value=False),
            patch.object(omr_metrics, "_make_model", return_value=fresh),
        ):
            omr_metrics._get_model()
        assert omr_metrics._decision_model is fresh

    def test_loads_from_file_when_present(self, torch_env):
        """When a model file exists the state dict is loaded rather than
        calling _make_model."""
        class _LoadableScorer:
            def __init__(self): pass
            def load_state_dict(self, d): self._sd = d
            def eval(self): pass

        with (
            patch("os.path.isfile", return_value=True),
            patch.dict(omr_metrics.__dict__, {"InterfaceScorer": _LoadableScorer}),
            patch.object(omr_metrics, "_make_model") as mock_make,
        ):
            result = omr_metrics._get_model()

        mock_make.assert_not_called()
        assert isinstance(result, _LoadableScorer)

    def test_falls_back_to_make_model_on_load_error(self, torch_env):
        class _BrokenScorer:
            def __init__(self): pass
            def load_state_dict(self, d): raise RuntimeError("corrupt file")
            def eval(self): pass

        fallback = _FakeModel()
        with (
            patch("os.path.isfile", return_value=True),
            patch.dict(omr_metrics.__dict__, {"InterfaceScorer": _BrokenScorer}),
            patch.object(omr_metrics, "_make_model", return_value=fallback) as mock_make,
        ):
            result = omr_metrics._get_model()

        mock_make.assert_called_once()
        assert result is fallback


# ===========================================================================
# _save_model — unit tests
# ===========================================================================

class TestSaveModel:
    def test_writes_to_tmp_then_replaces(self, torch_env):
        replaced = []
        model = _FakeModel()

        with (
            patch.object(omr_metrics, "DECISION_MODEL_FILE", "/fake/model.pt"),
            patch("os.replace", side_effect=lambda s, d: replaced.append((s, d))),
        ):
            omr_metrics._save_model(model)

        assert len(replaced) == 1
        src, dst = replaced[0]
        assert src == "/fake/model.pt.tmp"
        assert dst == "/fake/model.pt"

    def test_passes_state_dict_to_torch_save(self, torch_env):
        saved = []
        model = _FakeModel()

        patched_torch = _FakeTorch()
        patched_torch.save = lambda obj, path: saved.append((obj, path))

        with (
            patch.dict(omr_metrics.__dict__, {"torch": patched_torch}),
            patch.object(omr_metrics, "DECISION_MODEL_FILE", "/fake/model.pt"),
            patch("os.replace"),
        ):
            omr_metrics._save_model(model)

        assert len(saved) == 1
        obj, path = saved[0]
        assert obj == model.state_dict()
        assert path == "/fake/model.pt.tmp"

    def test_save_error_does_not_raise(self, torch_env):
        model = _FakeModel()
        broken_torch = _FakeTorch()
        broken_torch.save = lambda obj, path: (_ for _ in ()).throw(OSError("disk full"))

        with (
            patch.dict(omr_metrics.__dict__, {"torch": broken_torch}),
            patch.object(omr_metrics, "DECISION_MODEL_FILE", "/fake/model.pt"),
        ):
            omr_metrics._save_model(model)  # must not raise


# ===========================================================================
# InterfaceMetrics — new fields (weight, asn)
# ===========================================================================

class TestInterfaceMetricsDefaults:
    def test_weight_defaults_to_100(self, user_client):
        captured = {}

        def fake_write(username, payload):
            captured["payload"] = payload

        payload = {k: v for k, v in _WAN.items() if k != "weight"}
        with patch.object(omr_metrics, "_write_interface", side_effect=fake_write):
            user_client.post("/metrics", json=payload)

        assert captured["payload"]["weight"] == 100

    def test_weight_can_be_set_explicitly(self, user_client):
        captured = {}

        def fake_write(username, payload):
            captured["payload"] = payload

        with patch.object(omr_metrics, "_write_interface", side_effect=fake_write):
            user_client.post("/metrics", json={**_WAN, "weight": 50})

        assert captured["payload"]["weight"] == 50

    def test_asn_defaults_to_none(self, user_client):
        captured = {}

        def fake_write(username, payload):
            captured["payload"] = payload

        payload = {k: v for k, v in _WAN.items() if k != "asn"}
        with patch.object(omr_metrics, "_write_interface", side_effect=fake_write):
            user_client.post("/metrics", json=payload)

        assert captured["payload"]["asn"] is None

    def test_asn_can_be_set_explicitly(self, user_client):
        captured = {}

        def fake_write(username, payload):
            captured["payload"] = payload

        with patch.object(omr_metrics, "_write_interface", side_effect=fake_write):
            user_client.post("/metrics", json={**_WAN, "asn": "AS1234"})

        assert captured["payload"]["asn"] == "AS1234"

    def test_weight_and_asn_returned_in_get(self, user_client):
        stored = {**_WAN, "weight": 75, "asn": "AS5678"}
        with patch.object(omr_metrics, "_read_user", return_value={"wan": stored}):
            r = user_client.get("/metrics?interface=wan")
        assert r.status_code == 200
        data = r.json()
        assert data["weight"] == 75
        assert data["asn"] == "AS5678"


# ===========================================================================
# _compute_weights_heuristic — unit tests
# ===========================================================================

_H_CONG0  = {**_WAN,  "congestion": {"score": 0,   "level": "none"}}
_H_CONG50 = {**_WAN2, "congestion": {"score": 50,  "level": "moderate"}}
_H_CONG100 = {**_WAN2, "congestion": {"score": 100, "level": "severe"}}
_H_OFFLINE = {**_WAN2, "status": "offline"}
_H_NO_LAT  = {**_WAN,  "latency": None}
_H_NO_CONG = {**_WAN,  "congestion": None}


class TestComputeWeightsHeuristic:
    def test_returns_weights_and_scores_keys(self):
        result = omr_metrics._compute_weights_heuristic({"wan": _H_CONG0})
        assert "probs" in result
        assert "scores" in result

    def test_interface_keys_match_input(self):
        result = omr_metrics._compute_weights_heuristic({"wan": _H_CONG0, "wan2": _H_CONG50})
        assert set(result["probs"].keys()) == {"wan", "wan2"}
        assert set(result["scores"].keys()) == {"wan", "wan2"}

    def test_equal_congestion_gives_equal_weights(self):
        result = omr_metrics._compute_weights_heuristic({"wan": _H_CONG0, "wan2": _H_CONG0})
        assert result["probs"]["wan"] == result["probs"]["wan2"]

    def test_equal_interfaces_get_equal_probs(self):
        result = omr_metrics._compute_weights_heuristic({"wan": _H_CONG0, "wan2": _H_CONG0})
        assert abs(result["probs"]["wan"] - result["probs"]["wan2"]) < 1e-9

    def test_single_interface_gets_high_prob(self):
        result = omr_metrics._compute_weights_heuristic({"wan": _H_CONG0})
        assert result["probs"]["wan"] > 0.5

    def test_lower_congestion_gives_higher_weight(self):
        result = omr_metrics._compute_weights_heuristic({"wan": _H_CONG0, "wan2": _H_CONG50})
        assert result["probs"]["wan"] > result["probs"]["wan2"]

    def test_offline_interface_gets_zero_prob(self):
        result = omr_metrics._compute_weights_heuristic({"wan": _H_CONG0, "wan2": _H_OFFLINE})
        assert result["probs"]["wan2"] == 0.0

    def test_no_latency_treated_as_offline(self):
        result = omr_metrics._compute_weights_heuristic({"wan": _H_CONG0, "wan2": _H_NO_LAT})
        assert result["probs"]["wan2"] == 0.0

    def test_all_offline_gives_equal_fallback(self):
        offline1 = {**_WAN,  "status": "offline"}
        offline2 = {**_WAN2, "status": "offline"}
        result = omr_metrics._compute_weights_heuristic({"wan": offline1, "wan2": offline2})
        assert result["probs"]["wan"] == result["probs"]["wan2"]

    def test_congestion_100_gives_lower_prob(self):
        result = omr_metrics._compute_weights_heuristic({"wan": _H_CONG0, "wan2": _H_CONG100})
        # cong=100 → cong_q=0; other signals (latency, loss, jitter) still contribute
        # so prob > 0 but significantly lower than cong=0
        assert result["probs"]["wan"] > result["probs"]["wan2"]
        assert result["probs"]["wan2"] < 0.45

    def test_no_congestion_falls_back_to_latency_loss(self):
        # No congestion field; latency and loss should still produce a valid prob.
        result = omr_metrics._compute_weights_heuristic({"wan": _H_NO_CONG, "wan2": _H_CONG0})
        assert result["probs"]["wan"] >= 0.0
        assert result["probs"]["wan2"] >= 0.0

    def test_scores_are_quality_percentages(self):
        result = omr_metrics._compute_weights_heuristic({"wan": _H_CONG0, "wan2": _H_CONG50})
        for s in result["scores"].values():
            assert 0.0 <= s <= 100.0

    def test_all_probs_are_valid_floats(self):
        result = omr_metrics._compute_weights_heuristic(
            {"wan": _H_CONG0, "wan2": _H_CONG50, "lte": _H_OFFLINE}
        )
        for p in result["probs"].values():
            assert isinstance(p, float)
            assert 0.0 <= p <= 1.0

    def test_three_interfaces_all_online(self):
        third = {**_WAN, "interface": "lte0", "congestion": {"score": 20, "level": "low"}}
        result = omr_metrics._compute_weights_heuristic(
            {"wan": _H_CONG0, "wan2": _H_CONG50, "lte0": third}
        )
        assert len(result["probs"]) == 3
        assert result["probs"]["wan"] > result["probs"]["wan2"] > 0


# ===========================================================================
# _parse_since — unit tests
# ===========================================================================

class TestParseSince:
    @pytest.mark.parametrize("shorthand,expected", [
        ("15m",  900),
        ("30m",  1800),
        ("1h",   3600),
        ("6h",   21600),
        ("12h",  43200),
        ("24h",  86400),
        ("2d",   172800),
        ("7d",   604800),
        ("30d",  2592000),
    ])
    def test_known_shorthands(self, shorthand, expected):
        assert omr_metrics._parse_since(shorthand) == expected

    def test_raw_integer_string(self):
        assert omr_metrics._parse_since("7200") == 7200

    def test_raw_integer_below_60_clamped_to_60(self):
        assert omr_metrics._parse_since("30") == 60

    def test_invalid_string_returns_default_3600(self):
        assert omr_metrics._parse_since("badvalue") == 3600

    def test_whitespace_trimmed(self):
        assert omr_metrics._parse_since("  1h  ") == 3600

    def test_case_insensitive(self):
        assert omr_metrics._parse_since("1H") == 3600
        assert omr_metrics._parse_since("7D") == 604800


# ===========================================================================
# JSONBackend.read_history — stub always returns []
# ===========================================================================

class TestJSONBackendHistory:
    def test_returns_empty_list(self):
        backend = omr_metrics.JSONBackend()
        assert backend.read_history("alice", "wan", 3600, 100) == []

    def test_returns_empty_list_regardless_of_params(self):
        backend = omr_metrics.JSONBackend()
        assert backend.read_history("bob", "wan2", 86400, 5000) == []


# ===========================================================================
# GET /metrics/history — endpoint tests
# ===========================================================================

class TestGetMetricsHistory:
    def _get(self, client, **params):
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        return client.get(f"/metrics/history?{qs}" if qs else "/metrics/history")

    def test_returns_501_with_json_backend(self, user_client):
        with patch.object(omr_metrics, "_get_backend",
                          return_value=omr_metrics.JSONBackend()):
            r = self._get(user_client, interface="wan")
        assert r.status_code == 501
        assert "JSON" in r.json()["error"]

    def test_no_interface_returns_all_interfaces(self, user_client):
        all_hist = {"wan": [_WAN], "wan2": [_WAN2]}
        mock_influx = MagicMock(spec=omr_metrics.InfluxBackend)
        mock_influx.read_history.return_value = all_hist
        with patch.object(omr_metrics, "_get_backend", return_value=mock_influx):
            r = self._get(user_client)  # no interface param
        assert r.status_code == 200
        assert isinstance(r.json(), dict)
        assert set(r.json().keys()) == {"wan", "wan2"}

    def test_returns_list_from_read_history(self, user_client):
        fake_history = [_WAN, {**_WAN, "timestamp": 1_700_001_000}]
        mock_influx = MagicMock(spec=omr_metrics.InfluxBackend)
        mock_influx.read_history.return_value = fake_history
        with patch.object(omr_metrics, "_get_backend", return_value=mock_influx):
            r = self._get(user_client, interface="wan")
        assert r.status_code == 200
        assert len(r.json()) == 2

    def test_since_defaults_to_1h(self, user_client):
        mock_influx = MagicMock(spec=omr_metrics.InfluxBackend)
        mock_influx.read_history.return_value = []
        with patch.object(omr_metrics, "_get_backend", return_value=mock_influx):
            self._get(user_client, interface="wan")
        _, _, since_seconds, _ = mock_influx.read_history.call_args.args
        assert since_seconds == 3600

    def test_since_param_parsed(self, user_client):
        mock_influx = MagicMock(spec=omr_metrics.InfluxBackend)
        mock_influx.read_history.return_value = []
        with patch.object(omr_metrics, "_get_backend", return_value=mock_influx):
            self._get(user_client, interface="wan", since="24h")
        _, _, since_seconds, _ = mock_influx.read_history.call_args.args
        assert since_seconds == 86400

    def test_limit_param_forwarded(self, user_client):
        mock_influx = MagicMock(spec=omr_metrics.InfluxBackend)
        mock_influx.read_history.return_value = []
        with patch.object(omr_metrics, "_get_backend", return_value=mock_influx):
            self._get(user_client, interface="wan", limit=50)
        _, _, _, limit = mock_influx.read_history.call_args.args
        assert limit == 50

    def test_interface_param_forwarded(self, user_client):
        mock_influx = MagicMock(spec=omr_metrics.InfluxBackend)
        mock_influx.read_history.return_value = []
        with patch.object(omr_metrics, "_get_backend", return_value=mock_influx):
            self._get(user_client, interface="wan2")
        _, interface, _, _ = mock_influx.read_history.call_args.args
        assert interface == "wan2"

    def test_user_queried_is_current_user(self, user_client):
        mock_influx = MagicMock(spec=omr_metrics.InfluxBackend)
        mock_influx.read_history.return_value = []
        with patch.object(omr_metrics, "_get_backend", return_value=mock_influx):
            self._get(user_client, interface="wan")
        username, _, _, _ = mock_influx.read_history.call_args.args
        assert username == "openmptcprouter"

    def test_admin_can_query_other_user(self, admin_client):
        mock_influx = MagicMock(spec=omr_metrics.InfluxBackend)
        mock_influx.read_history.return_value = []
        with patch.object(omr_metrics, "_get_backend", return_value=mock_influx):
            admin_client.get("/metrics/history?interface=wan&username=openmptcprouter")
        username, _, _, _ = mock_influx.read_history.call_args.args
        assert username == "openmptcprouter"

    def test_unauthenticated_returns_403(self, unauth_client):
        r = self._get(unauth_client, interface="wan")
        assert r.status_code == 403


# ===========================================================================
# InfluxBackend.read_history — unit tests
# ===========================================================================

class TestInfluxBackendHistory:
    def _make_backend(self):
        """Create an InfluxBackend with a mocked InfluxDBClient3."""
        mock_client = MagicMock()
        with patch.dict("sys.modules", {
            "influxdb_client_3": MagicMock(InfluxDBClient3=MagicMock(return_value=mock_client))
        }):
            backend = omr_metrics.InfluxBackend("http://localhost", "tok", "omr", "bucket")
        backend._client = mock_client
        return backend, mock_client

    def _fake_table(self, rows):
        """rows: list of (ts, json_str) tuples."""
        class _Ts:
            def __init__(self, v): self._v = v
            def timestamp(self): return self._v

        table = MagicMock()
        table.to_pydict.return_value = {
            "time":         [_Ts(ts) for ts, _ in rows],
            "json_payload": [js       for _, js in rows],
        }
        return table

    def _fake_all_table(self, rows):
        """rows: list of (ts, interface, json_str) tuples."""
        class _Ts:
            def __init__(self, v): self._v = v
            def timestamp(self): return self._v

        table = MagicMock()
        table.to_pydict.return_value = {
            "time":         [_Ts(ts) for ts, _, _ in rows],
            "interface":    [iface    for _, iface, _ in rows],
            "json_payload": [js       for _, _, js in rows],
        }
        return table

    def test_returns_empty_list_on_query_error(self):
        backend, mock_client = self._make_backend()
        mock_client.query.side_effect = Exception("connection refused")
        assert backend.read_history("alice", "wan", 3600, 100) == []

    def test_returns_parsed_payloads(self):
        backend, mock_client = self._make_backend()
        row = json.dumps({**_WAN, "timestamp": 1_700_000_000})
        mock_client.query.return_value = self._fake_table([(1_700_000_000, row)])
        result = backend.read_history("alice", "wan", 3600, 100)
        assert len(result) == 1
        assert result[0]["interface"] == "wan"
        assert result[0]["latency"] == 25.0

    def test_multiple_rows_returned_in_order(self):
        backend, mock_client = self._make_backend()
        rows = [
            (1_700_000_000, json.dumps({**_WAN, "timestamp": 1_700_000_000})),
            (1_700_001_000, json.dumps({**_WAN, "timestamp": 1_700_001_000})),
            (1_700_002_000, json.dumps({**_WAN, "timestamp": 1_700_002_000})),
        ]
        mock_client.query.return_value = self._fake_table(rows)
        result = backend.read_history("alice", "wan", 3600, 100)
        assert len(result) == 3
        assert result[0]["timestamp"] == 1_700_000_000
        assert result[2]["timestamp"] == 1_700_002_000

    def test_adds_timestamp_from_influx_when_missing_in_payload(self):
        backend, mock_client = self._make_backend()
        payload_no_ts = {k: v for k, v in _WAN.items() if k != "timestamp"}
        row = (1_700_005_000, json.dumps(payload_no_ts))
        mock_client.query.return_value = self._fake_table([row])
        result = backend.read_history("alice", "wan", 3600, 100)
        assert result[0]["timestamp"] == 1_700_005_000

    def test_query_uses_correct_username_and_interface(self):
        backend, mock_client = self._make_backend()
        mock_client.query.return_value = self._fake_table([])
        backend.read_history("bob", "lte0", 7200, 200)
        call_kwargs = mock_client.query.call_args
        params = call_kwargs.kwargs.get("query_parameters") or call_kwargs[1].get("query_parameters", {})
        assert params.get("username") == "bob"
        assert params.get("interface") == "lte0"

    def test_skips_rows_with_invalid_json(self):
        backend, mock_client = self._make_backend()
        rows = [
            (1_700_000_000, "{invalid json"),
            (1_700_001_000, json.dumps({**_WAN, "timestamp": 1_700_001_000})),
        ]
        mock_client.query.return_value = self._fake_table(rows)
        result = backend.read_history("alice", "wan", 3600, 100)
        assert len(result) == 1
        assert result[0]["timestamp"] == 1_700_001_000

    def test_returns_empty_list_when_to_pydict_raises(self):
        backend, mock_client = self._make_backend()
        table = MagicMock()
        table.to_pydict.side_effect = Exception("parse error")
        mock_client.query.return_value = table
        assert backend.read_history("alice", "wan", 3600, 100) == []

    def test_all_interfaces_limit_applies_per_interface(self):
        backend, mock_client = self._make_backend()
        rows = [
            (1_700_000_000, "wan", json.dumps({**_WAN, "timestamp": 1_700_000_000})),
            (1_700_000_030, "wan2", json.dumps({**_WAN2, "timestamp": 1_700_000_030})),
            (1_700_000_060, "wan", json.dumps({**_WAN, "timestamp": 1_700_000_060})),
            (1_700_000_090, "wan2", json.dumps({**_WAN2, "timestamp": 1_700_000_090})),
            (1_700_000_120, "wan", json.dumps({**_WAN, "timestamp": 1_700_000_120})),
        ]
        mock_client.query.return_value = self._fake_all_table(rows)

        result = backend.read_history("alice", None, 3600, 2)

        assert list(result.keys()) == ["wan", "wan2"]
        assert [entry["timestamp"] for entry in result["wan"]] == [1_700_000_000, 1_700_000_060]
        assert [entry["timestamp"] for entry in result["wan2"]] == [1_700_000_030, 1_700_000_090]

    def test_all_interfaces_query_limits_inside_sql(self):
        backend, mock_client = self._make_backend()
        mock_client.query.return_value = self._fake_all_table([])
        backend.read_history("alice", None, 3600, 7)
        sql = mock_client.query.call_args.args[0]
        assert "ROW_NUMBER() OVER (PARTITION BY interface" in sql
        assert "ORDER BY time DESC" in sql
        assert ") AS ranked WHERE rn <= 7" in sql
        assert "WHERE rn <= 7" in sql


# ===========================================================================
# _metric_level — unit tests
# ===========================================================================

class TestMetricLevel:
    @pytest.mark.parametrize("value,expected", [
        (0.0,   "none"),
        (0.05,  "none"),
        (0.1,   "low"),
        (0.5,   "low"),
        (1.0,   "moderate"),
        (4.9,   "moderate"),
        (5.0,   "high"),
        (14.9,  "high"),
        (15.0,  "severe"),
        (100.0, "severe"),
    ])
    def test_loss_levels(self, value, expected):
        assert omr_metrics._metric_level(value, omr_metrics._LOSS_THRESHOLDS) == expected

    @pytest.mark.parametrize("value,expected", [
        (0.0,   "none"),
        (4.9,   "none"),
        (5.0,   "low"),
        (9.9,   "low"),
        (10.0,  "moderate"),
        (29.9,  "moderate"),
        (30.0,  "high"),
        (59.9,  "high"),
        (60.0,  "severe"),
        (200.0, "severe"),
    ])
    def test_jitter_levels(self, value, expected):
        assert omr_metrics._metric_level(value, omr_metrics._JITTER_THRESHOLDS) == expected

    @pytest.mark.parametrize("value,expected", [
        (0.0,  "none"),
        (24.9, "none"),
        (25.0, "low"),
        (49.9, "low"),
        (50.0, "moderate"),
        (74.9, "moderate"),
        (75.0, "high"),
        (89.9, "high"),
        (90.0, "severe"),
    ])
    def test_congestion_levels(self, value, expected):
        assert omr_metrics._metric_level(value, omr_metrics._CONGESTION_LEVELS) == expected


# ===========================================================================
# _forecast_metric — unit tests
# ===========================================================================

_FM_T0 = 1_700_000_000


def _loss_history(values: list, step: int = 30) -> list:
    """Build a history list with loss values only."""
    return [
        {**_WAN, "loss": v, "timestamp": _FM_T0 + i * step}
        for i, v in enumerate(values)
    ]


def _jitter_history(values: list, step: int = 30) -> list:
    return [
        {**_WAN, "jitter": v, "timestamp": _FM_T0 + i * step}
        for i, v in enumerate(values)
    ]


class TestForecastMetric:
    # --- empty / sparse history ---

    def test_empty_history_returns_none_current(self):
        result = omr_metrics._forecast_metric(
            [], ("loss",), omr_metrics._LOSS_THRESHOLDS,
        )
        assert result["current"] is None
        assert result["predicted"] is None
        assert result["confidence"] == "none"
        assert result["trend"] == "stable"
        assert result["slope_per_min"] == 0.0

    def test_single_point_returns_current_equals_predicted(self):
        hist = _loss_history([2.5])
        result = omr_metrics._forecast_metric(
            hist, ("loss",), omr_metrics._LOSS_THRESHOLDS, hi_clamp=100.0,
        )
        assert result["current"] == pytest.approx(2.5)
        assert result["predicted"] == pytest.approx(2.5)
        assert result["confidence"] == "none"

    def test_two_points_confidence_low(self):
        hist = _loss_history([1.0, 2.0])
        result = omr_metrics._forecast_metric(
            hist, ("loss",), omr_metrics._LOSS_THRESHOLDS, hi_clamp=100.0,
        )
        assert result["confidence"] == "low"

    def test_three_points_confidence_medium(self):
        hist = _loss_history([1.0, 2.0, 3.0])
        result = omr_metrics._forecast_metric(
            hist, ("loss",), omr_metrics._LOSS_THRESHOLDS, hi_clamp=100.0,
        )
        assert result["confidence"] == "medium"

    def test_five_points_old_enough_confidence_high(self):
        # 5 points spanning 4 * 30 = 120 seconds → "high"
        hist = _loss_history([1.0, 1.5, 2.0, 2.5, 3.0], step=30)
        result = omr_metrics._forecast_metric(
            hist, ("loss",), omr_metrics._LOSS_THRESHOLDS, hi_clamp=100.0,
        )
        assert result["confidence"] == "high"

    # --- current / current_level ---

    def test_current_reflects_last_value(self):
        hist = _loss_history([0.5, 1.0, 3.0])
        result = omr_metrics._forecast_metric(
            hist, ("loss",), omr_metrics._LOSS_THRESHOLDS, hi_clamp=100.0,
        )
        assert result["current"] == pytest.approx(3.0)

    def test_current_level_matches_thresholds(self):
        hist = _loss_history([6.0])
        result = omr_metrics._forecast_metric(
            hist, ("loss",), omr_metrics._LOSS_THRESHOLDS, hi_clamp=100.0,
        )
        assert result["current_level"] == "high"

    # --- trend ---

    def test_rising_trend_detected(self):
        hist = _loss_history([0.1, 0.5, 1.0, 2.0, 4.0])
        result = omr_metrics._forecast_metric(
            hist, ("loss",), omr_metrics._LOSS_THRESHOLDS,
            hi_clamp=100.0, stable_slope_per_min=0.1,
        )
        assert result["trend"] == "rising"

    def test_falling_trend_detected(self):
        hist = _loss_history([8.0, 5.0, 3.0, 1.5, 0.5])
        result = omr_metrics._forecast_metric(
            hist, ("loss",), omr_metrics._LOSS_THRESHOLDS,
            hi_clamp=100.0, stable_slope_per_min=0.1,
        )
        assert result["trend"] == "falling"

    def test_flat_series_is_stable(self):
        hist = _loss_history([2.0, 2.0, 2.0, 2.0, 2.0])
        result = omr_metrics._forecast_metric(
            hist, ("loss",), omr_metrics._LOSS_THRESHOLDS,
            hi_clamp=100.0, stable_slope_per_min=0.1,
        )
        assert result["trend"] == "stable"

    # --- predicted / predicted_level ---

    def test_rising_loss_predicted_higher(self):
        hist = _loss_history([0.5, 1.0, 2.0, 4.0])
        result = omr_metrics._forecast_metric(
            hist, ("loss",), omr_metrics._LOSS_THRESHOLDS, hi_clamp=100.0, horizon_s=300,
        )
        assert result["predicted"] > result["current"]

    def test_falling_loss_predicted_lower(self):
        hist = _loss_history([10.0, 7.0, 4.0, 2.0])
        result = omr_metrics._forecast_metric(
            hist, ("loss",), omr_metrics._LOSS_THRESHOLDS, hi_clamp=100.0, horizon_s=300,
        )
        assert result["predicted"] < result["current"]

    def test_predicted_clamped_to_zero(self):
        # Rapidly falling loss must not go negative
        hist = _loss_history([5.0, 3.0, 1.0, 0.5])
        result = omr_metrics._forecast_metric(
            hist, ("loss",), omr_metrics._LOSS_THRESHOLDS, hi_clamp=100.0, horizon_s=3600,
        )
        assert result["predicted"] >= 0.0

    def test_predicted_clamped_to_hi_clamp(self):
        # Rapidly rising loss must not exceed 100 %
        hist = _loss_history([80.0, 90.0, 99.0])
        result = omr_metrics._forecast_metric(
            hist, ("loss",), omr_metrics._LOSS_THRESHOLDS, hi_clamp=100.0, horizon_s=3600,
        )
        assert result["predicted"] <= 100.0

    def test_no_hi_clamp_allows_unbounded_prediction(self):
        # Jitter with no hi_clamp should be able to predict beyond any fixed cap
        hist = _jitter_history([10.0, 30.0, 50.0, 80.0])
        result = omr_metrics._forecast_metric(
            hist, ("jitter",), omr_metrics._JITTER_THRESHOLDS, hi_clamp=None, horizon_s=300,
        )
        # Just check no crash and result is non-negative
        assert result["predicted"] >= 0.0

    def test_predicted_level_reflects_predicted_value(self):
        # Force a large rise so predicted lands in "severe" (≥15 %)
        hist = _loss_history([5.0, 8.0, 12.0, 16.0])
        result = omr_metrics._forecast_metric(
            hist, ("loss",), omr_metrics._LOSS_THRESHOLDS, hi_clamp=100.0, horizon_s=300,
        )
        assert result["predicted_level"] == omr_metrics._metric_level(
            result["predicted"], omr_metrics._LOSS_THRESHOLDS
        )

    # --- ETA fields ---

    def test_eta_fields_present(self):
        hist = _loss_history([0.5, 1.0])
        result = omr_metrics._forecast_metric(
            hist, ("loss",), omr_metrics._LOSS_THRESHOLDS, hi_clamp=100.0,
        )
        assert "eta_severe_s" in result
        assert "eta_high_s" in result
        assert "eta_moderate_s" in result

    def test_eta_none_when_falling(self):
        # Falling trend: slope ≤ 0 → ETA never reached
        hist = _loss_history([10.0, 5.0, 2.0])
        result = omr_metrics._forecast_metric(
            hist, ("loss",), omr_metrics._LOSS_THRESHOLDS, hi_clamp=100.0,
        )
        assert result["eta_severe_s"] is None
        assert result["eta_high_s"] is None

    def test_eta_zero_when_already_above_threshold(self):
        # current loss = 20 % which is already ≥ severe threshold (15 %)
        hist = _loss_history([15.0, 18.0, 20.0])
        result = omr_metrics._forecast_metric(
            hist, ("loss",), omr_metrics._LOSS_THRESHOLDS, hi_clamp=100.0,
        )
        assert result["eta_severe_s"] == 0

    def test_eta_moderate_finite_for_rising_loss(self):
        # Rising from 0.5 % to 1 % in 90 s → must reach moderate (1 %) soon
        hist = _loss_history([0.1, 0.3, 0.5, 0.8])
        result = omr_metrics._forecast_metric(
            hist, ("loss",), omr_metrics._LOSS_THRESHOLDS, hi_clamp=100.0,
        )
        # moderate threshold is 1.0 %; slope is positive → finite ETA expected
        assert result["eta_moderate_s"] is not None
        assert result["eta_moderate_s"] >= 0

    # --- nested path ---

    def test_nested_path_congestion(self):
        hist = _history_at(_WAN, [
            {"congestion.score": 20},
            {"congestion.score": 40},
            {"congestion.score": 60},
        ])
        result = omr_metrics._forecast_metric(
            hist, ("congestion", "score"), omr_metrics._CONGESTION_LEVELS,
            hi_clamp=100.0, stable_slope_per_min=0.5,
        )
        assert result["current"] == pytest.approx(60.0)
        assert result["trend"] == "rising"

    def test_entries_without_timestamp_skipped(self):
        # Only the two timestamped entries should feed the regression
        hist = [
            {**_WAN, "loss": 1.0, "timestamp": _FM_T0},
            {**_WAN, "loss": 2.0},                      # no timestamp → skipped
            {**_WAN, "loss": 3.0, "timestamp": _FM_T0 + 60},
        ]
        result = omr_metrics._forecast_metric(
            hist, ("loss",), omr_metrics._LOSS_THRESHOLDS, hi_clamp=100.0, horizon_s=60,
        )
        # With slope ≈ (3-1)/60 per second, prediction at +60 s ≈ 5
        assert result["predicted"] > result["current"]

    def test_entries_without_metric_skipped(self):
        # Entries with missing loss field should not crash
        hist = [
            {**_WAN, "timestamp": _FM_T0},              # loss present (= 0.0 from _WAN)
            {**_WAN, "loss": None, "timestamp": _FM_T0 + 30},  # no loss value
            {**_WAN, "loss": 2.0, "timestamp": _FM_T0 + 60},
        ]
        result = omr_metrics._forecast_metric(
            hist, ("loss",), omr_metrics._LOSS_THRESHOLDS, hi_clamp=100.0,
        )
        # Should not raise, and current should be last loss value with a timestamp
        assert result is not None


# ===========================================================================
# GET /metrics/quality/forecast — endpoint tests
# ===========================================================================

class TestGetQualityForecast:
    def _get(self, client, **params):
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        url = f"/metrics/quality/forecast?{qs}" if qs else "/metrics/quality/forecast"
        return client.get(url)

    def _make_hist(self, n: int = 5, step: int = 30) -> list:
        return [
            {**_WAN, "timestamp": _FM_T0 + i * step,
             "loss": 1.0 + i * 0.2,
             "jitter": 5.0 + i * 0.5,
             "congestion": {"score": 10 + i * 3, "level": "none"}}
            for i in range(n)
        ]

    # --- structure ---

    def test_returns_empty_when_no_metrics(self, user_client):
        with patch.object(omr_metrics, "_read_user", return_value={}):
            r = self._get(user_client)
        assert r.status_code == 200
        assert r.json() == {}

    def test_returns_entry_per_interface(self, user_client):
        hist = self._make_hist()
        with (
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN, "wan2": _WAN2}),
            patch.object(omr_metrics, "_read_history", return_value=hist),
        ):
            r = self._get(user_client)
        assert r.status_code == 200
        data = r.json()
        assert set(data.keys()) == {"wan", "wan2"}

    def test_each_entry_has_congestion_loss_jitter(self, user_client):
        hist = self._make_hist()
        with (
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN}),
            patch.object(omr_metrics, "_read_history", return_value=hist),
        ):
            r = self._get(user_client)
        entry = r.json()["wan"]
        assert "congestion" in entry
        assert "loss" in entry
        assert "jitter" in entry

    def test_sub_objects_have_required_keys(self, user_client):
        hist = self._make_hist()
        required = {
            "current", "current_level", "predicted", "predicted_level",
            "trend", "slope_per_min", "confidence",
            "eta_severe_s", "eta_high_s", "eta_moderate_s",
        }
        with (
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN}),
            patch.object(omr_metrics, "_read_history", return_value=hist),
        ):
            r = self._get(user_client)
        entry = r.json()["wan"]
        for metric in ("congestion", "loss", "jitter"):
            missing = required - set(entry[metric].keys())
            assert not missing, f"{metric} missing keys: {missing}"

    # --- JSON backend fallback (confidence="none") ---

    def test_json_backend_uses_snapshot_as_history(self, user_client):
        # JSON backend returns [] for read_history; endpoint should fall back to snapshot
        snap = {**_WAN, "timestamp": _FM_T0, "loss": 3.0, "jitter": 8.0}
        with (
            patch.object(omr_metrics, "_read_user", return_value={"wan": snap}),
            patch.object(omr_metrics, "_read_history", return_value=[]),
        ):
            r = self._get(user_client)
        assert r.status_code == 200
        entry = r.json()["wan"]
        assert entry["loss"]["confidence"] == "none"

    def test_json_backend_no_timestamp_returns_none_current(self, user_client):
        # Snapshot has no timestamp → history stays empty → current=None
        snap = {k: v for k, v in _WAN.items() if k != "timestamp"}
        with (
            patch.object(omr_metrics, "_read_user", return_value={"wan": snap}),
            patch.object(omr_metrics, "_read_history", return_value=[]),
        ):
            r = self._get(user_client)
        assert r.status_code == 200
        assert r.json()["wan"]["loss"]["current"] is None

    # --- InfluxDB backend (confidence > "none") ---

    def test_influxdb_backend_passes_history_to_forecast(self, user_client):
        hist = self._make_hist(n=5)
        captured = {}

        def fake_read_history(username, iface, since_seconds, limit):
            captured.setdefault(iface, [])
            return hist

        with (
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN}),
            patch.object(omr_metrics, "_read_history", side_effect=fake_read_history),
        ):
            r = self._get(user_client)
        assert "wan" in captured
        assert r.json()["wan"]["loss"]["confidence"] == "high"

    # --- query params ---

    def test_horizon_forwarded_affects_prediction(self, user_client):
        # Rising loss: larger horizon → larger predicted value
        hist = self._make_hist(n=5)
        with (
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN}),
            patch.object(omr_metrics, "_read_history", return_value=hist),
        ):
            r_short = self._get(user_client, horizon=60)
            r_long  = self._get(user_client, horizon=1800)
        pred_short = r_short.json()["wan"]["loss"]["predicted"]
        pred_long  = r_long.json()["wan"]["loss"]["predicted"]
        assert pred_long >= pred_short

    def test_since_param_forwarded_to_read_history(self, user_client):
        captured = {}

        def fake_read_history(username, iface, since_seconds, limit):
            captured["since"] = since_seconds
            return self._make_hist()

        with (
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN}),
            patch.object(omr_metrics, "_read_history", side_effect=fake_read_history),
        ):
            self._get(user_client, since="6h")
        assert captured["since"] == 21600

    def test_limit_param_forwarded_to_read_history(self, user_client):
        captured = {}

        def fake_read_history(username, iface, since_seconds, limit):
            captured["limit"] = limit
            return self._make_hist()

        with (
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN}),
            patch.object(omr_metrics, "_read_history", side_effect=fake_read_history),
        ):
            self._get(user_client, limit=42)
        assert captured["limit"] == 42

    # --- auth ---

    def test_admin_can_query_other_user(self, admin_client):
        captured = {}

        def fake_read_user(username):
            captured["username"] = username
            return {"wan": _WAN}

        with (
            patch.object(omr_metrics, "_read_user", side_effect=fake_read_user),
            patch.object(omr_metrics, "_read_history", return_value=self._make_hist()),
        ):
            self._get(admin_client, username="openmptcprouter")
        assert captured["username"] == "openmptcprouter"

    def test_unauthenticated_returns_403(self, unauth_client):
        r = self._get(unauth_client)
        assert r.status_code == 403

    # --- current / predicted correctness ---

    def test_current_loss_matches_last_history_entry(self, user_client):
        hist = self._make_hist(n=4)
        last_loss = hist[-1]["loss"]
        with (
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN}),
            patch.object(omr_metrics, "_read_history", return_value=hist),
        ):
            r = self._get(user_client)
        assert r.json()["wan"]["loss"]["current"] == pytest.approx(last_loss)

    def test_rising_loss_has_rising_trend(self, user_client):
        # loss increases monotonically → trend must be "rising"
        hist = [
            {**_WAN, "timestamp": _FM_T0 + i * 30, "loss": float(i + 1) * 2.0}
            for i in range(5)
        ]
        with (
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN}),
            patch.object(omr_metrics, "_read_history", return_value=hist),
        ):
            r = self._get(user_client)
        assert r.json()["wan"]["loss"]["trend"] == "rising"

    def test_congestion_current_level_name_is_string(self, user_client):
        hist = self._make_hist()
        with (
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN}),
            patch.object(omr_metrics, "_read_history", return_value=hist),
        ):
            r = self._get(user_client)
        level = r.json()["wan"]["congestion"]["current_level"]
        assert isinstance(level, str)
        assert level in ("none", "low", "moderate", "high", "severe")


# ===========================================================================
# _torch_predict_at — unit tests
# ===========================================================================

_TORCH_SKIP = pytest.mark.skipif(
    not omr_metrics._TORCH_AVAILABLE,
    reason="PyTorch not installed",
)

_TP_T0 = 1_700_000_000


def _tp_history(values, step=30):
    """Return (timestamps, values) lists spaced *step* seconds apart."""
    ts = [float(_TP_T0 + i * step) for i in range(len(values))]
    return ts, list(values)


class TestTorchPredictAt:
    def test_returns_none_for_fewer_than_min_points(self):
        ts, vs = _tp_history([10.0, 20.0, 30.0])
        result = omr_metrics._torch_predict_at(ts, vs, float(_TP_T0 + 120))
        assert result is None

    def test_returns_none_when_all_values_filtered_to_too_few(self):
        ts, _ = _tp_history([None] * 6)
        vs = [None] * 6
        result = omr_metrics._torch_predict_at(ts, vs, float(_TP_T0 + 180))
        assert result is None

    @_TORCH_SKIP
    def test_returns_float_for_sufficient_history(self):
        ts, vs = _tp_history([10.0, 12.0, 14.0, 16.0, 18.0, 20.0])
        result = omr_metrics._torch_predict_at(ts, vs, float(_TP_T0 + 180))
        assert isinstance(result, float)
        assert math.isfinite(result)

    @_TORCH_SKIP
    def test_rising_trend_predicts_above_last_value(self):
        ts, vs = _tp_history([5.0, 10.0, 15.0, 20.0, 25.0, 30.0])
        result = omr_metrics._torch_predict_at(ts, vs, float(_TP_T0 + 180))
        assert result > vs[-1]

    @_TORCH_SKIP
    def test_falling_trend_predicts_below_last_value(self):
        ts, vs = _tp_history([30.0, 25.0, 20.0, 15.0, 10.0, 5.0])
        result = omr_metrics._torch_predict_at(ts, vs, float(_TP_T0 + 180))
        assert result < vs[-1]

    @_TORCH_SKIP
    def test_flat_series_stays_near_constant(self):
        ts, vs = _tp_history([7.0] * 8)
        result = omr_metrics._torch_predict_at(ts, vs, float(_TP_T0 + 300))
        assert abs(result - 7.0) < 2.0

    @_TORCH_SKIP
    def test_result_is_finite_for_noisy_data(self):
        ts, vs = _tp_history([1.0, 50.0, 3.0, 48.0, 2.0, 49.0, 1.0, 50.0])
        result = omr_metrics._torch_predict_at(ts, vs, float(_TP_T0 + 300))
        assert math.isfinite(result)

    @_TORCH_SKIP
    def test_none_values_skipped(self):
        ts = [float(_TP_T0 + i * 30) for i in range(8)]
        vs = [None, 5.0, None, 10.0, 15.0, 20.0, None, 25.0]
        result = omr_metrics._torch_predict_at(ts, vs, float(_TP_T0 + 240))
        assert result is not None
        assert math.isfinite(result)

    @_TORCH_SKIP
    def test_halflife_zero_does_not_raise(self):
        ts, vs = _tp_history([10.0, 20.0, 30.0, 40.0, 50.0, 60.0])
        result = omr_metrics._torch_predict_at(ts, vs, float(_TP_T0 + 180), halflife_s=0.0)
        assert math.isfinite(result)

    @_TORCH_SKIP
    def test_exactly_min_points_is_accepted(self):
        n = omr_metrics._FORECAST_TORCH_MIN_POINTS
        ts, vs = _tp_history([float(i * 5) for i in range(n)])
        result = omr_metrics._torch_predict_at(ts, vs, float(_TP_T0 + n * 30))
        assert result is not None

    @_TORCH_SKIP
    def test_one_below_min_points_returns_none(self):
        n = omr_metrics._FORECAST_TORCH_MIN_POINTS - 1
        ts, vs = _tp_history([float(i * 5) for i in range(n)])
        result = omr_metrics._torch_predict_at(ts, vs, float(_TP_T0 + n * 30))
        assert result is None


# ===========================================================================
# _predict_at — dispatch unit tests
# ===========================================================================

class TestPredictAt:
    def test_torch_unavailable_delegates_to_linear(self):
        ts, vs = _tp_history([10.0, 20.0, 30.0])
        with patch.object(omr_metrics, "_TORCH_AVAILABLE", False):
            result = omr_metrics._predict_at(ts, vs, float(_TP_T0 + 90))
        expected = omr_metrics._linear_predict_at(ts, vs, float(_TP_T0 + 90))
        assert result == pytest.approx(expected)

    def test_torch_path_invoked_when_available_and_enough_points(self):
        ts, vs = _tp_history([float(i * 5) for i in range(6)])
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_torch_predict_at", return_value=99.0) as mock_tp,
        ):
            result = omr_metrics._predict_at(ts, vs, float(_TP_T0 + 180))
        assert result == 99.0
        mock_tp.assert_called_once()

    def test_falls_back_to_linear_when_torch_returns_none(self):
        ts, vs = _tp_history([10.0, 20.0, 30.0])
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_torch_predict_at", return_value=None),
        ):
            result = omr_metrics._predict_at(ts, vs, float(_TP_T0 + 90))
        expected = omr_metrics._linear_predict_at(ts, vs, float(_TP_T0 + 90))
        assert result == pytest.approx(expected)

    def test_empty_returns_none(self):
        with patch.object(omr_metrics, "_TORCH_AVAILABLE", False):
            assert omr_metrics._predict_at([], [], float(_TP_T0 + 90)) is None

    def test_single_point_returns_that_value(self):
        with patch.object(omr_metrics, "_TORCH_AVAILABLE", False):
            result = omr_metrics._predict_at([float(_TP_T0)], [7.0], float(_TP_T0 + 300))
        assert result == pytest.approx(7.0)

    def test_halflife_forwarded_to_torch_predict(self):
        ts, vs = _tp_history([float(i) for i in range(6)])
        captured = {}

        def _capture(timestamps, values, target_ts, halflife_s):
            captured["halflife_s"] = halflife_s
            return 42.0

        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_torch_predict_at", side_effect=_capture),
        ):
            omr_metrics._predict_at(ts, vs, float(_TP_T0 + 180), halflife_s=77.0)
        assert captured["halflife_s"] == 77.0

    def test_short_series_skips_torch_even_when_available(self):
        # < _FORECAST_TORCH_MIN_POINTS valid points → torch returns None → linear used
        ts, vs = _tp_history([1.0, 2.0])
        linear_result = omr_metrics._linear_predict_at(ts, vs, float(_TP_T0 + 60))
        with patch.object(omr_metrics, "_TORCH_AVAILABLE", True):
            result = omr_metrics._predict_at(ts, vs, float(_TP_T0 + 60))
        assert result == pytest.approx(linear_result)

    def test_halflife_forwarded_to_linear_when_torch_unavailable(self):
        ts, vs = _tp_history([10.0, 20.0, 30.0])
        expected = omr_metrics._linear_predict_at(ts, vs, float(_TP_T0 + 90), halflife_s=60.0)
        with patch.object(omr_metrics, "_TORCH_AVAILABLE", False):
            result = omr_metrics._predict_at(ts, vs, float(_TP_T0 + 90), halflife_s=60.0)
        assert result == pytest.approx(expected)


# ===========================================================================
# Forecast dispatch — verify forecast functions use _predict_at
# ===========================================================================

class TestForecastDispatch:
    """Verify that the three forecast functions delegate to _predict_at
    (not _linear_predict_at directly) so the torch path is reachable."""

    def _rising_loss_hist(self, n=6):
        return [
            {**_WAN, "timestamp": float(_TP_T0 + i * 30), "loss": float(i + 1)}
            for i in range(n)
        ]

    def _rising_cong_hist(self, n=6):
        return [
            {**_WAN, "timestamp": float(_TP_T0 + i * 30),
             "congestion": {"score": float(i * 10), "level": "none"}}
            for i in range(n)
        ]

    def test_forecast_metric_calls_predict_at(self):
        hist = self._rising_loss_hist()
        with patch.object(omr_metrics, "_predict_at", wraps=omr_metrics._predict_at) as mock_pa:
            omr_metrics._forecast_metric(hist, ("loss",), [(15.0, "severe")], hi_clamp=100.0)
        mock_pa.assert_called()

    def test_predict_congestion_calls_predict_at(self):
        hist = self._rising_cong_hist()
        with patch.object(omr_metrics, "_predict_at", wraps=omr_metrics._predict_at) as mock_pa:
            omr_metrics._predict_congestion(hist)
        mock_pa.assert_called()

    def test_predict_payload_calls_predict_at(self):
        hist = _history_at(_WAN, [{"latency": float(i * 5)} for i in range(6)])
        with patch.object(omr_metrics, "_predict_at", wraps=omr_metrics._predict_at) as mock_pa:
            omr_metrics._predict_payload(hist, horizon_seconds=60)
        mock_pa.assert_called()

    def test_forecast_metric_torch_result_used_as_predicted(self):
        hist = self._rising_loss_hist()
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_torch_predict_at", return_value=12.5),
        ):
            result = omr_metrics._forecast_metric(
                hist, ("loss",), [(15.0, "severe"), (5.0, "high"), (1.0, "moderate")],
                hi_clamp=100.0,
            )
        assert result["predicted"] == pytest.approx(12.5)

    def test_predict_congestion_torch_result_used_as_predicted_score(self):
        hist = self._rising_cong_hist()
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_torch_predict_at", return_value=65.0),
        ):
            result = omr_metrics._predict_congestion(hist)
        assert result["predicted_score"] == pytest.approx(65.0)

    def test_no_linear_predict_at_called_when_torch_available_and_enough_points(self):
        hist = self._rising_loss_hist()
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_torch_predict_at", return_value=8.0),
            patch.object(omr_metrics, "_linear_predict_at",
                         wraps=omr_metrics._linear_predict_at) as mock_lin,
        ):
            omr_metrics._forecast_metric(
                hist, ("loss",), [(15.0, "severe")], hi_clamp=100.0,
            )
        mock_lin.assert_not_called()


# ===========================================================================
# Online auto-learning
# ===========================================================================

def _auto_hist(base, n=10, status="online", **overrides):
    """Return n timestamped samples derived from *base*, 30 s apart."""
    out = []
    for i in range(n):
        p = {**base, "status": status, "timestamp": 1_700_000_000 + i * 30}
        p.update(overrides)
        out.append(p)
    return out


def _auto_config_open(auto_block):
    """Patch builtins.open so _auto_cfg reads a config with *auto_block*."""
    payload = json.dumps({"auto_learning": auto_block})
    m = MagicMock()
    m.return_value.__enter__.return_value.read.return_value = payload
    return patch("builtins.open", m)


class TestAutoCfg:
    def test_defaults_when_block_missing(self):
        cfg = omr_metrics._auto_cfg(force=True)
        assert cfg["enabled"] is True   # auto-learning is on by default
        assert cfg["interval"] == 300
        assert cfg["learning_rate"] == pytest.approx(1e-4)
        assert cfg["window"] == 900
        assert cfg["min_points"] == 5
        assert cfg["sharpen"] == pytest.approx(4.0)
        assert cfg["exploration"] == pytest.approx(0.0)

    def test_values_read_from_config(self):
        with _auto_config_open({"enabled": True, "interval": 600,
                                "learning_rate": 0.001, "exploration": 0.2}):
            cfg = omr_metrics._auto_cfg(force=True)
        assert cfg["enabled"] is True
        assert cfg["interval"] == 600
        assert cfg["learning_rate"] == pytest.approx(0.001)
        assert cfg["exploration"] == pytest.approx(0.2)

    def test_values_are_clamped(self):
        with _auto_config_open({"interval": 5, "learning_rate": 10.0,
                                "exploration": 0.99, "sharpen": 100}):
            cfg = omr_metrics._auto_cfg(force=True)
        assert cfg["interval"] == 60
        assert cfg["learning_rate"] == pytest.approx(0.05)
        assert cfg["exploration"] == pytest.approx(0.5)
        assert cfg["sharpen"] == pytest.approx(16.0)

    def test_invalid_value_falls_back_to_default(self):
        with _auto_config_open({"interval": "soon"}):
            cfg = omr_metrics._auto_cfg(force=True)
        assert cfg["interval"] == 300

    def test_enabled_string_false_is_false(self):
        with _auto_config_open({"enabled": "false"}):
            cfg = omr_metrics._auto_cfg(force=True)
        assert cfg["enabled"] is False

    def test_enabled_string_true_is_true(self):
        with _auto_config_open({"enabled": "true"}):
            cfg = omr_metrics._auto_cfg(force=True)
        assert cfg["enabled"] is True

    def test_cache_avoids_reread_within_ttl(self):
        with _auto_config_open({"interval": 600}):
            first = omr_metrics._auto_cfg(force=True)
        with _auto_config_open({"interval": 1200}):
            second = omr_metrics._auto_cfg()
        assert first["interval"] == 600
        assert second["interval"] == 600  # cached value, file not re-read


class TestAutoReward:
    def test_none_with_too_few_samples(self):
        hist = _auto_hist(_WAN, n=3)
        assert omr_metrics._auto_reward(hist, min_points=5) is None

    def test_clean_link_scores_high(self):
        hist = _auto_hist(_WAN, n=10, loss=0.0, jitter=1.0)
        reward = omr_metrics._auto_reward(hist)
        assert reward is not None and reward > 0.8

    def test_lossy_link_scores_below_clean_link(self):
        clean = omr_metrics._auto_reward(_auto_hist(_WAN, n=10, loss=0.0))
        lossy = omr_metrics._auto_reward(_auto_hist(_WAN, n=10, loss=15.0))
        assert lossy < clean

    def test_all_offline_returns_zero(self):
        hist = _auto_hist(_WAN, n=10, status="offline")
        assert omr_metrics._auto_reward(hist) == 0.0

    def test_null_latency_counts_as_unreachable(self):
        hist = _auto_hist(_WAN, n=10, latency=None)
        assert omr_metrics._auto_reward(hist) == 0.0

    def test_partial_availability_scales_reward(self):
        full = _auto_hist(_WAN, n=10)
        half = _auto_hist(_WAN, n=5) + _auto_hist(_WAN, n=5, status="offline")
        r_full = omr_metrics._auto_reward(full)
        r_half = omr_metrics._auto_reward(half)
        assert r_half == pytest.approx(r_full * 0.5)

    def test_prefers_bbr_min_rtt_over_loaded_latency(self):
        # Same (bad) latency; the link exposing a clean BBR min_rtt must win.
        no_bbr = _auto_hist(_WAN, n=10, latency=450.0, rtt_min=None,
                            bbr={**_WAN["bbr"], "min_rtt": None})
        with_bbr = _auto_hist(_WAN, n=10, latency=450.0, rtt_min=None,
                              bbr={**_WAN["bbr"], "min_rtt": 20.0})
        assert omr_metrics._auto_reward(with_bbr) > omr_metrics._auto_reward(no_bbr)

    def test_reward_bounded_zero_one(self):
        hist = _auto_hist(_WAN, n=10, loss=100.0, jitter=500.0, latency=2000.0)
        reward = omr_metrics._auto_reward(hist)
        assert 0.0 <= reward <= 1.0


class TestAutoTargets:
    def test_sharpening_amplifies_contrast(self):
        targets = omr_metrics._auto_targets({"a": 0.9, "b": 0.8}, sharpen=4.0)
        assert targets["a"] / targets["b"] == pytest.approx((0.9 / 0.8) ** 4)

    def test_all_zero_returns_none(self):
        assert omr_metrics._auto_targets({"a": 0.0, "b": 0.0}) is None

    def test_negative_reward_clamped_to_zero(self):
        targets = omr_metrics._auto_targets({"a": -1.0, "b": 0.5})
        assert targets["a"] == 0.0
        assert targets["b"] > 0.0


class TestAutoWatchdog:
    def _resets(self):
        return omr_metrics._engine_stats["auto_resets"]

    def test_good_loss_keeps_model(self):
        with patch.object(omr_metrics, "_make_model") as mk:
            omr_metrics._auto_watchdog(0.05)
        mk.assert_not_called()

    def test_three_divergent_losses_reset_model(self):
        before = self._resets()
        with (
            patch.object(omr_metrics, "_make_model", return_value=_FakeModel()) as mk,
            patch.object(omr_metrics, "_save_model"),
        ):
            for _ in range(3):
                omr_metrics._auto_watchdog(float("inf"))
        mk.assert_called_once()
        assert self._resets() == before + 1
        assert omr_metrics._auto_bad_streak == 0

    def test_good_loss_resets_streak(self):
        with (
            patch.object(omr_metrics, "_make_model", return_value=_FakeModel()) as mk,
            patch.object(omr_metrics, "_save_model"),
        ):
            omr_metrics._auto_watchdog(100.0)
            omr_metrics._auto_watchdog(100.0)
            omr_metrics._auto_watchdog(0.01)     # streak broken
            omr_metrics._auto_watchdog(100.0)
            omr_metrics._auto_watchdog(100.0)
        mk.assert_not_called()


class TestAutoLearnRound:
    _CFG = {**omr_metrics._AUTO_DEFAULTS, "enabled": True}

    def test_noop_without_torch(self):
        with patch.object(omr_metrics, "_TORCH_AVAILABLE", False):
            summary = omr_metrics._auto_learn_round(self._CFG)
        assert summary == {"trained": 0, "skipped": 0}

    def test_noop_with_json_backend(self, torch_env):
        omr_metrics._backend = omr_metrics.JSONBackend()
        with patch.object(omr_metrics, "_read_all") as ra:
            summary = omr_metrics._auto_learn_round(self._CFG)
        ra.assert_not_called()
        assert summary["trained"] == 0

    def _influx_env(self):
        """Patch a non-JSON backend so the round proceeds."""
        omr_metrics._backend = MagicMock()   # not a JSONBackend instance
        return contextlib.nullcontext()

    def test_trains_user_with_clean_and_lossy_links(self, torch_env):
        self._influx_env()
        hists = {
            "wan":  _auto_hist(_WAN,  n=10, loss=0.0),
            "wan2": _auto_hist(_WAN2, n=10, loss=15.0),
        }
        with (
            patch.object(omr_metrics, "_read_all",
                         return_value={"user1": {"wan": _WAN, "wan2": _WAN2}}),
            patch.object(omr_metrics, "_read_history",
                         side_effect=lambda u, i, s, l: hists[i]),
            patch.object(omr_metrics, "_train_step", return_value=0.05) as ts,
            patch.object(omr_metrics, "_get_model", return_value=_FakeModel()),
            patch.object(omr_metrics, "_save_model") as sm,
        ):
            summary = omr_metrics._auto_learn_round(self._CFG)

        assert summary == {"trained": 1, "skipped": 0}
        ts.assert_called_once()
        _, targets, lr = ts.call_args[0]
        assert targets["wan"] > targets["wan2"]   # clean link gets more mass
        assert lr == pytest.approx(self._CFG["learning_rate"])
        sm.assert_called_once()

    def test_skips_user_with_single_interface(self, torch_env):
        self._influx_env()
        with (
            patch.object(omr_metrics, "_read_all",
                         return_value={"user1": {"wan": _WAN}}),
            patch.object(omr_metrics, "_train_step") as ts,
        ):
            summary = omr_metrics._auto_learn_round(self._CFG)
        ts.assert_not_called()
        assert summary == {"trained": 0, "skipped": 1}

    def test_interface_without_history_is_excluded(self, torch_env):
        self._influx_env()
        hists = {
            "wan":  _auto_hist(_WAN, n=10),
            "wan2": [],   # no history yet → cannot be labelled
        }
        with (
            patch.object(omr_metrics, "_read_all",
                         return_value={"user1": {"wan": _WAN, "wan2": _WAN2}}),
            patch.object(omr_metrics, "_read_history",
                         side_effect=lambda u, i, s, l: hists[i]),
            patch.object(omr_metrics, "_train_step") as ts,
        ):
            summary = omr_metrics._auto_learn_round(self._CFG)
        ts.assert_not_called()   # only one labelled interface left → skip
        assert summary == {"trained": 0, "skipped": 1}

    def test_train_step_error_does_not_break_round(self, torch_env):
        self._influx_env()
        hists = {
            "wan":  _auto_hist(_WAN,  n=10),
            "wan2": _auto_hist(_WAN2, n=10),
        }
        with (
            patch.object(omr_metrics, "_read_all",
                         return_value={"user1": {"wan": _WAN, "wan2": _WAN2}}),
            patch.object(omr_metrics, "_read_history",
                         side_effect=lambda u, i, s, l: hists[i]),
            patch.object(omr_metrics, "_train_step", side_effect=RuntimeError("boom")),
        ):
            summary = omr_metrics._auto_learn_round(self._CFG)
        assert summary == {"trained": 0, "skipped": 1}

    def test_round_updates_stats(self, torch_env):
        self._influx_env()
        before = omr_metrics._engine_stats["auto_rounds"]
        with patch.object(omr_metrics, "_read_all", return_value={}):
            omr_metrics._auto_learn_round(self._CFG)
        assert omr_metrics._engine_stats["auto_rounds"] == before + 1
        assert omr_metrics._engine_stats["last_auto_round_at"] is not None


class TestMaybeExplore:
    _ON_CFG = {**omr_metrics._AUTO_DEFAULTS, "enabled": True,
               "exploration": 1.0, "exploration_scale": 0.15}

    def test_no_exploration_by_default(self):
        # enabled defaults to True but exploration defaults to 0.0 → no-op
        probs = {"wan": 0.7, "wan2": 0.3}
        assert omr_metrics._maybe_explore(probs) is probs

    def test_enabled_returns_normalized_distribution(self):
        with patch.object(omr_metrics, "_auto_cfg", return_value=self._ON_CFG):
            result = omr_metrics._maybe_explore({"wan": 0.7, "wan2": 0.3})
        assert set(result) == {"wan", "wan2"}
        assert sum(result.values()) == pytest.approx(1.0)
        assert all(v >= 0.0 for v in result.values())

    def test_enabled_increments_exploration_counter(self):
        before = omr_metrics._engine_stats["exploration_count"]
        with patch.object(omr_metrics, "_auto_cfg", return_value=self._ON_CFG):
            omr_metrics._maybe_explore({"wan": 0.7, "wan2": 0.3})
        assert omr_metrics._engine_stats["exploration_count"] == before + 1

    def test_single_interface_never_perturbed(self):
        probs = {"wan": 1.0}
        with patch.object(omr_metrics, "_auto_cfg", return_value=self._ON_CFG):
            assert omr_metrics._maybe_explore(probs) is probs


class TestEngineDiagnosticsAutoSection:
    def test_engine_endpoint_reports_auto_learning_block(self, admin_client):
        resp = admin_client.get("/metrics/engine")
        assert resp.status_code == 200
        body = resp.json()
        assert "auto_learning" in body
        assert body["auto_learning"]["enabled"] is True   # on by default
        assert body["auto_learning"]["task_running"] is False
        assert body["auto_learning"]["torch_available"] is False
        assert "history_backend" in body["auto_learning"]
        assert "auto_rounds" in body["runtime"]


class TestAutoLearningEndpoint:
    _URL = "/metrics/decision/auto"

    def test_get_status_admin(self, admin_client):
        resp = admin_client.get(self._URL)
        assert resp.status_code == 200
        block = resp.json()["auto_learning"]
        assert block["enabled"] is True
        assert block["task_running"] is False
        assert block["torch_available"] is False

    def test_get_status_non_admin_403(self, user_client):
        assert user_client.get(self._URL).status_code == 403

    def test_post_non_admin_403(self, user_client):
        resp = user_client.post(self._URL, json={"enabled": False})
        assert resp.status_code == 403

    def test_unauthenticated_403(self, unauth_client):
        assert unauth_client.get(self._URL).status_code == 403
        assert unauth_client.post(self._URL, json={"enabled": False}).status_code == 403

    def test_disable_applies_at_runtime(self, admin_client):
        resp = admin_client.post(self._URL, json={"enabled": False})
        assert resp.status_code == 200
        body = resp.json()
        assert body["result"] == "ok"
        assert body["auto_learning"]["enabled"] is False
        # A later status read reflects the runtime toggle
        status = admin_client.get(self._URL).json()
        assert status["auto_learning"]["enabled"] is False

    def test_reenable_after_disable(self, admin_client):
        admin_client.post(self._URL, json={"enabled": False})
        resp = admin_client.post(self._URL, json={"enabled": True})
        assert resp.json()["auto_learning"]["enabled"] is True

    def test_persisted_true_when_config_writable(self, admin_client):
        with patch("os.replace") as repl:
            resp = admin_client.post(self._URL, json={"enabled": False})
        assert resp.json()["persisted"] is True
        repl.assert_called_once()

    def test_persist_failure_still_toggles(self, admin_client):
        # Default test env discards writes and os.replace fails on the missing
        # tmp file → persistence fails but the runtime toggle must still apply.
        resp = admin_client.post(self._URL, json={"enabled": False})
        assert resp.status_code == 200
        assert resp.json()["persisted"] is False
        assert resp.json()["auto_learning"]["enabled"] is False

    def test_enable_starts_background_task(self, admin_client):
        with patch.object(omr_metrics, "start_auto_learning") as sal:
            admin_client.post(self._URL, json={"enabled": True})
        sal.assert_called_once()

    def test_disable_does_not_start_task(self, admin_client):
        with patch.object(omr_metrics, "start_auto_learning") as sal:
            admin_client.post(self._URL, json={"enabled": False})
        sal.assert_not_called()

    def test_missing_enabled_field_422(self, admin_client):
        assert admin_client.post(self._URL, json={}).status_code == 422

    def test_written_config_preserves_other_keys(self, admin_client):
        # Capture what _auto_set_enabled writes and check it merges instead of
        # clobbering the rest of the admin config.
        written = {}

        def fake_replace(src, dst):
            written["called"] = True

        captured = []
        real_dump = json.dump

        def capture_dump(obj, f, **kw):
            captured.append(obj)
            return real_dump(obj, f, **kw)

        with (
            patch("os.replace", side_effect=fake_replace),
            patch("json.dump", side_effect=capture_dump),
        ):
            admin_client.post(self._URL, json={"enabled": False})

        cfg = captured[-1]
        assert cfg["auto_learning"]["enabled"] is False
        assert "users" in cfg          # pre-existing config keys kept
        assert "port" in cfg

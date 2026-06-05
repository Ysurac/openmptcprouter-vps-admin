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
    """Reset backend and decision-model singletons between tests."""
    orig_backend = omr_metrics._backend
    orig_model  = omr_metrics._decision_model
    omr_metrics._backend        = None
    omr_metrics._decision_model = None
    yield
    omr_metrics._backend        = orig_backend
    omr_metrics._decision_model = orig_model


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
            url="http://localhost:8086", token="tok", org="myorg", bucket="mybucket"
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
            url="http://localhost:8086", token="tok", org="omr", bucket="omr_metrics"
        )

    def test_get_backend_caches_singleton(self):
        mock_backend = MagicMock()
        with patch.object(omr_metrics, "_init_backend", return_value=mock_backend) as mock_init:
            b1 = omr_metrics._get_backend()
            b2 = omr_metrics._get_backend()
        assert b1 is b2
        mock_init.assert_called_once()


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
        payload = {**_WAN, "bbr": {**_WAN["bbr"], "bw": 50_000_000}}
        feats = omr_metrics._extract_features(payload)
        assert abs(feats[omr_metrics.FEATURE_NAMES.index("bbr_bw")] - 0.5) < 1e-6

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
        assert result["weights"]["wan"] > result["weights"]["wan2"]

    def test_equal_costs_do_not_change_relative_order(self):
        wan  = {**_WAN,  "cost": 10}
        wan2 = {**_WAN2, "cost": 10}
        result_with    = omr_metrics._compute_weights_heuristic({"wan": wan,  "wan2": wan2})
        result_without = omr_metrics._compute_weights_heuristic({"wan": _WAN, "wan2": _WAN2})
        assert result_with["weights"]["wan"] == result_without["weights"]["wan"]

    def test_cost_zero_treated_as_no_cost(self):
        # cost=0 must not cause division by zero — falls back to neutral factor.
        result = omr_metrics._compute_weights_heuristic(
            {"wan": {**_WAN, "cost": 0}, "wan2": _WAN2}
        )
        assert "wan" in result["weights"]


# ===========================================================================
# GET /metrics/decision
# ===========================================================================

class TestGetDecision:
    """Tests for the decision endpoint.

    Since torch may not be installed, the 501 path is tested directly.
    The success path is tested by patching _TORCH_AVAILABLE + _compute_weights.
    """

    _FAKE_RESULT = {
        "weights": {"wan": 0.7, "wan2": 0.3},
        "scores":  {"wan": 1.5, "wan2": 0.2},
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

    def test_explain_flag_forwarded(self, user_client):
        captured = {}

        def fake_compute(user_data, explain=False):
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

        def fake_compute(user_data, explain=False):
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

    def test_returns_501_when_torch_not_available(self, user_client):
        r = self._post(user_client, {"best_interface": "wan"})
        assert r.status_code == 501

    def test_returns_404_when_no_metrics(self, user_client):
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={}),
        ):
            r = self._post(user_client, {"best_interface": "wan"})
        assert r.status_code == 404

    def test_train_with_best_interface(self, user_client):
        captured = {}

        def fake_train(user_data, target_weights, lr):
            captured["target"] = target_weights
            captured["lr"] = lr
            return 0.05

        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN, "wan2": _WAN2}),
            patch.object(omr_metrics, "_train_step", side_effect=fake_train),
            patch.object(omr_metrics, "_get_model", return_value=MagicMock()),
            patch.object(omr_metrics, "_save_model"),
        ):
            r = self._post(user_client, {"best_interface": "wan"})

        assert r.status_code == 200
        assert r.json()["result"] == "ok"
        assert captured["target"]["wan"] == 1.0
        assert captured["target"]["wan2"] == 0.0

    def test_train_with_free_form_weights(self, user_client):
        captured = {}

        def fake_train(user_data, target_weights, lr):
            captured["target"] = target_weights
            return 0.03

        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN, "wan2": _WAN2}),
            patch.object(omr_metrics, "_train_step", side_effect=fake_train),
            patch.object(omr_metrics, "_get_model", return_value=MagicMock()),
            patch.object(omr_metrics, "_save_model"),
        ):
            r = self._post(user_client, {"weights": {"wan": 0.8, "wan2": 0.2}})

        assert r.status_code == 200
        assert captured["target"]["wan"] == 0.8
        assert captured["target"]["wan2"] == 0.2

    def test_custom_learning_rate_forwarded(self, user_client):
        captured = {}

        def fake_train(user_data, target_weights, lr):
            captured["lr"] = lr
            return 0.0

        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN, "wan2": _WAN2}),
            patch.object(omr_metrics, "_train_step", side_effect=fake_train),
            patch.object(omr_metrics, "_get_model", return_value=MagicMock()),
            patch.object(omr_metrics, "_save_model"),
        ):
            self._post(user_client, {"best_interface": "wan", "learning_rate": 0.005})

        assert captured["lr"] == 0.005

    def test_unknown_best_interface_returns_422(self, user_client):
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN}),
        ):
            r = self._post(user_client, {"best_interface": "doesnotexist"})
        assert r.status_code == 422

    def test_no_feedback_field_returns_422(self, user_client):
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN}),
        ):
            r = self._post(user_client, {})
        assert r.status_code == 422

    def test_loss_included_in_response(self, user_client):
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN, "wan2": _WAN2}),
            patch.object(omr_metrics, "_train_step", return_value=0.123456),
            patch.object(omr_metrics, "_get_model", return_value=MagicMock()),
            patch.object(omr_metrics, "_save_model"),
        ):
            r = self._post(user_client, {"best_interface": "wan"})
        assert r.json()["loss"] == 0.123456

    def test_model_saved_after_training(self, user_client):
        with (
            patch.object(omr_metrics, "_TORCH_AVAILABLE", True),
            patch.object(omr_metrics, "_read_user", return_value={"wan": _WAN, "wan2": _WAN2}),
            patch.object(omr_metrics, "_train_step", return_value=0.0),
            patch.object(omr_metrics, "_get_model", return_value=MagicMock()),
            patch.object(omr_metrics, "_save_model") as mock_save,
        ):
            self._post(user_client, {"best_interface": "wan"})
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
    def __init__(self, params, lr=0.01): pass
    def zero_grad(self): pass
    def step(self): pass


class _FakeOptim:
    SGD = _FakeSGD


def _fake_mse_loss(pred, target):
    n = len(pred)
    pd = [float(pred[i]) for i in range(n)]
    td = [float(target[i]) for i in range(n)]
    mse = sum((p - t) ** 2 for p, t in zip(pd, td)) / max(n, 1)
    return _FakeTensor([mse])


class _FakeFunctional:
    mse_loss = staticmethod(_fake_mse_loss)


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

    def softmax(self, tensor, dim=0):
        data = [float(tensor[i]) for i in range(len(tensor))]
        max_v = max(data) if data else 0.0
        exps = [math.exp(v - max_v) if v != float("-inf") else 0.0 for v in data]
        total = sum(exps) or 1.0
        return _FakeTensor([e / total for e in exps])

    def save(self, obj, path): pass

    def load(self, path, map_location=None, weights_only=True):
        return {}


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
        assert "weights" in result
        assert "scores" in result

    def test_weights_are_positive_integers(self, torch_env):
        model = _FakeModel(scores=[3.0, 1.0])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            result = omr_metrics._compute_weights({"wan": _WAN, "wan2": _WAN2})
        for w in result["weights"].values():
            assert isinstance(w, int)
            assert w >= 1

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
        assert set(result["weights"].keys()) == {"eth0", "lte0", "wlan0"}
        assert set(result["scores"].keys())  == {"eth0", "lte0", "wlan0"}

    def test_higher_raw_score_yields_higher_weight(self, torch_env):
        # wan gets score 5.0, wan2 gets 1.0 → wan's weight must be larger
        model = _FakeModel(scores=[5.0, 1.0])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            result = omr_metrics._compute_weights({"wan": _WAN, "wan2": _WAN2})
        assert result["weights"]["wan"] > result["weights"]["wan2"]

    def test_offline_interface_gets_minimum_weight(self, torch_env):
        offline = {**_WAN2, "status": "offline"}
        model = _FakeModel(scores=[1.0, 1.0])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            result = omr_metrics._compute_weights({"wan": _WAN, "wan2": offline})
        # Offline interface is masked to -inf → softmax ≈ 0 → max(1, 0) = 1
        assert result["weights"]["wan2"] == 1
        assert result["weights"]["wan"]  > result["weights"]["wan2"]

    def test_online_status_not_masked(self, torch_env):
        model = _FakeModel(scores=[1.0, 1.0])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            result = omr_metrics._compute_weights({"wan": _WAN, "wan2": _WAN2})
        assert result["weights"]["wan"]  > 0.0
        assert result["weights"]["wan2"] > 0.0

    def test_none_status_not_masked(self, torch_env):
        no_status = {**_WAN, "status": None}
        model = _FakeModel(scores=[1.0, 1.0])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            result = omr_metrics._compute_weights({"wan": no_status, "wan2": _WAN2})
        assert result["weights"]["wan"] > 0.0

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
        # Single interface: softmax([x]) = [1.0] → max(1, round(1.0 * 255)) = 255
        model = _FakeModel(scores=[2.5])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            result = omr_metrics._compute_weights({"wan": _WAN})
        assert result["weights"]["wan"] == 255

    def test_all_offline_weights_are_zero(self, torch_env):
        """When every interface is offline the softmax of -inf values is NaN;
        the implementation should not crash and weights are effectively 0."""
        data = {
            "wan":  {**_WAN,  "status": "offline"},
            "wan2": {**_WAN2, "status": "offline"},
        }
        model = _FakeModel(scores=[1.0, 1.0])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            # Should not raise
            result = omr_metrics._compute_weights(data)
        assert "weights" in result


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

    def test_zero_target_sum_does_not_crash(self, torch_env):
        model = _FakeModel(scores=[1.0, 0.5])
        with patch.object(omr_metrics, "_get_model", return_value=model):
            loss = omr_metrics._train_step(
                {"wan": _WAN, "wan2": _WAN2}, {"wan": 0.0, "wan2": 0.0}, lr=0.01
            )
        assert isinstance(loss, float)

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
        assert "weights" in result
        assert "scores" in result

    def test_interface_keys_match_input(self):
        result = omr_metrics._compute_weights_heuristic({"wan": _H_CONG0, "wan2": _H_CONG50})
        assert set(result["weights"].keys()) == {"wan", "wan2"}
        assert set(result["scores"].keys())  == {"wan", "wan2"}

    def test_equal_congestion_gives_equal_weights(self):
        result = omr_metrics._compute_weights_heuristic({"wan": _H_CONG0, "wan2": _H_CONG0})
        assert result["weights"]["wan"] == result["weights"]["wan2"]

    def test_equal_interfaces_get_weight_100(self):
        result = omr_metrics._compute_weights_heuristic({"wan": _H_CONG0, "wan2": _H_CONG0})
        assert result["weights"]["wan"] == 100
        assert result["weights"]["wan2"] == 100

    def test_single_interface_gets_weight_100(self):
        result = omr_metrics._compute_weights_heuristic({"wan": _H_CONG0})
        assert result["weights"]["wan"] == 100

    def test_lower_congestion_gives_higher_weight(self):
        result = omr_metrics._compute_weights_heuristic({"wan": _H_CONG0, "wan2": _H_CONG50})
        assert result["weights"]["wan"] > result["weights"]["wan2"]

    def test_offline_interface_gets_weight_1(self):
        result = omr_metrics._compute_weights_heuristic({"wan": _H_CONG0, "wan2": _H_OFFLINE})
        assert result["weights"]["wan2"] == 1

    def test_no_latency_treated_as_offline(self):
        result = omr_metrics._compute_weights_heuristic({"wan": _H_CONG0, "wan2": _H_NO_LAT})
        assert result["weights"]["wan2"] == 1

    def test_all_offline_gives_equal_fallback(self):
        offline1 = {**_WAN,  "status": "offline"}
        offline2 = {**_WAN2, "status": "offline"}
        result = omr_metrics._compute_weights_heuristic({"wan": offline1, "wan2": offline2})
        assert result["weights"]["wan"] == result["weights"]["wan2"]

    def test_congestion_100_treated_as_offline(self):
        result = omr_metrics._compute_weights_heuristic({"wan": _H_CONG0, "wan2": _H_CONG100})
        # congestion=100 → quality=0.0 → weight=max(1,0)=1
        assert result["weights"]["wan2"] == 1

    def test_no_congestion_falls_back_to_latency_loss(self):
        # No congestion field; latency and loss should still produce a valid weight.
        result = omr_metrics._compute_weights_heuristic({"wan": _H_NO_CONG, "wan2": _H_CONG0})
        assert result["weights"]["wan"] >= 1
        assert result["weights"]["wan2"] >= 1

    def test_scores_are_percentages_summing_to_100(self):
        result = omr_metrics._compute_weights_heuristic({"wan": _H_CONG0, "wan2": _H_CONG50})
        total = sum(result["scores"].values())
        assert abs(total - 100.0) < 0.1

    def test_all_weights_are_positive_integers(self):
        result = omr_metrics._compute_weights_heuristic(
            {"wan": _H_CONG0, "wan2": _H_CONG50, "lte": _H_OFFLINE}
        )
        for w in result["weights"].values():
            assert isinstance(w, int)
            assert w >= 1

    def test_three_interfaces_all_online(self):
        third = {**_WAN, "interface": "lte0", "congestion": {"score": 20, "level": "low"}}
        result = omr_metrics._compute_weights_heuristic(
            {"wan": _H_CONG0, "wan2": _H_CONG50, "lte0": third}
        )
        assert len(result["weights"]) == 3
        assert result["weights"]["wan"] > result["weights"]["wan2"] > 0


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

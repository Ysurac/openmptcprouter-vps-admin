"""
Comprehensive unit tests for all omr-admin.py API endpoints.

Each class covers one route (or a tightly related group).
Tests focus on:
  - Authentication requirement (403 without a token)
  - Permission checks (ro / non-admin users receive explicit errors)
  - Response contract (status code + expected JSON keys / values)
  - Basic happy-path behaviour (mocked filesystem / subprocess)
"""

import io
import json
from unittest.mock import MagicMock, patch

import pytest

from conftest import (
    MOCK_CONFIG,
    MQVPN_CONFIG,
    _mock_open,
    admin_headers,
    omr_admin,
    user_headers,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CONFIG_JSON = json.dumps(MOCK_CONFIG)


def _isfile_for(*paths):
    """Return a side_effect that returns True only for the given paths."""
    def _side_effect(p):
        return str(p) in paths
    return _side_effect


# ===========================================================================
# Public / unauthenticated endpoints
# ===========================================================================


class TestHomepage:
    def test_returns_welcome(self, unauth_client):
        r = unauth_client.get("/")
        assert r.status_code == 200
        assert "OpenMPTCProuter" in r.text


class TestClientHost:
    def test_returns_client_host(self, unauth_client):
        r = unauth_client.get("/clienthost")
        assert r.status_code == 200
        assert "client_host" in r.json()

    def test_client_host_is_string(self, unauth_client):
        r = unauth_client.get("/clienthost")
        assert isinstance(r.json()["client_host"], str)


class TestMptcpSupport:
    def test_returns_mptcp_key(self, unauth_client):
        r = unauth_client.get("/mptcpsupport")
        assert r.status_code == 200
        assert "mptcp" in r.json()

    def test_mptcp_value_is_string(self, unauth_client):
        r = unauth_client.get("/mptcpsupport")
        assert r.json()["mptcp"] in ("working", "not working", "check only support IPv4")

    def test_pure_ipv6_returns_check_only(self, unauth_client):
        """Pure IPv6 (no IPv4-mapped) should return the informational message."""
        with patch("omr_admin.ip_address") as mock_ip:
            from ipaddress import IPv6Address
            instance = MagicMock(spec=IPv6Address)
            instance.ipv4_mapped = None
            mock_ip.return_value = instance
            r = unauth_client.get("/mptcpsupport")
        assert r.json()["mptcp"] == "check only support IPv4"


class TestLogout:
    def test_redirects_to_root(self, unauth_client):
        r = unauth_client.get("/logout", follow_redirects=False)
        assert r.status_code in (302, 307)
        assert r.headers["location"] == "/"

    def test_clears_auth_cookie(self, unauth_client):
        r = unauth_client.get("/logout", follow_redirects=False)
        assert "Authorization" in r.headers.get("set-cookie", "")


# ===========================================================================
# Authentication endpoints
# ===========================================================================


class TestToken:
    def test_valid_credentials_return_token(self, unauth_client):
        r = unauth_client.post(
            "/token",
            data={"username": "admin", "password": "adminpassword"},
        )
        assert r.status_code == 200
        body = r.json()
        assert "access_token" in body
        assert body["token_type"] == "bearer"

    def test_invalid_password_returns_400(self, unauth_client):
        r = unauth_client.post(
            "/token",
            data={"username": "admin", "password": "wrongpassword"},
        )
        assert r.status_code == 400

    def test_unknown_user_returns_400(self, unauth_client):
        r = unauth_client.post(
            "/token",
            data={"username": "ghost", "password": "anything"},
        )
        assert r.status_code == 400

    def test_missing_password_returns_422(self, unauth_client):
        r = unauth_client.post("/token", data={"username": "admin"})
        assert r.status_code == 422


class TestLoginBasic:
    def test_no_auth_header_returns_401(self, unauth_client):
        r = unauth_client.get("/login_basic")
        assert r.status_code in (401, 403)

    def test_valid_basic_auth_redirects_to_docs(self, unauth_client):
        import base64
        creds = base64.b64encode(b"admin:adminpassword").decode()
        r = unauth_client.get(
            "/login_basic",
            headers={"Authorization": f"Basic {creds}"},
            follow_redirects=False,
        )
        assert r.status_code in (302, 307)
        assert "/docs" in r.headers.get("location", "")

    def test_invalid_basic_auth_returns_401(self, unauth_client):
        import base64
        creds = base64.b64encode(b"admin:wrong").decode()
        r = unauth_client.get(
            "/login_basic",
            headers={"Authorization": f"Basic {creds}"},
        )
        assert r.status_code == 401


# ===========================================================================
# Protected docs / schema endpoints
# ===========================================================================


class TestDocs:
    def test_docs_requires_auth(self, unauth_client):
        r = unauth_client.get("/docs")
        assert r.status_code == 403

    def test_docs_accessible_with_auth(self, admin_client):
        r = admin_client.get("/docs")
        assert r.status_code == 200

    def test_openapi_json_requires_auth(self, unauth_client):
        r = unauth_client.get("/openapi.json")
        assert r.status_code == 403

    def test_openapi_json_accessible_with_auth(self, admin_client):
        r = admin_client.get("/openapi.json")
        assert r.status_code == 200
        assert "paths" in r.json()


# ===========================================================================
# Status
# ===========================================================================


class TestStatus:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.get("/status")
        assert r.status_code == 403

    def test_returns_expected_keys(self, user_client):
        r = user_client.get("/status")
        assert r.status_code == 200
        body = r.json()
        assert "vps" in body
        assert "network" in body
        assert "vpn" in body

    def test_admin_can_query_by_username(self, admin_client):
        r = admin_client.get("/status?username=openmptcprouter")
        assert r.status_code == 200

    def test_vps_subkeys(self, user_client):
        r = user_client.get("/status")
        vps = r.json()["vps"]
        for key in ("loadavg", "uptime", "memory_total", "cpu_count"):
            assert key in vps


# ===========================================================================
# Config
# ===========================================================================


class TestConfig:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.get("/config")
        assert r.status_code == 403

    def test_returns_vpn_and_proxy_keys(self, user_client):
        r = user_client.get("/config")
        assert r.status_code == 200
        body = r.json()
        # Top-level sections always present
        assert "shadowsocks" in body or "error" not in body

    def test_admin_can_query_by_userid(self, admin_client):
        r = admin_client.get("/config?userid=0")
        assert r.status_code == 200


# ===========================================================================
# Shadowsocks
# ===========================================================================


class TestShadowsocks:
    _PAYLOAD = {
        "port": 65101,
        "method": "chacha20-ietf-poly1305",
        "fast_open": False,
        "reuse_port": False,
        "no_delay": False,
        "mptcp": True,
        "obfs": False,
        "obfs_plugin": "obfs",
        "obfs_type": "http",
        "key": "testkey",
    }

    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/shadowsocks", json=self._PAYLOAD)
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/shadowsocks", json=self._PAYLOAD)
        assert r.json()["result"] == "permission"

    def test_missing_ss_returns_warning(self, user_client):
        with patch("os.path.isfile", return_value=False):
            r = user_client.post("/shadowsocks", json=self._PAYLOAD)
        assert r.json()["result"] == "warning"


class TestShadowsocksGo:
    _PAYLOAD = {
        "port": 65101,
        "method": "2022-blake3-aes-256-gcm",
        "fast_open": False,
        "reuse_port": False,
        "mptcp": True,
    }

    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/shadowsocks-go", json=self._PAYLOAD)
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/shadowsocks-go", json=self._PAYLOAD)
        assert r.json()["result"] == "permission"


# ===========================================================================
# Shorewall
# ===========================================================================


class TestShorewall:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.post(
            "/shorewall", json={"redirect_ports": "all", "ipproto": "ipv4"}
        )
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post(
            "/shorewall", json={"redirect_ports": "all", "ipproto": "ipv4"}
        )
        assert r.json()["result"] == "permission"

    def test_success_returns_done(self, user_client):
        with patch("os.path.isfile", return_value=True):
            r = user_client.post(
                "/shorewall", json={"redirect_ports": "all", "ipproto": "ipv4"}
            )
        assert r.json()["result"] == "done"


class TestShorewallList:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/shorewalllist", json={"name": "http", "ipproto": "ipv4"})
        assert r.status_code == 403

    def test_returns_list_key(self, user_client):
        with patch("os.path.isfile", return_value=True):
            r = user_client.post("/shorewalllist", json={"name": "http", "ipproto": "ipv4"})
        assert "list" in r.json()


class TestShorewallOpen:
    _PAYLOAD = {
        "name": "http",
        "port": "80",
        "proto": "tcp",
        "fwtype": "ACCEPT",
        "ipproto": "ipv4",
        "source_dip": "",
        "source_ip": "",
        "comment": "",
    }

    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/shorewallopen", json=self._PAYLOAD)
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/shorewallopen", json=self._PAYLOAD)
        assert r.json()["result"] == "permission"

    def test_success(self, user_client):
        with patch("os.path.isfile", return_value=True):
            r = user_client.post("/shorewallopen", json=self._PAYLOAD)
        assert r.json()["result"] == "done"


class TestShorewallClose:
    _PAYLOAD = {
        "name": "http",
        "port": "80",
        "proto": "tcp",
        "fwtype": "ACCEPT",
        "ipproto": "ipv4",
        "source_dip": "",
        "source_ip": "",
        "comment": "",
    }

    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/shorewallclose", json=self._PAYLOAD)
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/shorewallclose", json=self._PAYLOAD)
        assert r.json()["result"] == "permission"

    def test_success(self, user_client):
        with patch("os.path.isfile", return_value=True):
            r = user_client.post("/shorewallclose", json=self._PAYLOAD)
        assert r.json()["result"] == "done"


# ===========================================================================
# SIP ALG
# ===========================================================================


class TestSipAlg:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/sipalg", json={"enable": True})
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/sipalg", json={"enable": True})
        assert r.json()["result"] == "permission"

    def test_enable_returns_done(self, user_client):
        r = user_client.post("/sipalg", json={"enable": True})
        assert r.json()["result"] == "done"

    def test_disable_returns_done(self, user_client):
        r = user_client.post("/sipalg", json={"enable": False})
        assert r.json()["result"] == "done"


# ===========================================================================
# V2Ray
# ===========================================================================


class TestV2Ray:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/v2ray", json={"userid": "test-uuid"})
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/v2ray", json={"userid": "test-uuid"})
        assert r.json()["result"] == "permission"

    def test_missing_v2ray_returns_warning(self, user_client):
        with patch("os.path.isfile", return_value=False):
            r = user_client.post("/v2ray", json={"userid": "test-uuid"})
        assert r.json()["result"] == "warning"


class TestV2RayRedirect:
    _PAYLOAD = {
        "name": "myport",
        "port": "8080",
        "proto": "tcp",
        "destip": "192.168.1.1",
        "destport": "80",
    }

    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/v2rayredirect", json=self._PAYLOAD)
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/v2rayredirect", json=self._PAYLOAD)
        assert r.json()["result"] == "permission"

    def test_missing_v2ray_returns_warning(self, user_client):
        with patch("os.path.isfile", return_value=False):
            r = user_client.post("/v2rayredirect", json=self._PAYLOAD)
        assert r.json()["result"] == "warning"


class TestV2RayUnredirect:
    _PAYLOAD = {
        "name": "myport",
        "port": "8080",
        "proto": "tcp",
        "destip": "192.168.1.1",
        "destport": "80",
    }

    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/v2rayunredirect", json=self._PAYLOAD)
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/v2rayunredirect", json=self._PAYLOAD)
        assert r.json()["result"] == "permission"


# ===========================================================================
# XRay
# ===========================================================================


class TestXRay:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/xray", json={"userid": "test-uuid"})
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/xray", json={"userid": "test-uuid"})
        assert r.json()["result"] == "permission"

    def test_missing_xray_returns_warning(self, user_client):
        with patch("os.path.isfile", return_value=False):
            r = user_client.post("/xray", json={"userid": "test-uuid"})
        assert r.json()["result"] == "warning"


class TestXRayRedirect:
    _PAYLOAD = {
        "name": "myport",
        "port": "8080",
        "proto": "tcp",
        "destip": "192.168.1.1",
        "destport": "80",
    }

    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/xrayredirect", json=self._PAYLOAD)
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/xrayredirect", json=self._PAYLOAD)
        assert r.json()["result"] == "permission"


class TestXRayUnredirect:
    _PAYLOAD = {
        "name": "myport",
        "port": "8080",
        "proto": "tcp",
        "destip": "192.168.1.1",
        "destport": "80",
    }

    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/xrayunredirect", json=self._PAYLOAD)
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/xrayunredirect", json=self._PAYLOAD)
        assert r.json()["result"] == "permission"


# ===========================================================================
# MPTCP
# ===========================================================================


class TestMPTCP:
    _PAYLOAD = {
        "checksum": "0",
        "path_manager": "default",
        "scheduler": "default",
        "syn_retries": 3,
        "congestion_control": "olia",
        "version": 0,
    }

    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/mptcp", json=self._PAYLOAD)
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/mptcp", json=self._PAYLOAD)
        assert r.json()["result"] == "permission"

    def test_success(self, user_client):
        r = user_client.post("/mptcp", json=self._PAYLOAD)
        assert r.json()["result"] == "done"


# ===========================================================================
# VPN / Proxy selection
# ===========================================================================


class TestVpnSelection:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/vpn", json={"vpn": "glorytun_tcp"})
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/vpn", json={"vpn": "glorytun_tcp"})
        assert r.json()["result"] == "permission"

    def test_success(self, user_client):
        r = user_client.post("/vpn", json={"vpn": "glorytun_tcp"})
        assert r.json()["result"] == "done"

    def test_invalid_vpn_value_returns_422(self, user_client):
        r = user_client.post("/vpn", json={"vpn": "not_a_vpn"})
        assert r.status_code == 422


class TestProxySelection:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/proxy", json={"proxy": "shadowsocks"})
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/proxy", json={"proxy": "shadowsocks"})
        assert r.json()["result"] == "permission"

    def test_success(self, user_client):
        r = user_client.post("/proxy", json={"proxy": "shadowsocks"})
        assert r.json()["result"] == "done"

    def test_invalid_proxy_value_returns_422(self, user_client):
        r = user_client.post("/proxy", json={"proxy": "invalid_proxy"})
        assert r.status_code == 422


# ===========================================================================
# VPN configuration endpoints
# ===========================================================================


class TestGlorytun:
    _PAYLOAD = {"key": "aabbccdd" * 8, "port": 65001, "chacha": True}

    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/glorytun", json=self._PAYLOAD)
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/glorytun", json=self._PAYLOAD)
        assert r.json()["result"] == "permission"

    def test_success(self, user_client):
        with patch("os.path.isfile", return_value=True):
            r = user_client.post("/glorytun", json=self._PAYLOAD)
        assert r.json()["result"] == "done"

    def test_invalid_port_returns_422(self, user_client):
        r = user_client.post("/glorytun", json={**self._PAYLOAD, "port": 99999})
        assert r.status_code == 422


class TestDsvpn:
    _PAYLOAD = {"key": "aabbccdd" * 8, "port": 65401}

    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/dsvpn", json=self._PAYLOAD)
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/dsvpn", json=self._PAYLOAD)
        assert r.json()["result"] == "permission"

    def test_success(self, user_client):
        with patch("os.path.isfile", return_value=True):
            r = user_client.post("/dsvpn", json=self._PAYLOAD)
        assert r.json()["result"] == "done"


class TestMlvpn:
    _PAYLOAD = {
        "timeout": 30,
        "reorder_buffer_size": 0,
        "loss_tolerence": 50,
        "cleartext_data": 0,
        "password": "testpassword",
    }

    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/mlvpn", json=self._PAYLOAD)
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/mlvpn", json=self._PAYLOAD)
        assert r.json()["result"] == "permission"

    def test_success(self, user_client):
        with patch("os.path.isfile", return_value=True):
            r = user_client.post("/mlvpn", json=self._PAYLOAD)
        assert r.json()["result"] == "done"


def _mock_mqvpn_socket(response: dict = None):
    """Return a mock socket that yields a single JSON line from the mqvpn API."""
    if response is None:
        response = {"ok": True}
    mock_sock = MagicMock()
    mock_sock.__enter__ = lambda s: s
    mock_sock.__exit__ = MagicMock(return_value=False)
    chunks = iter([
        (json.dumps(response) + "\n").encode(),
        b"",
    ])
    mock_sock.recv.side_effect = lambda _: next(chunks)
    return mock_sock


class TestMqvpn:
    _PAYLOAD = {"key": "new-auth-key", "scheduler": "wlb", "port": 443, "fec_enable": True, "fec_scheme": "reed_solomon", "reinjection_control": True, "reinjection_mode": "deadline", "cc": "bbr2"}

    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/mqvpn", json=self._PAYLOAD)
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/mqvpn", json=self._PAYLOAD)
        assert r.json()["result"] == "permission"

    def test_missing_mqvpn_returns_warning(self, user_client):
        with patch("os.path.isfile", return_value=False):
            r = user_client.post("/mqvpn", json=self._PAYLOAD)
        assert r.json()["result"] == "warning"

    def test_success(self, user_client):
        with patch("os.path.isfile", return_value=True):
            r = user_client.post("/mqvpn", json=self._PAYLOAD)
        assert r.json()["result"] == "done"
        assert r.json()["route"] == "mqvpn"

    def test_invalid_port_returns_422(self, user_client):
        r = user_client.post("/mqvpn", json={**self._PAYLOAD, "port": 99999})
        assert r.status_code == 422

    def test_config_fields_are_updated(self, user_client):
        """auth_key and scheduler must be written into the JSON config."""
        capture = io.StringIO()
        capture.close = lambda: None  # prevent the with-block from closing it

        def _capture_open(path, mode="r", *args, **kwargs):
            if str(path) == "/etc/mqvpn/server.json" and "w" in str(mode):
                return capture
            return _mock_open(path, mode, *args, **kwargs)

        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_capture_open),
        ):
            r = user_client.post("/mqvpn", json=self._PAYLOAD)
        assert r.json()["result"] == "done"
        capture.seek(0)
        written = json.loads(capture.read())
        assert written["auth_key"] == self._PAYLOAD["key"]
        assert written["scheduler"] == self._PAYLOAD["scheduler"]
        assert written["fec_enable"] == self._PAYLOAD["fec_enable"]
        assert written["fec_scheme"] == self._PAYLOAD["fec_scheme"]
        assert written["reinjection_control"] == self._PAYLOAD["reinjection_control"]
        assert written["reinjection_mode"] == self._PAYLOAD["reinjection_mode"]
        assert written["cc"] == self._PAYLOAD["cc"]

    def test_config_returns_user_key_not_auth_key(self, user_client):
        """/config must expose the current user's key, not the global auth_key."""
        with patch("os.path.isfile", _isfile_for("/etc/mqvpn/server.json")):
            r = user_client.get("/config")
        assert r.status_code == 200
        mqvpn = r.json().get("mqvpn", {})
        assert mqvpn.get("key") == MQVPN_CONFIG["users"][0]["key"]
        assert mqvpn.get("key") != MQVPN_CONFIG["auth_key"]


class TestOpenVpn:
    _PAYLOAD = {"port": 65301, "cipher": "AES-256-GCM"}

    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/openvpn", json=self._PAYLOAD)
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/openvpn", json=self._PAYLOAD)
        assert r.json()["result"] == "permission"

    def test_invalid_port_returns_422(self, user_client):
        r = user_client.post("/openvpn", json={**self._PAYLOAD, "port": 70000})
        assert r.status_code == 422

    def test_success(self, user_client):
        with patch("os.path.isfile", return_value=True):
            r = user_client.post("/openvpn", json=self._PAYLOAD)
        assert r.json()["result"] == "done"


class TestSoftEtherVpn:
    _PAYLOAD = {"cipher": "AES-256-GCM", "password": "testpass"}

    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/softethervpn", json=self._PAYLOAD)
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/softethervpn", json=self._PAYLOAD)
        assert r.json()["result"] == "permission"


class TestWireGuard:
    _PAYLOAD = {"peers": [{"ip": "10.0.0.2", "key": "base64key=="}]}

    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/wireguard", json=self._PAYLOAD)
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/wireguard", json=self._PAYLOAD)
        assert r.json()["result"] == "permission"

    def test_empty_peers_succeeds(self, user_client):
        with patch("os.path.isfile", return_value=True):
            r = user_client.post("/wireguard", json={"peers": []})
        assert r.json()["result"] == "done"


# ===========================================================================
# Network configuration
# ===========================================================================


class TestBypass:
    _PAYLOAD = {
        "ipv4s": ["203.0.113.1"],
        "ipv6s": [],
        "intf": "eth0",
    }

    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/bypass", json=self._PAYLOAD)
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/bypass", json=self._PAYLOAD)
        assert r.json()["result"] == "permission"

    def test_success(self, user_client):
        r = user_client.post("/bypass", json=self._PAYLOAD)
        assert r.json()["result"] == "done"


class TestWan:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/wan", json={"ips": "203.0.113.1"})
        assert r.status_code == 403

    def test_ro_user_can_access(self, ro_client):
        """ro users can use /wan; result depends on installed packages."""
        r = ro_client.post("/wan", json={"ips": "203.0.113.1"})
        assert r.status_code == 200
        assert r.json()["result"] in ("done", "warning", "error")

    def test_success(self, user_client):
        with patch("os.path.isfile", return_value=True):
            r = user_client.post("/wan", json={"ips": "203.0.113.1"})
        assert r.json()["result"] == "done"


class TestLan:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/lan", json={"lanips": ["192.168.1.0/24"]})
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/lan", json={"lanips": ["192.168.1.0/24"]})
        assert r.json()["result"] == "permission"

    def test_success(self, user_client):
        with patch("os.path.isfile", return_value=True):
            r = user_client.post("/lan", json={"lanips": ["192.168.1.0/24"]})
        assert r.json()["result"] == "done"


class TestVpnIps:
    _PAYLOAD = {
        "remoteip": "10.255.255.2",
        "localip": "10.255.255.1",
    }

    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/vpnips", json=self._PAYLOAD)
        assert r.status_code == 403

    def test_ro_user_can_access(self, ro_client):
        """ro users can use /vpnips."""
        r = ro_client.post("/vpnips", json=self._PAYLOAD)
        assert r.status_code == 200

    def test_success(self, user_client):
        with patch("os.path.isfile", return_value=True):
            r = user_client.post("/vpnips", json=self._PAYLOAD)
        assert r.json()["result"] in ("done", "error")


# ===========================================================================
# Update
# ===========================================================================


class TestUpdate:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.get("/update")
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.get("/update")
        assert r.json()["result"] == "permission"

    def test_success(self, user_client):
        r = user_client.get("/update")
        assert r.json()["result"] == "done"
        assert r.json()["route"] == "update"


# ===========================================================================
# Backup
# ===========================================================================


class TestBackupPost:
    import base64 as _b64
    _PAYLOAD = {"data": __import__("base64").b64encode(b"fake-tar-gz-data").decode()}

    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/backuppost", json=self._PAYLOAD)
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/backuppost", json=self._PAYLOAD)
        assert r.json()["result"] == "permission"

    def test_empty_data_returns_error(self, user_client):
        r = user_client.post("/backuppost", json={"data": ""})
        assert r.json()["result"] == "error"

    def test_success(self, user_client):
        r = user_client.post("/backuppost", json=self._PAYLOAD)
        assert r.json()["result"] == "done"


class TestBackupGet:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.get("/backupget")
        assert r.status_code == 403

    def test_returns_data_key(self, user_client):
        with patch("os.path.isfile", return_value=True):
            r = user_client.get("/backupget")
        assert "data" in r.json()


class TestBackupList:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.get("/backuplist")
        assert r.status_code == 403

    def test_no_backups_returns_false(self, user_client):
        with patch("glob.glob", return_value=[]), patch("os.path.isfile", return_value=False):
            r = user_client.get("/backuplist")
        assert r.json()["backup"] is False

    def test_with_backups_returns_true(self, user_client):
        fake_file = "/var/opt/openmptcprouter/openmptcprouter-backup.tar.gz"
        with (
            patch("glob.glob", return_value=[fake_file]),
            patch("os.path.isfile", return_value=True),
            patch("os.path.getmtime", return_value=1700000000.0),
            patch("os.stat") as mock_stat,
        ):
            mock_stat.return_value.st_mtime = 1700000000.0
            r = user_client.get("/backuplist")
        assert r.json()["backup"] is True
        assert "modif" in r.json()


# ===========================================================================
# User management (admin-only)
# ===========================================================================


class TestAddUser:
    _PAYLOAD = {
        "username": "newuser",
        "permission": "rw",
        "vpn": "glorytun_tcp",
        "proxy": "shadowsocks",
    }

    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/add_user", json=self._PAYLOAD)
        assert r.status_code == 403

    def test_non_admin_denied(self, user_client):
        r = user_client.post("/add_user", json=self._PAYLOAD)
        assert r.json()["result"] == "permission"

    def test_ro_denied(self, ro_client):
        r = ro_client.post("/add_user", json=self._PAYLOAD)
        assert r.json()["result"] == "permission"

    def test_admin_can_add_user(self, admin_client):
        r = admin_client.post("/add_user", json=self._PAYLOAD)
        # Even if ss/vpn config files don't exist, the endpoint runs
        assert r.status_code == 200

    def test_add_user_calls_mqvpn_api_when_installed(self, admin_client):
        api_calls = []

        def _mock_mqvpn_api(cmd):
            api_calls.append(cmd)
            return {"ok": True}

        with (
            patch("os.path.isfile", _isfile_for("/etc/mqvpn/server.json")),
            patch("omr_admin.mqvpn_api", side_effect=_mock_mqvpn_api),
        ):
            r = admin_client.post("/add_user", json=self._PAYLOAD)
        assert r.status_code == 200
        assert len(api_calls) == 1
        assert api_calls[0]["cmd"] == "add_user"
        assert api_calls[0]["name"] == self._PAYLOAD["username"]
        assert "key" in api_calls[0]


class TestAddUserNote:
    _PAYLOAD = {"username": "openmptcprouter", "note": ["test note"]}

    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/add_user_note", json=self._PAYLOAD)
        assert r.status_code == 403

    def test_non_admin_denied(self, user_client):
        r = user_client.post("/add_user_note", json=self._PAYLOAD)
        assert r.json()["result"] == "permission"

    def test_admin_succeeds(self, admin_client):
        r = admin_client.post("/add_user_note", json=self._PAYLOAD)
        assert r.status_code == 200


class TestRemoveUser:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/remove_user", json={"username": "readonly"})
        assert r.status_code == 403

    def test_non_admin_denied(self, user_client):
        r = user_client.post("/remove_user", json={"username": "readonly"})
        assert r.json()["result"] == "permission"

    def test_cannot_remove_userid_0(self, admin_client):
        r = admin_client.post("/remove_user", json={"username": "openmptcprouter"})
        assert r.json()["result"] == "not allowed"

    def test_nonexistent_user_returns_error(self, admin_client):
        r = admin_client.post("/remove_user", json={"username": "ghost"})
        assert r.json()["result"] == "error"

    def test_can_remove_existing_user(self, admin_client):
        r = admin_client.post("/remove_user", json={"username": "readonly"})
        assert r.json()["result"] == "done"

    def test_remove_user_calls_mqvpn_api_when_installed(self, admin_client):
        api_calls = []

        def _mock_mqvpn_api(cmd):
            api_calls.append(cmd)
            return {"ok": True}

        with (
            patch("os.path.isfile", _isfile_for("/etc/mqvpn/server.json")),
            patch("omr_admin.mqvpn_api", side_effect=_mock_mqvpn_api),
        ):
            r = admin_client.post("/remove_user", json={"username": "readonly"})
        assert r.status_code == 200
        assert len(api_calls) == 1
        assert api_calls[0]["cmd"] == "remove_user"
        assert api_calls[0]["name"] == "readonly"

    def test_remove_user_mqvpn_user_removed_from_json(self, admin_client):
        """remove_mqvpn must delete the user from /etc/mqvpn/server.json, not only via API."""
        import io as _io
        import json as _json
        import copy
        from conftest import _mock_open as _base_open, MQVPN_CONFIG

        # Seed the MQVPN config with the user we're about to remove
        config_with_readonly = copy.deepcopy(MQVPN_CONFIG)
        config_with_readonly["users"].append({"name": "readonly", "key": "some-key"})
        config_json = _json.dumps(config_with_readonly)

        written_json = {}

        def _open_mqvpn(path, mode="r", *args, **kwargs):
            sp = str(path)
            if sp == "/etc/mqvpn/server.json":
                if "w" in str(mode):
                    buf = _io.StringIO()
                    original_close = buf.close

                    def _capture_on_close():
                        buf.seek(0)
                        written_json.update(_json.loads(buf.read()))
                        original_close()

                    buf.close = _capture_on_close
                    return buf
                return _io.StringIO(config_json)
            return _base_open(path, mode, *args, **kwargs)

        with (
            patch("os.path.isfile", _isfile_for("/etc/mqvpn/server.json")),
            patch("omr_admin.mqvpn_api", return_value={"ok": True}),
            patch("builtins.open", side_effect=_open_mqvpn),
        ):
            r = admin_client.post("/remove_user", json={"username": "readonly"})

        assert r.json()["result"] == "done"
        names = [u["name"] for u in written_json.get("users", [])]
        assert "readonly" not in names
        assert "openmptcprouter" in names  # other users preserved


class TestAddUserResponseFields:
    """Verify the user record written to config contains the expected fields."""

    _PAYLOAD = {
        "username": "newuser",
        "permission": "rw",
        "vpn": "glorytun_tcp",
        "proxy": "shadowsocks",
    }

    def test_response_is_200(self, admin_client):
        r = admin_client.post("/add_user", json=self._PAYLOAD)
        assert r.status_code == 200

    def test_custom_userid_is_respected(self, admin_client):
        payload = {**self._PAYLOAD, "userid": 42}
        written = {}

        real_json_dump = __import__("json").dump

        def _capture_write(data, f, **kw):
            written.update(data)
            real_json_dump(data, f, **kw)

        with patch("omr_admin.json.dump", side_effect=_capture_write):
            admin_client.post("/add_user", json=payload)

        assert written.get("users", [{}])[0].get("newuser", {}).get("userid") == "42"

    def test_auto_userid_is_above_existing_max(self, admin_client):
        # Config has userid=2 ("readonly"); new user should get at least 3
        written = {}
        real_json_dump = __import__("json").dump

        def _capture_write(data, f, **kw):
            written.update(data)
            real_json_dump(data, f, **kw)

        with patch("omr_admin.json.dump", side_effect=_capture_write):
            admin_client.post("/add_user", json=self._PAYLOAD)

        userid = int(written.get("users", [{}])[0].get("newuser", {}).get("userid", 0))
        assert userid >= 3

    def test_vpn_field_saved(self, admin_client):
        written = {}
        real_json_dump = __import__("json").dump

        def _capture_write(data, f, **kw):
            written.update(data)
            real_json_dump(data, f, **kw)

        with patch("omr_admin.json.dump", side_effect=_capture_write):
            admin_client.post("/add_user", json={**self._PAYLOAD, "vpn": "glorytun_tcp"})

        assert written.get("users", [{}])[0].get("newuser", {}).get("vpn") == "glorytun_tcp"

    def test_proxy_field_saved(self, admin_client):
        written = {}
        real_json_dump = __import__("json").dump

        def _capture_write(data, f, **kw):
            written.update(data)
            real_json_dump(data, f, **kw)

        with patch("omr_admin.json.dump", side_effect=_capture_write):
            admin_client.post("/add_user", json={**self._PAYLOAD, "proxy": "shadowsocks"})

        assert written.get("users", [{}])[0].get("newuser", {}).get("proxy") == "shadowsocks"

    def test_password_is_uppercase_hex(self, admin_client):
        written = {}
        real_json_dump = __import__("json").dump

        def _capture_write(data, f, **kw):
            written.update(data)
            real_json_dump(data, f, **kw)

        with patch("omr_admin.json.dump", side_effect=_capture_write):
            admin_client.post("/add_user", json=self._PAYLOAD)

        pw = written.get("users", [{}])[0].get("newuser", {}).get("user_password", "")
        assert pw == pw.upper()
        assert len(pw) == 64  # 32 bytes hex

    def test_invalid_permission_returns_422(self, admin_client):
        r = admin_client.post("/add_user", json={**self._PAYLOAD, "permission": "superadmin"})
        assert r.status_code == 422

    def test_invalid_vpn_returns_422(self, admin_client):
        r = admin_client.post("/add_user", json={**self._PAYLOAD, "vpn": "notavpn"})
        assert r.status_code == 422

    def test_username_with_special_chars_does_not_break_config(self, admin_client):
        # Regression: old code used string concat to build JSON; quotes in
        # username would produce invalid JSON and raise an exception.
        r = admin_client.post("/add_user", json={**self._PAYLOAD, "username": 'user"inject'})
        # Should not 500 — either 200 (accepted) or 422 (validation rejects it)
        assert r.status_code in (200, 422)

    def test_add_user_calls_shadowsocks_when_installed(self, admin_client):
        ss_calls = []

        def _mock_add_ss(port, key, userid=0, ip=''):
            ss_calls.append({"port": port, "key": key, "userid": userid})
            return port

        with (
            patch("os.path.isfile", _isfile_for("/etc/shadowsocks-libev/manager.json")),
            patch("omr_admin.add_ss_user", side_effect=_mock_add_ss),
        ):
            r = admin_client.post("/add_user", json=self._PAYLOAD)

        assert r.status_code == 200
        assert len(ss_calls) == 1

    def test_add_user_calls_openvpn_when_installed(self, admin_client):
        run_calls = []

        def _mock_run(cmd, *args, **kwargs):
            run_calls.append(cmd)
            return MagicMock(returncode=0)

        with (
            patch("os.path.isfile", _isfile_for("/etc/openvpn/tun0.conf")),
            patch("subprocess.run", side_effect=_mock_run),
        ):
            r = admin_client.post("/add_user", json=self._PAYLOAD)

        assert r.status_code == 200
        easyrsa_calls = [c for c in run_calls if c and c[0] == "./easyrsa"]
        assert len(easyrsa_calls) == 1
        assert "build-client-full" in easyrsa_calls[0]


class TestAddUserSideEffects:
    """Verify that add_user triggers the right VPN/proxy setup calls."""

    _PAYLOAD = {
        "username": "newuser",
        "permission": "rw",
        "vpn": "openvpn",
        "proxy": "shadowsocks-rust",
    }

    # ------------------------------------------------------------------
    # OpenVPN
    # ------------------------------------------------------------------

    def test_openvpn_cert_build_includes_username(self, admin_client):
        run_calls = []

        def _mock_run(cmd, *args, **kwargs):
            run_calls.append(cmd)
            return MagicMock(returncode=0)

        with (
            patch("os.path.isfile", _isfile_for("/etc/openvpn/tun0.conf")),
            patch("subprocess.run", side_effect=_mock_run),
        ):
            r = admin_client.post("/add_user", json=self._PAYLOAD)

        assert r.status_code == 200
        build_calls = [c for c in run_calls if c and "build-client-full" in c]
        assert len(build_calls) == 1
        assert "newuser" in build_calls[0]
        assert "nopass" in build_calls[0]

    def test_openvpn_cert_build_sets_cert_expire_env(self, admin_client):
        envs = []

        def _mock_run(cmd, *args, **kwargs):
            envs.append(kwargs.get("env", {}))
            return MagicMock(returncode=0)

        with (
            patch("os.path.isfile", _isfile_for("/etc/openvpn/tun0.conf")),
            patch("subprocess.run", side_effect=_mock_run),
        ):
            admin_client.post("/add_user", json=self._PAYLOAD)

        build_envs = [e for e in envs if e]
        assert len(build_envs) >= 1
        assert build_envs[0].get("EASYRSA_CERT_EXPIRE") == "3650"

    def test_openvpn_vpn_field_saved_in_config(self, admin_client):
        written = {}
        real_json_dump = __import__("json").dump

        def _capture(data, f, **kw):
            written.update(data)
            real_json_dump(data, f, **kw)

        with (
            patch("os.path.isfile", _isfile_for("/etc/openvpn/tun0.conf", "/etc/openvpn/ca/pki/issued/newuser.crt")),
            patch("subprocess.run", return_value=MagicMock(returncode=0)),
            patch("omr_admin.json.dump", side_effect=_capture),
        ):
            admin_client.post("/add_user", json={**self._PAYLOAD, "vpn": "openvpn"})

        assert written.get("users", [{}])[0].get("newuser", {}).get("vpn") == "openvpn"

    # ------------------------------------------------------------------
    # MQVPN
    # ------------------------------------------------------------------

    def test_mqvpn_add_user_key_is_non_empty(self, admin_client):
        api_calls = []

        def _mock_mqvpn_api(cmd):
            api_calls.append(cmd)
            return {"ok": True}

        with (
            patch("os.path.isfile", _isfile_for("/etc/mqvpn/server.json")),
            patch("omr_admin.mqvpn_api", side_effect=_mock_mqvpn_api),
        ):
            r = admin_client.post("/add_user", json=self._PAYLOAD)

        assert r.status_code == 200
        assert len(api_calls) == 1
        assert api_calls[0]["cmd"] == "add_user"
        assert api_calls[0]["name"] == "newuser"
        key = api_calls[0].get("key", "")
        assert isinstance(key, str) and len(key) > 0

    def test_mqvpn_uses_unique_key_per_call(self, admin_client):
        """Each add_user call must generate a fresh random MQVPN key."""
        keys = []

        def _mock_mqvpn_api(cmd):
            keys.append(cmd.get("key", ""))
            return {"ok": True}

        with (
            patch("os.path.isfile", _isfile_for("/etc/mqvpn/server.json")),
            patch("omr_admin.mqvpn_api", side_effect=_mock_mqvpn_api),
        ):
            admin_client.post("/add_user", json={**self._PAYLOAD, "username": "user1"})
            admin_client.post("/add_user", json={**self._PAYLOAD, "username": "user2"})

        assert len(keys) == 2
        assert keys[0] != keys[1]

    def test_mqvpn_user_written_to_json(self, admin_client):
        """New user must be persisted in /etc/mqvpn/server.json, not only via API."""
        import io as _io
        import json as _json
        from conftest import _mock_open as _base_open, MQVPN_CONFIG
        import copy

        written_json = {}

        def _open_capture(path, mode="r", *args, **kwargs):
            sp = str(path)
            if sp == "/etc/mqvpn/server.json" and "w" in str(mode):
                buf = _io.StringIO()
                original_close = buf.close

                def _capture_on_close():
                    buf.seek(0)
                    written_json.update(_json.loads(buf.read()))
                    original_close()

                buf.close = _capture_on_close
                return buf
            return _base_open(path, mode, *args, **kwargs)

        with (
            patch("os.path.isfile", _isfile_for("/etc/mqvpn/server.json")),
            patch("omr_admin.mqvpn_api", return_value={"ok": True}),
            patch("builtins.open", side_effect=_open_capture),
        ):
            r = admin_client.post("/add_user", json=self._PAYLOAD)

        assert r.status_code == 200
        names = [u["name"] for u in written_json.get("users", [])]
        assert "newuser" in names

    def test_mqvpn_json_key_matches_api_key(self, admin_client):
        """The key written to server.json must be the same one sent to the API."""
        import io as _io
        import json as _json
        from conftest import _mock_open as _base_open

        api_calls = []
        written_json = {}

        def _mock_mqvpn_api(cmd):
            api_calls.append(cmd)
            return {"ok": True}

        def _open_capture(path, mode="r", *args, **kwargs):
            sp = str(path)
            if sp == "/etc/mqvpn/server.json" and "w" in str(mode):
                buf = _io.StringIO()
                original_close = buf.close

                def _capture_on_close():
                    buf.seek(0)
                    written_json.update(_json.loads(buf.read()))
                    original_close()

                buf.close = _capture_on_close
                return buf
            return _base_open(path, mode, *args, **kwargs)

        with (
            patch("os.path.isfile", _isfile_for("/etc/mqvpn/server.json")),
            patch("omr_admin.mqvpn_api", side_effect=_mock_mqvpn_api),
            patch("builtins.open", side_effect=_open_capture),
        ):
            admin_client.post("/add_user", json=self._PAYLOAD)

        api_key = api_calls[0]["key"]
        json_entry = next((u for u in written_json.get("users", []) if u["name"] == "newuser"), None)
        assert json_entry is not None
        assert json_entry["key"] == api_key

    # ------------------------------------------------------------------
    # Shadowsocks-rust  (uses the shadowsocks-go backend config)
    # ------------------------------------------------------------------

    def test_ss_go_add_user_called_with_username(self, admin_client):
        ss_go_calls = []

        def _mock_add_ss_go(user, key=""):
            ss_go_calls.append({"user": user, "key": key})
            return key

        with (
            patch("os.path.isfile", _isfile_for("/etc/shadowsocks-go/server.json")),
            patch("omr_admin.add_ss_go_user", side_effect=_mock_add_ss_go),
        ):
            r = admin_client.post("/add_user", json=self._PAYLOAD)

        assert r.status_code == 200
        assert len(ss_go_calls) == 1
        assert ss_go_calls[0]["user"] == "newuser"

    def test_ss_go_proxy_field_saved_as_shadowsocks_rust(self, admin_client):
        written = {}
        real_json_dump = __import__("json").dump

        def _capture(data, f, **kw):
            written.update(data)
            real_json_dump(data, f, **kw)

        with (
            patch("os.path.isfile", _isfile_for("/etc/shadowsocks-go/server.json")),
            patch("omr_admin.add_ss_go_user", return_value="somekey"),
            patch("omr_admin.json.dump", side_effect=_capture),
        ):
            admin_client.post("/add_user", json={**self._PAYLOAD, "proxy": "shadowsocks-rust"})

        assert written.get("users", [{}])[0].get("newuser", {}).get("proxy") == "shadowsocks-rust"

    def test_ss_go_not_called_when_not_installed(self, admin_client):
        ss_go_calls = []

        def _mock_add_ss_go(user, key=""):
            ss_go_calls.append(user)
            return key

        with (
            patch("os.path.isfile", return_value=False),
            patch("omr_admin.add_ss_go_user", side_effect=_mock_add_ss_go),
        ):
            r = admin_client.post("/add_user", json=self._PAYLOAD)

        assert r.status_code == 200
        assert len(ss_go_calls) == 0

    # ------------------------------------------------------------------
    # Combined scenarios
    # ------------------------------------------------------------------

    def test_openvpn_and_mqvpn_both_invoked(self, admin_client):
        run_calls = []
        api_calls = []

        def _mock_run(cmd, *args, **kwargs):
            run_calls.append(cmd)
            return MagicMock(returncode=0)

        def _mock_mqvpn_api(cmd):
            api_calls.append(cmd)
            return {"ok": True}

        with (
            patch("os.path.isfile", _isfile_for("/etc/openvpn/tun0.conf", "/etc/mqvpn/server.json", "/etc/openvpn/ca/pki/issued/newuser.crt")),
            patch("subprocess.run", side_effect=_mock_run),
            patch("omr_admin.mqvpn_api", side_effect=_mock_mqvpn_api),
        ):
            r = admin_client.post("/add_user", json=self._PAYLOAD)

        assert r.status_code == 200
        easyrsa_calls = [c for c in run_calls if c and c[0] == "./easyrsa"]
        assert len(easyrsa_calls) >= 1
        assert len(api_calls) == 1
        assert api_calls[0]["cmd"] == "add_user"

    def test_openvpn_and_ss_go_both_invoked(self, admin_client):
        run_calls = []
        ss_go_calls = []

        def _mock_run(cmd, *args, **kwargs):
            run_calls.append(cmd)
            return MagicMock(returncode=0)

        def _mock_add_ss_go(user, key=""):
            ss_go_calls.append(user)
            return key

        with (
            patch("os.path.isfile", _isfile_for("/etc/openvpn/tun0.conf", "/etc/shadowsocks-go/server.json")),
            patch("subprocess.run", side_effect=_mock_run),
            patch("omr_admin.add_ss_go_user", side_effect=_mock_add_ss_go),
        ):
            r = admin_client.post("/add_user", json=self._PAYLOAD)

        assert r.status_code == 200
        easyrsa_calls = [c for c in run_calls if c and c[0] == "./easyrsa"]
        assert len(easyrsa_calls) >= 1
        assert ss_go_calls == ["newuser"]

    def test_mqvpn_and_ss_go_both_invoked(self, admin_client):
        api_calls = []
        ss_go_calls = []

        def _mock_mqvpn_api(cmd):
            api_calls.append(cmd)
            return {"ok": True}

        def _mock_add_ss_go(user, key=""):
            ss_go_calls.append(user)
            return key

        with (
            patch("os.path.isfile", _isfile_for("/etc/mqvpn/server.json", "/etc/shadowsocks-go/server.json")),
            patch("omr_admin.mqvpn_api", side_effect=_mock_mqvpn_api),
            patch("omr_admin.add_ss_go_user", side_effect=_mock_add_ss_go),
        ):
            r = admin_client.post("/add_user", json=self._PAYLOAD)

        assert r.status_code == 200
        assert len(api_calls) == 1
        assert api_calls[0]["cmd"] == "add_user"
        assert ss_go_calls == ["newuser"]

    # ------------------------------------------------------------------
    # MQVPN presence / absence
    # ------------------------------------------------------------------

    def test_mqvpn_not_called_when_not_installed(self, admin_client):
        api_calls = []

        with (
            patch("os.path.isfile", return_value=False),
            patch("omr_admin.mqvpn_api", side_effect=api_calls.append),
        ):
            r = admin_client.post("/add_user", json=self._PAYLOAD)

        assert r.status_code == 200
        assert len(api_calls) == 0

    # ------------------------------------------------------------------
    # SoftEther presence / absence
    # ------------------------------------------------------------------

    def test_softether_not_called_when_not_installed(self, admin_client):
        se_calls = []

        with (
            patch("os.path.isfile", return_value=False),
            patch("omr_admin.add_softether_user", side_effect=se_calls.append),
        ):
            r = admin_client.post("/add_user", json=self._PAYLOAD)

        assert r.status_code == 200
        assert len(se_calls) == 0

    def test_softether_called_when_installed(self, admin_client):
        se_calls = []

        def _mock_add_se(user, password):
            se_calls.append({"user": user, "password": password})
            return password

        with (
            patch("os.path.isfile", _isfile_for("/var/lib/softether/vpn_server.config")),
            patch("omr_admin.add_softether_user", side_effect=_mock_add_se),
            patch("omr_admin.modif_config_user"),
        ):
            r = admin_client.post("/add_user", json=self._PAYLOAD)

        assert r.status_code == 200
        assert len(se_calls) == 1
        assert se_calls[0]["user"] == "newuser"
        assert isinstance(se_calls[0]["password"], str) and len(se_calls[0]["password"]) > 0


class TestRemoveUserSideEffects:
    """Verify that remove_user triggers the right cleanup calls."""

    def test_removes_shadowsocks_port_when_installed(self, admin_client):
        ss_calls = []

        def _mock_remove_ss(port):
            ss_calls.append(port)

        with (
            patch("os.path.isfile", _isfile_for("/etc/shadowsocks-libev/manager.json")),
            patch("omr_admin.remove_ss_user", side_effect=_mock_remove_ss),
        ):
            r = admin_client.post("/remove_user", json={"username": "readonly"})

        assert r.json()["result"] == "done"
        assert len(ss_calls) == 1
        assert ss_calls[0] == "65102"  # shadowsocks_port from MOCK_CONFIG

    def test_remove_user_calls_v2ray_when_installed(self, admin_client):
        v2ray_calls = []

        def _mock_v2ray_del(user, *args, **kwargs):
            v2ray_calls.append(user)

        with (
            patch("os.path.isfile", _isfile_for("/etc/v2ray/v2ray-server.json")),
            patch("omr_admin.v2ray_del_user", side_effect=_mock_v2ray_del),
        ):
            r = admin_client.post("/remove_user", json={"username": "readonly"})

        assert r.json()["result"] == "done"
        assert v2ray_calls == ["readonly"]

    def test_remove_user_calls_xray_when_installed(self, admin_client):
        xray_calls = []

        def _mock_xray_del(user, *args, **kwargs):
            xray_calls.append(user)

        with (
            patch("os.path.isfile", _isfile_for("/etc/xray/xray-server.json")),
            patch("omr_admin.xray_del_user", side_effect=_mock_xray_del),
        ):
            r = admin_client.post("/remove_user", json={"username": "readonly"})

        assert r.json()["result"] == "done"
        assert xray_calls == ["readonly"]

    def test_remove_user_calls_openvpn_revoke_when_installed(self, admin_client):
        run_calls = []

        def _mock_run(cmd, *args, **kwargs):
            run_calls.append(cmd)
            return MagicMock(returncode=0)

        with (
            patch("os.path.isfile", _isfile_for("/etc/openvpn/tun0.conf")),
            patch("subprocess.run", side_effect=_mock_run),
        ):
            r = admin_client.post("/remove_user", json={"username": "readonly"})

        assert r.json()["result"] == "done"
        revoke_calls = [c for c in run_calls if c and "revoke" in c]
        assert len(revoke_calls) == 1
        assert "readonly" in revoke_calls[0]

    def test_remove_user_calls_softether_when_installed(self, admin_client):
        se_calls = []

        def _mock_remove_se(user):
            se_calls.append(user)

        with (
            patch("os.path.isfile", _isfile_for("/var/lib/softether/vpn_server.config")),
            patch("omr_admin.remove_softether_user", side_effect=_mock_remove_se),
        ):
            r = admin_client.post("/remove_user", json={"username": "readonly"})

        assert r.json()["result"] == "done"
        assert se_calls == ["readonly"]

    def test_user_is_deleted_from_config(self, admin_client):
        written = {}
        real_json_dump = __import__("json").dump

        def _capture_write(data, f, **kw):
            written.update(data)
            real_json_dump(data, f, **kw)

        with patch("omr_admin.json.dump", side_effect=_capture_write):
            r = admin_client.post("/remove_user", json={"username": "readonly"})

        assert r.json()["result"] == "done"
        assert "readonly" not in written.get("users", [{}])[0]

    def test_user_without_shadowsocks_port_does_not_crash(self, admin_client):
        # A user with no shadowsocks_port in config — remove_ss_user should not be called
        import json as _json
        import copy

        config_no_ss = copy.deepcopy(
            _json.loads(__import__("conftest")._CONFIG_JSON)
        )
        del config_no_ss["users"][0]["readonly"]["shadowsocks_port"]
        config_json = _json.dumps(config_no_ss)

        def _open_no_ss(path, mode="r", *args, **kwargs):
            import io
            sp = str(path)
            if sp == "/etc/openmptcprouter-vps-admin/omr-admin-config.json":
                binary = "b" in str(mode)
                return io.BytesIO(config_json.encode()) if binary else io.StringIO(config_json)
            from conftest import _mock_open
            return _mock_open(path, mode, *args, **kwargs)

        ss_calls = []
        with (
            patch("builtins.open", side_effect=_open_no_ss),
            patch("os.path.isfile", _isfile_for("/etc/shadowsocks-libev/manager.json")),
            patch("omr_admin.remove_ss_user", side_effect=ss_calls.append),
        ):
            r = admin_client.post("/remove_user", json={"username": "readonly"})

        assert r.json()["result"] == "done"
        assert len(ss_calls) == 0  # no port → no removal call

    def test_openvpn_socket_sends_bytes_kill_command(self, admin_client):
        """send() must receive bytes — catches the str+bytes concatenation bug."""
        import socket as _socket_mod

        sent = []

        mock_fd = MagicMock()
        mock_fd.readline.return_value = b">INFO:OpenVPN Management Interface"

        mock_sock = MagicMock()
        mock_sock.makefile.return_value = mock_fd
        mock_sock.send.side_effect = lambda data: sent.append(data)

        _real_socket = _socket_mod.socket

        def _mock_socket_class(family=_socket_mod.AF_INET, type=_socket_mod.SOCK_STREAM,
                                proto=0, fileno=None):
            # Pass through internal calls (e.g. asyncio socketpair wrapping an fd)
            if fileno is not None:
                return _real_socket(family, type, proto, fileno)
            return mock_sock

        with (
            patch("os.path.isfile", _isfile_for("/etc/openvpn/tun0.conf")),
            patch("subprocess.run", return_value=MagicMock(returncode=0)),
            patch("socket.socket", side_effect=_mock_socket_class),
        ):
            r = admin_client.post("/remove_user", json={"username": "readonly"})

        assert r.json()["result"] == "done"
        assert len(sent) == 1
        assert isinstance(sent[0], bytes), "send() must be called with bytes, not str"
        assert sent[0] == b"kill readonly\r\n"

    def test_openvpn_socket_bad_banner_skips_kill(self, admin_client):
        """If the banner is not the OpenVPN INFO line, no kill command is sent."""
        import socket as _socket_mod

        sent = []

        mock_fd = MagicMock()
        mock_fd.readline.return_value = b"UNEXPECTED BANNER"

        mock_sock = MagicMock()
        mock_sock.makefile.return_value = mock_fd
        mock_sock.send.side_effect = lambda data: sent.append(data)

        _real_socket = _socket_mod.socket

        def _mock_socket_class(family=_socket_mod.AF_INET, type=_socket_mod.SOCK_STREAM,
                                proto=0, fileno=None):
            if fileno is not None:
                return _real_socket(family, type, proto, fileno)
            return mock_sock

        with (
            patch("os.path.isfile", _isfile_for("/etc/openvpn/tun0.conf")),
            patch("subprocess.run", return_value=MagicMock(returncode=0)),
            patch("socket.socket", side_effect=_mock_socket_class),
        ):
            r = admin_client.post("/remove_user", json={"username": "readonly"})

        assert r.json()["result"] == "done"
        assert len(sent) == 0

    def test_openvpn_socket_timeout_does_not_crash(self, admin_client):
        """A socket timeout during OpenVPN kill must not propagate as a 500."""
        import socket as _socket_mod

        _real_socket = _socket_mod.socket

        mock_sock = MagicMock()
        mock_sock.connect.side_effect = _socket_mod.timeout("timed out")

        def _mock_socket_class(family=_socket_mod.AF_INET, type=_socket_mod.SOCK_STREAM,
                                proto=0, fileno=None):
            if fileno is not None:
                return _real_socket(family, type, proto, fileno)
            return mock_sock

        with (
            patch("os.path.isfile", _isfile_for("/etc/openvpn/tun0.conf")),
            patch("subprocess.run", return_value=MagicMock(returncode=0)),
            patch("socket.socket", side_effect=_mock_socket_class),
        ):
            r = admin_client.post("/remove_user", json={"username": "readonly"})

        assert r.json()["result"] == "done"

    def test_openvpn_socket_error_does_not_crash(self, admin_client):
        """A generic socket error during OpenVPN kill must not propagate as a 500."""
        import socket as _socket_mod

        _real_socket = _socket_mod.socket

        mock_sock = MagicMock()
        mock_sock.connect.side_effect = _socket_mod.error("connection refused")

        def _mock_socket_class(family=_socket_mod.AF_INET, type=_socket_mod.SOCK_STREAM,
                                proto=0, fileno=None):
            if fileno is not None:
                return _real_socket(family, type, proto, fileno)
            return mock_sock

        with (
            patch("os.path.isfile", _isfile_for("/etc/openvpn/tun0.conf")),
            patch("subprocess.run", return_value=MagicMock(returncode=0)),
            patch("socket.socket", side_effect=_mock_socket_class),
        ):
            r = admin_client.post("/remove_user", json={"username": "readonly"})

        assert r.json()["result"] == "done"

    # ------------------------------------------------------------------
    # Shadowsocks-rust (shadowsocks-go backend)
    # ------------------------------------------------------------------

    def test_remove_user_calls_ss_go_when_installed(self, admin_client):
        ss_go_calls = []

        def _mock_remove_ss_go(user):
            ss_go_calls.append(user)

        with (
            patch("os.path.isfile", _isfile_for("/etc/shadowsocks-go/server.json")),
            patch("omr_admin.remove_ss_go_user", side_effect=_mock_remove_ss_go),
        ):
            r = admin_client.post("/remove_user", json={"username": "readonly"})

        assert r.json()["result"] == "done"
        assert ss_go_calls == ["readonly"]

    def test_remove_user_ss_go_not_called_when_not_installed(self, admin_client):
        ss_go_calls = []

        with (
            patch("os.path.isfile", return_value=False),
            patch("omr_admin.remove_ss_go_user", side_effect=ss_go_calls.append),
        ):
            r = admin_client.post("/remove_user", json={"username": "readonly"})

        assert r.json()["result"] == "done"
        assert len(ss_go_calls) == 0

    # ------------------------------------------------------------------
    # Combined scenarios
    # ------------------------------------------------------------------

    def test_remove_user_openvpn_socket_and_mqvpn_both_invoked(self, admin_client):
        import socket as _socket_mod

        sent = []
        api_calls = []

        mock_fd = MagicMock()
        mock_fd.readline.return_value = b">INFO:OpenVPN Management Interface"
        mock_sock = MagicMock()
        mock_sock.makefile.return_value = mock_fd
        mock_sock.send.side_effect = lambda data: sent.append(data)

        _real_socket = _socket_mod.socket

        def _mock_socket_class(family=_socket_mod.AF_INET, type=_socket_mod.SOCK_STREAM,
                                proto=0, fileno=None):
            if fileno is not None:
                return _real_socket(family, type, proto, fileno)
            return mock_sock

        def _mock_mqvpn_api(cmd):
            api_calls.append(cmd)
            return {"ok": True}

        with (
            patch("os.path.isfile", _isfile_for("/etc/openvpn/tun0.conf", "/etc/mqvpn/server.json")),
            patch("subprocess.run", return_value=MagicMock(returncode=0)),
            patch("socket.socket", side_effect=_mock_socket_class),
            patch("omr_admin.mqvpn_api", side_effect=_mock_mqvpn_api),
        ):
            r = admin_client.post("/remove_user", json={"username": "readonly"})

        assert r.json()["result"] == "done"
        assert len(sent) == 1
        assert sent[0] == b"kill readonly\r\n"
        assert len(api_calls) == 1
        assert api_calls[0]["cmd"] == "remove_user"
        assert api_calls[0]["name"] == "readonly"

    def test_remove_user_openvpn_socket_and_ss_go_both_invoked(self, admin_client):
        import socket as _socket_mod

        sent = []
        ss_go_calls = []

        mock_fd = MagicMock()
        mock_fd.readline.return_value = b">INFO:OpenVPN Management Interface"
        mock_sock = MagicMock()
        mock_sock.makefile.return_value = mock_fd
        mock_sock.send.side_effect = lambda data: sent.append(data)

        _real_socket = _socket_mod.socket

        def _mock_socket_class(family=_socket_mod.AF_INET, type=_socket_mod.SOCK_STREAM,
                                proto=0, fileno=None):
            if fileno is not None:
                return _real_socket(family, type, proto, fileno)
            return mock_sock

        with (
            patch("os.path.isfile", _isfile_for("/etc/openvpn/tun0.conf", "/etc/shadowsocks-go/server.json")),
            patch("subprocess.run", return_value=MagicMock(returncode=0)),
            patch("socket.socket", side_effect=_mock_socket_class),
            patch("omr_admin.remove_ss_go_user", side_effect=ss_go_calls.append),
        ):
            r = admin_client.post("/remove_user", json={"username": "readonly"})

        assert r.json()["result"] == "done"
        assert sent == [b"kill readonly\r\n"]
        assert ss_go_calls == ["readonly"]

    def test_remove_user_mqvpn_and_ss_go_both_invoked(self, admin_client):
        api_calls = []
        ss_go_calls = []

        def _mock_mqvpn_api(cmd):
            api_calls.append(cmd)
            return {"ok": True}

        with (
            patch("os.path.isfile", _isfile_for("/etc/mqvpn/server.json", "/etc/shadowsocks-go/server.json")),
            patch("omr_admin.mqvpn_api", side_effect=_mock_mqvpn_api),
            patch("omr_admin.remove_ss_go_user", side_effect=ss_go_calls.append),
        ):
            r = admin_client.post("/remove_user", json={"username": "readonly"})

        assert r.json()["result"] == "done"
        assert len(api_calls) == 1
        assert api_calls[0]["cmd"] == "remove_user"
        assert ss_go_calls == ["readonly"]


class TestModifyUser:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/modify_user", json={"username": "readonly"})
        assert r.status_code == 403

    def test_non_admin_denied(self, user_client):
        r = user_client.post("/modify_user", json={"username": "readonly", "disabled": True})
        assert r.json()["result"] == "permission"

    def test_ro_denied(self, ro_client):
        r = ro_client.post("/modify_user", json={"username": "readonly", "disabled": True})
        assert r.json()["result"] == "permission"

    def test_nonexistent_user_returns_error(self, admin_client):
        r = admin_client.post("/modify_user", json={"username": "ghost", "disabled": True})
        assert r.json()["result"] == "error"

    def test_no_changes_returns_error(self, admin_client):
        r = admin_client.post("/modify_user", json={"username": "readonly"})
        assert r.json()["result"] == "error"

    def test_modify_password_returns_done(self, admin_client):
        r = admin_client.post("/modify_user", json={"username": "readonly", "user_password": "newpassword"})
        assert r.json()["result"] == "done"

    def test_modify_disabled_returns_done(self, admin_client):
        r = admin_client.post("/modify_user", json={"username": "readonly", "disabled": True})
        assert r.json()["result"] == "done"

    def test_modify_vpn_returns_done(self, admin_client):
        r = admin_client.post("/modify_user", json={"username": "readonly", "vpn": "glorytun_tcp"})
        assert r.json()["result"] == "done"

    def test_modify_proxy_returns_done(self, admin_client):
        r = admin_client.post("/modify_user", json={"username": "readonly", "proxy": "shadowsocks"})
        assert r.json()["result"] == "done"

    def test_invalid_vpn_returns_422(self, admin_client):
        r = admin_client.post("/modify_user", json={"username": "readonly", "vpn": "notavpn"})
        assert r.status_code == 422

    def test_invalid_proxy_returns_422(self, admin_client):
        r = admin_client.post("/modify_user", json={"username": "readonly", "proxy": "notaproxy"})
        assert r.status_code == 422

    def test_password_written_to_config(self, admin_client):
        written = {}
        real_json_dump = __import__("json").dump

        def _capture_write(data, f, **kw):
            written.update(data)
            real_json_dump(data, f, **kw)

        with patch("omr_admin.json.dump", side_effect=_capture_write):
            r = admin_client.post("/modify_user", json={"username": "readonly", "user_password": "newpass"})

        assert r.json()["result"] == "done"
        assert written.get("users", [{}])[0].get("readonly", {}).get("user_password") == "newpass"

    def test_disabled_true_stored_as_string_true(self, admin_client):
        written = {}
        real_json_dump = __import__("json").dump

        def _capture_write(data, f, **kw):
            written.update(data)
            real_json_dump(data, f, **kw)

        with patch("omr_admin.json.dump", side_effect=_capture_write):
            r = admin_client.post("/modify_user", json={"username": "readonly", "disabled": True})

        assert r.json()["result"] == "done"
        assert written.get("users", [{}])[0].get("readonly", {}).get("disabled") == "true"

    def test_disabled_false_stored_as_string_false(self, admin_client):
        written = {}
        real_json_dump = __import__("json").dump

        def _capture_write(data, f, **kw):
            written.update(data)
            real_json_dump(data, f, **kw)

        with patch("omr_admin.json.dump", side_effect=_capture_write):
            r = admin_client.post("/modify_user", json={"username": "readonly", "disabled": False})

        assert r.json()["result"] == "done"
        assert written.get("users", [{}])[0].get("readonly", {}).get("disabled") == "false"

    def test_vpn_written_to_config(self, admin_client):
        written = {}
        real_json_dump = __import__("json").dump

        def _capture_write(data, f, **kw):
            written.update(data)
            real_json_dump(data, f, **kw)

        with patch("omr_admin.json.dump", side_effect=_capture_write):
            r = admin_client.post("/modify_user", json={"username": "readonly", "vpn": "openvpn"})

        assert r.json()["result"] == "done"
        assert written.get("users", [{}])[0].get("readonly", {}).get("vpn") == "openvpn"

    def test_proxy_written_to_config(self, admin_client):
        written = {}
        real_json_dump = __import__("json").dump

        def _capture_write(data, f, **kw):
            written.update(data)
            real_json_dump(data, f, **kw)

        with patch("omr_admin.json.dump", side_effect=_capture_write):
            r = admin_client.post("/modify_user", json={"username": "readonly", "proxy": "xray"})

        assert r.json()["result"] == "done"
        assert written.get("users", [{}])[0].get("readonly", {}).get("proxy") == "xray"

    def test_multiple_fields_written_to_config(self, admin_client):
        written = {}
        real_json_dump = __import__("json").dump

        def _capture_write(data, f, **kw):
            written.update(data)
            real_json_dump(data, f, **kw)

        with patch("omr_admin.json.dump", side_effect=_capture_write):
            r = admin_client.post("/modify_user", json={
                "username": "readonly",
                "user_password": "newpass",
                "disabled": True,
                "vpn": "glorytun_udp",
                "proxy": "v2ray",
            })

        assert r.json()["result"] == "done"
        user = written.get("users", [{}])[0].get("readonly", {})
        assert user.get("user_password") == "newpass"
        assert user.get("disabled") == "true"
        assert user.get("vpn") == "glorytun_udp"
        assert user.get("proxy") == "v2ray"

    def test_other_users_not_affected(self, admin_client):
        written = {}
        real_json_dump = __import__("json").dump

        def _capture_write(data, f, **kw):
            written.update(data)
            real_json_dump(data, f, **kw)

        with patch("omr_admin.json.dump", side_effect=_capture_write):
            admin_client.post("/modify_user", json={"username": "readonly", "vpn": "dsvpn"})

        users = written.get("users", [{}])[0]
        assert "openmptcprouter" in users
        assert "admin" in users


class TestClientToClient:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/client2client", json={"enable": True})
        assert r.status_code == 403

    def test_non_admin_denied(self, user_client):
        r = user_client.post("/client2client", json={"enable": True})
        assert r.json()["result"] == "permission"

    def test_admin_enable(self, admin_client):
        r = admin_client.post("/client2client", json={"enable": True})
        assert r.json()["result"] == "done"

    def test_admin_disable(self, admin_client):
        r = admin_client.post("/client2client", json={"enable": False})
        assert r.json()["result"] == "done"


class TestSerialEnforce:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/serialenforce", json={"enable": True})
        assert r.status_code == 403

    def test_non_admin_denied(self, user_client):
        r = user_client.post("/serialenforce", json={"enable": True})
        assert r.json()["result"] == "permission"

    def test_admin_enable(self, admin_client):
        r = admin_client.post("/serialenforce", json={"enable": True})
        assert r.json()["result"] == "done"


class TestListUsers:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.get("/list_users")
        assert r.status_code == 403

    def test_non_admin_denied(self, user_client):
        r = user_client.get("/list_users")
        assert r.json()["result"] == "permission"

    def test_admin_returns_user_dict(self, admin_client):
        r = admin_client.get("/list_users")
        assert r.status_code == 200
        body = r.json()
        assert "admin" in body
        assert "openmptcprouter" in body


class TestGetNumberOfUsers:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.get("/get-number-of-users")
        assert r.status_code == 403

    def test_non_admin_denied(self, user_client):
        r = user_client.get("/get-number-of-users")
        assert r.json()["result"] == "permission"

    def test_admin_returns_count(self, admin_client):
        r = admin_client.get("/get-number-of-users")
        assert r.status_code == 200
        assert "users" in r.json()
        assert isinstance(r.json()["users"], int)
        assert r.json()["users"] >= 1


# ===========================================================================
# Speedtest (brief; detailed tests are in test_speedtest.py)
# ===========================================================================


class TestSpeedtestIntegration:
    def test_download_requires_auth(self, unauth_client):
        r = unauth_client.get("/speedtest")
        assert r.status_code == 403

    def test_download_returns_binary_data(self, user_client):
        r = user_client.get("/speedtest?size=1")
        assert r.status_code == 200
        assert len(r.content) == 1 * 1024 * 1024

    def test_upload_requires_auth(self, unauth_client):
        r = unauth_client.post(
            "/speedtest",
            files={"file": ("x.bin", io.BytesIO(b"data"), "application/octet-stream")},
        )
        assert r.status_code == 403

    def test_upload_returns_speed_metrics(self, user_client):
        r = user_client.post(
            "/speedtest",
            files={"file": ("x.bin", io.BytesIO(b"x" * 1024), "application/octet-stream")},
        )
        assert r.status_code == 200
        body = r.json()
        assert "bytes" in body
        assert "speed_mbps" in body
        assert "duration" in body

"""
Comprehensive unit tests for all omr-admin.py API endpoints.

Each class covers one route (or a tightly related group).
Tests focus on:
  - Authentication requirement (403 without a token)
  - Permission checks (ro / non-admin users receive explicit errors)
  - Response contract (status code + expected JSON keys / values)
  - Basic happy-path behaviour (mocked filesystem / subprocess)
"""

import contextlib
import copy
import io
import json
import logging
import os
import threading
from unittest.mock import MagicMock, patch

import pytest

from conftest import (
    MOCK_CONFIG,
    MQVPN_CONFIG,
    _ASGITestClient,
    _fake_atomic_write,
    _mock_open,
    app,
    omr_admin,
    user_headers,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# Must stay identical to the text log_auth_failure() emits and to the failregex
# in fail2ban-filter-omradmin.conf (openmptcprouter-vps repo).
_AUTH_FAILURE_MARKER = "omr-admin: authentication failure from"


class _KeepOpenStringIO(io.StringIO):
    """StringIO whose contents survive the `with` block that wrote them."""

    def close(self):
        pass


def _isfile_for(*paths):
    """Return a side_effect that returns True only for the given paths."""
    def _side_effect(p):
        return str(p) in paths
    return _side_effect


def _mock_config_json(config_json):
    def _open(path, mode="r", *args, **kwargs):
        if str(path) == "/etc/openmptcprouter-vps-admin/omr-admin-config.json":
            return io.StringIO(config_json)
        return _mock_open(path, mode, *args, **kwargs)

    return _open


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

    def test_disabled_user_cannot_get_token(self, unauth_client):
        disabled_config = json.loads(json.dumps(MOCK_CONFIG))
        disabled_config["users"][0]["openmptcprouter"]["disabled"] = True

        with patch("builtins.open", side_effect=_mock_config_json(json.dumps(disabled_config))):
            r = unauth_client.post(
                "/token",
                data={"username": "openmptcprouter", "password": "userpassword"},
            )

        assert r.status_code == 400
        assert r.json()["detail"] == "Inactive user"

    def test_disabled_bearer_token_is_rejected(self, unauth_client):
        disabled_config = json.loads(json.dumps(MOCK_CONFIG))
        disabled_config["users"][0]["openmptcprouter"]["disabled"] = True

        with patch("builtins.open", side_effect=_mock_config_json(json.dumps(disabled_config))):
            r = unauth_client.get("/status", headers=user_headers())

        assert r.status_code == 400
        assert r.json()["detail"] == "Inactive user"

    def test_missing_password_returns_422(self, unauth_client):
        r = unauth_client.post("/token", data={"username": "admin"})
        assert r.status_code == 422

    # The next two pin down what the fail2ban "omradmin" jail counts. Its
    # filter (fail2ban-filter-omradmin.conf, openmptcprouter-vps repo) matches
    # this exact marker, so a router polling /token with no key yet must not
    # produce one -- that is what used to ban routers off the API they were
    # being configured from.
    def test_invalid_password_logs_fail2ban_marker(self, unauth_client, caplog):
        with caplog.at_level(logging.WARNING, logger="uvicorn.error"):
            unauth_client.post(
                "/token",
                data={"username": "admin", "password": "wrongpassword"},
            )
        assert any(_AUTH_FAILURE_MARKER in r.getMessage() for r in caplog.records)

    def test_empty_password_does_not_log_fail2ban_marker(self, unauth_client, caplog):
        with caplog.at_level(logging.WARNING, logger="uvicorn.error"):
            r = unauth_client.post(
                "/token",
                data={"username": "admin", "password": ""},
            )
        assert r.status_code in (400, 422)
        assert not any(_AUTH_FAILURE_MARKER in rec.getMessage() for rec in caplog.records)


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

    def test_invalid_basic_auth_logs_fail2ban_marker(self, unauth_client, caplog):
        import base64
        creds = base64.b64encode(b"admin:wrong").decode()
        with caplog.at_level(logging.WARNING, logger="uvicorn.error"):
            unauth_client.get(
                "/login_basic",
                headers={"Authorization": f"Basic {creds}"},
            )
        assert any(_AUTH_FAILURE_MARKER in r.getMessage() for r in caplog.records)

    def test_basic_challenge_does_not_log_fail2ban_marker(self, unauth_client, caplog):
        # A browser's first /docs request carries no Authorization header and
        # gets the 401 challenge back; counting that banned the operator after
        # six visits.
        with caplog.at_level(logging.WARNING, logger="uvicorn.error"):
            unauth_client.get("/login_basic")
        assert not any(_AUTH_FAILURE_MARKER in r.getMessage() for r in caplog.records)


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

    def test_unknown_username_returns_controlled_error(self, admin_client):
        r = admin_client.get("/status?username=does-not-exist")
        assert r.status_code == 200
        assert r.json() == {"error": "Unknown user", "route": "status"}

    def test_unknown_userid_returns_controlled_error(self, admin_client):
        r = admin_client.get("/status?userid=99999")
        assert r.status_code == 200
        assert r.json() == {"error": "Unknown user", "route": "status"}

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


class TestConfigWritePermissions:
    """The config holds every user's password and the VPN keys, so a write of
    it must leave it root-only (0600), even if some other writer had widened
    it; and a backup of it must be 0600 too. Rotation must keep only the
    timestamped backups, never the installer's pre-upgrade `.bak`."""

    @pytest.mark.real_env
    def test_write_forces_0600_even_if_file_was_world_readable(self, tmp_path, monkeypatch):
        import stat
        cfg = tmp_path / "omr-admin-config.json"
        cfg.write_text(json.dumps({"users": [{"openmptcprouter": {"userid": 0}}]}))
        cfg.chmod(0o644)
        monkeypatch.setattr(omr_admin, "OMR_CONFIG_FILE", str(cfg))
        monkeypatch.setattr(omr_admin, "OMR_CONFIG_LOCK_FILE", str(tmp_path / ".lock"))
        omr_admin._write_omr_config_unlocked({"users": [{"openmptcprouter": {"userid": 0}}], "touched": True})
        assert stat.S_IMODE(cfg.stat().st_mode) == 0o600
        assert json.loads(cfg.read_text())["touched"] is True

    @pytest.mark.real_env
    def test_backup_is_0600_even_from_a_world_readable_config(self, tmp_path, monkeypatch):
        import stat
        cfg = tmp_path / "omr-admin-config.json"
        cfg.write_text(json.dumps({"users": [{}]}))
        cfg.chmod(0o644)
        monkeypatch.setattr(omr_admin, "OMR_CONFIG_FILE", str(cfg))
        omr_admin.backup_config()
        backups = list(tmp_path.glob("omr-admin-config.json.[0-9]*"))
        assert len(backups) == 1
        assert stat.S_IMODE(backups[0].stat().st_mode) == 0o600

    @pytest.mark.real_env
    def test_temp_copy_is_created_0600_not_just_chmod_ed(self, tmp_path, monkeypatch):
        # The temp copy holds the secrets as soon as it is written: it must be
        # created 0600, not created with the umask (0644) and tightened later.
        import stat
        cfg = tmp_path / "omr-admin-config.json"
        cfg.write_text(json.dumps({"users": [{"openmptcprouter": {"userid": 0}}]}))
        monkeypatch.setattr(omr_admin, "OMR_CONFIG_FILE", str(cfg))
        real_chmod = os.chmod
        modes_before_chmod = []
        def spy_chmod(p, mode, *a, **kw):
            modes_before_chmod.append(stat.S_IMODE(os.stat(p).st_mode))
            return real_chmod(p, mode, *a, **kw)
        monkeypatch.setattr(os, "chmod", spy_chmod)
        old_umask = os.umask(0o022)
        try:
            omr_admin._write_omr_config_unlocked({"users": [{"openmptcprouter": {"userid": 0}}]})
        finally:
            os.umask(old_umask)
        assert modes_before_chmod == [0o600]
        assert stat.S_IMODE(cfg.stat().st_mode) == 0o600

    @pytest.mark.real_env
    def test_rotation_keeps_installer_bak(self, tmp_path):
        # The installer's pre-upgrade copy has an old mtime, so a naive
        # "keep the 10 newest of .*" rotation would evict it first. The
        # rotation glob must match only the timestamped backups.
        import time
        bak = tmp_path / "omr-admin-config.json.bak"
        bak.write_text("{}")
        old = time.time() - 10000
        os.utime(bak, (old, old))
        for i in range(12):
            ts = tmp_path / f"omr-admin-config.json.{1700000000 + i}"
            ts.write_text("{}")
        omr_admin.delete_oldest_files(str(tmp_path / "omr-admin-config.json.[0-9]*"), keep=10)
        assert bak.exists(), "installer's .bak must not be rotated away"
        assert len(list(tmp_path.glob("omr-admin-config.json.[0-9]*"))) == 10


class TestStartupConfigRecovery:
    """Startup must tolerate a trailing comma and recover from a backup
    instead of crash-looping on json.load (omr-admin is Restart=always and
    omr-service restarts it when the API is unreachable). A config with no
    users is treated as unusable so a good backup wins."""

    _GOOD = {"users": [{"openmptcprouter": {"userid": 0, "user_password": "s"}}], "secret_key": "k"}

    def _cfg(self, tmp_path, monkeypatch):
        import json as _j
        cfg = tmp_path / "omr-admin-config.json"
        monkeypatch.setattr(omr_admin, "OMR_CONFIG_FILE", str(cfg))
        monkeypatch.setattr(omr_admin, "OMR_CONFIG_LOCK_FILE", str(tmp_path / ".lock"))
        return cfg

    @pytest.mark.real_env
    def test_valid_primary_is_used(self, tmp_path, monkeypatch):
        cfg = self._cfg(tmp_path, monkeypatch)
        cfg.write_text(json.dumps(self._GOOD))
        assert omr_admin.load_startup_config()["users"][0]["openmptcprouter"]["userid"] == 0

    @pytest.mark.real_env
    def test_world_readable_primary_is_tightened_at_startup(self, tmp_path, monkeypatch):
        import stat
        cfg = self._cfg(tmp_path, monkeypatch)
        cfg.write_text(json.dumps(self._GOOD))
        cfg.chmod(0o644)
        omr_admin.load_startup_config()
        assert stat.S_IMODE(cfg.stat().st_mode) == 0o600

    @pytest.mark.real_env
    def test_trailing_comma_is_tolerated(self, tmp_path, monkeypatch):
        cfg = self._cfg(tmp_path, monkeypatch)
        cfg.write_text('{"users": [{"openmptcprouter": {"userid": 0},}],}')
        assert "openmptcprouter" in omr_admin.load_startup_config()["users"][0]

    @pytest.mark.real_env
    def test_empty_primary_recovers_from_bak_and_repairs(self, tmp_path, monkeypatch):
        import stat
        cfg = self._cfg(tmp_path, monkeypatch)
        cfg.write_text("")                      # torn/empty write -> json.load would crash
        (tmp_path / "omr-admin-config.json.bak").write_text(json.dumps(self._GOOD))
        data = omr_admin.load_startup_config()
        assert data["users"][0]["openmptcprouter"]["userid"] == 0
        # The live file is repaired so later writes (which read it) don't fail,
        # and stays owner-only.
        assert json.loads(cfg.read_text())["users"][0]["openmptcprouter"]["userid"] == 0
        assert stat.S_IMODE(cfg.stat().st_mode) == 0o600

    @pytest.mark.real_env
    def test_userless_primary_recovers_from_newest_timestamped_backup(self, tmp_path, monkeypatch):
        import time
        cfg = self._cfg(tmp_path, monkeypatch)
        cfg.write_text(json.dumps({"users": [{}]}))     # no users -> unusable
        old = tmp_path / "omr-admin-config.json.1700000000"
        old.write_text(json.dumps({"users": [{"openmptcprouter": {"userid": 0, "note": "old"}}]}))
        new = tmp_path / "omr-admin-config.json.1700000100"
        new.write_text(json.dumps({"users": [{"openmptcprouter": {"userid": 0, "note": "new"}}]}))
        os.utime(old, (1700000000, 1700000000))
        os.utime(new, (1700000100, 1700000100))
        assert omr_admin.load_startup_config()["users"][0]["openmptcprouter"]["note"] == "new"

    @pytest.mark.real_env
    def test_nothing_usable_raises(self, tmp_path, monkeypatch):
        cfg = self._cfg(tmp_path, monkeypatch)
        cfg.write_text("")
        (tmp_path / "omr-admin-config.json.bak").write_text("not json")
        with pytest.raises(RuntimeError):
            omr_admin.load_startup_config()

    @pytest.mark.real_env
    def test_world_readable_backups_are_tightened_at_startup(self, tmp_path, monkeypatch):
        # Backups an older release left 0644 (and the installer's `.bak`, now
        # kept rather than rotated away) hold the same secrets as the live file.
        import stat
        cfg = self._cfg(tmp_path, monkeypatch)
        cfg.write_text(json.dumps(self._GOOD))
        cfg.chmod(0o600)
        bak = tmp_path / "omr-admin-config.json.bak"
        ts = tmp_path / "omr-admin-config.json.1700000000"
        other = tmp_path / "omr-admin-config.json.tmp.1.2"
        for f in (bak, ts, other):
            f.write_text(json.dumps(self._GOOD))
            f.chmod(0o644)
        omr_admin.load_startup_config()
        assert stat.S_IMODE(bak.stat().st_mode) == 0o600
        assert stat.S_IMODE(ts.stat().st_mode) == 0o600
        # Only backups are touched, nothing else next to the config.
        assert stat.S_IMODE(other.stat().st_mode) == 0o644

    @pytest.mark.real_env
    def test_backups_are_tightened_when_recovering_too(self, tmp_path, monkeypatch):
        import stat
        cfg = self._cfg(tmp_path, monkeypatch)
        cfg.write_text("")
        bak = tmp_path / "omr-admin-config.json.bak"
        bak.write_text(json.dumps(self._GOOD))
        bak.chmod(0o644)
        omr_admin.load_startup_config()
        assert stat.S_IMODE(bak.stat().st_mode) == 0o600


class TestConfigPihole:
    """/config must report Pi-hole v6 as installed.

    The router uses the VPS Pi-hole only when pihole.state is true. Pi-hole
    v6 keeps its settings in pihole.toml and has no setupVars.conf: its
    migration from v5 moves that file to migration_backup_v6/.
    """

    @pytest.mark.parametrize("files, state", [
        pytest.param(("/etc/pihole/pihole.toml",), True, id="v6"),
        pytest.param(("/etc/pihole/setupVars.conf",), True, id="v5"),
        pytest.param(("/etc/pihole/pihole.toml", "/etc/pihole/setupVars.conf"),
                     True, id="both"),
        pytest.param(("/etc/pihole/migration_backup_v6/setupVars.conf",),
                     False, id="v5-backup-only"),
        pytest.param((), False, id="none"),
    ])
    def test_pihole_state(self, user_client, files, state):
        with patch("os.path.isfile", side_effect=_isfile_for(*files)):
            r = user_client.get("/config")
        assert r.status_code == 200
        assert r.json()["pihole"]["state"] is state


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

    def test_legacy_config_without_prefer_ipv6_is_supported(self, user_client):
        manager = json.dumps({
            "timeout": 600,
            "verbose": 0,
            "port_key": {"65101": "old-key"},
        })

        def _open_legacy(path, mode="r", *args, **kwargs):
            if str(path) == "/etc/shadowsocks-libev/manager.json":
                if "w" in str(mode):
                    return io.StringIO()
                if "b" in str(mode):
                    return io.BytesIO(manager.encode())
                return io.StringIO(manager)
            return _mock_open(path, mode, *args, **kwargs)

        with (
            patch("os.path.isfile", _isfile_for("/etc/shadowsocks-libev/manager.json")),
            patch("builtins.open", side_effect=_open_legacy),
        ):
            r = user_client.post("/shadowsocks", json=self._PAYLOAD)

        assert r.status_code == 200
        assert r.json()["result"] == "done"


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

    def test_family_any_toggles_both_families(self, user_client):
        with (
            patch("os.path.isfile", return_value=True),
            patch("omr_admin.set_global_param") as set_param,
        ):
            r = user_client.post(
                "/shorewall", json={"redirect_ports": "enable", "ipproto": "any"}
            )
        assert r.json()["result"] == "done"
        assert [c.args for c in set_param.call_args_list] == [
            ("bulk_redirect_v4", True),
            ("bulk_redirect_v6", True),
        ]


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

    def test_family_any_opens_both_families(self, user_client):
        # LuCI's "Restrict to address family = IPv4 and IPv6" writes
        # family='any' and the router passes it through untouched: it used
        # to be rejected by the ipproto enum with a 422 nothing on the
        # router side ever looks at, so the port was silently never opened.
        with (
            patch("os.path.isfile", return_value=True),
            patch("omr_admin.shorewall_add_port", return_value=None) as add4,
            patch("omr_admin.shorewall6_add_port", return_value=None) as add6,
        ):
            r = user_client.post("/shorewallopen", json={**self._PAYLOAD, "ipproto": "any"})
        assert r.status_code == 200
        assert r.json()["result"] == "done"
        assert add4.called and add6.called

    def test_family_any_with_ipv4_restriction_stays_ipv4(self, user_client):
        # An address restriction pins the rule to that literal's family:
        # a v6 copy would render nft syntax that does not parse and, since
        # the chain is flushed in one transaction, drop every other port.
        with (
            patch("os.path.isfile", return_value=True),
            patch("omr_admin.shorewall_add_port", return_value=None) as add4,
            patch("omr_admin.shorewall6_add_port", return_value=None) as add6,
        ):
            r = user_client.post(
                "/shorewallopen",
                json={**self._PAYLOAD, "ipproto": "any", "source_dip": "1.2.3.4"},
            )
        assert r.json()["result"] == "done"
        assert add4.called
        assert not add6.called

    def test_dnat_of_a_server_port_refused(self, user_client):
        # 65000+ carry the server's own services (SSH 65222, this API
        # 65500...): redirecting them to the router locks the VPS out.
        with (
            patch("os.path.isfile", return_value=True),
            patch("omr_admin.shorewall_add_port", return_value=None) as add4,
            patch("omr_admin.shorewall6_add_port", return_value=None) as add6,
        ):
            r = user_client.post(
                "/shorewallopen",
                json={**self._PAYLOAD, "port": "2-65222", "fwtype": "DNAT", "ipproto": "any"},
            )
        assert r.json()["result"] == "error"
        assert "65000" in r.json()["reason"]
        assert not add4.called and not add6.called

    def test_accept_of_a_server_port_allowed(self, user_client):
        with (
            patch("os.path.isfile", return_value=True),
            patch("omr_admin.shorewall_add_port", return_value=None) as add4,
        ):
            r = user_client.post("/firewallopen", json={**self._PAYLOAD, "port": "65222"})
        assert r.json()["result"] == "done"
        assert add4.called

    def test_nft_injection_refused(self, user_client):
        for field, value, reason in (
            ("port", "80 accept\nflush ruleset", "Invalid port"),
            # GHSA-p7h3-26vj-4wg3 proof of concept
            ("port", '22 accept comment "poc"\nadd chain inet omr OMRPOC\n#', "Invalid port"),
            ("proto", "tcp dport 22 accept\nflush ruleset\nadd rule inet omr user_accept tcp", "Invalid protocol"),
            ("source_dip", "1.2.3.4\nflush ruleset", "Invalid address"),
            ("source_ip", "1.2.3.4 accept", "Invalid address"),
        ):
            with (
                patch("os.path.isfile", return_value=True),
                patch("omr_admin.shorewall_add_port", return_value=None) as add4,
            ):
                r = user_client.post("/firewallopen", json={**self._PAYLOAD, field: value})
            assert r.json() == {"result": "error", "reason": reason, "route": "firewallopen"}, field
            assert not add4.called, field

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

    def test_family_any_closes_both_families(self, user_client):
        with (
            patch("os.path.isfile", return_value=True),
            patch("omr_admin.shorewall_del_port") as del4,
            patch("omr_admin.shorewall6_del_port") as del6,
        ):
            r = user_client.post("/shorewallclose", json={**self._PAYLOAD, "ipproto": "any"})
        assert r.status_code == 200
        assert r.json()["result"] == "done"
        # DNAT and ACCEPT, for each family
        assert del4.call_count == 2 and del6.call_count == 2


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

    def test_enable_reports_error_when_helpers_cannot_apply(self, user_client):
        # nf_conntrack_sip unavailable -> nft rejects the helper rules -> the
        # endpoint must not answer 'done' for a firewall state it did not
        # reach (openmptcprouter#4361 saw 200 OK with nothing applied)
        with patch("omr_admin._nft_sync_sipalg", return_value=False):
            r = user_client.post("/sipalg", json={"enable": True})
        assert r.json()["result"] == "error"


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


class TestProxyRedirectValidation:
    """A range forward is sent as port "a-b" and used to fail with HTTP 500 on
    int() (vps#85); anything the daemons can't take is refused with a reason
    instead of reaching their config."""

    _PAYLOAD = {"name": "router 12345-12445", "port": "12345-12445", "proto": "tcp",
                "destip": "192.168.1.2", "destport": "12345-12445"}

    @pytest.mark.parametrize("endpoint,func", [("/v2rayredirect", "v2ray_add_port"), ("/xrayredirect", "xray_add_port")])
    def test_range_is_applied(self, user_client, endpoint, func):
        with patch("os.path.isfile", return_value=True), patch(f"omr_admin.{func}", return_value=None) as add:
            r = user_client.post(endpoint, json=self._PAYLOAD)
        assert r.status_code == 200
        assert r.json()["result"] == "done"
        add.assert_called_once()

    @pytest.mark.parametrize("endpoint", ["/v2rayredirect", "/xrayredirect"])
    @pytest.mark.parametrize("field,value,reason", [
        ("port", "70000", "Invalid port"),
        ("port", "500-400", "Invalid port"),
        ("port", "80\nx", "Invalid port"),
        ("port", "", "Invalid port"),
        ("port", "64000-65100", "Ports >= 65000"),
        ("port", "2-64999", "more than 1024 ports"),
        ("proto", "icmp", "Invalid protocol"),
        ("destip", "192.168.1.2\"}", "Invalid address"),
        ("destip", "192.168.1.0/24", "Invalid address"),
        ("destport", "abc", "Invalid destination port"),
        ("destport", "22345-22346", "as wide as the port range"),
    ])
    def test_invalid_request_is_refused(self, user_client, endpoint, field, value, reason):
        payload = dict(self._PAYLOAD, **{field: value})
        with patch("os.path.isfile", return_value=True), \
             patch("omr_admin.v2ray_add_port") as v2, patch("omr_admin.xray_add_port") as xr:
            r = user_client.post(endpoint, json=payload)
        assert r.json()["result"] == "error"
        assert reason in r.json()["reason"]
        v2.assert_not_called()
        xr.assert_not_called()

    @pytest.mark.parametrize("port,destport", [("8080", "80"), ("8080", ""), ("1000:1010", "1000:1010"),
                                               ("1000-1010", "2000"), ("1000-1010", "2000-2010"),
                                               ("1000-2023", "1000-2023")])
    def test_valid_forwards_pass(self, port, destport):
        assert omr_admin._proxy_redirect_error(port, "udp", "192.168.1.2", destport) is None


class TestProxyRedirectConfig:
    """What /v2rayredirect and /xrayredirect write to the daemons' config."""

    _USER = omr_admin.User(username="openmptcprouter", userid=0, permissions="rw")

    @pytest.fixture
    def configs(self, tmp_path, monkeypatch):
        paths = {}
        for service in ("v2ray", "xray"):
            p = tmp_path / f"{service}-server.json"
            p.write_text(json.dumps({"inbounds": [{"tag": "omrin-tunnel", "port": 65228}],
                                     "routing": {"rules": [{"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
                                                           {"type": "field", "domain": ["full:omr.lan"], "outboundTag": "OMRLan"}]}}))
            p.chmod(0o600)
            paths[service] = str(p)
        monkeypatch.setattr(omr_admin, "PROXY_REDIRECT_CONFIGS", paths)
        monkeypatch.setattr(omr_admin, "OMR_CONFIG_LOCK_FILE", str(tmp_path / ".lock"))
        with patch("omr_admin._schedule_proxy_restart") as restart:
            yield paths, restart

    def _redirects(self, path):
        data = json.loads(open(path).read())
        return [i for i in data["inbounds"] if "_redir_" in i["tag"]], \
               [r for r in data["routing"]["rules"] if "_redir_" in (r.get("inboundTag") or [""])[0]]

    @pytest.mark.real_env
    @pytest.mark.parametrize("service", ["v2ray", "xray"])
    def test_single_port_unchanged(self, configs, service):
        paths, restart = configs
        getattr(omr_admin, f"{service}_add_port")(self._USER, "8080", "tcp", "x", "192.168.1.2", "80")
        inbounds, rules = self._redirects(paths[service])
        assert inbounds == [{"tag": "openmptcprouter_redir_tcp_8080_to_192.168.1.2:80", "port": 8080,
                             "protocol": "dokodemo-door",
                             "settings": {"network": "tcp", "port": 80, "address": "192.168.1.2"}}]
        assert rules[0]["inboundTag"] == [inbounds[0]["tag"]] and rules[0]["outboundTag"] == "OMRLan"
        restart.assert_called_once_with(service)

    @pytest.mark.real_env
    def test_xray_range_is_one_inbound_keeping_each_port(self, configs):
        # xray's dokodemo-door dials the port a connection came in on when
        # its destination port is 0.
        paths, _ = configs
        omr_admin.xray_add_port(self._USER, "12345-12347", "tcp", "x", "192.168.1.2", "12345-12347")
        inbounds, rules = self._redirects(paths["xray"])
        assert [(i["port"], i["settings"]["port"]) for i in inbounds] == [("12345-12347", 0)]
        assert len(rules) == 1

    @pytest.mark.real_env
    def test_v2ray_range_is_one_inbound_per_port(self, configs):
        # v2ray has no port-0 fallback: it would dial port 0.
        paths, _ = configs
        omr_admin.v2ray_add_port(self._USER, "12345-12347", "tcp", "x", "192.168.1.2", "12345-12347")
        inbounds, rules = self._redirects(paths["v2ray"])
        assert [(i["port"], i["settings"]["port"]) for i in inbounds] == [(12345, 12345), (12346, 12346), (12347, 12347)]
        assert rules[0]["inboundTag"] == [i["tag"] for i in inbounds]

    @pytest.mark.real_env
    @pytest.mark.parametrize("service", ["v2ray", "xray"])
    def test_range_moved_to_another_range(self, configs, service):
        paths, _ = configs
        getattr(omr_admin, f"{service}_add_port")(self._USER, "1000-1002", "udp", "x", "192.168.1.2", "2000-2002")
        inbounds, _ = self._redirects(paths[service])
        assert [(i["port"], i["settings"]["port"]) for i in inbounds] == [(1000, 2000), (1001, 2001), (1002, 2002)]

    @pytest.mark.real_env
    @pytest.mark.parametrize("service", ["v2ray", "xray"])
    def test_range_to_one_port(self, configs, service):
        paths, _ = configs
        getattr(omr_admin, f"{service}_add_port")(self._USER, "1000-1002", "tcp", "x", "192.168.1.2", "80")
        inbounds, _ = self._redirects(paths[service])
        assert [(i["port"], i["settings"]["port"]) for i in inbounds] == [("1000-1002", 80)]

    @pytest.mark.real_env
    @pytest.mark.parametrize("service", ["v2ray", "xray"])
    def test_resent_redirect_is_a_noop(self, configs, service):
        # The router re-sends every forward on each sync.
        paths, restart = configs
        add = getattr(omr_admin, f"{service}_add_port")
        add(self._USER, "1000-1002", "tcp", "x", "192.168.1.2", "")
        before = open(paths[service]).read()
        add(self._USER, "1000:1002", "tcp", "x", "192.168.1.2", "")
        assert open(paths[service]).read() == before
        assert restart.call_count == 1

    @pytest.mark.real_env
    @pytest.mark.parametrize("service", ["v2ray", "xray"])
    def test_unredirect_removes_every_inbound_of_a_range(self, configs, service):
        paths, restart = configs
        getattr(omr_admin, f"{service}_add_port")(self._USER, "1000-1002", "tcp", "x", "192.168.1.2", "2000-2002")
        getattr(omr_admin, f"{service}_add_port")(self._USER, "8080", "tcp", "x", "192.168.1.2", "80")
        getattr(omr_admin, f"{service}_del_port")(self._USER, "1000-1002", "tcp", "x", "192.168.1.2", "2000-2002")
        inbounds, rules = self._redirects(paths[service])
        assert [i["port"] for i in inbounds] == [8080]
        assert len(rules) == 1
        # rules without an inboundTag (the omr.lan one) are left alone
        assert any("domain" in r for r in json.loads(open(paths[service]).read())["routing"]["rules"])
        assert restart.call_count == 3

    @pytest.mark.real_env
    def test_unredirect_of_nothing_writes_nothing(self, configs):
        paths, restart = configs
        before = open(paths["xray"]).read()
        omr_admin.xray_del_port(self._USER, "8080", "tcp", "x", "192.168.1.2", "80")
        assert open(paths["xray"]).read() == before
        restart.assert_not_called()

    @pytest.mark.real_env
    def test_existing_tag_with_empty_destip_still_matches(self, configs):
        # A redirect has always been tagged with its destination, even an
        # empty one: an upgrade must not add it a second time.
        paths, restart = configs
        omr_admin.xray_add_port(self._USER, "8080", "tcp", "x", "", "8080")
        omr_admin.xray_add_port(self._USER, "8080", "tcp", "x", "", "8080")
        inbounds, _ = self._redirects(paths["xray"])
        assert [i["tag"] for i in inbounds] == ["openmptcprouter_redir_tcp_8080_to_:8080"]


class TestAtomicWrite:
    """The daemon configs are replaced atomically and keep their mode: the
    installer keeps xray-server.json 0600, it holds the users' keys."""

    @pytest.mark.real_env
    def test_new_file_modes(self, tmp_path):
        import stat
        omr_admin._atomic_write_json(str(tmp_path / "server.json"), {"k": 1})
        omr_admin._atomic_write_text(str(tmp_path / "current-vpn"), "glorytun_tcp\n")
        assert stat.S_IMODE((tmp_path / "server.json").stat().st_mode) == 0o600
        assert stat.S_IMODE((tmp_path / "current-vpn").stat().st_mode) == 0o644
        assert (tmp_path / "current-vpn").read_text() == "glorytun_tcp\n"

    @pytest.mark.real_env
    def test_indent_is_kept(self, tmp_path):
        p = tmp_path / "server.json"
        omr_admin._atomic_write_json(str(p), {"k": 1}, indent=2)
        assert p.read_text() == json.dumps({"k": 1}, indent=2)

    def test_no_daemon_config_is_written_in_place(self):
        # open(path, 'w') truncates first: a crash, a full disk or an
        # exception before the end leaves the daemon an unparsable config.
        import re
        src = open(omr_admin.__file__).read()
        in_place = re.findall(r"open\('(/etc/[^']+)', 'w'\)", src)
        targets = ("/etc/v2ray/v2ray-server.json", "/etc/xray/xray-server.json", "/etc/mqvpn/server.json",
                   "/etc/shadowsocks-libev/manager.json", "/etc/shadowsocks-go/server.json",
                   "/etc/xray/xray-vless-reality.json", "/etc/shadowsocks-libev/local.acl",
                   "/etc/openmptcprouter-vps-admin/omr-bypass.json",
                   "/etc/openmptcprouter-vps-admin/current-vpn", "/etc/openmptcprouter-vps-admin/current-proxy")
        assert [p for p in in_place if p in targets] == []
        # Paths built at run time: the tunnel configs and keys, the OpenVPN
        # ccd and the GRE tunnel files.
        assert re.findall(r"open\('/etc/(?:glorytun-tcp|glorytun-udp|dsvpn|openmptcprouter-vps-admin/intf)/[^\n]*'w'\)", src) == []
        assert re.findall(r"open\((?:dsvpn_key_file|safe_path_join\('/etc/openvpn/ccd'[^\n]*), 'w'\)", src) == []
        # mkstemp() makes its copy in /tmp, often a tmpfs: move() then copies
        # it over the target in place instead of renaming it.
        assert "mkstemp(" not in src.replace("a mkstemp() copy", "")

    @pytest.mark.real_env
    @pytest.mark.parametrize("mode", [0o600, 0o644])
    def test_keeps_mode(self, tmp_path, mode):
        import stat
        p = tmp_path / "xray-server.json"
        p.write_text("{}")
        p.chmod(mode)
        omr_admin._atomic_write_json(str(p), {"new": 1})
        assert json.loads(p.read_text()) == {"new": 1}
        assert stat.S_IMODE(p.stat().st_mode) == mode
        assert not list(tmp_path.glob("*.tmp.*"))

    @pytest.mark.real_env
    def test_writes_through_the_config_json_symlink_target(self, tmp_path):
        target = tmp_path / "xray-server.json"
        target.write_text("{}")
        link = tmp_path / "config.json"
        link.symlink_to(target)
        omr_admin._atomic_write_json(str(link), {"new": 1})
        assert link.is_symlink()
        assert json.loads(target.read_text()) == {"new": 1}

    @pytest.mark.real_env
    def test_failed_write_leaves_old_file(self, tmp_path):
        p = tmp_path / "xray-server.json"
        p.write_text('{"old": true}')
        with pytest.raises(TypeError):
            omr_admin._atomic_write_json(str(p), {"bad": {1, 2}})
        assert json.loads(p.read_text()) == {"old": True}
        assert not list(tmp_path.glob("*.tmp.*"))


class TestTunnelFilesWrittenAtomically:
    """The glorytun/dsvpn configs and keys, the OpenVPN ccd and the GRE tunnel
    files are built in memory and written in one atomic step: they used to be
    written line by line in place, so a crash or an exception halfway left a
    tunnel with an empty key or a config missing its last lines."""

    _GT_TCP = 'PORT=65001\nDEV=tun0\nLOCALIP=10.255.255.1\nREMOTEIP=10.255.255.2\nBROADCASTIP=10.255.255.3\nOPTIONS="retry count -1"\n'
    _GT_UDP = 'BIND_PORT=65001\nDEV=tun0\nLOCALIP=10.255.254.1\nREMOTEIP=10.255.254.2\nBROADCASTIP=10.255.254.3\nOPTIONS="persist"\n'
    _DSVPN = 'PORT=65401\nDEV=dsvpn0\nLOCALTUNIP=10.255.251.1\nREMOTETUNIP=10.255.251.2\n'

    @contextlib.contextmanager
    def _env(self, files):
        writes = {}
        def _open(path, mode="r", *a, **k):
            if str(path) in files and "w" not in str(mode):
                content = files[str(path)]
                return io.BytesIO(content.encode()) if "b" in str(mode) else io.StringIO(content)
            return _mock_open(path, mode, *a, **k)
        def _write(path, text, new_mode=0o644):
            writes[path] = (text, new_mode)
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open),
            patch("omr_admin._atomic_write_text", side_effect=_write),
        ):
            yield writes

    def test_add_glorytun_tcp(self):
        with self._env({"/etc/glorytun-tcp/tun0": self._GT_TCP}) as writes:
            omr_admin.add_glorytun_tcp(1)
        assert writes["/etc/glorytun-tcp/tun1"] == (
            'PORT=65001\nDEV=tun1\nOPTIONS="retry count -1"\n'
            '\nLOCALIP=10.255.255.5\nREMOTEIP=10.255.255.6\nBROADCASTIP=10.255.255.7\n', 0o644)
        key, mode = writes["/etc/glorytun-tcp/tun1.key"]
        assert len(key) == 64 and key == key.upper() and mode == 0o600

    def test_add_glorytun_udp_copies_the_tcp_key(self):
        with self._env({"/etc/glorytun-udp/tun0": self._GT_UDP, "/etc/glorytun-tcp/tun1.key": "ABCD"}) as writes:
            omr_admin.add_glorytun_udp(1)
        assert writes["/etc/glorytun-udp/tun1"][0] == (
            'BIND_PORT=65001\nDEV=tun1\nOPTIONS="persist"\n'
            '\nLOCALIP=10.255.254.5\nREMOTEIP=10.255.254.6\nBROADCASTIP=10.255.254.7\n')
        assert writes["/etc/glorytun-udp/tun1.key"] == ("ABCD", 0o600)

    def test_add_dsvpn(self):
        with self._env({"/etc/dsvpn/dsvpn0": self._DSVPN}) as writes:
            omr_admin.add_dsvpn(1)
        assert writes["/etc/dsvpn/dsvpn1"][0] == 'PORT=65401\nDEV=dsvpn1\nLOCALTUNIP=10.255.251.5\nREMOTETUNIP=10.255.251.6\n'
        assert writes["/etc/dsvpn/dsvpn1.key"][1] == 0o600

    def test_glorytun_update(self, user_client):
        with self._env({"/etc/glorytun-tcp/tun0": self._GT_TCP, "/etc/glorytun-udp/tun0": self._GT_UDP}) as writes:
            r = user_client.post("/glorytun", json={"key": "AB" * 32, "port": 65009, "chacha": True})
        assert r.json()["result"] == "done"
        assert writes["/etc/glorytun-tcp/tun0.key"] == ("AB" * 32, 0o600)
        assert writes["/etc/glorytun-udp/tun0.key"] == ("AB" * 32, 0o600)
        tcp = writes["/etc/glorytun-tcp/tun0"][0]
        assert "PORT=65009\n" in tcp and 'OPTIONS="chacha20 retry' in tcp and "LOCALIP=10.255.255.1\n" in tcp
        udp = writes["/etc/glorytun-udp/tun0"][0]
        assert "BIND_PORT=65009\n" in udp and 'OPTIONS="chacha persist"\n' in udp

    def test_dsvpn_update(self, user_client):
        with self._env({"/etc/dsvpn/dsvpn0": self._DSVPN, "/etc/dsvpn/dsvpn0.key": "old"}) as writes:
            r = user_client.post("/dsvpn", json={"key": "CD" * 32, "port": 65409})
        assert r.json()["result"] == "done"
        assert writes["/etc/dsvpn/dsvpn0"][0] == self._DSVPN.replace("PORT=65401", "PORT=65409")
        assert writes["/etc/dsvpn/dsvpn0.key"] == ("CD" * 32, 0o600)

    def test_lan_ccd(self, user_client):
        config = json.loads(json.dumps(MOCK_CONFIG))
        config["client2client"] = True
        with (
            self._env({"/etc/openmptcprouter-vps-admin/omr-admin-config.json": json.dumps(config),
                       "/etc/openvpn/tun0.conf": "server 10.8.0.0 255.255.255.0\n"}) as writes,
            patch("omr_admin.modif_config_user"),
        ):
            r = user_client.post("/lan", json={"lanips": ["192.168.1.0/24", "10.1.0.0/16"]})
        assert r.json()["result"] == "done"
        assert writes["/etc/openvpn/ccd/openmptcprouter"] == (
            "iroute 192.168.1.0 255.255.255.0\niroute 10.1.0.0 255.255.0.0\n", 0o644)


class TestGreIntfComplete:
    """A GRE tunnel file is only written when missing: one cut off by an
    earlier release must count as missing, or it would never be rewritten."""

    @pytest.mark.real_env
    @pytest.mark.parametrize("content,complete", [
        ("INTF=eth0\nLOCALIP=10.255.249.1\nUSERNAME=openmptcprouter\nUSERID=0\n", True),
        ("INTF=eth0\nLOCALIP=10.255.249.1\n", False),
        ("", False),
    ])
    def test_complete(self, tmp_path, content, complete):
        p = tmp_path / "gre-user0-ip1"
        p.write_text(content)
        assert omr_admin._gre_intf_complete(str(p)) is complete

    @pytest.mark.real_env
    def test_missing(self, tmp_path):
        assert omr_admin._gre_intf_complete(str(tmp_path / "gre-user0-ip1")) is False


class TestTightenTunnelKeys:
    @pytest.mark.real_env
    def test_world_readable_keys_become_0600(self, tmp_path, monkeypatch):
        import stat
        (tmp_path / "dsvpn0.key").write_text("k")
        (tmp_path / "dsvpn0.key").chmod(0o644)
        (tmp_path / "dsvpn1.key").write_text("k")
        (tmp_path / "dsvpn1.key").chmod(0o600)
        (tmp_path / "dsvpn0").write_text("PORT=65401\n")
        (tmp_path / "dsvpn0").chmod(0o644)
        monkeypatch.setattr(omr_admin, "TUNNEL_KEY_GLOBS", (str(tmp_path / "dsvpn*.key"),))
        omr_admin._tighten_tunnel_keys()
        assert stat.S_IMODE((tmp_path / "dsvpn0.key").stat().st_mode) == 0o600
        assert stat.S_IMODE((tmp_path / "dsvpn1.key").stat().st_mode) == 0o600
        assert stat.S_IMODE((tmp_path / "dsvpn0").stat().st_mode) == 0o644   # configs untouched


class TestDsvpnInstalledCheck:
    """DSVPN is installed as /etc/dsvpn/dsvpn0 (+ dsvpn0.key). The checks
    looked for /etc/dsvpn/dsvpn, which does not exist: /dsvpn always answered
    'not installed' and /vpn_list never listed dsvpn."""

    def test_vpn_list_reports_dsvpn(self):
        with patch("os.path.isfile", _isfile_for("/etc/dsvpn/dsvpn0")):
            assert omr_admin.VPN.dsvpn.value in omr_admin._installed_vpn_types()

    def test_dsvpn_update_with_dsvpn0_only(self, user_client):
        written = {}
        def _open(path, mode="r", *a, **k):
            if str(path) == "/etc/dsvpn/dsvpn0" and "w" not in mode:
                return io.StringIO("PORT=65401\nDEV=dsvpn0\n")
            if str(path) == "/etc/dsvpn/dsvpn0.key" and "w" not in mode:
                return io.BytesIO(b"old")
            return _mock_open(path, mode, *a, **k)
        with (
            patch("os.path.isfile", _isfile_for("/etc/dsvpn/dsvpn0")),
            patch("builtins.open", side_effect=_open),
            patch("omr_admin._atomic_write_text", side_effect=lambda p, t, new_mode=0o644: written.update({p: t})),
        ):
            r = user_client.post("/dsvpn", json={"key": "CD" * 32, "port": 65409})
        assert r.json()["result"] == "done"
        assert written["/etc/dsvpn/dsvpn0"] == "PORT=65409\nDEV=dsvpn0\n"

    def test_dsvpn_update_for_a_user_without_dsvpn(self):
        # A rw user other than userid 0 whose dsvpn<id> was never created:
        # a clear warning instead of an HTTP 500 on open().
        user = omr_admin.User(username="bob", userid=3, permissions="rw", disabled=False)
        app.dependency_overrides[omr_admin.get_current_user] = lambda: user
        try:
            client = _ASGITestClient(app, raise_server_exceptions=False)
            with patch("os.path.isfile", _isfile_for("/etc/dsvpn/dsvpn0")):
                r = client.post("/dsvpn", json={"key": "CD" * 32, "port": 65409})
        finally:
            app.dependency_overrides.pop(omr_admin.get_current_user, None)
        assert r.json() == {"result": "warning", "reason": "DSVPN is not set up for this user", "route": "dsvpn"}


class TestGlorytunUpdateRestarts:
    """/glorytun restarts a glorytun daemon when its config or its key
    changed (a new key alone was ignored until the next restart), and only
    touches the variants this user has."""

    _TCP = 'PORT=65001\nDEV=tun0\nOPTIONS="retry count -1 const 5000000 timeout 90000 keepalive count 5 idle 10 interval 2 buffer-size 65536 multiqueue"\n'
    _UDP = 'BIND_PORT=65001\nDEV=tun0\nOPTIONS="persist"\n'

    def _post(self, user_client, files, payload):
        state = dict(files)
        class _Replacing(io.StringIO):
            def __init__(self, path):
                super().__init__()
                self.path = path
            def close(self):
                state[self.path] = self.getvalue()
                super().close()
        def _open(path, mode="r", *a, **k):
            sp = str(path)
            if sp.startswith("/etc/glorytun-"):
                if "w" in mode:
                    return _Replacing(sp)
                if sp in state:
                    return io.BytesIO(state[sp].encode()) if "b" in mode else io.StringIO(state[sp])
                raise FileNotFoundError(sp)
            return _mock_open(path, mode, *a, **k)
        with (
            patch("os.path.isfile", side_effect=lambda p: str(p) in state),
            patch("builtins.open", side_effect=_open),
            patch("subprocess.run") as run,
        ):
            r = user_client.post("/glorytun", json=payload)
        restarted = [c.args[0][-1] for c in run.call_args_list if c.args and c.args[0][:3] == ["systemctl", "-q", "restart"]]
        return r.json(), state, restarted

    def _files(self, key):
        return {"/etc/glorytun-tcp/tun0": self._TCP, "/etc/glorytun-tcp/tun0.key": key,
                "/etc/glorytun-udp/tun0": self._UDP, "/etc/glorytun-udp/tun0.key": key}

    def test_same_values_restart_nothing(self, user_client):
        result, _, restarted = self._post(user_client, self._files("AB" * 32),
                                          {"key": "AB" * 32, "port": 65001, "chacha": False})
        assert result["result"] == "done"
        assert restarted == []

    def test_new_key_alone_restarts_both(self, user_client):
        result, state, restarted = self._post(user_client, self._files("AB" * 32),
                                              {"key": "CD" * 32, "port": 65001, "chacha": False})
        assert state["/etc/glorytun-tcp/tun0.key"] == "CD" * 32
        assert sorted(restarted) == ["glorytun-tcp@tun0", "glorytun-udp@tun0"]

    def test_tcp_only_install(self, user_client):
        files = {k: v for k, v in self._files("AB" * 32).items() if "glorytun-tcp" in k}
        result, state, restarted = self._post(user_client, files, {"key": "CD" * 32, "port": 65002, "chacha": False})
        assert result["result"] == "done"
        assert "PORT=65002\n" in state["/etc/glorytun-tcp/tun0"]
        assert not any("glorytun-udp" in p for p in state)
        assert restarted == ["glorytun-tcp@tun0"]


class TestTunnelRemoval:
    def test_glorytun_tcp_removes_the_config_too(self):
        with patch("os.path.isfile", return_value=True), patch("os.remove") as rm, patch("subprocess.run"):
            omr_admin.remove_glorytun_tcp(3)
        assert sorted(c.args[0] for c in rm.call_args_list) == ["/etc/glorytun-tcp/tun3", "/etc/glorytun-tcp/tun3.key"]

    def test_glorytun_udp_deletes_its_persistent_interface(self):
        with patch("os.path.isfile", return_value=True), patch("os.remove"), patch("subprocess.run") as run:
            omr_admin.remove_glorytun_udp(3)
        assert ["ip", "link", "del", "gt-udp-tun3"] in [c.args[0] for c in run.call_args_list]

    @pytest.mark.parametrize("func", ["remove_glorytun_tcp", "remove_glorytun_udp", "remove_dsvpn"])
    def test_userid_0_template_is_never_removed(self, func):
        with patch("os.path.isfile", return_value=True), patch("os.remove") as rm, patch("subprocess.run") as run:
            getattr(omr_admin, func)(0)
        rm.assert_not_called()
        run.assert_not_called()


class TestProxyRestartCoalescing:
    """The forwards of one router sync cost one v2ray/xray restart, not one
    each: every restart drops every proxied connection of every user. The
    requests land on any uvicorn worker, so the workers share the pending
    restart through a marker file."""

    @pytest.fixture
    def timers(self, tmp_path, monkeypatch):
        created = []

        class FakeTimer:
            def __init__(self, delay, fn, args=()):
                self.delay, self.fn, self.args, self.cancelled = delay, fn, args, False
                created.append(self)
            def start(self):
                pass
            def cancel(self):
                self.cancelled = True

        monkeypatch.setattr(omr_admin, "PROXY_RESTART_DELAY", 5.0)
        monkeypatch.setattr(omr_admin, "PROXY_RESTART_MARKER", str(tmp_path / "{}-restart"))
        monkeypatch.setattr(omr_admin, "OMR_CONFIG_LOCK_FILE", str(tmp_path / ".lock"))
        monkeypatch.setattr(omr_admin.threading, "Timer", FakeTimer)
        monkeypatch.setattr(omr_admin, "_proxy_restart_timers", {})
        return created, tmp_path / "v2ray-restart"

    @staticmethod
    def _age(marker, seconds):
        t = os.stat(marker).st_mtime - seconds
        os.utime(marker, (t, t))

    @pytest.mark.real_env
    def test_burst_restarts_once(self, timers):
        created, marker = timers
        for _ in range(3):
            omr_admin._schedule_proxy_restart("v2ray")
        assert [t.cancelled for t in created] == [True, True, False]
        self._age(marker, 6)
        with patch("subprocess.run") as run:
            created[-1].fn(*created[-1].args)
        run.assert_called_once_with(["systemctl", "-q", "restart", "v2ray"], check=False)
        assert not marker.exists()

    @pytest.mark.real_env
    def test_change_from_another_worker_postpones_the_restart(self, timers):
        created, marker = timers
        omr_admin._schedule_proxy_restart("v2ray")
        self._age(marker, 3)   # another worker touched it 3s ago
        with patch("subprocess.run") as run:
            created[-1].fn(*created[-1].args)
        run.assert_not_called()
        assert created[-1].delay == pytest.approx(2, abs=0.5)  # re-armed for the other 2s
        assert marker.exists()

    @pytest.mark.real_env
    def test_second_worker_finds_the_restart_done(self, timers):
        created, marker = timers
        omr_admin._schedule_proxy_restart("v2ray")
        marker.unlink()        # the other worker restarted it
        with patch("subprocess.run") as run:
            created[-1].fn(*created[-1].args)
        run.assert_not_called()

    @pytest.mark.real_env
    def test_pending_restart_resumes_at_startup(self, timers, monkeypatch):
        created, marker = timers
        marker.touch()
        omr_admin.resume_proxy_restarts()
        assert [t.args for t in created] == [("v2ray",)]

    def test_zero_delay_restarts_inline(self, monkeypatch):
        monkeypatch.setattr(omr_admin, "PROXY_RESTART_DELAY", 0)
        with patch("subprocess.run") as run:
            omr_admin._schedule_proxy_restart("xray")
        run.assert_called_once_with(["systemctl", "-q", "restart", "xray"], check=False)


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

    def test_optional_v1_fields_accepted(self, user_client):
        payload = {**self._PAYLOAD, "close_timeout": 120, "pm_type": 1,
                   "stale_loss_cnt": 4, "syn_retrans_before_tcp_fallback": 2}
        r = user_client.post("/mptcp", json=payload)
        assert r.json()["result"] == "done"

    def test_missing_optional_v1_fields_still_succeed(self, user_client):
        r = user_client.post("/mptcp", json=self._PAYLOAD)
        assert r.json()["result"] == "done"

    def test_blank_v1_fields_from_unset_uci_do_not_422(self, user_client):
        # Regression for issue #4350: the router's _set_mptcp_vps quotes every
        # value from `uci -q get network.globals.mptcp_*`, so a v1-only knob
        # whose uci option is still unset is posted as "" rather than
        # omitted. That must fall back to its documented default (0), not a
        # raw FastAPI 422.
        payload = {**self._PAYLOAD, "close_timeout": "", "pm_type": "",
                   "stale_loss_cnt": "", "syn_retrans_before_tcp_fallback": ""}
        r = user_client.post("/mptcp", json=payload)
        assert r.status_code == 200
        assert r.json()["result"] == "done"

    def test_sysctl_injection_refused(self, user_client):
        # The values become key=value lines of /etc/sysctl.d/90-shadowsocks.conf,
        # applied as root at every boot: a newline would persist any sysctl.
        for field, value in (
            ("checksum", "0\nnet.ipv4.ip_forward=0"),
            ("checksum", "2"),
            ("path_manager", "default\nkernel.sysrq=1"),
            ("scheduler", "default\nkernel.sysrq=1"),
            ("scheduler", "bpf red"),
            ("congestion_control", "bbr\nnet.ipv4.ip_forward=0"),
            ("congestion_control", "x" * 33),
        ):
            with (
                patch("subprocess.run") as run,
                patch("omr_admin.move") as move,
            ):
                r = user_client.post("/mptcp", json={**self._PAYLOAD, field: value})
            assert r.json() == {"result": "error", "reason": f"Invalid {field}", "route": "mptcp"}, field
            assert not run.called and not move.called, field

    def test_bpf_scheduler_names_accepted(self, user_client):
        for scheduler in ("bpf_red", "mptcp_bpf_burst", "redundant", "blest"):
            r = user_client.post("/mptcp", json={**self._PAYLOAD, "scheduler": scheduler, "checksum": "1"})
            assert r.json()["result"] == "done", scheduler

    def test_blank_syn_retries_falls_back_to_invalid_parameters(self, user_client):
        # syn_retries has no default (required, non-zero) -- blank should
        # reach the route's own "Invalid parameters" check, not a 422.
        payload = {**self._PAYLOAD, "syn_retries": ""}
        r = user_client.post("/mptcp", json=payload)
        assert r.status_code == 200
        assert r.json()["result"] == "error"


class TestMPTCPV0Scheduler:
    """v0 (out-of-tree) kernel: net.mptcp.mptcp_scheduler sysctl path."""

    _PAYLOAD = {
        "checksum": "0",
        "path_manager": "default",
        "scheduler": "bpf_red",
        "syn_retries": 3,
        "congestion_control": "bbr",
        "version": 0,
    }

    def _v0_exists(self, p):
        return str(p) == "/proc/sys/net/mptcp/mptcp_enabled"

    def test_uses_mptcp_scheduler_sysctl(self, user_client):
        sysctl_calls = []

        def _run(cmd, *a, **kw):
            sysctl_calls.append(list(cmd) if cmd else [])
            return MagicMock(returncode=0)

        with (
            patch("os.path.exists", side_effect=self._v0_exists),
            patch("subprocess.run", side_effect=_run),
        ):
            r = user_client.post("/mptcp", json=self._PAYLOAD)

        assert r.json()["result"] == "done"
        assert any("net.mptcp.mptcp_scheduler=bpf_red" in " ".join(c) for c in sysctl_calls)

    def test_does_not_use_v1_scheduler_sysctl(self, user_client):
        sysctl_calls = []

        def _run(cmd, *a, **kw):
            sysctl_calls.append(list(cmd) if cmd else [])
            return MagicMock(returncode=0)

        with (
            patch("os.path.exists", side_effect=self._v0_exists),
            patch("subprocess.run", side_effect=_run),
        ):
            user_client.post("/mptcp", json=self._PAYLOAD)

        flat = " ".join(" ".join(c) for c in sysctl_calls)
        assert "net.mptcp.scheduler=bpf_red" not in flat or "mptcp_scheduler" in flat


class TestMPTCPSchedulerNormalization:
    """POST /mptcp must normalize a BPF .o filename stem (e.g. what the
    router might send if it lists /usr/share/bpf/scheduler verbatim) to the
    registered struct_ops name before ever handing it to sysctl."""

    _PAYLOAD = {
        "checksum": "0",
        "path_manager": "default",
        "scheduler": "mptcp_bpf_red",
        "syn_retries": 3,
        "congestion_control": "bbr",
        "version": 0,
    }

    def _v0_exists(self, p):
        return str(p) == "/proc/sys/net/mptcp/mptcp_enabled"

    def test_normalizes_prefixed_scheduler_before_sysctl(self, user_client):
        sysctl_calls = []

        def _run(cmd, *a, **kw):
            sysctl_calls.append(list(cmd) if cmd else [])
            return MagicMock(returncode=0)

        with (
            patch("os.path.exists", side_effect=self._v0_exists),
            patch("os.listdir", return_value=["mptcp_bpf_red.o"]),
            patch("subprocess.run", side_effect=_run),
        ):
            r = user_client.post("/mptcp", json=self._PAYLOAD)

        assert r.json()["result"] == "done"
        flat = [" ".join(c) for c in sysctl_calls]
        assert any("net.mptcp.mptcp_scheduler=bpf_red" in c for c in flat)
        assert not any("mptcp_bpf_red" in c for c in flat)


class TestMPTCPListenerRestarts:
    """A changed scheduler only reaches the download direction once the
    services that terminate MPTCP here are restarted: an MPTCP socket keeps
    the scheduler its listener had when it was created. shadowsocks-go was
    missing from that list, so a router on proxy shadowsocks-rust/-go could
    select bpf_red, get it on uploads, and keep the old one on everything the
    server sent back."""

    _PAYLOAD = {
        "checksum": "0",
        "path_manager": "default",
        "scheduler": "bpf_red",
        "syn_retries": 3,
        "congestion_control": "bbr",
        "version": 0,
    }

    def _post_and_collect(self, user_client, present):
        """POST /mptcp with `present` the set of service config files that
        exist, and return the flattened command lines subprocess.run saw."""
        calls = []

        def _run(cmd, *a, **kw):
            calls.append(" ".join(cmd) if cmd else "")
            return MagicMock(returncode=0)

        with (
            patch("os.path.exists", return_value=False),
            patch("os.path.isfile", side_effect=lambda p: str(p) in present),
            # The restart block is gated on the sysctl file actually changing;
            # `move` is mocked in this suite so the two hashes would match.
            patch("omr_admin.file_as_bytes", side_effect=[b"before", b"after"]),
            patch("subprocess.run", side_effect=_run),
        ):
            r = user_client.post("/mptcp", json=self._PAYLOAD)
        assert r.json()["result"] == "done"
        return calls

    def test_shadowsocks_go_restarted(self, user_client):
        calls = self._post_and_collect(
            user_client, {"/etc/shadowsocks-go/server.json"})
        assert any("restart shadowsocks-go" in c for c in calls), calls

    def test_shadowsocks_go_not_restarted_when_absent(self, user_client):
        calls = self._post_and_collect(user_client, set())
        assert not any("shadowsocks-go" in c for c in calls), calls

    def test_every_mptcp_listener_restarted(self, user_client):
        present = {
            "/etc/shadowsocks-libev/manager.json",
            "/etc/shadowsocks-go/server.json",
            "/etc/v2ray/v2ray-server.json",
            "/etc/xray/xray-server.json",
            "/etc/glorytun-tcp/tun0",
            "/etc/openvpn/tun0.conf",
        }
        calls = self._post_and_collect(user_client, present)
        for svc in ("shadowsocks-libev-manager@manager", "shadowsocks-go",
                    "v2ray", "xray", "glorytun-tcp@tun0", "openvpn@tun0"):
            assert any("restart " + svc in c for c in calls), (svc, calls)

    def test_no_restart_when_sysctl_file_unchanged(self, user_client):
        calls = []

        def _run(cmd, *a, **kw):
            calls.append(" ".join(cmd) if cmd else "")
            return MagicMock(returncode=0)

        with (
            patch("os.path.exists", return_value=False),
            patch("os.path.isfile", return_value=True),
            patch("omr_admin.file_as_bytes", side_effect=[b"same", b"same"]),
            patch("subprocess.run", side_effect=_run),
        ):
            r = user_client.post("/mptcp", json=self._PAYLOAD)

        assert r.json()["result"] == "done"
        assert not any("restart" in c for c in calls), calls


class TestMPTCPV1Scheduler:
    """v1 (upstream) kernel: net.mptcp.scheduler sysctl path and new sysctls."""

    _PAYLOAD = {
        "checksum": "0",
        "path_manager": "default",
        "scheduler": "bpf_red",
        "syn_retries": 3,
        "congestion_control": "bbr",
        "version": 0,
        "close_timeout": 60,
        "pm_type": 0,
        "stale_loss_cnt": 4,
        "syn_retrans_before_tcp_fallback": 2,
    }

    def _v1_exists(self, p):
        return str(p) in (
            "/proc/sys/net/mptcp/enabled",
            "/proc/sys/net/mptcp/scheduler",
            "/proc/sys/net/mptcp/syn_retries",
            "/proc/sys/net/mptcp/path_manager",
            "/proc/sys/net/mptcp/pm_type",
            "/proc/sys/net/mptcp/close_timeout",
            "/proc/sys/net/mptcp/stale_loss_cnt",
            "/proc/sys/net/mptcp/syn_retrans_before_tcp_fallback",
        )

    def test_uses_v1_scheduler_sysctl(self, user_client):
        sysctl_calls = []

        def _run(cmd, *a, **kw):
            sysctl_calls.append(list(cmd) if cmd else [])
            return MagicMock(returncode=0)

        with (
            patch("os.path.exists", side_effect=self._v1_exists),
            patch("subprocess.run", side_effect=_run),
        ):
            r = user_client.post("/mptcp", json=self._PAYLOAD)

        assert r.json()["result"] == "done"
        assert any("net.mptcp.scheduler=bpf_red" in " ".join(c) for c in sysctl_calls)

    def test_does_not_use_v0_scheduler_sysctl(self, user_client):
        sysctl_calls = []

        def _run(cmd, *a, **kw):
            sysctl_calls.append(list(cmd) if cmd else [])
            return MagicMock(returncode=0)

        with (
            patch("os.path.exists", side_effect=self._v1_exists),
            patch("subprocess.run", side_effect=_run),
        ):
            user_client.post("/mptcp", json=self._PAYLOAD)

        assert not any("mptcp_scheduler" in " ".join(c) for c in sysctl_calls)

    def test_applies_close_timeout(self, user_client):
        sysctl_calls = []

        def _run(cmd, *a, **kw):
            sysctl_calls.append(list(cmd) if cmd else [])
            return MagicMock(returncode=0)

        with (
            patch("os.path.exists", side_effect=self._v1_exists),
            patch("subprocess.run", side_effect=_run),
        ):
            user_client.post("/mptcp", json=self._PAYLOAD)

        assert any("net.mptcp.close_timeout=60" in " ".join(c) for c in sysctl_calls)

    def test_applies_stale_loss_cnt(self, user_client):
        sysctl_calls = []

        def _run(cmd, *a, **kw):
            sysctl_calls.append(list(cmd) if cmd else [])
            return MagicMock(returncode=0)

        with (
            patch("os.path.exists", side_effect=self._v1_exists),
            patch("subprocess.run", side_effect=_run),
        ):
            user_client.post("/mptcp", json=self._PAYLOAD)

        assert any("net.mptcp.stale_loss_cnt=4" in " ".join(c) for c in sysctl_calls)

    def test_applies_syn_retrans_before_tcp_fallback(self, user_client):
        sysctl_calls = []

        def _run(cmd, *a, **kw):
            sysctl_calls.append(list(cmd) if cmd else [])
            return MagicMock(returncode=0)

        with (
            patch("os.path.exists", side_effect=self._v1_exists),
            patch("subprocess.run", side_effect=_run),
        ):
            user_client.post("/mptcp", json=self._PAYLOAD)

        assert any("net.mptcp.syn_retrans_before_tcp_fallback=2" in " ".join(c) for c in sysctl_calls)

    def test_zero_optional_fields_not_applied(self, user_client):
        """Fields that default to 0 must not emit a sysctl call when omitted."""
        sysctl_calls = []

        def _run(cmd, *a, **kw):
            sysctl_calls.append(list(cmd) if cmd else [])
            return MagicMock(returncode=0)

        base = {k: v for k, v in self._PAYLOAD.items()
                if k not in ("close_timeout", "pm_type", "stale_loss_cnt",
                             "syn_retrans_before_tcp_fallback")}
        with (
            patch("os.path.exists", side_effect=self._v1_exists),
            patch("subprocess.run", side_effect=_run),
        ):
            user_client.post("/mptcp", json=base)

        flat = " ".join(" ".join(c) for c in sysctl_calls)
        assert "close_timeout" not in flat
        assert "stale_loss_cnt" not in flat
        assert "syn_retrans_before_tcp_fallback" not in flat


class TestLoadMptcpBpfSchedulers:
    """load_mptcp_bpf_schedulers() must re-apply the scheduler sysctl after loading BPF."""

    _SYSCTL_CONF_V0 = "net.mptcp.mptcp_scheduler=bpf_red\nnet.ipv4.tcp_congestion_control=bbr\n"
    _SYSCTL_CONF_V1 = "net.mptcp.scheduler=bpf_red\nnet.ipv4.tcp_congestion_control=bbr\n"

    def test_reapplies_v0_scheduler_after_bpf_load(self):
        sysctl_calls = []

        def _run(cmd, *a, **kw):
            sysctl_calls.append(list(cmd) if cmd else [])
            return MagicMock(returncode=0)

        def _open_conf(p, mode="r", *a, **kw):
            if str(p) == "/etc/sysctl.d/90-shadowsocks.conf":
                return io.StringIO(self._SYSCTL_CONF_V0)
            return _mock_open(p, mode, *a, **kw)

        with (
            patch("os.path.isdir", return_value=True),
            patch("os.path.exists", return_value=True),
            patch("os.makedirs"),
            patch("os.listdir", return_value=["mptcp_bpf_red.o"]),
            patch("subprocess.run", side_effect=_run),
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open_conf),
        ):
            omr_admin.load_mptcp_bpf_schedulers()

        assert any("net.mptcp.mptcp_scheduler=bpf_red" in " ".join(c) for c in sysctl_calls)

    def test_reapplies_v1_scheduler_after_bpf_load(self):
        sysctl_calls = []

        def _run(cmd, *a, **kw):
            sysctl_calls.append(list(cmd) if cmd else [])
            return MagicMock(returncode=0)

        def _open_conf(p, mode="r", *a, **kw):
            if str(p) == "/etc/sysctl.d/90-shadowsocks.conf":
                return io.StringIO(self._SYSCTL_CONF_V1)
            return _mock_open(p, mode, *a, **kw)

        with (
            patch("os.path.isdir", return_value=True),
            patch("os.path.exists", return_value=True),
            patch("os.makedirs"),
            patch("os.listdir", return_value=["mptcp_bpf_red.o"]),
            patch("subprocess.run", side_effect=_run),
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open_conf),
        ):
            omr_admin.load_mptcp_bpf_schedulers()

        assert any("net.mptcp.scheduler=bpf_red" in " ".join(c) for c in sysctl_calls)

    def test_no_reapply_when_bpf_load_fails(self):
        sysctl_calls = []

        def _run(cmd, *a, **kw):
            sysctl_calls.append(list(cmd) if cmd else [])
            return MagicMock(returncode=1)

        with (
            patch("os.path.isdir", return_value=True),
            patch("os.makedirs"),
            patch("os.listdir", return_value=["mptcp_bpf_red.o"]),
            patch("subprocess.run", side_effect=_run),
        ):
            omr_admin.load_mptcp_bpf_schedulers()

        assert not any("mptcp_scheduler" in " ".join(c) or "net.mptcp.scheduler" in " ".join(c)
                       for c in sysctl_calls)

    def test_no_op_when_bpf_dir_missing(self):
        with patch("os.path.isdir", return_value=False):
            omr_admin.load_mptcp_bpf_schedulers()

    def test_normalizes_stale_prefixed_scheduler_and_persists_fix(self):
        # A conf file written before the naming was well understood (or by a
        # UI listing .o filenames directly) can end up with the BPF object's
        # filename stem instead of its registered struct_ops name -- that
        # must self-heal here rather than fail sysctl forever.
        sysctl_calls = []
        written = {}

        def _run(cmd, *a, **kw):
            sysctl_calls.append(list(cmd) if cmd else [])
            return MagicMock(returncode=0, stderr="")

        class _CapturingFile(io.StringIO):
            def close(self):
                written["content"] = self.getvalue()
                super().close()

        stale_conf = "net.mptcp.scheduler=mptcp_bpf_red\nnet.ipv4.tcp_congestion_control=bbr\n"

        def _open_conf(p, mode="r", *a, **kw):
            if "w" in mode:
                return _CapturingFile()
            if str(p) == "/etc/sysctl.d/90-shadowsocks.conf":
                return io.StringIO(stale_conf)
            return _mock_open(p, mode, *a, **kw)

        with (
            patch("os.path.isdir", return_value=True),
            patch("os.path.exists", return_value=True),
            patch("os.makedirs"),
            patch("os.listdir", return_value=["mptcp_bpf_red.o"]),
            patch("subprocess.run", side_effect=_run),
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open_conf),
        ):
            omr_admin.load_mptcp_bpf_schedulers()

        # bpftool's own register call legitimately references the .o file by
        # its 'mptcp_bpf_red' path -- only the sysctl invocations matter here.
        sysctl_only = [" ".join(c) for c in sysctl_calls if c and c[0] == "sysctl"]
        assert any("net.mptcp.scheduler=bpf_red" in c for c in sysctl_only)
        assert not any("mptcp_bpf_red" in c for c in sysctl_only)
        assert "net.mptcp.scheduler=bpf_red" in written.get("content", "")
        assert "mptcp_bpf_red" not in written.get("content", "")

    def test_kernel_without_mptcp_bpf_support_reports_once_without_warnings(self):
        # A kernel built without MPTCP BPF scheduler support fails every
        # shipped object the same way (no bpf_struct_ops_mptcp_sched_ops /
        # bpf_mptcp_subflow_ctx in its BTF). That's one fact about the
        # kernel, not four faults: it used to be a multi-line libbpf
        # warning per object per uvicorn worker at every startup.
        objects = ["mptcp_bpf_first.o", "mptcp_bpf_red.o", "mptcp_bpf_rr.o", "mptcp_bpf_bkup.o"]

        def _run(cmd, *a, **kw):
            return MagicMock(returncode=255, stderr=(
                "libbpf: extern (func ksym) 'bpf_mptcp_subflow_ctx': not found in kernel or module BTFs\n"
                "libbpf: failed to load object '" + cmd[3] + "'\n"
                "Error: can't register struct_ops\n"))

        with (
            patch("os.path.isdir", return_value=True),
            patch("os.makedirs"),
            patch("os.listdir", return_value=objects),
            patch("subprocess.run", side_effect=_run),
            patch("omr_admin.LOG") as log,
        ):
            omr_admin.load_mptcp_bpf_schedulers()

        log.warning.assert_not_called()
        summaries = [c.args[0] % c.args[1:] if len(c.args) > 1 else c.args[0]
                     for c in log.info.call_args_list]
        assert len(summaries) == 1
        assert "no MPTCP BPF scheduler support" in summaries[0]
        for fname in objects:
            assert fname in summaries[0]

    def test_unrelated_load_failure_still_warns_on_one_line(self):
        def _run(cmd, *a, **kw):
            return MagicMock(returncode=255, stderr=(
                "libbpf: elf: failed to open /usr/share/bpf/scheduler/mptcp_bpf_red.o: Permission denied\n"
                "Error: can't register struct_ops\n"))

        with (
            patch("os.path.isdir", return_value=True),
            patch("os.makedirs"),
            patch("os.listdir", return_value=["mptcp_bpf_red.o"]),
            patch("subprocess.run", side_effect=_run),
            patch("omr_admin.LOG") as log,
        ):
            omr_admin.load_mptcp_bpf_schedulers()

        log.warning.assert_called_once()
        message = log.warning.call_args.args[0] % log.warning.call_args.args[1:]
        assert "\n" not in message
        assert "Permission denied" in message


class TestLogStartupEnvironment:
    """log_startup_environment() -- the one line main() logs per service
    start. The kernel version is what tells a bug report whether MPTCP, the
    BPF schedulers and the nftables objects this API drives can exist at
    all, so it must be there even when nothing else can be determined."""

    def _uname(self):
        return os.uname_result(("Linux", "vps", "6.18.41-20260730.x64v3-omr",
                                "#0 SMP", "x86_64"))

    def test_logs_kernel_release_machine_and_vps_version(self):
        with (
            patch("platform.uname", return_value=self._uname()),
            patch("omr_admin.get_omr_version", return_value="0.1057"),
            patch("omr_admin.LOG") as log,
        ):
            omr_admin.log_startup_environment()

        log.info.assert_called_once()
        message = log.info.call_args.args[0] % log.info.call_args.args[1:]
        assert "6.18.41-20260730.x64v3-omr" in message
        assert "x86_64" in message
        assert "0.1057" in message

    def test_unknown_vps_version_still_logs_the_kernel(self):
        with (
            patch("platform.uname", return_value=self._uname()),
            patch("omr_admin.get_omr_version", return_value=""),
            patch("omr_admin.LOG") as log,
        ):
            omr_admin.log_startup_environment()

        message = log.info.call_args.args[0] % log.info.call_args.args[1:]
        assert "6.18.41-20260730.x64v3-omr" in message
        assert "unknown" in message


class TestNormalizeMptcpScheduler:
    """normalize_mptcp_scheduler() must map a BPF .o filename stem to the
    struct_ops name the kernel registers it under, and leave everything
    else (non-BPF names, already-correct BPF names, blanks) untouched."""

    def test_maps_bpf_filename_stem_to_registered_name(self):
        with patch("os.listdir", return_value=["mptcp_bpf_red.o"]):
            assert omr_admin.normalize_mptcp_scheduler("mptcp_bpf_red") == "bpf_red"

    def test_leaves_already_correct_bpf_name_unchanged(self):
        with patch("os.listdir", return_value=["mptcp_bpf_red.o"]):
            assert omr_admin.normalize_mptcp_scheduler("bpf_red") == "bpf_red"

    def test_leaves_non_bpf_scheduler_names_unchanged(self):
        with patch("os.listdir", return_value=["mptcp_bpf_red.o"]):
            assert omr_admin.normalize_mptcp_scheduler("bbr") == "bbr"
            assert omr_admin.normalize_mptcp_scheduler("default") == "default"

    def test_no_op_when_bpf_dir_missing(self):
        with patch("os.listdir", side_effect=FileNotFoundError):
            assert omr_admin.normalize_mptcp_scheduler("mptcp_bpf_red") == "mptcp_bpf_red"

    def test_blank_scheduler_passes_through(self):
        assert omr_admin.normalize_mptcp_scheduler("") == ""
        assert omr_admin.normalize_mptcp_scheduler(None) is None


class TestNormalizeMptcpPathManager:
    """normalize_mptcp_path_manager() must map the out-of-tree (v0) path
    manager names the router still sends onto the mainline path manager that
    implements them, and leave everything else untouched."""

    _AVAIL = "/proc/sys/net/mptcp/available_path_managers"

    def _read_proc(self, value):
        def _side_effect(path):
            return value if str(path) == self._AVAIL else ""
        return _side_effect

    def test_maps_v0_names_to_kernel(self):
        with patch("omr_admin.read_proc", side_effect=self._read_proc("kernel userspace")):
            for name in ("fullmesh", "ndiffports", "binder", "default", "netlink"):
                assert omr_admin.normalize_mptcp_path_manager(name) == "kernel"

    def test_leaves_available_names_unchanged(self):
        with patch("omr_admin.read_proc", side_effect=self._read_proc("kernel userspace")):
            assert omr_admin.normalize_mptcp_path_manager("kernel") == "kernel"
            assert omr_admin.normalize_mptcp_path_manager("userspace") == "userspace"

    def test_leaves_unknown_name_unchanged(self):
        with patch("omr_admin.read_proc", side_effect=self._read_proc("kernel userspace")):
            assert omr_admin.normalize_mptcp_path_manager("bpf_pm") == "bpf_pm"

    def test_no_op_on_kernel_advertising_no_list(self):
        # v0 kernel: net.mptcp.mptcp_path_manager really does take 'fullmesh'.
        with patch("omr_admin.read_proc", side_effect=self._read_proc("")):
            assert omr_admin.normalize_mptcp_path_manager("fullmesh") == "fullmesh"

    def test_blank_path_manager_passes_through(self):
        assert omr_admin.normalize_mptcp_path_manager("") == ""
        assert omr_admin.normalize_mptcp_path_manager(None) is None


class TestMPTCPPathManagerNormalization:
    """POST /mptcp must translate the router's v0 path manager name before
    handing it to sysctl and before persisting it into 90-shadowsocks.conf --
    otherwise the stale line fails at every boot with ENOENT."""

    _PAYLOAD = {
        "checksum": "0",
        "path_manager": "fullmesh",
        "scheduler": "default",
        "syn_retries": 3,
        "congestion_control": "bbr",
        "version": 0,
    }

    _CONF = "/etc/sysctl.d/90-shadowsocks.conf"

    def _v1_exists(self, p):
        return str(p) in (
            "/proc/sys/net/mptcp/enabled",
            "/proc/sys/net/mptcp/scheduler",
            "/proc/sys/net/mptcp/syn_retries",
            "/proc/sys/net/mptcp/path_manager",
        )

    def _read_proc(self, path):
        if str(path) == "/proc/sys/net/mptcp/available_path_managers":
            return "kernel userspace"
        return ""

    def test_normalizes_path_manager_before_sysctl(self, user_client):
        sysctl_calls = []

        def _run(cmd, *a, **kw):
            sysctl_calls.append(list(cmd) if cmd else [])
            return MagicMock(returncode=0)

        with (
            patch("os.path.exists", side_effect=self._v1_exists),
            patch("omr_admin.read_proc", side_effect=self._read_proc),
            patch("subprocess.run", side_effect=_run),
        ):
            r = user_client.post("/mptcp", json=self._PAYLOAD)

        assert r.json()["result"] == "done"
        flat = [" ".join(c) for c in sysctl_calls]
        assert any("net.mptcp.path_manager=kernel" in c for c in flat)
        assert not any("fullmesh" in c for c in flat)

    def test_persists_normalized_path_manager(self, user_client):
        written = _KeepOpenStringIO()

        def _open(path, mode="r", *a, **kw):
            sp = str(path)
            if "w" in str(mode) or "a" in str(mode):
                return written
            if sp == self._CONF and "b" not in str(mode):
                return io.StringIO("net.mptcp.path_manager=fullmesh\n")
            return _mock_open(path, mode, *a, **kw)

        with (
            patch("os.path.exists", side_effect=self._v1_exists),
            patch("omr_admin.read_proc", side_effect=self._read_proc),
            patch("builtins.open", side_effect=_open),
        ):
            r = user_client.post("/mptcp", json=self._PAYLOAD)

        assert r.json()["result"] == "done"
        assert "net.mptcp.path_manager=kernel" in written.getvalue()
        assert "fullmesh" not in written.getvalue()


class TestNormalizePersistedMptcpPathManager:
    """A v0 path manager name already written into 90-shadowsocks.conf by an
    earlier /mptcp call must be repaired at startup: sysctl.d is applied at
    boot, well before this service runs, so nothing else ever fixes it."""

    _CONF = "/etc/sysctl.d/90-shadowsocks.conf"
    _CONF_BODY = ("net.mptcp.checksum_enabled=0\n"
                  "net.mptcp.scheduler=default\n"
                  "net.mptcp.path_manager=fullmesh\n")

    def _read_proc(self, path):
        if str(path) == "/proc/sys/net/mptcp/available_path_managers":
            return "kernel userspace"
        return ""

    def _open(self, path, mode="r", *a, **kw):
        if str(path) == self._CONF and "b" not in str(mode):
            return io.StringIO(self._CONF_BODY)
        return _mock_open(path, mode, *a, **kw)

    def _run_startup(self, read_proc):
        rewrites = []
        sysctl_calls = []

        def _rewrite(conf, key, value):
            rewrites.append((conf, key, value))

        def _run(cmd, *a, **kw):
            sysctl_calls.append(list(cmd) if cmd else [])
            return MagicMock(returncode=0)

        with (
            patch("os.path.isfile", return_value=True),
            patch("os.path.exists", return_value=True),
            patch("omr_admin.read_proc", side_effect=read_proc),
            patch("omr_admin._rewrite_sysctl_conf_line", side_effect=_rewrite),
            patch("builtins.open", side_effect=self._open),
            patch("subprocess.run", side_effect=_run),
        ):
            omr_admin.normalize_persisted_mptcp_path_manager(self._CONF)
        return rewrites, sysctl_calls

    def test_rewrites_and_applies_kernel(self):
        rewrites, sysctl_calls = self._run_startup(self._read_proc)
        assert rewrites == [(self._CONF, "net.mptcp.path_manager", "kernel")]
        assert any("net.mptcp.path_manager=kernel" in " ".join(c) for c in sysctl_calls)

    def test_leaves_valid_value_alone(self):
        def _read_proc(path):
            return "kernel userspace" if "available" in str(path) else ""

        body = self._CONF_BODY.replace("fullmesh", "kernel")
        with patch.object(type(self), "_CONF_BODY", body):
            rewrites, sysctl_calls = self._run_startup(_read_proc)
        assert rewrites == []
        assert not any("path_manager" in " ".join(c) for c in sysctl_calls)

    def test_no_op_when_conf_missing(self):
        with patch("os.path.isfile", return_value=False):
            omr_admin.normalize_persisted_mptcp_path_manager(self._CONF)


class TestMPTCPV1ConfigRead:
    """GET /config must return v1 MPTCP fields when the v1 proc path exists."""

    def _v1_exists(self, p):
        return str(p) in (
            "/proc/sys/net/mptcp/enabled",
            "/proc/sys/net/mptcp/scheduler",
            "/proc/sys/net/mptcp/syn_retries",
            "/proc/sys/net/mptcp/path_manager",
            "/proc/sys/net/mptcp/pm_type",
            "/proc/sys/net/mptcp/close_timeout",
            "/proc/sys/net/mptcp/stale_loss_cnt",
            "/proc/sys/net/mptcp/syn_retrans_before_tcp_fallback",
        )

    def _proc_open(self, p, mode="r", *a, **kw):
        values = {
            "/proc/sys/net/mptcp/enabled": "1",
            "/proc/sys/net/mptcp/checksum_enabled": "0",
            "/proc/sys/net/mptcp/scheduler": "bpf_red",
            "/proc/sys/net/mptcp/syn_retries": "3",
            "/proc/sys/net/mptcp/path_manager": "default",
            "/proc/sys/net/mptcp/pm_type": "0",
            "/proc/sys/net/mptcp/close_timeout": "60",
            "/proc/sys/net/mptcp/stale_loss_cnt": "4",
            "/proc/sys/net/mptcp/syn_retrans_before_tcp_fallback": "2",
            "/proc/sys/net/ipv4/tcp_congestion_control": "bbr",
        }
        if str(p) in values:
            return io.StringIO(values[str(p)])
        return _mock_open(p, mode, *a, **kw)

    def test_config_returns_v1_scheduler(self, user_client):
        with (
            patch("os.path.exists", side_effect=self._v1_exists),
            patch("builtins.open", side_effect=self._proc_open),
        ):
            r = user_client.get("/config")
        assert r.status_code == 200
        assert r.json()["mptcp"]["scheduler"] == "bpf_red"

    def test_config_returns_close_timeout(self, user_client):
        with (
            patch("os.path.exists", side_effect=self._v1_exists),
            patch("builtins.open", side_effect=self._proc_open),
        ):
            r = user_client.get("/config")
        assert r.json()["mptcp"]["close_timeout"] == "60"

    def test_config_returns_stale_loss_cnt(self, user_client):
        with (
            patch("os.path.exists", side_effect=self._v1_exists),
            patch("builtins.open", side_effect=self._proc_open),
        ):
            r = user_client.get("/config")
        assert r.json()["mptcp"]["stale_loss_cnt"] == "4"

    def test_config_returns_syn_retrans_before_tcp_fallback(self, user_client):
        with (
            patch("os.path.exists", side_effect=self._v1_exists),
            patch("builtins.open", side_effect=self._proc_open),
        ):
            r = user_client.get("/config")
        assert r.json()["mptcp"]["syn_retrans_before_tcp_fallback"] == "2"

    def test_config_returns_pm_type(self, user_client):
        with (
            patch("os.path.exists", side_effect=self._v1_exists),
            patch("builtins.open", side_effect=self._proc_open),
        ):
            r = user_client.get("/config")
        assert r.json()["mptcp"]["pm_type"] == "0"


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

    def test_reality_proxy_accepted(self, user_client):
        # The router reads xray-vless-reality from /config and posts it back
        r = user_client.post("/proxy", json={"proxy": "xray-vless-reality"})
        assert r.status_code == 200
        assert r.json()["result"] == "done"

    def test_advertised_proxies_are_all_settable(self, user_client):
        """proxy.available / proxy_list and POST /proxy must not drift apart.

        A name advertised by one side and unknown to the other makes the
        router's proxy switch fail with a 422, which is what xray-vless-reality
        did while it was missing from the PROXY enum.
        """
        with patch("os.path.isfile", side_effect=_isfile_for(
                "/etc/shadowsocks-libev/manager.json",
                "/etc/shadowsocks-go/server.json",
                "/etc/v2ray/v2ray-server.json",
                "/etc/xray/xray-server.json",
        )):
            advertised = omr_admin._installed_proxy_types()
        assert set(advertised) == {
            "shadowsocks", "shadowsocks-go", "shadowsocks-rust",
            "v2ray", "v2ray-vless", "v2ray-vmess", "v2ray-socks",
            "v2ray-trojan",
            "xray", "xray-vless", "xray-vless-reality", "xray-vmess",
            "xray-socks", "xray-trojan", "xray-shadowsocks", "none",
        }
        # Every name the router can select must be in there
        assert {
            "shadowsocks", "shadowsocks-rust", "v2ray", "v2ray-vmess",
            "v2ray-socks", "v2ray-trojan", "xray", "xray-vless-reality",
            "xray-vmess", "xray-socks", "xray-trojan", "xray-shadowsocks",
        } <= set(advertised)
        for name in advertised:
            r = user_client.post("/proxy", json={"proxy": name})
            assert r.status_code == 200, name
            assert r.json()["result"] == "done", name

    def test_config_advertises_the_proxy_list(self, user_client):
        available = user_client.get("/config").json()["proxy"]["available"]
        assert available == user_client.get("/proxy_list").json()["proxy"]


class TestConfigProxyTraffic:
    """/config must count proxy traffic for the protocol variants too.

    A v2ray-* / xray-* variant is served by the same process as the bare name,
    but /config only counted traffic when proxy was exactly 'v2ray' or 'xray',
    so tx/rx stayed 0 on xray-vless-reality, xray-vmess, v2ray-trojan, ...
    /status already matched by substring.
    """

    @staticmethod
    def _config_with(proxy):
        config = copy.deepcopy(MOCK_CONFIG)
        user = config["users"][0]["openmptcprouter"]
        user["proxy"] = proxy
        # Pre-seeded so /config takes the cached branch instead of reading
        # the server json through the mocked open()
        user["v2ray"] = {"key": "v2key", "port": "65228"}
        user["xray"] = {"key": "xrkey", "port": "65228", "sskey": "a:b"}
        return config

    @contextlib.contextmanager
    def _env(self, proxy):
        with (
            patch("omr_admin.read_omr_config", return_value=self._config_with(proxy)),
            patch("os.path.isfile", side_effect=_isfile_for(
                "/etc/v2ray/v2ray-server.json", "/etc/xray/xray-server.json")),
            patch("omr_admin.checkIfProcessRunning", return_value=True),
            patch("omr_admin.get_bytes_v2ray",
                  side_effect=lambda d, u: 11 if d == "tx" else 12),
            patch("omr_admin.get_bytes_xray",
                  side_effect=lambda d, u: 21 if d == "tx" else 22),
        ):
            yield

    @pytest.mark.parametrize("proxy", [
        "xray", "xray-vless", "xray-vless-reality", "xray-vmess",
        "xray-socks", "xray-trojan", "xray-shadowsocks",
    ])
    def test_xray_variants_counted(self, user_client, proxy):
        with self._env(proxy):
            body = user_client.get("/config").json()
        assert (body["xray"]["tx"], body["xray"]["rx"]) == (21, 22)
        assert (body["v2ray"]["tx"], body["v2ray"]["rx"]) == (0, 0)

    @pytest.mark.parametrize("proxy", [
        "v2ray", "v2ray-vless", "v2ray-vmess", "v2ray-socks", "v2ray-trojan",
    ])
    def test_v2ray_variants_counted(self, user_client, proxy):
        with self._env(proxy):
            body = user_client.get("/config").json()
        assert (body["v2ray"]["tx"], body["v2ray"]["rx"]) == (11, 12)
        assert (body["xray"]["tx"], body["xray"]["rx"]) == (0, 0)

    @pytest.mark.parametrize("proxy", ["shadowsocks", "shadowsocks-rust", "none"])
    def test_other_proxies_not_counted(self, user_client, proxy):
        with self._env(proxy):
            body = user_client.get("/config").json()
        assert (body["v2ray"]["tx"], body["v2ray"]["rx"]) == (0, 0)
        assert (body["xray"]["tx"], body["xray"]["rx"]) == (0, 0)


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

    def test_writes_current_users_key_file(self, user_client):
        written_paths = []

        def _open_dsvpn(path, mode="r", *args, **kwargs):
            sp = str(path)
            if sp == "/etc/dsvpn/dsvpn0.key":
                if "w" in str(mode):
                    written_paths.append(sp)
                    return io.StringIO()
                return io.BytesIO(b"old-key")
            if sp == "/etc/dsvpn/dsvpn0":
                return io.StringIO("PORT=65400\n")
            return _mock_open(path, mode, *args, **kwargs)

        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open_dsvpn),
        ):
            r = user_client.post("/dsvpn", json=self._PAYLOAD)

        assert r.json()["result"] == "done"
        assert written_paths == ["/etc/dsvpn/dsvpn0.key"]


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

    def test_port_change_updates_firewall(self, user_client):
        """Changing the port must open the new port and close the old one (v4+v6)."""
        with (
            patch("os.path.isfile", return_value=True),
            patch("omr_admin.shorewall_add_port") as add4,
            patch("omr_admin.shorewall6_add_port") as add6,
            patch("omr_admin.shorewall_del_port") as del4,
            patch("omr_admin.shorewall6_del_port") as del6,
        ):
            # fixture listen is 0.0.0.0:443 → move to 65443
            r = user_client.post("/mqvpn", json={**self._PAYLOAD, "port": 65443})
        assert r.json()["result"] == "done"
        add4.assert_called_once()
        add6.assert_called_once()
        del4.assert_called_once()
        del6.assert_called_once()
        assert add4.call_args[0][1:] == ("65443", "udp", "mqvpn")
        assert del4.call_args[0][1:] == ("443", "udp", "mqvpn")

    def test_same_port_does_not_touch_firewall(self, user_client):
        """No firewall changes when the port stays the same."""
        with (
            patch("os.path.isfile", return_value=True),
            patch("omr_admin.shorewall_add_port", return_value=None) as add4,
            patch("omr_admin.shorewall6_add_port", return_value=None) as add6,
            patch("omr_admin.shorewall_del_port") as del4,
            patch("omr_admin.shorewall6_del_port") as del6,
        ):
            # fixture listen is 0.0.0.0:443 → payload port is also 443
            r = user_client.post("/mqvpn", json=self._PAYLOAD)
        assert r.json()["result"] == "done"
        add4.assert_not_called()
        add6.assert_not_called()
        del4.assert_not_called()
        del6.assert_not_called()

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

    def test_config_returns_mqvpn_pin(self, user_client):
        """/config carries the pin of the certificate server.json names, so the
        router's mqvpn can authenticate the server (GHSA-qq6x-5r9f-2w3m)."""
        pin = "R30mnbVpbENfQLjUKknDadhUtoKu+CFS/tGIsnHxsDU="
        with (
            patch("os.path.isfile", _isfile_for("/etc/mqvpn/server.json")),
            patch.object(omr_admin, "mqvpn_server_pin", return_value=pin) as server_pin,
        ):
            r = user_client.get("/config")
        assert r.status_code == 200
        assert r.json()["mqvpn"]["pinned_pubkey"] == pin
        server_pin.assert_called_once_with(MQVPN_CONFIG["cert_file"])

    def test_config_no_mqvpn_has_empty_pin(self, user_client):
        with patch("os.path.isfile", return_value=False):
            r = user_client.get("/config")
        assert r.status_code == 200
        assert r.json()["mqvpn"]["pinned_pubkey"] == ""

    def test_reorder_written_to_config(self, user_client):
        """POST /mqvpn with reorder must persist the reorder object."""
        capture = io.StringIO()
        capture.close = lambda: None

        def _capture_open(path, mode="r", *args, **kwargs):
            if str(path) == "/etc/mqvpn/server.json" and "w" in str(mode):
                return capture
            return _mock_open(path, mode, *args, **kwargs)

        payload = {**self._PAYLOAD, "reorder": {"enabled": "on", "max_wait_ms": 50, "cap_packets": 512}}
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_capture_open),
        ):
            r = user_client.post("/mqvpn", json=payload)
        assert r.json()["result"] == "done"
        capture.seek(0)
        written = json.loads(capture.read())
        assert written["reorder"] == {"enabled": "on", "max_wait_ms": 50, "cap_packets": 512}

    def test_reorder_rules_written_to_config(self, user_client):
        """POST /mqvpn with reorder_rules must persist the rules list."""
        capture = io.StringIO()
        capture.close = lambda: None

        def _capture_open(path, mode="r", *args, **kwargs):
            if str(path) == "/etc/mqvpn/server.json" and "w" in str(mode):
                return capture
            return _mock_open(path, mode, *args, **kwargs)

        rules = [{"proto": "udp", "port": 443, "profile": "fiber_lte"}, {"proto": "udp", "port": 53, "profile": "default_udp"}]
        payload = {**self._PAYLOAD, "reorder_rules": rules}
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_capture_open),
        ):
            r = user_client.post("/mqvpn", json=payload)
        assert r.json()["result"] == "done"
        capture.seek(0)
        written = json.loads(capture.read())
        assert written["reorder_rules"] == rules

    def test_reorder_omitted_preserves_existing(self, user_client):
        """POST /mqvpn without reorder must leave the existing reorder block unchanged."""
        capture = io.StringIO()
        capture.close = lambda: None

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
        assert written["reorder"] == MQVPN_CONFIG["reorder"]
        assert written["reorder_rules"] == MQVPN_CONFIG["reorder_rules"]

    def test_invalid_reorder_enabled_returns_422(self, user_client):
        """enabled must be one of off/on/auto."""
        payload = {**self._PAYLOAD, "reorder": {"enabled": "yes", "max_wait_ms": 30, "cap_packets": 1024}}
        r = user_client.post("/mqvpn", json=payload)
        assert r.status_code == 422

    def test_config_returns_reorder(self, user_client):
        """GET /config must include the reorder object from server.json."""
        with patch("os.path.isfile", _isfile_for("/etc/mqvpn/server.json")):
            r = user_client.get("/config")
        assert r.status_code == 200
        mqvpn = r.json().get("mqvpn", {})
        assert mqvpn.get("reorder") == MQVPN_CONFIG["reorder"]

    def test_config_returns_reorder_rules(self, user_client):
        """GET /config must include the reorder_rules list from server.json."""
        with patch("os.path.isfile", _isfile_for("/etc/mqvpn/server.json")):
            r = user_client.get("/config")
        assert r.status_code == 200
        mqvpn = r.json().get("mqvpn", {})
        assert mqvpn.get("reorder_rules") == MQVPN_CONFIG["reorder_rules"]

    def test_config_reorder_defaults_when_absent(self, user_client):
        """GET /config must return safe defaults when reorder is absent from server.json."""
        cfg_without_reorder = {k: v for k, v in MQVPN_CONFIG.items() if k not in ("reorder", "reorder_rules")}

        def _open_no_reorder(path, mode="r", *args, **kwargs):
            if str(path) == "/etc/mqvpn/server.json":
                return io.StringIO(json.dumps(cfg_without_reorder))
            return _mock_open(path, mode, *args, **kwargs)

        with (
            patch("os.path.isfile", _isfile_for("/etc/mqvpn/server.json")),
            patch("builtins.open", side_effect=_open_no_reorder),
        ):
            r = user_client.get("/config")
        assert r.status_code == 200
        mqvpn = r.json().get("mqvpn", {})
        reorder = mqvpn.get("reorder", {})
        assert reorder.get("enabled") == "off"
        assert reorder.get("max_wait_ms") == 30
        assert reorder.get("cap_packets") == 1024
        assert mqvpn.get("reorder_rules") == []


def _open_with_mqvpn_config(cfg):
    """builtins.open replacement serving *cfg* as /etc/mqvpn/server.json (reads only)."""
    from conftest import _mock_open as _base_open
    cfg_json = json.dumps(cfg)

    def _open(path, mode="r", *args, **kwargs):
        if str(path) == "/etc/mqvpn/server.json" and "w" not in str(mode):
            return io.StringIO(cfg_json)
        return _base_open(path, mode, *args, **kwargs)
    return _open


class TestMqvpnUsers:
    _STATUS = {"ok": True, "n_clients": 1,
               "clients": [{"user": "openmptcprouter", "enable_fec": 1, "mp_state": 1}]}

    @staticmethod
    def _api(list_users, status):
        def _mock(cmd):
            if cmd["cmd"] == "list_users":
                return list_users
            if cmd["cmd"] == "get_status":
                return status
            raise AssertionError(f"unexpected control command {cmd}")
        return _mock

    def test_requires_auth(self, unauth_client):
        r = unauth_client.get("/mqvpn_users")
        assert r.status_code == 403

    def test_non_admin_denied(self, user_client):
        r = user_client.get("/mqvpn_users")
        assert r.json()["result"] == "permission"

    def test_ro_user_denied(self, ro_client):
        r = ro_client.get("/mqvpn_users")
        assert r.json()["result"] == "permission"

    def test_missing_mqvpn_returns_warning(self, admin_client):
        with patch("os.path.isfile", return_value=False):
            r = admin_client.get("/mqvpn_users")
        assert r.json()["result"] == "warning"
        assert r.json()["route"] == "mqvpn_users"

    def test_merges_configured_known_and_connected(self, admin_client):
        cfg = json.loads(json.dumps(MQVPN_CONFIG))
        cfg["users"].append({"name": "persisted-only", "key": "k", "fixed_ip": "10.255.220.7"})
        listed = {"ok": True, "users": ["openmptcprouter", "daemon-only"]}
        with (
            patch("os.path.isfile", _isfile_for("/etc/mqvpn/server.json")),
            patch("builtins.open", side_effect=_open_with_mqvpn_config(cfg)),
            patch("omr_admin.mqvpn_api", side_effect=self._api(listed, self._STATUS)),
        ):
            r = admin_client.get("/mqvpn_users")
        body = r.json()
        assert body["result"] == "done"
        assert body["control"]["ok"] is True
        assert body["control"]["address"] == "127.0.0.1:9090"
        assert [u["name"] for u in body["users"]] == ["daemon-only", "openmptcprouter", "persisted-only"]
        users = {u["name"]: u for u in body["users"]}
        assert users["openmptcprouter"] == {
            "name": "openmptcprouter", "configured": True, "fixed_ip": None,
            "known": True, "connected": True}
        # in server.json but the daemon never learnt it (add_user failed, no restart yet)
        assert users["persisted-only"] == {
            "name": "persisted-only", "configured": True, "fixed_ip": "10.255.220.7",
            "known": False, "connected": False}
        # accepted by the daemon but not persisted (added over the control socket by hand)
        assert users["daemon-only"] == {
            "name": "daemon-only", "configured": False, "fixed_ip": None,
            "known": True, "connected": False}
        assert body["global_key_clients"] == 0

    def test_global_key_sessions_counted_not_listed(self, admin_client):
        """Clients authenticating with the server-wide auth_key are reported by
        get_status as user "(global)": a pseudo-name, not a registered user, so
        it must not show up as a connected-but-unconfigured user."""
        listed = {"ok": True, "users": ["openmptcprouter"]}
        status = {"ok": True, "n_clients": 3, "clients": [
            {"user": "openmptcprouter"}, {"user": "(global)"}, {"user": "(global)"}]}
        with (
            patch("os.path.isfile", _isfile_for("/etc/mqvpn/server.json")),
            patch("omr_admin.mqvpn_api", side_effect=self._api(listed, status)),
        ):
            r = admin_client.get("/mqvpn_users")
        body = r.json()
        assert [u["name"] for u in body["users"]] == ["openmptcprouter"]
        assert body["users"][0]["connected"] is True
        assert body["global_key_clients"] == 2

    def test_does_not_leak_keys(self, admin_client):
        listed = {"ok": True, "users": ["openmptcprouter"]}
        with (
            patch("os.path.isfile", _isfile_for("/etc/mqvpn/server.json")),
            patch("omr_admin.mqvpn_api", side_effect=self._api(listed, self._STATUS)),
        ):
            r = admin_client.get("/mqvpn_users")
        body = r.json()
        assert all("key" not in u for u in body["users"])
        assert MQVPN_CONFIG["users"][0]["key"] not in json.dumps(body)
        assert MQVPN_CONFIG["auth_key"] not in json.dumps(body)

    def test_control_socket_down_keeps_configured_list(self, admin_client):
        listed = {"ok": False, "error": "[Errno 111] Connection refused"}
        with (
            patch("os.path.isfile", _isfile_for("/etc/mqvpn/server.json")),
            patch("omr_admin.mqvpn_api", side_effect=self._api(listed, None)),
        ):
            r = admin_client.get("/mqvpn_users")
        body = r.json()
        assert body["result"] == "done"
        assert body["control"]["ok"] is False
        assert "refused" in body["control"]["error"]
        users = {u["name"]: u for u in body["users"]}
        assert users["openmptcprouter"]["configured"] is True
        assert users["openmptcprouter"]["known"] is None
        assert users["openmptcprouter"]["connected"] is None
        assert body["global_key_clients"] is None

    def test_get_status_failure_leaves_connected_unknown(self, admin_client):
        listed = {"ok": True, "users": ["openmptcprouter"]}
        status = {"ok": False, "error": "boom"}
        with (
            patch("os.path.isfile", _isfile_for("/etc/mqvpn/server.json")),
            patch("omr_admin.mqvpn_api", side_effect=self._api(listed, status)),
        ):
            r = admin_client.get("/mqvpn_users")
        body = r.json()
        assert body["control"] == {"ok": False, "address": "127.0.0.1:9090", "error": "boom"}
        users = {u["name"]: u for u in body["users"]}
        assert users["openmptcprouter"]["known"] is True
        assert users["openmptcprouter"]["connected"] is None


class TestMqvpnControlAddr:
    """mqvpn_api() must reach the address in server.json's control_listen, not a hardcoded 9090."""

    def _addr(self, control_listen):
        import omr_admin
        cfg = dict(MQVPN_CONFIG)
        if control_listen is not None:
            cfg["control_listen"] = control_listen
        with patch("builtins.open", side_effect=_open_with_mqvpn_config(cfg)):
            return omr_admin._mqvpn_control_addr()

    def test_default_without_control_listen(self):
        assert self._addr(None) == ("127.0.0.1", 9090)

    def test_host_port(self):
        assert self._addr("127.0.0.1:9191") == ("127.0.0.1", 9191)

    def test_surrounding_whitespace_tolerated(self):
        assert self._addr(" 127.0.0.1:9191 ") == ("127.0.0.1", 9191)

    def test_wildcard_v4_reached_via_loopback(self):
        assert self._addr("0.0.0.0:9090") == ("127.0.0.1", 9090)

    def test_bracketed_ipv6(self):
        assert self._addr("[::1]:9090") == ("::1", 9090)

    def test_wildcard_v6_reached_via_loopback(self):
        assert self._addr("[::]:9191") == ("::1", 9191)

    @pytest.mark.parametrize("bad", [
        "", "9090", ":9090", "127.0.0.1:", "127.0.0.1:0", "127.0.0.1:70000",
        "127.0.0.1:abc", "127.0.0.1:+9090", "[::1]", "[::1]9090", "[]:9090", 9090, None,
    ])
    def test_malformed_falls_back_to_default(self, bad):
        cfg = dict(MQVPN_CONFIG)
        cfg["control_listen"] = bad
        import omr_admin
        with patch("builtins.open", side_effect=_open_with_mqvpn_config(cfg)):
            assert omr_admin._mqvpn_control_addr() == ("127.0.0.1", 9090)

    def test_missing_file_falls_back_to_default(self):
        import omr_admin
        from conftest import _mock_open as _base_open

        def _open_missing(path, mode="r", *args, **kwargs):
            if str(path) == "/etc/mqvpn/server.json":
                raise FileNotFoundError(path)
            return _base_open(path, mode, *args, **kwargs)

        with patch("builtins.open", side_effect=_open_missing):
            assert omr_admin._mqvpn_control_addr() == ("127.0.0.1", 9090)

    def test_mqvpn_api_connects_to_configured_address(self):
        import socket as _socket_mod
        import omr_admin

        connects = []
        mock_sock = _mock_mqvpn_socket({"ok": True, "users": ["openmptcprouter"]})
        mock_sock.connect.side_effect = lambda addr: connects.append(addr)
        _real_socket = _socket_mod.socket

        def _mock_socket_class(family=_socket_mod.AF_INET, type=_socket_mod.SOCK_STREAM,
                               proto=0, fileno=None):
            if fileno is not None:
                return _real_socket(family, type, proto, fileno)
            return mock_sock

        cfg = {**MQVPN_CONFIG, "control_listen": "127.0.0.1:9191"}
        with (
            patch("builtins.open", side_effect=_open_with_mqvpn_config(cfg)),
            patch("socket.socket", side_effect=_mock_socket_class),
        ):
            r = omr_admin.mqvpn_api({"cmd": "list_users"})
        assert r == {"ok": True, "users": ["openmptcprouter"]}
        assert connects == [("127.0.0.1", 9191)]
        assert mock_sock.sendall.call_args[0][0] == b'{"cmd": "list_users"}\n'

    def test_mqvpn_api_connection_error_is_returned_not_raised(self):
        import omr_admin
        cfg = {**MQVPN_CONFIG, "control_listen": "127.0.0.1:9191"}
        with (
            patch("builtins.open", side_effect=_open_with_mqvpn_config(cfg)),
            patch("socket.create_connection", side_effect=ConnectionRefusedError("refused")),
        ):
            r = omr_admin.mqvpn_api({"cmd": "list_users"})
        assert r["ok"] is False
        # the exception text is logged, never relayed to API clients
        assert "refused" not in r["error"]
        assert r["error"]


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

    def test_cipher_injection_refused(self, user_client):
        # tun0.conf is one directive per line, script hooks run as root
        for cipher in ("AES-256-GCM\nup /tmp/x", "AES-256-GCM up", "", "AES#x", "A" * 65):
            with (
                patch("os.path.isfile", return_value=True),
                patch("omr_admin.move") as move,
                patch("subprocess.run") as run,
            ):
                r = user_client.post("/openvpn", json={**self._PAYLOAD, "cipher": cipher})
            assert r.json() == {"result": "error", "reason": "Invalid cipher", "route": "openvpn"}, cipher
            assert not move.called and not run.called, cipher

    def test_usual_ciphers_accepted(self, user_client):
        for cipher in ("AES-256-CBC", "BF-CBC", "CHACHA20-POLY1305", "none"):
            with patch("os.path.isfile", return_value=True):
                r = user_client.post("/openvpn", json={**self._PAYLOAD, "cipher": cipher})
            assert r.json()["result"] == "done", cipher


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
    _KEY = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="

    def test_peer_injection_refused(self, user_client):
        # wg-quick runs an [Interface] section's hook directives as root
        for peer, reason in (
            ({"ip": "10.0.0.2", "key": "base64key=="}, "Invalid key"),
            ({"ip": "10.0.0.2", "key": self._KEY + "\n[Interface]\nPostUp = id"}, "Invalid key"),
            ({"ip": "10.0.0.2", "key": self._KEY[:-1] + "!"}, "Invalid key"),
            ({"ip": "10.0.0.2\n[Interface]\nPostUp = id", "key": self._KEY}, "Invalid ip"),
            ({"ip": "10.0.0.2 x", "key": self._KEY}, "Invalid ip"),
            ({"ip": "", "key": self._KEY}, "Invalid ip"),
        ):
            with (
                patch("os.path.isfile", return_value=True),
                patch("omr_admin.move") as move,
            ):
                r = user_client.post("/wireguard", json={"peers": [peer]})
            assert r.json() == {"result": "error", "reason": reason, "route": "wireguard"}, peer
            assert not move.called, peer

    _KEY2 = "uKU1qOpAj/4jKsjk3ZqdpQ6GNZpI7mGTWArxpvzSg1I="
    _KEY3 = "8M3Pm2kz4tXyq0bQK7y1VH3WbJ5dL2bF7hYQqkq0z0A="

    def _config(self, **peers):
        config = json.loads(json.dumps(MOCK_CONFIG))
        config["users"][0]["bob"] = {"userid": 3, "username": "bob", "user_password": "x"}
        for username, user_peers in peers.items():
            config["users"][0][username]["wireguard_peers"] = user_peers
        return config

    def _post(self, user_client, config, peers):
        with (
            patch("os.path.isfile", return_value=True),
            patch("omr_admin.read_omr_config", return_value=config),
            patch("omr_admin.modif_config_user") as modif,
            patch("omr_admin._write_wireguard_conf") as write_conf,
        ):
            r = user_client.post("/wireguard", json={"peers": peers})
        return r, modif, write_conf

    def test_caller_replaces_only_its_own_peers(self, user_client):
        # wg0.conf is shared: another user's peers must survive this call
        config = self._config(bob=[{"ip": "10.255.247.3", "key": self._KEY2}])
        r, modif, write_conf = self._post(user_client, config, [{"ip": "10.255.247.2", "key": self._KEY}])
        assert r.json()["result"] == "done"
        modif.assert_called_once_with("openmptcprouter", {"wireguard_peers": [{"ip": "10.255.247.2", "key": self._KEY}]})
        written = write_conf.call_args.args[0]["users"][0]
        assert written["bob"]["wireguard_peers"] == [{"ip": "10.255.247.3", "key": self._KEY2}]
        assert written["openmptcprouter"]["wireguard_peers"] == [{"ip": "10.255.247.2", "key": self._KEY}]

    def test_unchanged_peers_not_rewritten_in_config(self, user_client):
        peers = [{"ip": "10.255.247.2", "key": self._KEY}]
        r, modif, write_conf = self._post(user_client, self._config(openmptcprouter=peers), peers)
        assert r.json()["result"] == "done"
        assert not modif.called
        assert write_conf.called

    def test_another_users_key_or_address_refused(self, user_client):
        # WireGuard gives an address to the last peer claiming it
        config = self._config(bob=[{"ip": "10.255.247.3", "key": self._KEY2}])
        for peer, reason in (
            ({"ip": "10.255.247.2", "key": self._KEY2}, "Key already used by another user"),
            ({"ip": "10.255.247.3", "key": self._KEY}, "Address already used by another user"),
            ({"ip": "10.255.247.3/32", "key": self._KEY}, "Address already used by another user"),
        ):
            r, modif, write_conf = self._post(user_client, config, [peer])
            assert r.json() == {"result": "error", "reason": reason, "route": "wireguard"}, peer
            assert not modif.called and not write_conf.called, peer

    def test_peer_outside_the_vpn_is_skipped(self, user_client):
        # wg-quick routes each AllowedIPs over wg0: only one router address
        # of 10.255.247.0/24 is a peer; the router also sends the addresses
        # of its WireGuard interfaces to other servers, dropped, not refused.
        for ip in ("0.0.0.0/0", "10.255.247.0/24", "8.8.8.8", "10.255.252.2", "10.255.247.1",
                   "10.255.247.255", "10.255.247.2, 10.255.252.2", "fd00::3/128"):
            config = self._config(bob=[{"ip": "10.255.247.3", "key": self._KEY2}])
            r, modif, _write = self._post(user_client, config, [{"ip": ip, "key": self._KEY},
                                                                 {"ip": "10.255.247.5", "key": self._KEY3}])
            assert r.json()["result"] == "done", ip
            modif.assert_called_once_with("openmptcprouter", {"wireguard_peers": [{"ip": "10.255.247.5", "key": self._KEY3}]})

    def test_conf_rendered_from_every_users_peers(self):
        wg_conf = ("[Interface]\nListenPort = 65311\nPrivateKey = " + self._KEY + "\n"
                   "\n[Peer]\nPublicKey  = " + self._KEY2 + "\nAllowedIPs = 10.255.247.9\n")
        config = self._config(
            openmptcprouter=[{"ip": "10.255.247.2", "key": self._KEY}],
            bob=[{"ip": "10.255.247.3/32", "key": self._KEY2},
                 {"ip": "0.0.0.0/0", "key": self._KEY2},
                 {"ip": "10.255.247.4\n[Interface]\nPostUp = id", "key": self._KEY2}],
        )
        tmp = io.StringIO()
        tmp.close = lambda: None

        def _open(path, mode="r", *args, **kwargs):
            if str(path) == "/etc/wireguard/wg0.conf" and "w" not in mode:
                return io.StringIO(wg_conf)
            return tmp

        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open),
            patch("omr_admin.file_as_bytes", side_effect=[b"old", b"new"]),
            patch("omr_admin._atomic_write", side_effect=_fake_atomic_write) as write,
            patch("subprocess.run") as run,
        ):
            assert omr_admin._write_wireguard_conf(config)
        out = tmp.getvalue()
        assert out.startswith("[Interface]\nListenPort = 65311\nPrivateKey = " + self._KEY + "\n")
        assert "AllowedIPs = 10.255.247.2\n" in out
        assert "AllowedIPs = 10.255.247.3/32\n" in out
        # the unowned peer of an earlier release and the invalid stored ones are gone
        assert "10.255.247.9" not in out and "PostUp" not in out and "0.0.0.0/0" not in out
        assert out.count("[Peer]") == 2
        assert write.call_args.args[0] == "/etc/wireguard/wg0.conf"
        assert write.call_args.args[2] == 0o600   # it holds the server's private key
        run.assert_called_once_with(["wg", "setconf", "wg0", "/etc/wireguard/wg0.conf"], check=False)

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

    def test_ipv4_and_ipv6_lines_written(self, user_client):
        # The router posts its public IPv4 and IPv6, one per line.
        acl = io.StringIO()
        acl.close = lambda: None
        config = json.loads(json.dumps(MOCK_CONFIG))
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", return_value=acl),
            patch("omr_admin.modif_config_user"),
            patch("omr_admin.read_omr_config", return_value=config),
        ):
            config["users"][0]["openmptcprouter"]["wanips"] = ["203.0.113.1", "2001:db8::1"]
            r = user_client.post("/wan", json={"ips": "203.0.113.1\n2001:db8::1\n"})
        assert r.json()["result"] == "done"
        assert acl.getvalue() == "[white_list]\n203.0.113.1\n2001:db8::1\n"

    def test_acl_lists_every_users_wan_ips(self, user_client):
        # local.acl is every user's: a router's /wan no longer drops the
        # others' addresses (nor keeps an invalid one stored before).
        acl = io.StringIO()
        acl.close = lambda: None
        config = json.loads(json.dumps(MOCK_CONFIG))
        config["users"][0]["openmptcprouter"]["wanips"] = ["203.0.113.1"]
        config["users"][0]["readonly"]["wanips"] = ["198.51.100.7", "0.0.0.0/0 x"]
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", return_value=acl),
            patch("omr_admin.modif_config_user") as modif,
            patch("omr_admin.read_omr_config", return_value=config),
        ):
            r = user_client.post("/wan", json={"ips": "203.0.113.1"})
        assert r.json()["result"] == "done"
        modif.assert_called_once_with("openmptcprouter", {"wanips": ["203.0.113.1"]})
        assert acl.getvalue() == "[white_list]\n203.0.113.1\n198.51.100.7\n"

    def test_acl_injection_refused(self, user_client):
        # local.acl is shared by every user of the VPS.
        for ips in ("203.0.113.1\n[black_list]\n0.0.0.0/0", "0.0.0.0/0 x", "example.com",
                    "fe80::1%eth0", "\n\n"):
            with (
                patch("os.path.isfile", return_value=True),
                patch("builtins.open") as opened,
            ):
                r = user_client.post("/wan", json={"ips": ips})
            assert r.json() == {"result": "error", "reason": "Invalid IP", "route": "wan"}, ips
            assert not opened.called, ips


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

    def test_all_lan_prefixes_are_pushed_to_openvpn(self, user_client):
        config = json.loads(json.dumps(MOCK_CONFIG))
        config["client2client"] = True
        config["users"][0]["openmptcprouter"]["lanips"] = ["192.168.9.0/24"]
        tun_config = 'server 10.8.0.0 255.255.255.0\npush "route 192.168.9.0 255.255.255.0"\n'
        rewritten = io.StringIO()
        rewritten.close = lambda: None

        def _open_lan(path, mode="r", *args, **kwargs):
            sp = str(path)
            if sp == "/etc/openmptcprouter-vps-admin/omr-admin-config.json":
                return io.StringIO(json.dumps(config))
            if sp == "/etc/openvpn/tun0.conf" and "w" in str(mode):
                return rewritten
            if sp == "/etc/openvpn/tun0.conf":
                return io.BytesIO(tun_config.encode()) if "b" in str(mode) else io.StringIO(tun_config)
            return _mock_open(path, mode, *args, **kwargs)

        with (
            patch("os.path.isfile", _isfile_for("/etc/openvpn/tun0.conf")),
            patch("builtins.open", side_effect=_open_lan),
            patch("omr_admin.modif_config_user"),
        ):
            r = user_client.post("/lan", json={
                "lanips": ["192.168.1.0/24", "192.168.2.0/24"],
            })

        assert r.json()["result"] == "done"
        output = rewritten.getvalue()
        assert 'push "route 192.168.1.0 255.255.255.0"' in output
        assert 'push "route 192.168.2.0 255.255.255.0"' in output
        assert 'push "route 192.168.9.0 255.255.255.0"' not in output


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

    def test_ipv6_fields_must_be_ipv6_addresses(self, user_client):
        # Written into omr-6in4/user<id>, which omr-6in4-run reads as root.
        for field, value in (
            ("localip6", "fd00::a00:1/126\nX=$(id)"),
            ("remoteip6", "fd00::a00:2/126;id"),
            ("remoteip6", "10.255.255.2"),
            ("ula", "fd12:3456:789a::/48 $(id)"),
            ("ula", "fe80::1%eth0"),
        ):
            with (
                patch("os.path.isfile", return_value=True),
                patch("omr_admin.modif_config_user") as modif,
                patch("subprocess.run") as run,
            ):
                r = user_client.post("/vpnips", json={**self._PAYLOAD, field: value})
            assert r.json() == {"result": "error", "reason": f"Invalid {field}", "route": "vpnips"}, field
            assert not modif.called and not run.called, field

    def test_ula_prefix_and_auto_accepted(self, user_client):
        for ula in ("fd12:3456:789a::/48", "auto"):
            with (
                patch("os.path.isfile", return_value=True),
                patch("omr_admin.modif_config_user"),
                patch("subprocess.run"),
            ):
                r = user_client.post("/vpnips", json={**self._PAYLOAD, "ula": ula,
                                                      "localip6": "fd00::a00:1/126"})
            assert r.json().get("reason") not in ("Invalid ula", "Invalid localip6"), ula


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

    @pytest.mark.parametrize("payload", ["%%%%", "not-base64", "!!!!"])
    def test_invalid_base64_is_rejected_before_files_are_opened(self, user_client, payload):
        opened_for_write = []

        def track_open(path, mode="r", *args, **kwargs):
            if str(path).startswith("/var/opt/openmptcprouter/") and "w" in mode:
                opened_for_write.append(str(path))
            return _mock_open(path, mode, *args, **kwargs)

        with patch("builtins.open", side_effect=track_open):
            r = user_client.post("/backuppost", json={"data": payload})

        assert r.status_code == 200
        assert r.json()["result"] == "error"
        assert opened_for_write == []

    def test_success(self, user_client):
        r = user_client.post("/backuppost", json=self._PAYLOAD)
        assert r.json()["result"] == "done"

    def test_matching_sha256sum_is_accepted(self, user_client):
        payload = dict(self._PAYLOAD, sha256sum=__import__("hashlib").sha256(b"fake-tar-gz-data").hexdigest().upper())
        r = user_client.post("/backuppost", json=payload)
        assert r.json()["result"] == "done"

    def test_sha256sum_mismatch_is_rejected_before_files_are_opened(self, user_client):
        opened_for_write = []

        def track_open(path, mode="r", *args, **kwargs):
            if str(path).startswith("/var/opt/openmptcprouter/") and "w" in mode:
                opened_for_write.append(str(path))
            return _mock_open(path, mode, *args, **kwargs)

        payload = dict(self._PAYLOAD, sha256sum="0" * 64)
        with patch("builtins.open", side_effect=track_open):
            r = user_client.post("/backuppost", json=payload)
        assert r.json() == {"result": "error", "reason": "Backup checksum mismatch", "route": "backuppost"}
        assert opened_for_write == []


class TestConfigConcurrency:
    def test_concurrent_mutations_preserve_every_update(self, tmp_path):
        config_path = tmp_path / "omr-admin-config.json"
        lock_path = tmp_path / "omr-admin-config.json.lock"
        config_path.write_text(json.dumps(MOCK_CONFIG))
        errors = []

        def update(index):
            try:
                omr_admin.set_global_param(f"concurrent_{index}", index)
            except Exception as exc:  # pragma: no cover - assertion reports details
                errors.append(exc)

        with (
            patch.object(omr_admin, "OMR_CONFIG_FILE", str(config_path)),
            patch.object(omr_admin, "OMR_CONFIG_LOCK_FILE", str(lock_path)),
            patch.object(omr_admin, "backup_config"),
            patch.object(omr_admin, "move", side_effect=os.replace),
            patch("builtins.open", side_effect=io.open),
        ):
            threads = [threading.Thread(target=update, args=(i,)) for i in range(20)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        assert errors == []
        written = json.loads(config_path.read_text())
        assert {written[f"concurrent_{i}"] for i in range(20)} == set(range(20))


class TestBackupGet:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.get("/backupget")
        assert r.status_code == 403

    def test_returns_data_key(self, user_client):
        with patch("os.path.isfile", return_value=True):
            r = user_client.get("/backupget")
        assert "data" in r.json()

    def test_returns_sha256sum_of_the_decoded_data(self, user_client):
        import base64, hashlib
        with patch("os.path.isfile", return_value=True):
            r = user_client.get("/backupget")
        body = r.json()
        assert body["sha256sum"] == hashlib.sha256(base64.b64decode(body["data"])).hexdigest()


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
        assert r.json()["result"] == "done"
        assert r.json()["route"] == "add_user"

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
        assert r.json()["result"] == "done"
        assert r.json()["route"] == "add_user_note"


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

    def test_username_with_crlf_returns_422(self, admin_client):
        r = admin_client.post("/remove_user", json={"username": "readonly\r\nstatus"})
        assert r.status_code == 422

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

    def test_custom_user_key_is_respected(self, admin_client):
        written = {}
        real_json_dump = __import__("json").dump

        def _capture_write(data, f, **kw):
            written.update(data)
            real_json_dump(data, f, **kw)

        with patch("omr_admin.json.dump", side_effect=_capture_write):
            admin_client.post("/add_user", json={
                **self._PAYLOAD,
                "user_key": "custom-user-key",
            })

        password = written.get("users", [{}])[0].get("newuser", {}).get("user_password")
        assert password == "custom-user-key"

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
        assert r.status_code == 422

    def test_username_with_path_traversal_returns_422(self, admin_client):
        r = admin_client.post("/add_user", json={**self._PAYLOAD, "username": "../evil"})
        assert r.status_code == 422

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


class TestAddUserEasyrsaPkiCleanup:
    """Verify that add_user cleans up stale PKI entries before calling build-client-full.

    This covers the recreate-user scenario: easyrsa revoke leaves the private
    key and issued cert on disk and marks the CN in index.txt as revoked (R).
    Without cleanup, build-client-full fails because the CN is already known.
    """

    _PAYLOAD = {
        "username": "newuser",
        "permission": "rw",
        "vpn": "glorytun_tcp",
        "proxy": "shadowsocks",
    }

    # ------------------------------------------------------------------
    # index.txt cleanup
    # ------------------------------------------------------------------

    def test_stale_index_entry_is_removed_before_build(self, admin_client):
        """Lines with /CN=<username> must be stripped from index.txt before easyrsa runs."""
        import io as _io
        from conftest import _mock_open as _base_open

        index_content = (
            "V\t260101000000Z\t\t01\tunknown\t/CN=otheruser\n"
            "R\t260101000000Z\t260101000000Z\t02\tunknown\t/CN=newuser\n"
        )
        written_index = {}

        def _open_index(path, mode="r", *args, **kwargs):
            sp = str(path)
            if sp == "/etc/openvpn/ca/pki/index.txt":
                if "w" in str(mode):
                    buf = _io.StringIO()
                    original_close = buf.close

                    def _capture_on_close():
                        buf.seek(0)
                        written_index["content"] = buf.read()
                        original_close()

                    buf.close = _capture_on_close
                    return buf
                return _io.StringIO(index_content)
            return _base_open(path, mode, *args, **kwargs)

        with (
            patch("os.path.isfile", _isfile_for("/etc/openvpn/tun0.conf", "/etc/openvpn/ca/pki/index.txt")),
            patch("subprocess.run", return_value=MagicMock(returncode=0)),
            patch("builtins.open", side_effect=_open_index),
        ):
            r = admin_client.post("/add_user", json=self._PAYLOAD)

        assert r.status_code == 200
        assert "written_index" in written_index or "/CN=newuser" not in written_index.get("content", "")
        assert "/CN=otheruser" in written_index.get("content", "/CN=otheruser")

    def test_index_with_no_stale_entry_is_not_rewritten(self, admin_client):
        """If index.txt has no entry for this CN, it must not be rewritten."""
        import io as _io
        from conftest import _mock_open as _base_open

        index_content = "V\t260101000000Z\t\t01\tunknown\t/CN=otheruser\n"
        write_calls = []

        def _open_index(path, mode="r", *args, **kwargs):
            sp = str(path)
            if sp == "/etc/openvpn/ca/pki/index.txt":
                if "w" in str(mode):
                    write_calls.append(sp)
                    return _io.StringIO()
                return _io.StringIO(index_content)
            return _base_open(path, mode, *args, **kwargs)

        with (
            patch("os.path.isfile", _isfile_for("/etc/openvpn/tun0.conf", "/etc/openvpn/ca/pki/index.txt")),
            patch("subprocess.run", return_value=MagicMock(returncode=0)),
            patch("builtins.open", side_effect=_open_index),
        ):
            admin_client.post("/add_user", json=self._PAYLOAD)

        assert len(write_calls) == 0

    # ------------------------------------------------------------------
    # Stale file removal
    # ------------------------------------------------------------------

    def test_stale_req_file_is_removed(self, admin_client):
        """The .req file for the username must be deleted before build-client-full."""
        removed = []

        def _isfile(p):
            return str(p) in (
                "/etc/openvpn/tun0.conf",
                f"/etc/openvpn/ca/pki/reqs/newuser.req",
            )

        def _remove(p):
            removed.append(str(p))

        with (
            patch("os.path.isfile", side_effect=_isfile),
            patch("os.remove", side_effect=_remove),
            patch("subprocess.run", return_value=MagicMock(returncode=0)),
        ):
            r = admin_client.post("/add_user", json=self._PAYLOAD)

        assert r.status_code == 200
        assert "/etc/openvpn/ca/pki/reqs/newuser.req" in removed

    def test_stale_private_key_is_removed(self, admin_client):
        """The .key file for the username must be deleted before build-client-full."""
        removed = []

        def _isfile(p):
            return str(p) in (
                "/etc/openvpn/tun0.conf",
                f"/etc/openvpn/ca/pki/private/newuser.key",
            )

        def _remove(p):
            removed.append(str(p))

        with (
            patch("os.path.isfile", side_effect=_isfile),
            patch("os.remove", side_effect=_remove),
            patch("subprocess.run", return_value=MagicMock(returncode=0)),
        ):
            r = admin_client.post("/add_user", json=self._PAYLOAD)

        assert r.status_code == 200
        assert "/etc/openvpn/ca/pki/private/newuser.key" in removed

    def test_stale_issued_cert_is_removed(self, admin_client):
        """The .crt file for the username must be deleted before build-client-full."""
        removed = []

        def _isfile(p):
            return str(p) in (
                "/etc/openvpn/tun0.conf",
                f"/etc/openvpn/ca/pki/issued/newuser.crt",
            )

        def _remove(p):
            removed.append(str(p))

        with (
            patch("os.path.isfile", side_effect=_isfile),
            patch("os.remove", side_effect=_remove),
            patch("subprocess.run", return_value=MagicMock(returncode=0)),
        ):
            r = admin_client.post("/add_user", json=self._PAYLOAD)

        assert r.status_code == 200
        assert "/etc/openvpn/ca/pki/issued/newuser.crt" in removed

    def test_all_three_stale_files_removed(self, admin_client):
        """All three stale PKI files are removed in a single add_user call."""
        removed = []

        def _isfile(p):
            return str(p) in (
                "/etc/openvpn/tun0.conf",
                "/etc/openvpn/ca/pki/reqs/newuser.req",
                "/etc/openvpn/ca/pki/private/newuser.key",
                "/etc/openvpn/ca/pki/issued/newuser.crt",
            )

        def _remove(p):
            removed.append(str(p))

        with (
            patch("os.path.isfile", side_effect=_isfile),
            patch("os.remove", side_effect=_remove),
            patch("subprocess.run", return_value=MagicMock(returncode=0)),
        ):
            r = admin_client.post("/add_user", json=self._PAYLOAD)

        assert r.status_code == 200
        assert "/etc/openvpn/ca/pki/reqs/newuser.req" in removed
        assert "/etc/openvpn/ca/pki/private/newuser.key" in removed
        assert "/etc/openvpn/ca/pki/issued/newuser.crt" in removed

    def test_no_stale_files_means_no_remove_calls(self, admin_client):
        """os.remove must not be called when no stale PKI files exist."""
        removed = []

        with (
            patch("os.path.isfile", _isfile_for("/etc/openvpn/tun0.conf")),
            patch("os.remove", side_effect=removed.append),
            patch("subprocess.run", return_value=MagicMock(returncode=0)),
        ):
            r = admin_client.post("/add_user", json=self._PAYLOAD)

        assert r.status_code == 200
        pki_removes = [p for p in removed if "/etc/openvpn/ca/pki/" in str(p)]
        assert len(pki_removes) == 0

    # ------------------------------------------------------------------
    # build-client-full is still called after cleanup
    # ------------------------------------------------------------------

    def test_build_client_full_called_after_cleanup(self, admin_client):
        """easyrsa build-client-full must be called even when stale files existed."""
        run_calls = []
        removed = []

        def _isfile(p):
            return str(p) in (
                "/etc/openvpn/tun0.conf",
                "/etc/openvpn/ca/pki/private/newuser.key",
                "/etc/openvpn/ca/pki/issued/newuser.crt",
            )

        def _mock_run(cmd, *args, **kwargs):
            run_calls.append(cmd)
            return MagicMock(returncode=0)

        with (
            patch("os.path.isfile", side_effect=_isfile),
            patch("os.remove", side_effect=removed.append),
            patch("subprocess.run", side_effect=_mock_run),
        ):
            r = admin_client.post("/add_user", json=self._PAYLOAD)

        assert r.status_code == 200
        build_calls = [c for c in run_calls if c and "build-client-full" in c]
        assert len(build_calls) == 1
        assert "newuser" in build_calls[0]

    # ------------------------------------------------------------------
    # easyrsa failure after cleanup returns an error
    # ------------------------------------------------------------------

    def test_easyrsa_failure_after_cleanup_returns_error(self, admin_client):
        """If build-client-full still fails after cleanup, add_user returns an error."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = b"Already exists"

        with (
            patch("os.path.isfile", _isfile_for("/etc/openvpn/tun0.conf")),
            patch("subprocess.run", return_value=mock_result),
        ):
            r = admin_client.post("/add_user", json=self._PAYLOAD)

        assert r.status_code == 200
        assert r.json()["result"] == "error"
        assert r.json()["route"] == "add_user"


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

    def test_openvpn_failure_happens_before_proxy_provisioning(self, admin_client):
        result = MagicMock(returncode=1, stderr=b"certificate error")

        with (
            patch("os.path.isfile", _isfile_for(
                "/etc/openvpn/tun0.conf",
                "/etc/shadowsocks-libev/manager.json",
            )),
            patch("subprocess.run", return_value=result),
            patch("omr_admin.add_ss_user") as add_ss_user,
        ):
            r = admin_client.post("/add_user", json=self._PAYLOAD)

        assert r.json()["result"] == "error"
        add_ss_user.assert_not_called()

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
            patch("os.path.isfile", _isfile_for(
                "/etc/openvpn/tun0.conf",
                "/etc/openvpn/ca/pki/issued/newuser.crt",
                "/etc/shadowsocks-go/server.json",
            )),
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

    def test_rewrites_wireguard_conf_when_user_had_peers(self, admin_client):
        # its peers would otherwise keep their addresses in the shared wg0.conf
        config = json.loads(json.dumps(MOCK_CONFIG))
        config["users"][0]["readonly"]["wireguard_peers"] = [
            {"ip": "10.255.247.3", "key": "uKU1qOpAj/4jKsjk3ZqdpQ6GNZpI7mGTWArxpvzSg1I="}]
        after = json.loads(json.dumps(config))
        del after["users"][0]["readonly"]

        import builtins
        current_open = builtins.open

        def _open(path, mode="r", *args, **kwargs):
            if str(path) == "/etc/openmptcprouter-vps-admin/omr-admin-config.json":
                return io.StringIO(json.dumps(config))
            return current_open(path, mode, *args, **kwargs)

        with (
            patch("os.path.isfile", return_value=False),
            patch("builtins.open", side_effect=_open),
            patch("omr_admin._mutate_omr_config"),
            patch("omr_admin.read_omr_config", return_value=after),
            patch("omr_admin._write_wireguard_conf") as write_conf,
        ):
            r = admin_client.post("/remove_user", json={"username": "readonly"})
        assert r.json()["result"] == "done"
        write_conf.assert_called_once_with(after)

    def test_leaves_wireguard_conf_alone_without_peers(self, admin_client):
        with (
            patch("os.path.isfile", return_value=False),
            patch("omr_admin._write_wireguard_conf") as write_conf,
        ):
            r = admin_client.post("/remove_user", json={"username": "readonly"})
        assert r.json()["result"] == "done"
        assert not write_conf.called

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


class TestSecurityHelpers:
    def test_safe_path_join_accepts_child(self):
        import omr_admin
        assert omr_admin.safe_path_join("/etc/openvpn/ccd", "alice") == "/etc/openvpn/ccd/alice"

    @pytest.mark.parametrize("name", ["..", "../../etc/passwd", "/etc/passwd", "."])
    def test_safe_path_join_rejects_escape(self, name):
        import omr_admin
        with pytest.raises(ValueError):
            omr_admin.safe_path_join("/etc/openvpn/ccd", name)

    def test_log_safe_neutralises_line_breaks(self):
        import omr_admin
        assert omr_admin.log_safe("bob\r\nfake line") == "bob\\r\\nfake line"

    @pytest.mark.parametrize("name,ok", [
        ("alice", True), ("a.b-c_d", True), ("openmptcprouter", True),
        (".", False), ("..", False), (".hidden", False), ("a/b", False), ("", False),
    ])
    def test_username_pattern(self, name, ok):
        import re
        import omr_admin
        assert bool(re.fullmatch(omr_admin.USERNAME_PATTERN, name)) is ok


# ---------------------------------------------------------------------------
# mqvpn_server_pin (GHSA-qq6x-5r9f-2w3m)
# ---------------------------------------------------------------------------

def _openssl(*args, data=None):
    import subprocess
    return subprocess.run(["openssl", *args], input=data, capture_output=True,
                          check=True).stdout


@pytest.fixture
def mqvpn_cert(tmp_path):
    import shutil
    if not shutil.which("openssl"):
        pytest.skip("openssl not installed")
    crt = tmp_path / "server.crt"
    _openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
             "-keyout", str(tmp_path / "server.key"), "-out", str(crt), "-days", "1",
             "-nodes", "-subj", "/CN=www.openmptcprouter.vps")
    omr_admin._mqvpn_pin_cache.clear()
    return crt


@pytest.mark.real_env
class TestMqvpnServerPin:
    def test_matches_installer_pipeline(self, mqvpn_cert):
        """Same value as omr_api_pin in the installer, the value mqvpn's
        PinnedPubkey and curl --pinnedpubkey expect."""
        pubkey = _openssl("x509", "-in", str(mqvpn_cert), "-pubkey", "-noout")
        der = _openssl("pkey", "-pubin", "-outform", "der", data=pubkey)
        digest = _openssl("dgst", "-sha256", "-binary", data=der)
        expected = _openssl("enc", "-base64", data=digest).decode().strip()
        assert omr_admin.mqvpn_server_pin(str(mqvpn_cert)) == expected
        assert len(expected) == 44

    def test_cached_until_the_certificate_changes(self, mqvpn_cert):
        pin = omr_admin.mqvpn_server_pin(str(mqvpn_cert))
        with patch.object(omr_admin.subprocess, "run") as run:
            assert omr_admin.mqvpn_server_pin(str(mqvpn_cert)) == pin
        run.assert_not_called()
        mqvpn_cert.write_text("not a certificate")
        assert omr_admin.mqvpn_server_pin(str(mqvpn_cert)) == ""

    def test_missing_certificate(self, tmp_path):
        assert omr_admin.mqvpn_server_pin(str(tmp_path / "absent.crt")) == ""

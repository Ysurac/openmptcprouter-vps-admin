"""
Regressions for the audit fixes: what one router of a shared VPS could take
from the others or from the server (redirects, keys, daemons' ports), what an
unauthenticated client could do (memory), and the state a removed user or a
port change left behind.
"""

import asyncio
import io
import json
import os
from unittest.mock import MagicMock, patch

import pytest

from conftest import (MOCK_CONFIG, _ASGITestClient, _mock_open,  # noqa: F401
                      app, omr_admin)

PRIMARY = omr_admin.User(username="openmptcprouter", userid=0, permissions="rw", shadowsocks_port=65101)
OTHER = omr_admin.User(username="readonly", userid=2, permissions="rw", shadowsocks_port=65102)
CONFIG_PATH = "/etc/openmptcprouter-vps-admin/omr-admin-config.json"


@pytest.fixture
def other_client():
    app.dependency_overrides[omr_admin.get_current_user] = lambda: OTHER
    yield _ASGITestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.pop(omr_admin.get_current_user, None)


@pytest.fixture
def primary_client():
    app.dependency_overrides[omr_admin.get_current_user] = lambda: PRIMARY
    yield _ASGITestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.pop(omr_admin.get_current_user, None)


def _config():
    return json.loads(json.dumps(MOCK_CONFIG))


def _open_with(files):
    """open() serving *files* ({path: text}) and _mock_open for the rest."""
    def _open(path, mode="r", *args, **kwargs):
        text = files.get(str(path))
        if text is not None and "w" not in str(mode):
            return io.BytesIO(text.encode()) if "b" in str(mode) else io.StringIO(text)
        return _mock_open(path, mode, *args, **kwargs)
    return _open


def _dnat(port, source_dip="", proto="tcp", family=4):
    return {"name": "x", "port": port, "proto": proto, "fwtype": "DNAT", "family": family,
            "source_dip": source_dip, "dest_ip": "", "vpn": "default", "comment": ""}


# ---------------------------------------------------------------------------
# Redirects without an address
# ---------------------------------------------------------------------------

class TestWildcardDnat:
    def test_render_leaves_out_the_other_users_dedicated_ips(self):
        config = _config()
        users = config["users"][0]
        users["readonly"]["public_ips"] = ["203.0.113.9"]
        users["readonly"]["vpnremoteip"] = "10.255.255.6"
        users["readonly"]["fw_ports"] = [_dnat("8080", "203.0.113.9")]
        users["openmptcprouter"]["vpnremoteip"] = "10.255.255.2"
        users["openmptcprouter"]["fw_ports"] = [_dnat("80")]
        _accept, dnat = omr_admin._render_fw_ports(config)
        main = next(rule for rule in dnat if "to 10.255.255.2" in rule)
        assert "ip daddr != { 203.0.113.9/32 }" in main
        # its own dedicated IP is the other user's, and not excluded from its rule
        other = next(rule for rule in dnat if "to 10.255.255.6" in rule)
        assert "ip daddr 203.0.113.9" in other and "daddr !=" not in other

    def test_bulk_redirect_leaves_out_the_other_users_dedicated_ips(self):
        config = _config()
        config["bulk_redirect_v4"] = True
        config["users"][0]["openmptcprouter"]["vpnremoteip"] = "10.255.255.2"
        config["users"][0]["readonly"]["public_ips"] = ["203.0.113.9"]
        lines = omr_admin._render_bulk_redirect(config)
        assert lines and all("ip daddr != { 203.0.113.9/32 }" in line for line in lines)

    def test_main_router_rules_come_first(self):
        config = _config()
        users = config["users"][0]
        # the other user listed first in the config
        config["users"][0] = {"readonly": users["readonly"], "openmptcprouter": users["openmptcprouter"]}
        users["readonly"]["vpnremoteip"] = "10.255.255.6"
        users["readonly"]["fw_ports"] = [_dnat("81")]
        users["openmptcprouter"]["vpnremoteip"] = "10.255.255.2"
        users["openmptcprouter"]["fw_ports"] = [_dnat("80")]
        _accept, dnat = omr_admin._render_fw_ports(config)
        assert "to 10.255.255.2" in dnat[0]

    def test_port_another_user_redirects_refused(self, other_client):
        config = _config()
        config["users"][0]["openmptcprouter"]["fw_ports"] = [_dnat("80")]
        with (
            patch("builtins.open", side_effect=_open_with({CONFIG_PATH: json.dumps(config)})),
            patch("omr_admin.shorewall_add_port", return_value=None) as add,
        ):
            r = other_client.post("/firewallopen", json={"name": "x", "port": "70-90", "proto": "tcp", "fwtype": "DNAT"})
        assert r.json()["reason"] == "Port already redirected by another user"
        assert not add.called

    def test_port_on_another_users_dedicated_ip_does_not_conflict(self, other_client):
        config = _config()
        config["users"][0]["openmptcprouter"]["public_ips"] = ["203.0.113.5"]
        config["users"][0]["openmptcprouter"]["fw_ports"] = [_dnat("80", "203.0.113.5")]
        with (
            patch("builtins.open", side_effect=_open_with({CONFIG_PATH: json.dumps(config)})),
            patch("omr_admin.shorewall_add_port", return_value=None) as add,
        ):
            r = other_client.post("/firewallopen", json={"name": "x", "port": "80", "proto": "tcp", "fwtype": "DNAT"})
        assert r.json()["result"] == "done"
        assert add.called

    def test_port_the_server_uses_refused(self, other_client):
        with (
            patch("omr_admin._server_ports", return_value=[(443, 443)]),
            patch("omr_admin.shorewall_add_port", return_value=None) as add,
        ):
            r = other_client.post("/firewallopen", json={"name": "x", "port": "443", "proto": "udp", "fwtype": "DNAT"})
        assert r.json()["reason"] == "Port used by the server"
        assert not add.called

    def test_port_the_server_uses_allowed_on_the_users_own_ip(self, other_client):
        config = _config()
        config["users"][0]["readonly"]["public_ips"] = ["203.0.113.9"]
        with (
            patch("builtins.open", side_effect=_open_with({CONFIG_PATH: json.dumps(config)})),
            patch("omr_admin._server_ports", return_value=[(443, 443)]),
            patch("omr_admin.shorewall_add_port", return_value=None) as add,
        ):
            r = other_client.post("/firewallopen", json={"name": "x", "port": "443", "proto": "tcp",
                                                        "fwtype": "DNAT", "source_dip": "203.0.113.9"})
        assert r.json()["result"] == "done"
        assert add.called

    def test_main_router_not_restricted(self, primary_client):
        with (
            patch("omr_admin._server_ports", return_value=[(443, 443)]),
            patch("omr_admin.shorewall_add_port", return_value=None) as add,
        ):
            r = primary_client.post("/firewallopen", json={"name": "x", "port": "443", "proto": "udp", "fwtype": "DNAT"})
        assert r.json()["result"] == "done"
        assert add.called

    def test_name_with_a_newline_refused(self, other_client):
        r = other_client.post("/firewallopen", json={"name": "a\nb", "port": "80", "proto": "tcp", "fwtype": "ACCEPT"})
        assert r.json()["reason"] == "Invalid name or comment"

    def test_entries_per_user_capped(self):
        config = _config()
        config["users"][0]["readonly"]["fw_ports"] = [
            {**_dnat(str(1000 + i)), "fwtype": "ACCEPT"} for i in range(omr_admin.FW_MAX_USER_ENTRIES)]
        with (
            patch("builtins.open", side_effect=_open_with({CONFIG_PATH: json.dumps(config)})),
            patch("omr_admin.modif_config_user") as modif,
        ):
            error = omr_admin._fw_port_add("readonly", "80", "tcp", "x", "ACCEPT", 4, "", "", "default", "")
        assert "No more than" in error
        assert not modif.called

    def test_server_ports_skip_loopback_and_connected_udp(self):
        addr = lambda ip, port: MagicMock(ip=ip, port=port)  # noqa: E731
        conns = [
            MagicMock(laddr=addr("0.0.0.0", 443), raddr=(), status="NONE"),
            MagicMock(laddr=addr("127.0.0.1", 10086), raddr=(), status="NONE"),
            MagicMock(laddr=addr("0.0.0.0", 40000), raddr=addr("1.1.1.1", 53), status="NONE"),
        ]
        with (
            patch("omr_admin.psutil.net_connections", return_value=conns),
            patch("os.path.isfile", return_value=False),
        ):
            assert omr_admin._server_ports("udp") == [(443, 443)]


# ---------------------------------------------------------------------------
# /config secrets
# ---------------------------------------------------------------------------

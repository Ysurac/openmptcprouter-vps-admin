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

from conftest import (_REAL_OPEN, MOCK_CONFIG, _ASGITestClient,  # noqa: F401
                      _mock_open, app, omr_admin)

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

class TestConfigSecrets:
    def _get(self, client):
        files = {"/etc/wireguard/vpn-client-private.key": "CLIENT-PRIVATE-KEY"}
        real_isfile = os.path.isfile
        with (
            patch("builtins.open", side_effect=_open_with(files)),
            patch("os.path.isfile", side_effect=lambda p: p in files or p == "/etc/mlvpn/mlvpn0.conf" or real_isfile(p)),
        ):
            return client.get("/config").json()

    def test_main_router_gets_them(self, primary_client):
        body = self._get(primary_client)
        assert body["mlvpn"]["key"] == "oldpassword"
        assert body["wireguard"]["client_key"] == "CLIENT-PRIVATE-KEY"
        assert "mlvpn" in body["vpn"]["available"]

    def test_other_router_does_not(self, other_client):
        body = self._get(other_client)
        assert body["mlvpn"]["key"] == ""
        assert body["wireguard"]["client_key"] == ""
        assert "mlvpn" not in body["vpn"]["available"]

    def test_bulk_redirect_state(self, primary_client):
        for state, expected in ((True, "enable"), (False, "disable")):
            config = _config()
            config["bulk_redirect_v4"] = state
            with patch("builtins.open", side_effect=_open_with({CONFIG_PATH: json.dumps(config)})):
                body = primary_client.get("/config").json()
            assert body["shorewall"]["redirect_ports"] == expected


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------

class TestBodyLimit:
    def _run(self, path, size):
        limit = next(m for m in app.user_middleware if m.cls is omr_admin._BodySizeLimit)
        middleware = omr_admin._BodySizeLimit(lambda *a: asyncio.sleep(0), **limit.kwargs)
        sent = []

        async def send(message):
            sent.append(message)

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        scope = {"type": "http", "path": path, "headers": [(b"content-length", str(size).encode())]}
        asyncio.run(middleware(scope, receive, send))
        return sent[0]["status"] if sent else None

    def test_every_path_has_a_limit(self):
        assert self._run("/add_user", omr_admin.REQUEST_MAX_SIZE + 1) == 413
        assert self._run("/add_user", omr_admin.REQUEST_MAX_SIZE) is None

    def test_streamed_speedtest_upload_is_not_limited(self):
        assert self._run("/speedtest", 50 * 1024 * 1024) is None


# ---------------------------------------------------------------------------
# WireGuard
# ---------------------------------------------------------------------------

class TestWireGuardNewline:
    _KEY = "uKU1qOpAj/4jKsjk3ZqdpQ6GNZpI7mGTWArxpvzSg1I="

    def test_newline_in_allowed_ips_refused(self):
        assert omr_admin._wireguard_peer_nets("10.255.247.5,\n10.255.247.6") is None
        assert omr_admin._wireguard_peer_nets("10.255.247.5, 10.255.247.6") is not None

    def test_endpoint_refuses_it(self, other_client):
        r = other_client.post("/wireguard", json={"peers": [{"ip": "10.255.247.5,\n10.255.247.6", "key": self._KEY}]})
        assert r.json()["reason"] == "Invalid ip"


# ---------------------------------------------------------------------------
# OpenVPN certificates
# ---------------------------------------------------------------------------

class TestPkiRetire:
    _INDEX = ("R\t360101000000Z\t250101000000Z\t01\tunknown\t/CN=bob\n"
              "V\t360101000000Z\t\t02\tunknown\t/CN=bob\n"
              "V\t360101000000Z\t\t03\tunknown\t/CN=bobby\n")

    def test_valid_certificate_revoked_and_revoked_one_kept(self):
        written = {}
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open_with({"/etc/openvpn/ca/pki/index.txt": self._INDEX})),
            patch("omr_admin._atomic_write_text", side_effect=lambda p, t, new_mode=0o644: written.update({p: t})),
            patch("omr_admin._openvpn_gen_crl") as gen_crl,
        ):
            assert omr_admin._pki_retire_user_certs("bob")
        lines = written["/etc/openvpn/ca/pki/index.txt"].splitlines()
        assert lines[0] == self._INDEX.splitlines()[0]          # still revoked, still in the CRL
        assert lines[1].startswith("R\t360101000000Z\t") and lines[1].split("\t")[2]
        assert lines[2].startswith("V\t")                        # bobby untouched
        gen_crl.assert_called_once()

    def test_nothing_valid_nothing_written(self):
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open_with({"/etc/openvpn/ca/pki/index.txt": self._INDEX})),
            patch("omr_admin._atomic_write_text") as write,
            patch("omr_admin._openvpn_gen_crl") as gen_crl,
        ):
            assert not omr_admin._pki_retire_user_certs("alice")
        assert not write.called and not gen_crl.called


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

class TestAddUserChecks:
    @pytest.mark.parametrize("payload,reason", [
        ({"username": "readonly"}, "User already exists"),
        ({"username": "admin"}, "User already exists"),
        ({"username": "DEFAULT"}, "Invalid username"),
        ({"username": "u" * 65}, "Invalid username"),
        ({"username": "new", "userid": 2}, "Userid already used"),
        ({"username": "new", "userid": 64}, "Invalid userid, 1 to 63"),
        ({"username": "new", "userid": -1}, "Invalid userid, 1 to 63"),
        ({"username": "new", "user_key": ""}, "Password too short, 8 characters at least"),
        ({"username": "new", "user_key": "MySecretKey"}, "Template password"),
    ])
    def test_refused_before_anything_is_created(self, admin_client, payload, reason):
        with patch("omr_admin._mutate_omr_config") as persist:
            r = admin_client.post("/add_user", json=payload)
        assert r.json()["reason"] == reason
        assert not persist.called

    def test_modify_user_refuses_an_empty_password(self, admin_client):
        r = admin_client.post("/modify_user", json={"username": "readonly", "user_password": ""})
        assert r.json()["result"] == "error"

    def test_empty_stored_password_never_logs_in(self):
        users = {"bob": {"username": "bob", "user_password": "", "permissions": "rw", "userid": 3}}
        assert not omr_admin.authenticate_user(users, "bob", "")

    def test_shadowsocks_port_stored_is_the_one_created(self, admin_client):
        created = []

        def _add(port, key, userid=0, ip=''):
            created.append(port)
            return 65110 + len(created) - 1

        with (
            patch("os.path.isfile", side_effect=lambda p: p == "/etc/shadowsocks-libev/manager.json"),
            patch("omr_admin.add_ss_user", side_effect=_add),
            patch("omr_admin.add_gre_tunnels"),
            patch("omr_admin.proxy_isolate_reverse_tunnels"),
            patch("omr_admin._mutate_omr_config") as persist,
        ):
            r = admin_client.post("/add_user", json={"username": "new", "ips": ["203.0.113.9", "203.0.113.10"]})
        assert r.json()["result"] == "done"
        latest = {"users": [{}]}
        persist.call_args[0][0](latest)
        assert latest["users"][0]["new"]["shadowsocks_port"] == 65110
        assert created == ["None", ""]   # the first asked for, the next one free

    def test_gre_tunnels_of_the_public_ips_once_the_user_is_saved(self, admin_client):
        order = MagicMock()
        with (
            patch("os.path.isfile", return_value=False),
            patch("omr_admin.add_gre_tunnels", side_effect=lambda *a: order.gre(*a)),
            patch("omr_admin.proxy_isolate_reverse_tunnels"),
            patch("omr_admin.read_omr_config", return_value=dict(json.loads(json.dumps(MOCK_CONFIG)), gre_tunnels=True)),
            patch("omr_admin._mutate_omr_config", side_effect=lambda *a: order.persist()),
        ):
            r = admin_client.post("/add_user", json={"username": "new", "ips": ["203.0.113.9", "203.0.113.10"]})
        assert r.json()["result"] == "done"
        # looked up in the config without the user, before: none ever made
        assert [c[0] for c in order.mock_calls] == ["persist", "gre"]
        assert order.gre.call_args.args == ("new",)

    def test_gre_tunnels_on_when_the_config_does_not_say(self, admin_client):
        config = json.loads(json.dumps(MOCK_CONFIG))
        del config["gre_tunnels"]
        with (
            patch("os.path.isfile", return_value=False),
            patch("omr_admin.add_gre_tunnels") as gre,
            patch("omr_admin.proxy_isolate_reverse_tunnels"),
            patch("omr_admin.read_omr_config", return_value=config),
            patch("omr_admin._mutate_omr_config"),
        ):
            r = admin_client.post("/add_user", json={"username": "new", "ips": ["203.0.113.9"]})
        assert r.json()["result"] == "done"
        gre.assert_called_once_with("new")

    def test_no_gre_tunnel_when_the_vps_has_them_off(self, admin_client):
        with (
            patch("os.path.isfile", return_value=False),
            patch("omr_admin.add_gre_tunnels") as gre,
            patch("omr_admin.proxy_isolate_reverse_tunnels"),
            patch("omr_admin.read_omr_config", return_value=dict(json.loads(json.dumps(MOCK_CONFIG)), gre_tunnels=False)),
            patch("omr_admin._mutate_omr_config"),
        ):
            r = admin_client.post("/add_user", json={"username": "new", "ips": ["203.0.113.9"]})
        assert r.json()["result"] == "done"
        gre.assert_not_called()


class TestRemoveUserTeardown:
    def test_every_shadowsocks_port_of_the_user_removed(self):
        manager = {"port_conf": {"65102": {"key": "a", "userid": 2}, "65103": {"key": "a", "userid": "2"},
                                 "65101": {"key": "b", "userid": 0}}}
        udata = {"userid": 2, "shadowsocks_port": 65102,
                 "gre_tunnels": {"gre-user2-ip1": {"shadowsocks_port": "65150"}}}
        with (
            patch("builtins.open", side_effect=_open_with({"/etc/shadowsocks-libev/manager.json": json.dumps(manager)})),
            patch("omr_admin.remove_ss_user") as remove,
        ):
            omr_admin._remove_user_ss_ports(udata, 2)
        assert sorted(call.args[0] for call in remove.call_args_list) == ["65102", "65103", "65150"]

    def test_lan_routes_of_the_user_only(self):
        tun0 = ('port 65301\npush "route 192.168.5.0 255.255.255.0"\n'
                'push "route 192.168.6.0 255.255.255.0"\n')
        users = {"readonly": {"lanips": ["192.168.5.1/24"]}, "openmptcprouter": {"lanips": ["192.168.6.1/24"]}}
        written = {}
        with (
            patch("os.path.isfile", side_effect=lambda p: p == "/etc/openvpn/tun0.conf"),
            patch("builtins.open", side_effect=_open_with({"/etc/openvpn/tun0.conf": tun0})),
            patch("omr_admin._atomic_write_text", side_effect=lambda p, t, new_mode=0o644: written.update({p: t})),
        ):
            omr_admin._remove_user_openvpn_lan("readonly", users["readonly"], users)
        assert "192.168.5.0" not in written["/etc/openvpn/tun0.conf"]
        assert "192.168.6.0" in written["/etc/openvpn/tun0.conf"]

    def test_firewall_resynced(self, admin_client):
        with (
            patch("os.path.isfile", return_value=False),
            patch("omr_admin._mutate_omr_config"),
            patch("omr_admin._nft_sync_ports") as sync_ports,
            patch("omr_admin._nft_sync_gre_snat") as sync_gre,
        ):
            r = admin_client.post("/remove_user", json={"username": "readonly"})
        assert r.json()["result"] == "done"
        assert sync_ports.called and sync_gre.called

    def test_admin_user_cannot_be_removed(self, admin_client):
        r = admin_client.post("/remove_user", json={"username": "admin"})
        assert r.json()["result"] == "not allowed"


# ---------------------------------------------------------------------------
# Shared daemons
# ---------------------------------------------------------------------------

class TestSharedDaemons:
    def test_shadowsocks_key_with_a_quote_refused(self, other_client):
        with patch("os.path.isfile", return_value=True):
            r = other_client.post("/shadowsocks", json={"port": 65102, "method": "chacha20", "fast_open": True,
                                                       "reuse_port": True, "no_delay": True,
                                                       "key": 'x","plugin":"/bin/sh'})
        assert r.json()["reason"] == "Invalid key"

    def test_shadowsocks_key_change_of_a_router_restarts_its_port_only(self, other_client):
        manager = {"port_conf": {"65102": {"key": "old", "userid": 2}}}
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open_with({"/etc/shadowsocks-libev/manager.json": json.dumps(manager)})),
            patch("omr_admin.file_as_bytes", side_effect=[b"a", b"b"]),
            patch("omr_admin._iface_global_addr", return_value=""),
            patch("omr_admin._ss_manager_command") as command,
            patch("subprocess.run") as run,
        ):
            r = other_client.post("/shadowsocks", json={"port": 65102, "method": "chacha20", "fast_open": True,
                                                       "reuse_port": True, "no_delay": True, "key": "new"})
        assert r.json()["reason"] == "changes applied"
        assert [c.args[0].split(":")[0] for c in command.call_args_list] == ["remove", "add"]
        assert not any("shadowsocks-libev-manager" in str(c) for c in run.call_args_list)

    def test_v2ray_redirect_of_an_xray_port_refused(self, tmp_path):
        xray = {"inbounds": [{"tag": "api", "listen": "127.0.0.1", "port": 10086, "protocol": "dokodemo-door",
                              "settings": {"network": "tcp"}}]}
        with (
            patch("builtins.open", side_effect=_open_with({"/etc/xray/xray-server.json": json.dumps(xray)})),
            patch("os.path.isfile", side_effect=lambda p: p == "/etc/xray/xray-server.json"),
        ):
            assert omr_admin._proxy_port_elsewhere("v2ray", "tcp", 10080, 10090) == "xray api"
            assert omr_admin._proxy_port_elsewhere("v2ray", "udp", 10080, 10090) is None
            assert omr_admin._proxy_port_elsewhere("xray", "tcp", 10080, 10090) is None

    def test_mqvpn_pins_capped_and_iface_checked(self, other_client):
        with patch("os.path.isfile", return_value=True):
            r = other_client.post("/mqvpn_weight", json={"weights": [{"iface": f"wan{i}", "weight": 1}
                                                                     for i in range(omr_admin.MQVPN_MAX_PINS + 1)]})
            assert r.json()["reason"] == "Too many interfaces"
            r = other_client.post("/mqvpn_dscp", json={"pins": [{"iface": "wan\n1", "dscp": ["cs1"]}]})
            assert r.json()["result"] == "error"

    def test_glorytun_port_of_another_user_refused(self, other_client):
        tunnels = {"/etc/glorytun-tcp/tun0": "PORT=65001\n", "/etc/glorytun-tcp/tun2": "PORT=65002\n"}
        with (
            patch("os.path.isfile", side_effect=lambda p: p in tunnels),
            patch("glob.glob", side_effect=lambda pattern: [p for p in tunnels if pattern.startswith("/etc/glorytun-tcp")]),
            patch("builtins.open", side_effect=_open_with(tunnels)),
        ):
            r = other_client.post("/glorytun", json={"key": "k" * 64, "port": 65001, "chacha": True})
            assert r.json()["reason"] == "Port already used by another user"
            r = other_client.post("/glorytun", json={"key": "k" * 64, "port": 65500, "chacha": True})
            assert r.json()["reason"] == "Port used by the server"

    def test_glorytun_empty_key_refused(self, other_client):
        with patch("os.path.isfile", return_value=True):
            r = other_client.post("/glorytun", json={"key": "", "port": 65002, "chacha": True})
        assert r.json()["reason"] == "Invalid key"

    def test_dsvpn_port_change_alone_restarts(self, primary_client):
        files = {"/etc/dsvpn/dsvpn0": "PORT=65401\n", "/etc/dsvpn/dsvpn0.key": "samekey"}
        written = dict(files)

        def _write(p, t, new_mode=0o644):
            written[p] = t

        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open_with(files)),
            patch("omr_admin.file_as_bytes", side_effect=lambda p: written[p].encode()),
            patch("omr_admin._atomic_write_text", side_effect=_write),
            patch("omr_admin.shorewall_add_port", return_value=None),
            patch("omr_admin.shorewall_del_port") as close,
            patch("subprocess.run") as run,
        ):
            r = primary_client.post("/dsvpn", json={"key": "samekey", "port": 65409})
        assert r.json()["result"] == "done"
        assert any("dsvpn-server@dsvpn0" in str(c) for c in run.call_args_list)
        close.assert_called_once_with("openmptcprouter", "65401", "tcp", "dsvpn")


# ---------------------------------------------------------------------------
# Small ones
# ---------------------------------------------------------------------------

class TestWan:
    def test_wide_prefix_refused(self, other_client):
        with patch("os.path.isfile", return_value=True):
            r = other_client.post("/wan", json={"ips": "0.0.0.0/0"})
        assert r.json()["reason"] == "Invalid IP"

    def test_too_many_refused(self, other_client):
        ips = "\n".join(f"203.0.113.{i}" for i in range(omr_admin.WAN_MAX_IPS + 1))
        with patch("os.path.isfile", return_value=True):
            r = other_client.post("/wan", json={"ips": ips})
        assert r.json()["reason"] == "Invalid IP"


class TestCookieAuth:
    def _request(self, path, headers):
        return MagicMock(url=MagicMock(path=path), headers=headers)

    def test_cross_site_refused(self):
        assert not omr_admin._cookie_auth_allowed(self._request("/update", {"sec-fetch-site": "cross-site"}))
        assert not omr_admin._cookie_auth_allowed(self._request("/update", {"sec-fetch-site": "same-site"}))
        assert not omr_admin._cookie_auth_allowed(self._request("/update", {}))
        assert not omr_admin._cookie_auth_allowed(self._request(
            "/update", {"referer": "https://evil.example/", "host": "vps:65500"}))

    def test_docs_and_same_origin_allowed(self):
        assert omr_admin._cookie_auth_allowed(self._request("/docs", {"sec-fetch-site": "cross-site"}))
        assert omr_admin._cookie_auth_allowed(self._request("/status", {"sec-fetch-site": "same-origin"}))
        assert omr_admin._cookie_auth_allowed(self._request(
            "/status", {"referer": "https://vps:65500/docs", "host": "vps:65500"}))


class TestMptcpPeer:
    def test_ss_address_matched_exactly(self):
        output = b"ESTAB 0 0 [::ffff:51.15.1.1]:65500 [::ffff:11.2.3.45]:40000\n"
        with patch("omr_admin._mptcp_connections", return_value=(None, output)):
            assert not omr_admin._mptcp_peer_present("1.2.3.4")
            assert omr_admin._mptcp_peer_present("11.2.3.45")

    def test_proc_address_matched_exactly(self):
        # 1.2.3.4 is 04030201; a longer hex field ending with it is another address
        with patch("omr_admin._mptcp_connections", return_value=("A04030201:1F90 0100007F:1F90\n", b"")):
            assert not omr_admin._mptcp_peer_present("1.2.3.4")
            assert omr_admin._mptcp_peer_present("127.0.0.1")


class TestSerialEnforce:
    def test_missing_serial_refused_when_enforced(self):
        config = _config()
        config["serial_enforce"] = True
        with patch("omr_admin.read_omr_config", return_value=config), \
             patch("omr_admin._mutate_omr_config") as mutate:
            assert not omr_admin.check_username_serial("readonly", None)
        assert not mutate.called

    def test_not_enforced(self):
        with patch("omr_admin.read_omr_config", return_value=_config()):
            assert omr_admin.check_username_serial("readonly", None)


class TestOpenvpnStats:
    def test_socket_closed_before_end(self):
        sock = MagicMock()
        sock.makefile.return_value = io.BytesIO(b">INFO:OpenVPN Management Interface\nbob,1.2.3.4:1,5,6\n")
        with patch("socket.socket", return_value=sock):
            assert omr_admin.get_bytes_openvpn("bob") == {"downlinkBytes": 5, "uplinkBytes": 6}


class TestXrayReverseMigration:
    def test_recorded_only_once_written(self):
        with (
            patch("os.path.isfile", side_effect=lambda p: p == "/etc/xray/xray-server.json"),
            patch("builtins.open", side_effect=_open_with({"/etc/xray/xray-server.json": "{}"})),
            patch("omr_admin._proxy_isolate_reverse", return_value=True),
            patch("omr_admin._atomic_write_json", side_effect=OSError("disk full")),
            patch("omr_admin.set_global_param") as set_param,
        ):
            omr_admin.proxy_isolate_reverse_tunnels()
        assert not set_param.called


class TestV2rayDelUser:
    def test_user_it_never_had_changes_nothing(self):
        config = {"inbounds": [{"tag": "omrin-tunnel", "settings": {"clients": [{"email": "openmptcprouter"}]}}],
                  "routing": {"rules": []}}
        with (
            patch("shutil.which", return_value="/usr/bin/v2ray"),
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open_with({"/etc/v2ray/v2ray-server.json": json.dumps(config)})),
            patch("omr_admin._atomic_write_json") as write,
            patch("subprocess.run") as run,
        ):
            omr_admin.v2ray_del_user("audituser")
        assert not write.called and not run.called

    def test_user_removed_restarts(self):
        config = {"inbounds": [{"tag": "omrin-tunnel", "settings": {"clients": [{"email": "bob"}]}}],
                  "routing": {"rules": []}}
        with (
            patch("shutil.which", return_value="/usr/bin/v2ray"),
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open_with({"/etc/v2ray/v2ray-server.json": json.dumps(config)})),
            patch("omr_admin._atomic_write_json") as write,
            patch("subprocess.run") as run,
        ):
            omr_admin.v2ray_del_user("bob")
        assert write.called and run.called


# ---------------------------------------------------------------------------
# Ports with a leading zero: nft reads them as octal
# ---------------------------------------------------------------------------

class TestLeadingZeroPort:
    def test_refused(self):
        # 0673 is 443 for nft, 673 for int(): checked as one, redirected as the other
        for port in ("0673", "065", "80-0443", "010:20", "0"):
            assert omr_admin._fw_entry_error(port, "udp", "DNAT") == "Invalid port", port
            assert omr_admin._proxy_redirect_error(port, "udp", "", "") == "Invalid port", port
        assert omr_admin._fw_entry_error("443", "udp", "DNAT") is None
        assert omr_admin._fw_entry_error("100-200", "udp", "DNAT") is None

    def test_firewallopen_refuses_it(self, other_client):
        with patch("omr_admin.shorewall_add_port", return_value=None) as add:
            r = other_client.post("/firewallopen", json={"name": "x", "port": "0673", "proto": "udp", "fwtype": "DNAT"})
        assert r.json()["reason"] == "Invalid port"
        assert not add.called

    def test_rendered_from_the_checked_ports(self):
        config = _config()
        users = config["users"][0]
        users["openmptcprouter"]["vpnremoteip"] = "10.255.255.2"
        users["openmptcprouter"]["fw_ports"] = [_dnat("0673"), _dnat("80:90")]
        _accept, dnat = omr_admin._render_fw_ports(config)
        # the stored one an older release accepted is skipped
        assert len(dnat) == 1 and " dport 80-90 " in dnat[0]


# ---------------------------------------------------------------------------
# A network as the address of a redirect
# ---------------------------------------------------------------------------

class TestDnatNetworkAddress:
    def test_owners_of_a_network(self):
        config = _config()
        config["users"][0]["readonly"]["public_ips"] = ["203.0.113.9"]
        config["users"][0]["openmptcprouter"]["public_ips"] = ["203.0.113.5"]
        assert set(omr_admin._public_ip_owners(config, "0.0.0.0/0")) == {"readonly", "openmptcprouter"}
        assert omr_admin._public_ip_owners(config, "0.0.0.0/0", contained=True) == []
        assert omr_admin._public_ip_owners(config, "203.0.113.9", contained=True) == ["readonly"]
        assert omr_admin._public_ip_owners(config, "not an address") == []

    def test_network_over_another_users_ip_refused(self, other_client):
        # the first owner found was the caller itself: the other one was missed
        config = _config()
        config["users"][0] = {"readonly": config["users"][0]["readonly"], **config["users"][0]}
        config["users"][0]["readonly"]["public_ips"] = ["203.0.113.9"]
        config["users"][0]["openmptcprouter"]["public_ips"] = ["203.0.113.5"]
        with (
            patch("builtins.open", side_effect=_open_with({CONFIG_PATH: json.dumps(config)})),
            patch("omr_admin.shorewall_add_port", return_value=None) as add,
        ):
            r = other_client.post("/firewallopen", json={"name": "x", "port": "8080", "proto": "tcp",
                                                        "fwtype": "DNAT", "source_dip": "0.0.0.0/0"})
        assert r.json()["reason"] == "Address used by another user"
        assert not add.called

    def test_network_around_its_own_ip_is_not_its_own_ip(self, other_client):
        # 0.0.0.0/0 is also the shared IPs: the server's ports are checked
        config = _config()
        config["users"][0]["readonly"]["public_ips"] = ["203.0.113.9"]
        with (
            patch("builtins.open", side_effect=_open_with({CONFIG_PATH: json.dumps(config)})),
            patch("omr_admin._server_ports", return_value=[(443, 443)]),
            patch("omr_admin.shorewall_add_port", return_value=None) as add,
        ):
            r = other_client.post("/firewallopen", json={"name": "x", "port": "443", "proto": "udp",
                                                        "fwtype": "DNAT", "source_dip": "0.0.0.0/0"})
        assert r.json()["reason"] == "Port used by the server"
        assert not add.called

    def test_rule_with_an_address_leaves_out_the_other_users_ips(self):
        config = _config()
        users = config["users"][0]
        users["openmptcprouter"]["public_ips"] = ["203.0.113.5"]
        users["readonly"]["vpnremoteip"] = "10.255.255.6"
        users["readonly"]["fw_ports"] = [_dnat("8080", "203.0.113.0/24")]
        _accept, dnat = omr_admin._render_fw_ports(config)
        rule = next(rule for rule in dnat if "to 10.255.255.6" in rule)
        assert "ip daddr 203.0.113.0/24" in rule and "ip daddr != { 203.0.113.5/32 }" in rule


# ---------------------------------------------------------------------------
# WireGuard: wg0.conf's [Interface]
# ---------------------------------------------------------------------------

class TestWireGuardInterface:
    _SERVER = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
    _PEER = "uKU1qOpAj/4jKsjk3ZqdpQ6GNZpI7mGTWArxpvzSg1I="

    def _write(self, wg_conf):
        config = _config()
        config["users"][0]["openmptcprouter"]["wireguard_peers"] = [{"ip": "10.255.247.2", "key": self._PEER}]
        out = io.StringIO()
        out.close = lambda: None

        def _open(path, mode="r", *args, **kwargs):
            if str(path) == "/etc/wireguard/wg0.conf":
                return out if "w" in mode else io.StringIO(wg_conf)
            return _mock_open(path, mode, *args, **kwargs)

        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open),
            patch("omr_admin.file_as_bytes", side_effect=[b"old", b"new"]),
            patch("omr_admin._wg_syncconf") as sync,
            patch("omr_admin.shorewall_add_port", return_value=None) as add,
        ):
            assert omr_admin._write_wireguard_conf(config, PRIMARY)
        return out.getvalue(), sync.call_args.args[0], add

    def test_interface_kept(self):
        # what wg-quick brings wg0 up with: its address was lost
        wg_conf = ("[Interface]\nPrivateKey = " + self._SERVER + "\nListenPort = 65311\n"
                   "Address = 10.255.247.1/24\nSaveConfig = true\nPostUp = true\n\n"
                   "[Peer]\nPublicKey = " + self._SERVER + "\nAllowedIPs = 10.255.247.9\n")
        out, live, add = self._write(wg_conf)
        assert out.startswith("[Interface]\nPrivateKey = " + self._SERVER + "\nListenPort = 65311\n"
                              "Address = 10.255.247.1/24\nSaveConfig = true\nPostUp = true\n\n[Peer]\n")
        assert out.count("Address") == 1 and "10.255.247.9" not in out and "10.255.247.2" in out
        # `wg` refuses wg-quick's keys
        assert live == ("[Interface]\nPrivateKey = " + self._SERVER + "\nListenPort = 65311\n\n"
                        "[Peer]\nPublicKey  = " + self._PEER + "\nAllowedIPs = 10.255.247.2\n")
        assert add.call_args.args[1:3] == ("65311", "udp")

    def test_lost_address_put_back(self):
        out, _live, _add = self._write("[Interface]\nListenPort = 65311\nPrivateKey = " + self._SERVER + "\n")
        assert "\nAddress = 10.255.247.1/24\n" in out

    def test_syncconf_gets_a_private_file_removed_after(self):
        seen = {}

        def _run(cmd, **kwargs):
            seen["cmd"] = cmd
            seen["mode"] = os.stat(cmd[3]).st_mode & 0o777
            with _REAL_OPEN(cmd[3]) as f:
                seen["text"] = f.read()
            return MagicMock(returncode=0, stderr="", stdout="")

        with patch("subprocess.run", side_effect=_run), patch("os.remove", side_effect=os.unlink):
            omr_admin._wg_syncconf("[Interface]\nListenPort = 1\n")
        assert seen["cmd"][:3] == ["wg", "syncconf", "wg0"]
        assert seen["mode"] == 0o600 and seen["text"] == "[Interface]\nListenPort = 1\n"
        assert not os.path.exists(seen["cmd"][3])


# ---------------------------------------------------------------------------
# Authentication off the event loop, MQVPN pushes out of the lock
# ---------------------------------------------------------------------------

class TestAuthOffTheEventLoop:
    def test_auth_paths_are_not_coroutines(self):
        # they take the config lock: on the event loop, every request of
        # the worker waited for the route holding it
        for func in (omr_admin.get_current_user, omr_admin.login_for_access_token,
                     omr_admin.login_basic, omr_admin.list_users):
            assert not asyncio.iscoroutinefunction(func), func.__name__

    def _mqvpn(self, client, route, payload):
        depths = []

        def _api(command):
            depths.append(getattr(omr_admin._omr_config_lock_state, "depth", 0))
            return {"ok": True}

        with (
            patch("os.path.isfile", return_value=True),
            patch("omr_admin.mqvpn_api", side_effect=_api),
            patch("omr_admin._atomic_write_json") as write,
        ):
            r = client.post(route, json=payload)
        return r.json(), depths, write

    def test_mqvpn_pushes_once_the_lock_is_released(self, primary_client):
        body, depths, write = self._mqvpn(primary_client, "/mqvpn_dscp", {"pins": [{"iface": "wan1", "dscp": ["ef"]}]})
        assert body["result"] == "done" and write.called
        assert depths == [0]
        body, depths, write = self._mqvpn(primary_client, "/mqvpn_weight", {"weights": [{"iface": "wan1", "weight": 3}]})
        assert body["result"] == "done" and write.called
        assert depths == [0]

    def test_mqvpn_pushes_stop_at_the_deadline(self, primary_client):
        with patch("omr_admin.MQVPN_PUSH_DEADLINE", -1):
            body, depths, write = self._mqvpn(primary_client, "/mqvpn_weight",
                                              {"weights": [{"iface": "wan1", "weight": 3}]})
        # persisted all the same, for mqvpn's next start
        assert body["result"] == "warning" and "too slow" in body["reason"]
        assert depths == [] and write.called


# ---------------------------------------------------------------------------
# Big request bodies only with a token
# ---------------------------------------------------------------------------

class TestBodyLimitNeedsToken:
    def _run(self, path, size, headers=()):
        limit = next(m for m in app.user_middleware if m.cls is omr_admin._BodySizeLimit)
        middleware = omr_admin._BodySizeLimit(lambda *a: asyncio.sleep(0), **limit.kwargs)
        sent = []

        async def send(message):
            sent.append(message)

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        scope = {"type": "http", "path": path,
                 "headers": [(b"content-length", str(size).encode()), *headers]}
        asyncio.run(middleware(scope, receive, send))
        return sent[0]["status"] if sent else None

    def test_backup_without_token_gets_the_default_limit(self):
        assert self._run("/backuppost", omr_admin.REQUEST_MAX_SIZE + 1) == 413
        assert self._run("/dscp_classify", omr_admin.REQUEST_MAX_SIZE + 1) == 413

    def test_backup_with_a_token_of_ours(self):
        import jwt
        from conftest import USER_TOKEN
        good = [(b"authorization", b"Bearer " + USER_TOKEN.encode())]
        assert self._run("/backuppost", 2 * 1024 * 1024, good) is None
        forged = jwt.encode({"sub": "admin"}, "not-our-key", algorithm="HS256")
        assert self._run("/backuppost", 2 * 1024 * 1024, [(b"authorization", b"Bearer " + forged.encode())]) == 413
        assert self._run("/backuppost", 2 * 1024 * 1024, [(b"authorization", b"Basic eDp5")]) == 413


# ---------------------------------------------------------------------------
# What ss-manager writes unescaped into ss-server's JSON config
# ---------------------------------------------------------------------------

class TestShadowsocksUnescaped:
    def test_method_with_a_quote_refused(self, primary_client):
        payload = {"port": 65101, "method": 'aes-256-gcm","plugin":"/bin/sh', "fast_open": False,
                   "reuse_port": False, "no_delay": False, "key": "testkey"}
        with patch("os.path.isfile", return_value=True), patch("omr_admin._shadowsocks_locked") as locked:
            r = primary_client.post("/shadowsocks", json=payload)
        assert r.json() == {"result": "error", "reason": "Invalid method", "route": "shadowsocks"}
        assert not locked.called

    def test_lookups_over_https(self):
        assert all(url.startswith("https://") for url in omr_admin.PUBLIC_IPV4_URLS + omr_admin.PUBLIC_HOSTNAME_URLS)

    def test_lookup_answer_checked(self):
        def _get(url, timeout):
            if url == "https://a":
                return MagicMock(ok=False, text="1.2.3.4")
            if url == "https://b":
                return MagicMock(ok=True, text='x","plugin":"/bin/sh')
            return MagicMock(ok=True, text=" vps.example.com\n")

        with patch("omr_admin.requests.get", side_effect=_get):
            assert omr_admin._public_lookup(("https://a", "https://b", "https://c"), omr_admin._is_hostname) == "vps.example.com"
            assert omr_admin._public_lookup(("https://a", "https://b"), omr_admin._is_hostname) == ""
        assert omr_admin._is_ipv4_address("192.0.2.1")
        assert not omr_admin._is_ipv4_address("<html>") and not omr_admin._is_ipv4_address("192.0.2.0/24")

    def test_stored_value_checked(self):
        with (
            patch("omr_admin._public_lookup", return_value="vps.example.com") as lookup,
            patch("omr_admin.set_global_param") as set_param,
        ):
            assert omr_admin._vps_hostname({"hostname": "ok.example.com"}) == "ok.example.com"
            assert omr_admin._vps_hostname({"hostname": ""}) == ""
            assert not lookup.called
            # kept unchecked by an older release
            assert omr_admin._vps_hostname({"hostname": 'x","plugin":"/bin/sh'}) == "vps.example.com"
            set_param.assert_called_once_with("hostname", "vps.example.com")
            assert omr_admin._vps_hostname({"internet": False}) == ""
            assert lookup.call_count == 1


# ---------------------------------------------------------------------------
# A broken PyTorch must not stop omr-admin
# ---------------------------------------------------------------------------

@pytest.mark.real_env
def test_omr_metrics_imports_with_a_broken_torch(tmp_path):
    import subprocess
    import sys
    (tmp_path / "torch").mkdir()
    (tmp_path / "torch" / "__init__.py").write_text("raise OSError('libtorch_cpu.so: cannot open shared object file')\n")
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    code = "import omr_metrics; print(omr_metrics._TORCH_AVAILABLE)"
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                            env={**os.environ, "PYTHONPATH": f"{tmp_path}{os.pathsep}{repo}",
                                 "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"

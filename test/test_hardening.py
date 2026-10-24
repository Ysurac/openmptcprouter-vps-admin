"""
Regressions for the audit fixes: what one router of a shared VPS could take
from the others or from the server (redirects, keys, daemons' ports), what an
unauthenticated client could do (memory), and the state a removed user or a
port change left behind.
"""

import asyncio
import fnmatch
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
        assert not omr_admin._wireguard_peer_in_vpn("10.255.247.5,\n10.255.247.6")
        with patch("omr_admin.modif_config_user") as modif, patch("omr_admin._write_wireguard_conf"), \
             patch("os.path.isfile", return_value=True):
            r = other_client.post("/wireguard", json={"peers": [{"ip": "10.255.247.5,\n10.255.247.6", "key": self._KEY}]})
        assert r.json() == {"result": "error", "reason": "Invalid ip", "route": "wireguard"}
        modif.assert_not_called()


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

    def test_retired_serials_returned(self):
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open_with({"/etc/openvpn/ca/pki/index.txt": self._INDEX})),
            patch("omr_admin._atomic_write_text"),
            patch("omr_admin._openvpn_gen_crl"),
        ):
            assert omr_admin._pki_retire_user_certs("bob") == ["02"]

    _SUSPENDED = ("R\t360101000000Z\t250101000000Z\t01\tunknown\t/CN=bob\n"
                  "R\t360101000000Z\t260101000000Z\t02\tunknown\t/CN=bob\n"
                  "V\t360101000000Z\t\t03\tunknown\t/CN=bobby\n")

    def test_suspended_certificate_valid_again(self):
        written = {}
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open_with({"/etc/openvpn/ca/pki/index.txt": self._SUSPENDED})),
            patch("omr_admin._atomic_write_text", side_effect=lambda p, t, new_mode=0o644: written.update({p: t})),
            patch("omr_admin._openvpn_gen_crl") as gen_crl,
        ):
            assert omr_admin._pki_restore_user_certs("bob", ["01", "02"]) == "02"
        lines = written["/etc/openvpn/ca/pki/index.txt"].splitlines()
        assert lines[0] == self._SUSPENDED.splitlines()[0]       # revoked before: stays
        assert lines[1] == "V\t360101000000Z\t\t02\tunknown\t/CN=bob"
        assert lines[2] == self._SUSPENDED.splitlines()[2]
        gen_crl.assert_called_once()

    def test_not_restored_without_its_files_or_with_another_valid(self):
        with (
            patch("os.path.isfile", side_effect=lambda p: not p.endswith("bob.key")),
            patch("omr_admin._atomic_write_text") as write,
        ):
            assert omr_admin._pki_restore_user_certs("bob", ["02"]) is None
        index = self._SUSPENDED + "V\t360101000000Z\t\t04\tunknown\t/CN=bob\n"
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open_with({"/etc/openvpn/ca/pki/index.txt": index})),
            patch("omr_admin._atomic_write_text") as write,
        ):
            assert omr_admin._pki_restore_user_certs("bob", ["02"]) is None
        assert not write.called


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

class TestAddUserChecks:
    @pytest.mark.parametrize("payload,reason", [
        ({"username": "readonly"}, "User already exists"),
        ({"username": "admin"}, "User already exists"),
        ({"username": "DEFAULT"}, "Invalid username"),
        ({"username": "ipp_tcp.txt"}, "Invalid username"),
        ({"username": "-help"}, "Invalid username"),
        ({"username": "u" * 65}, "Invalid username"),
        ({"username": "new", "userid": 2}, "Userid already used"),
        ({"username": "new", "userid": 64}, "Invalid userid, 2 to 63"),
        ({"username": "new", "userid": -1}, "Invalid userid, 2 to 63"),
        # 65001 and 65401: userid 0's glorytun and dsvpn ports
        ({"username": "new", "userid": 1}, "Invalid userid, 2 to 63"),
        ({"username": "new", "ips": ["0.0.0.0/0"]}, "Invalid IP"),
        ({"username": "new", "ips": ["not an ip"]}, "Invalid IP"),
        ({"username": "new", "shadowsocks_port": 65101}, "Shadowsocks port already used"),
        ({"username": "new", "user_key": ""}, "Password too short, 8 characters at least"),
        ({"username": "new", "user_key": "MySecretKey"}, "Template password"),
    ])
    def test_refused_before_anything_is_created(self, admin_client, payload, reason):
        with patch("omr_admin._mutate_omr_config") as persist:
            r = admin_client.post("/add_user", json=payload)
        assert r.json()["reason"] == reason
        assert not persist.called

    def test_ip_of_another_user_refused(self, admin_client):
        config = _config()
        config["users"][0]["readonly"]["public_ips"] = ["203.0.113.9"]
        with (
            patch("builtins.open", side_effect=_open_with({CONFIG_PATH: json.dumps(config)})),
            patch("omr_admin._mutate_omr_config") as persist,
        ):
            r = admin_client.post("/add_user", json={"username": "new", "ips": ["203.0.113.9"]})
        assert r.json()["reason"] == "IP already given to another user"
        assert not persist.called

    def test_shadowsocks_port_of_manager_json_or_a_listener_refused(self, admin_client):
        manager = {"port_conf": {"65120": {"key": "a", "userid": 7}}}
        listener = MagicMock(laddr=MagicMock(ip="0.0.0.0", port=8388), raddr=(), status="LISTEN", pid=None)
        with (
            patch("builtins.open", side_effect=_open_with({"/etc/shadowsocks-libev/manager.json": json.dumps(manager)})),
            patch("omr_admin.psutil.net_connections", return_value=[listener]),
            patch("omr_admin.add_ss_user") as add,
        ):
            for port in (65120, 8388):
                r = admin_client.post("/add_user", json={"username": "new", "shadowsocks_port": port})
                assert r.json()["reason"] == "Shadowsocks port already used"
        assert not add.called

    def test_failed_step_undoes_the_user(self, admin_client):
        with (
            patch("os.path.isfile", side_effect=lambda p: p in ("/etc/shadowsocks-libev/manager.json",
                                                                "/etc/glorytun-tcp/tun0")),
            patch("omr_admin.add_ss_user", return_value=65130),
            patch("omr_admin.proxy_isolate_reverse_tunnels"),
            patch("omr_admin._mutate_omr_config"),
            patch("omr_admin.add_glorytun_tcp", side_effect=OSError("disk full")),
            patch("omr_admin._teardown_user") as teardown,
        ):
            r = admin_client.post("/add_user", json={"username": "new", "userid": 9})
        assert r.json() == {"result": "error", "reason": "User creation failed", "route": "add_user"}
        name, udata, users = teardown.call_args.args
        assert name == "new"
        assert udata["userid"] == "9" and udata["shadowsocks_port"] == 65130
        assert users["new"] is udata and "openmptcprouter" in users

    def test_port_made_before_the_failed_step_undone(self, admin_client):
        with (
            patch("os.path.isfile", side_effect=lambda p: p in ("/etc/shadowsocks-libev/manager.json",
                                                                "/etc/shadowsocks-go/server.json")),
            patch("omr_admin.add_ss_user", return_value=65131),
            patch("omr_admin.add_ss_go_user", side_effect=OSError("ss-go down")),
            patch("omr_admin._teardown_user") as teardown,
        ):
            r = admin_client.post("/add_user", json={"username": "new"})
        assert r.json()["reason"] == "User creation failed"
        assert teardown.call_args.args[1]["shadowsocks_port"] == 65131

    def test_teardown_of_a_half_made_user_does_not_raise(self):
        # glorytun-udp's key without its config, dsvpn's config without its key
        present = {"/etc/glorytun-udp/tun9.key", "/etc/dsvpn/dsvpn9"}
        with (
            patch("os.path.isfile", side_effect=lambda p: p in present),
            patch("os.remove") as remove,
        ):
            omr_admin.remove_glorytun_udp(9)
            omr_admin.remove_dsvpn(9)
        assert sorted(c.args[0] for c in remove.call_args_list) == sorted(present)

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


class TestXrayRealityClients:
    def test_new_user_gets_a_reality_client(self):
        server = {"inbounds": [{"tag": "omrin-tunnel", "protocol": "vless", "settings": {"clients": []}},
                               {"tag": "omrin-vless-reality", "protocol": "vless",
                                "settings": {"clients": [{"id": "main", "flow": "xtls-rprx-vision"}]}}]}
        written = {}
        with (
            patch("shutil.which", return_value="/usr/bin/xray"),
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open_with({"/etc/xray/xray-server.json": json.dumps(server)})),
            patch("omr_admin._atomic_write_json", side_effect=lambda p, d, **k: written.update({p: d})),
            patch("omr_admin._xray_live_user") as live,
        ):
            omr_admin.xray_add_user("carol", "uuid-c", "k")
        reality = written["/etc/xray/xray-server.json"]["inbounds"][1]["settings"]["clients"]
        assert {"id": "uuid-c", "flow": "xtls-rprx-vision", "email": "carol"} in reality
        assert {"id": "main", "flow": "xtls-rprx-vision"} in reality
        assert "omrin-vless-reality" in [c.args[0]["tag"] for c in live.call_args_list]

    def test_reality_turned_on_gets_every_users_client(self):
        config = {"inbounds": [{"tag": "omrin-tunnel", "settings": {"clients": [
            {"id": "u0", "email": "openmptcprouter"}, {"id": "u2", "email": "readonly"},
            {"id": "rev", "email": "omr-reverse", "reverse": {"tag": "OMRLan"}}]}}]}
        reality = {"tag": "omrin-vless-reality", "settings": {"clients": [{"id": "u0", "flow": "xtls-rprx-vision"}]}}
        assert omr_admin._xray_reality_clients_from_tunnel(config, reality)
        assert reality["settings"]["clients"] == [{"id": "u0", "flow": "xtls-rprx-vision"},
                                                  {"id": "u2", "flow": "xtls-rprx-vision", "email": "readonly"}]
        assert not omr_admin._xray_reality_clients_from_tunnel(config, reality)


class TestRemoveMqvpn:
    _SERVER = json.dumps({"users": [{"name": "readonly", "key": "k2"}, {"name": "openmptcprouter", "key": "k0"}]})

    def _remove(self, api):
        with (
            patch("builtins.open", side_effect=_open_with({"/etc/mqvpn/server.json": self._SERVER})),
            patch("omr_admin._atomic_write_json"),
            patch("omr_admin.mqvpn_api", return_value=api),
            patch("subprocess.run") as run,
        ):
            omr_admin.remove_mqvpn("readonly")
        return [c.args[0] for c in run.call_args_list]

    def test_restarted_when_the_control_api_failed(self):
        # the running mqvpn still had the key: the user kept its access
        assert self._remove({"ok": False, "error": "unreachable"}) == \
            [["systemctl", "-q", "try-restart", "mqvpn"]]

    def test_not_restarted_when_removed_live(self):
        assert self._remove({"ok": True}) == []


class TestRemoveUserTeardown:
    def test_gre_links_of_the_user_deleted(self):
        # omr-service removes no tunnel without its file: the link kept its
        # /30, which the next user's tunnel was given
        udata = {"userid": 5, "gre_tunnels": {"gre-user5-ip0": {"network": "10.255.240.4/30"}}}
        with (
            patch("os.path.isfile", return_value=False),
            patch("os.listdir", return_value=["gre-user5-ip1", "gre-user50-ip0"]),
            patch("os.remove") as remove,
            patch("omr_admin._gre_drop_proxy_users"),
            patch("omr_admin._remove_user_openvpn_lan"),
            patch("omr_admin._apply_6in4_conf"),
            patch("omr_admin._remove_tunnel_unit"),
            patch("subprocess.run") as run,
        ):
            omr_admin._remove_user_resources("c", udata, {"c": udata})
        deleted = [c.args[0][3] for c in run.call_args_list if c.args[0][:3] == ["ip", "link", "del"]]
        assert deleted == ["gre-user5-ip0", "gre-user5-ip1"]
        assert [os.path.basename(c.args[0]) for c in remove.call_args_list] == ["gre-user5-ip1"]

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
            # the default port of a userid not made yet: /add_user writes it
            # for that user with no check
            for port in (65005, 65405):
                r = other_client.post("/glorytun", json={"key": "k" * 64, "port": port, "chacha": True})
                assert r.json()["reason"] == "Port reserved for another user", port
        assert omr_admin._tunnel_port_error(OTHER, 65402, ("tcp",), []) is None   # its own DSVPN default

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
            assert omr_admin._write_wireguard_conf(config)
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
        # as the main router's, whoever's change it was
        assert add.call_args.args[0].username == "openmptcprouter"

    def test_port_moved_to_the_main_router(self):
        # opened as the first user whose /wireguard changed wg0.conf: its
        # removal closed every user's WireGuard
        config = _config()
        config["users"][0]["readonly"]["fw_ports"] = [
            {"name": "wireguard", "port": "65311", "proto": "udp", "fwtype": "ACCEPT", "family": 4}]
        with (
            patch("omr_admin.read_omr_config", return_value=config),
            patch("omr_admin._fw_port_del") as delete,
            patch("omr_admin.shorewall_add_port") as add,
        ):
            omr_admin._wireguard_port_to_main_router("65311")
        delete.assert_called_once_with("readonly", "65311", "udp", "wireguard", "ACCEPT", 4)
        assert add.call_args.args[0].username == "openmptcprouter"

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

    def test_backup_with_a_nested_token_header(self):
        nested = [(b"authorization", b"Bearer " + _nested_header_token().encode())]
        assert self._run("/backuppost", 2 * 1024 * 1024, nested) == 413

    def test_token_form_limit_even_with_a_token(self):
        from conftest import USER_TOKEN
        good = [(b"authorization", b"Bearer " + USER_TOKEN.encode())]
        assert self._run("/token", omr_admin.TOKEN_MAX_SIZE + 1) == 413
        assert self._run("/token", omr_admin.TOKEN_MAX_SIZE + 1, good) == 413
        assert self._run("/token", omr_admin.TOKEN_MAX_SIZE) is None


def _nested_header_token(depth=2000):
    """A token whose header json.loads raises RecursionError on (pyjwt < 2.14)."""
    import base64

    def b64(text):
        return base64.urlsafe_b64encode(text.encode()).rstrip(b"=").decode()
    return b64('{"a":' + "[" * depth + "]" * depth + "}") + "." + b64("{}") + ".sig"


class TestJwtNestedHeader:
    def test_nested_header_is_403(self):
        client = _ASGITestClient(app, raise_server_exceptions=False)
        r = client.get("/config", headers={"Authorization": "Bearer " + _nested_header_token()})
        assert r.status_code == 403, r.text

    def test_any_decode_error_is_403(self):
        request = MagicMock(client=MagicMock(host="198.51.100.7"), headers={})
        for error in (RecursionError("nested"), ValueError("bad")):
            with patch("omr_admin.jwt.decode", side_effect=error):
                with pytest.raises(omr_admin.HTTPException) as exc:
                    omr_admin.get_current_user(request, "a.b.c")
                assert exc.value.status_code == 403
                assert omr_admin._bearer_token_signed({"headers": [(b"authorization", b"Bearer a.b.c")]}) is False


class TestTokenFormLimit:
    def test_big_urlencoded_login_refused(self):
        client = _ASGITestClient(app, raise_server_exceptions=False)
        body = "a;" * (omr_admin.TOKEN_MAX_SIZE // 2 + 1)
        with patch("omr_admin.authenticate_user") as authenticate:
            r = client.post("/token", content=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
        assert r.status_code == 413
        authenticate.assert_not_called()


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


# ---------------------------------------------------------------------------
# The API's TLS
# ---------------------------------------------------------------------------

class TestApiTls:
    def test_main_passes_tls_server_and_aead_ciphers(self):
        import ssl
        with (
            patch("omr_admin.uvicorn.run") as run,
            patch("omr_admin.log_startup_environment"),
        ):
            omr_admin.main(65500, "127.0.0.1", 2)
        kwargs = run.call_args.kwargs
        # 5, PROTOCOL_TLSv1_2, was TLS 1.2 alone
        assert kwargs["ssl_version"] == ssl.PROTOCOL_TLS_SERVER
        assert kwargs["ssl_ciphers"] == omr_admin.API_TLS_CIPHERS
        assert kwargs["proxy_headers"] is False

    def test_single_worker_gets_the_same(self):
        import ssl
        with (
            patch("omr_admin.uvicorn.Config") as config,
            patch("omr_admin.MPTCPServer") as server,
            patch("omr_admin.log_startup_environment"),
        ):
            server.return_value.serve = MagicMock(return_value=None)
            with patch("omr_admin.asyncio.new_event_loop") as loop, \
                 patch("omr_admin.asyncio.get_running_loop", side_effect=RuntimeError), \
                 patch("omr_admin.asyncio.set_event_loop"):
                omr_admin.main(65500, "127.0.0.1", 1)
        assert loop.return_value.run_until_complete.called
        kwargs = config.call_args.kwargs
        assert kwargs["ssl_version"] == ssl.PROTOCOL_TLS_SERVER
        assert kwargs["ssl_ciphers"] == omr_admin.API_TLS_CIPHERS


@pytest.mark.real_env
def test_api_tls_handshakes(tmp_path):
    """The context uvicorn builds from main()'s options: TLS 1.3, TLS 1.2
    with an AEAD suite, nothing older and no CBC suite."""
    import shutil
    import socket
    import ssl
    import subprocess
    import threading

    from uvicorn.config import create_ssl_context

    if shutil.which("openssl") is None:
        pytest.skip("no openssl binary to make a certificate")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-days", "1", "-nodes", "-x509",
                    "-keyout", str(key), "-out", str(cert), "-subj", "/CN=omr-test"],
                   check=True, capture_output=True)
    server_ctx = create_ssl_context(certfile=str(cert), keyfile=str(key), password=None,
                                    ssl_version=ssl.PROTOCOL_TLS_SERVER, cert_reqs=ssl.CERT_NONE,
                                    ca_certs=None, ciphers=omr_admin.API_TLS_CIPHERS)

    def handshake(minimum, maximum, ciphers=None):
        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE
        try:
            client_ctx.minimum_version, client_ctx.maximum_version = minimum, maximum
            if ciphers:
                client_ctx.set_ciphers(ciphers)
        except (ValueError, ssl.SSLError):
            return None  # this OpenSSL can't even offer it
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)

        def serve():
            conn, _ = listener.accept()
            try:
                with server_ctx.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            with socket.create_connection(listener.getsockname(), timeout=5) as sock, \
                 client_ctx.wrap_socket(sock) as tls:
                return tls.version(), tls.cipher()[0]
        except (ssl.SSLError, OSError):
            return None
        finally:
            thread.join(5)
            listener.close()

    v = ssl.TLSVersion
    assert handshake(v.TLSv1_3, v.TLSv1_3)[0] == "TLSv1.3"
    version, cipher = handshake(v.TLSv1_2, v.TLSv1_2)
    assert version == "TLSv1.2" and ("GCM" in cipher or "CHACHA20" in cipher), cipher
    # the only suite it negotiated before
    assert handshake(v.TLSv1_2, v.TLSv1_2, "ECDHE-RSA-AES256-SHA") is None
    assert handshake(v.TLSv1, v.TLSv1_1, "ALL:@SECLEVEL=0") is None


# ---------------------------------------------------------------------------
# A trailing comma in the config
# ---------------------------------------------------------------------------

class TestConfigTrailingComma:
    TEXT = json.dumps(MOCK_CONFIG)[:-1] + ',"vxlan_test": 1,}'

    def test_vxlan_reads_it(self):
        with patch("builtins.open", side_effect=_open_with({CONFIG_PATH: self.TEXT})):
            assert omr_admin.get_vxlan_config("openmptcprouter", 0)["mode"] == "l3"

    def test_main_does_not_parse_the_file_again(self):
        # load_startup_config read it at import, a trailing comma included:
        # a plain json.load in __main__ then crash-looped the service.
        source = _REAL_OPEN(omr_admin.__file__).read()
        main = source[source.index("if __name__ == '__main__':"):]
        code = "\n".join(line for line in main.splitlines() if not line.strip().startswith("#"))
        assert "json.load" not in code
        assert "omr-admin-config.json" not in code


# ---------------------------------------------------------------------------
# Workers starting together
# ---------------------------------------------------------------------------

class _TrackLock:
    """Stand-in for _omr_config_lock recording whether it is held."""
    def __init__(self):
        self.depth = 0
        self.exclusive = []

    def __call__(self, exclusive=True):
        import contextlib

        @contextlib.contextmanager
        def held():
            self.exclusive.append(exclusive)
            self.depth += 1
            try:
                yield
            finally:
                self.depth -= 1
        return held()


class TestMqvpnRestart:
    _PAYLOAD = {"key": "k", "scheduler": "wlb", "port": 443, "fec_enable": True, "fec_scheme": "reed_solomon",
                "reinjection_control": True, "reinjection_mode": "deadline", "cc": "bbr2"}
    _SERVER = {"listen": "0.0.0.0:443", "scheduler": "wlb", "fec_enable": True, "fec_scheme": "reed_solomon",
               "reinjection_control": True, "reinjection_mode": "deadline", "cc": "bbr2", "users": []}

    def _post(self, client, server, payload):
        lock = _TrackLock()
        restarts = []
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open_with({"/etc/mqvpn/server.json": server})),
            patch("omr_admin._atomic_write_json") as write,
            patch("omr_admin._omr_config_lock", side_effect=lock),
            patch("omr_admin._restart_service", side_effect=lambda unit: restarts.append(lock.depth)),
        ):
            r = client.post("/mqvpn", json=payload)
        assert r.json()["result"] == "done"
        return write, restarts

    def test_same_settings_in_another_layout_no_restart(self, primary_client):
        # written with indent=2 by add_mqvpn: every session of every user cut
        write, restarts = self._post(primary_client, json.dumps(self._SERVER, indent=2), self._PAYLOAD)
        assert not write.called and restarts == []

    def test_restart_out_of_the_config_lock(self, primary_client):
        write, restarts = self._post(primary_client, json.dumps(self._SERVER), dict(self._PAYLOAD, scheduler="minrtt"))
        assert write.call_args.kwargs.get("indent") == 2
        assert restarts == [0]


class TestStartupRaces:
    def test_ss_go_users_synced_under_the_lock(self):
        lock = _TrackLock()
        seen = []
        with (
            patch("omr_admin._omr_config_lock", side_effect=lock),
            patch("omr_admin._sync_ss_go_users_locked", side_effect=lambda: seen.append(lock.depth)),
        ):
            omr_admin.sync_ss_go_users()
        assert seen == [1] and lock.exclusive == [True]

    @pytest.mark.parametrize("func", ["xray_add_user", "v2ray_add_user", "xray_del_user", "v2ray_del_user"])
    def test_proxy_users_changed_under_the_lock(self, func):
        lock = _TrackLock()
        seen = []
        with (
            patch("omr_admin._omr_config_lock", side_effect=lock),
            patch(f"omr_admin._{func}_locked", side_effect=lambda *a: seen.append(lock.depth)),
        ):
            getattr(omr_admin, func)("alice")
        assert seen == [1] and lock.exclusive == [True]

    @pytest.mark.parametrize("func,render", [
        ("_nft_sync_ports", "_render_fw_ports"),
        ("_nft_sync_gre_snat", "_render_gre_snat"),
        ("_nft_sync_client2client", "_render_client2client"),
        ("_nft_resync_dscp_classify", "_dscp_classify_by_class"),
    ])
    def test_nft_rules_read_and_loaded_under_the_lock(self, func, render):
        lock = _TrackLock()
        seen = []

        def track(name, value):
            def side_effect(*a, **k):
                seen.append((name, lock.depth))
                return value
            return side_effect

        empty_classes = {dscp: {4: [], 6: []} for dscp in omr_admin.DSCP_CLASSIFY_CLASSES}
        with (
            patch("omr_admin._omr_config_lock", side_effect=lock),
            patch("omr_admin.read_omr_config", side_effect=track("read", _config())),
            patch(f"omr_admin.{render}", side_effect=track("render", empty_classes if "dscp" in render else ([], []) if "fw" in render else [])),
            patch("omr_admin._nft_run", side_effect=track("nft", True)),
        ):
            getattr(omr_admin, func)()
        assert seen and all(depth >= 1 for _, depth in seen), seen
        assert lock.exclusive[0] is True

    def test_v2ray_users_pushed_through_a_private_file(self):
        server = {"inbounds": [{"tag": "omrin-tunnel", "settings": {"clients": []}}]}
        pushed = []

        def run(cmd, **kwargs):
            if cmd[:3] == ["v2ray", "api", "adi"]:
                path = cmd[-1]
                pushed.append((path, oct(os.stat(path).st_mode & 0o777), json.loads(_REAL_OPEN(path).read())))
            return MagicMock(returncode=0)

        with (
            patch("shutil.which", return_value="/usr/bin/v2ray"),
            patch("os.path.isfile", return_value=True),
            patch("os.remove", side_effect=os.unlink),
            patch("builtins.open", side_effect=lambda p, *a, **k: io.StringIO(json.dumps(server))
                  if str(p) == "/etc/v2ray/v2ray-server.json" else _REAL_OPEN(p, *a, **k)),
            patch("omr_admin.file_as_bytes", return_value=b"x"),
            patch("omr_admin._atomic_write_json"),
            patch("omr_admin._omr_config_lock", side_effect=_TrackLock()),
            patch("subprocess.run", side_effect=run),
        ):
            omr_admin.v2ray_add_user("alice", "u-alice", restart=0)
        assert len(pushed) == 1
        path, mode, config = pushed[0]
        assert path != "/etc/v2ray/newconfig.json" and mode == "0o600"
        assert config["inbounds"][0]["settings"]["clients"][-1]["email"] == "alice"
        assert not os.path.exists(path)


# ---------------------------------------------------------------------------
# /config: the xray settings of now, for every router
# ---------------------------------------------------------------------------

class TestConfigXrayFresh:
    SERVER = {"inbounds": [
        {"tag": "omrin-tunnel", "port": 65248, "settings": {"clients": [{"id": "u-ro", "email": "readonly"}]},
         "streamSettings": {"network": "xhttp"}},
        {"tag": "omrin-shadowsocks-tunnel", "settings": {"password": "srv", "method": "2022-blake3-chacha20-poly1305",
                                                         "clients": [{"email": "readonly", "password": "usr"}]}},
        {"tag": "omrin-vless-reality", "port": 443},
    ]}

    def test_secondary_router_gets_what_the_main_router_set(self, other_client):
        config = _config()
        # stored at its first /config, before the main router changed them
        config["users"][0]["readonly"]["xray"] = {
            "key": "u-ro", "port": "65248", "sskey": "srv:usr", "vless_reality": False, "vless_reality_key": "",
            "ss_method": "2022-blake3-aes-256-gcm", "transport": "tcp", "reverse_key": "rev"}
        files = {CONFIG_PATH: json.dumps(config), "/etc/xray/xray-server.json": json.dumps(self.SERVER)}
        real_isfile = os.path.isfile
        with (
            patch("builtins.open", side_effect=_open_with(files)),
            patch("os.path.isfile", side_effect=lambda p: p in files or real_isfile(p)),
            patch("omr_admin.xray_user_reverse_key", return_value="rev"),
            patch("omr_admin.modif_config_user") as modif,
            # psutil reads /proc/<pid>/stat with open(), mocked here: a
            # process it has not seen yet broke the test
            patch("omr_admin.checkIfProcessRunning", return_value=False),
        ):
            body = other_client.get("/config").json()
        xray = body["xray"]["config"]
        assert xray["transport"] == "xhttp"
        assert xray["ss_method"] == "2022-blake3-chacha20-poly1305"
        assert xray["vless_reality"] is True
        assert xray["key"] == "u-ro" and xray["sskey"] == "srv:usr" and xray["reverse_key"] == "rev"
        modif.assert_any_call("readonly", {"xray": xray})


# ---------------------------------------------------------------------------
# /config: what another user, or a file, lacks is no 500
# ---------------------------------------------------------------------------

class TestConfigMissingKeys:
    def test_missing_port_method_mqvpn_key_and_lanips(self, other_client):
        config = _config()
        config["client2client"] = True
        config["users"][0]["openmptcprouter"]["lanips"] = []
        manager = {"port_conf": {}, "plugin": "obfs-server"}   # no port, no method, no plugin_opts
        mqvpn = {"users": [{"name": "readonly"}]}              # no key
        files = {CONFIG_PATH: json.dumps(config),
                 "/etc/shadowsocks-libev/manager.json": json.dumps(manager),
                 "/etc/mqvpn/server.json": json.dumps(mqvpn)}
        real_isfile = os.path.isfile
        with (
            patch("builtins.open", side_effect=_open_with(files)),
            patch("os.path.isfile", side_effect=lambda p: p in files or real_isfile(p)),
            patch("omr_admin.mqvpn_server_pin", return_value=""),
        ):
            r = other_client.get("/config")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["shadowsocks"]["key"] == "" and body["shadowsocks"]["method"] == "chacha20"
        assert body["mqvpn"]["key"] == ""
        assert body["client2client"]["lanips"] == []

    def test_openvpn_certificate_made_under_the_lock(self, other_client):
        lock = _TrackLock()
        made = []

        def run(cmd, **kwargs):
            if cmd[:2] == ["./easyrsa", "--batch"]:
                made.append(lock.depth)
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        real_isfile = os.path.isfile
        with (
            patch("os.path.isfile", side_effect=lambda p: p == "/etc/openvpn/tun0.conf" or real_isfile(p)),
            patch("omr_admin._omr_config_lock", side_effect=lock),
            patch("omr_admin._pki_retire_user_certs"),
            patch("subprocess.run", side_effect=run),
        ):
            other_client.get("/config")
        assert made == [1]

    def test_no_openvpn_certificate_for_a_user_removed_meanwhile(self, other_client):
        # /remove_user ran (certificate revoked and dropped) between the
        # read of the config and the lock: a new one let the router back in
        made = []

        def run(cmd, **kwargs):
            if cmd[:1] == ["./easyrsa"]:
                made.append(cmd)
            return MagicMock(returncode=0, stdout=b"", stderr=b"")
        real_isfile = os.path.isfile
        for latest in ({"users": [{}]},
                       {"users": [{"readonly": {"userid": 2, "disabled": "true", "access_suspended": {}}}]}):
            with (
                patch("os.path.isfile", side_effect=lambda p: p == "/etc/openvpn/tun0.conf" or real_isfile(p)),
                patch("omr_admin._read_omr_config_unlocked", return_value=latest),
                patch("subprocess.run", side_effect=run),
            ):
                other_client.get("/config")
        assert made == []

    def test_no_openvpn_certificate_for_a_suspended_user(self, admin_client):
        config = _config()
        config["users"][0]["readonly"].update(disabled="true", access_suspended={"openvpn": True})
        files = {CONFIG_PATH: json.dumps(config)}
        made = []

        def run(cmd, **kwargs):
            if cmd[:1] == ["./easyrsa"]:
                made.append(cmd)
            return MagicMock(returncode=0, stdout=b"", stderr=b"")
        real_isfile = os.path.isfile
        with (
            patch("builtins.open", side_effect=_open_with(files)),
            patch("os.path.isfile", side_effect=lambda p: p in files or p == "/etc/openvpn/tun0.conf" or real_isfile(p)),
            patch("subprocess.run", side_effect=run),
        ):
            r = admin_client.get("/config", params={"username": "readonly"})
        assert r.status_code == 200, r.text
        assert made == []


# ---------------------------------------------------------------------------
# The docs cookie: only as that cookie, from the address it was given to
# ---------------------------------------------------------------------------

class TestDocsCookieToken:
    @staticmethod
    def _login(client):
        import base64
        creds = base64.b64encode(b"admin:adminpassword").decode()
        r = client.get("/login_basic", headers={"Authorization": f"Basic {creds}"}, follow_redirects=False)
        cookie = r.headers.get("set-cookie", "")
        return cookie.split("Authorization=", 1)[1].split(";", 1)[0].strip('"')

    def test_cookie_works_where_it_was_given(self, unauth_client):
        cookie = self._login(unauth_client)
        r = unauth_client.get("/docs", headers={"Cookie": f'Authorization="{cookie}"'})
        assert r.status_code == 200

    def test_its_token_refused_as_a_header(self, unauth_client):
        cookie = self._login(unauth_client)
        token = cookie.replace("Bearer ", "").replace("\\040", " ").split()[-1]
        r = unauth_client.get("/status", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

    def test_its_token_refused_from_another_address(self):
        user = omr_admin.get_user(MOCK_CONFIG["users"][0], "admin")
        token = omr_admin.create_access_token(data={
            "sub": "admin", "pwd": omr_admin._password_fingerprint(user.user_password),
            "use": "docs", "ip": "198.51.100.7"})

        def request(host, headers=None):
            return MagicMock(client=MagicMock(host=host), headers=headers or {})

        assert omr_admin.get_current_user(request("198.51.100.7"), token).username == "admin"
        with pytest.raises(omr_admin.HTTPException):
            omr_admin.get_current_user(request("203.0.113.9"), token)
        with pytest.raises(omr_admin.HTTPException):
            omr_admin.get_current_user(request("198.51.100.7", {"Authorization": f"Bearer {token}"}), token)

    def test_api_token_unchanged(self):
        user = omr_admin.get_user(MOCK_CONFIG["users"][0], "admin")
        token = omr_admin.create_access_token(data={
            "sub": "admin", "pwd": omr_admin._password_fingerprint(user.user_password)})
        r = MagicMock(client=MagicMock(host="203.0.113.9"), headers={"Authorization": f"Bearer {token}"})
        assert omr_admin.get_current_user(r, token).username == "admin"


# ---------------------------------------------------------------------------
# shadowsocks-go: the older API path
# ---------------------------------------------------------------------------

class TestSsGoApiFallback:
    @staticmethod
    def _answers(*codes):
        it = iter(codes)
        calls = []

        def call(url, **kwargs):
            calls.append(url)
            code = next(it)
            if isinstance(code, Exception):
                raise code
            return MagicMock(status_code=code, ok=code < 400)
        return call, calls

    def test_404_tries_the_older_path(self):
        call, calls = self._answers(404, 200)
        with patch("os.path.exists", return_value=True), patch("omr_admin.requests.post", side_effect=call):
            omr_admin.add_ss_go_user("alice", "k")
        assert calls == list(omr_admin.SS_GO_USERS_URLS)

    def test_found_at_once_not_twice(self):
        call, calls = self._answers(200)
        with patch("os.path.exists", return_value=True), patch("omr_admin.requests.delete", side_effect=call):
            omr_admin.remove_ss_go_user("alice")
        assert calls == [omr_admin.SS_GO_USERS_URLS[0] + "/alice"]

    def test_timeout_not_retried(self):
        call, calls = self._answers(omr_admin.requests.exceptions.Timeout())
        with patch("os.path.exists", return_value=True), patch("omr_admin.requests.post", side_effect=call):
            omr_admin.add_ss_go_user("alice", "k")
        assert len(calls) == 1


# ---------------------------------------------------------------------------
# Failures reported, not taken for success
# ---------------------------------------------------------------------------

class TestRestartFailureLogged:
    def test_failed_restart_logged_and_reported(self, caplog):
        failed = MagicMock(returncode=1, stderr="Job for xray.service failed\n")
        with patch("subprocess.run", return_value=failed), caplog.at_level("WARNING", logger="uvicorn.error"):
            assert omr_admin._restart_service("xray") is False
        assert any("systemctl restart xray failed" in r.getMessage() and "Job for xray" in r.getMessage()
                   for r in caplog.records)

    def test_restart_ok(self):
        with patch("subprocess.run", return_value=MagicMock(returncode=0, stderr="")):
            assert omr_admin._restart_service("xray") is True


class TestFirewallEntryRefusedByNft:
    def test_rolled_back_and_reported(self):
        config = _config()
        saved = []

        def modif(user, changes):
            saved.append(changes["fw_ports"])
            config["users"][0][user].update(changes)

        with (
            patch("omr_admin.read_omr_config", side_effect=lambda: config),
            patch("omr_admin.modif_config_user", side_effect=modif),
            patch("omr_admin._nft_sync_ports", side_effect=[False, True]) as sync,
            patch("omr_admin._nft_base_table_exists", return_value=True),
        ):
            error = omr_admin._fw_port_add("readonly", "8080", "tcp", "x", "ACCEPT", 4, "", "", "default", "")
        assert error == "Firewall rule refused"
        assert len(saved) == 2 and saved[-1] == [] and config["users"][0]["readonly"]["fw_ports"] == []
        assert sync.call_count == 2

    def test_kept_when_nft_refuses_the_chains_without_it_too(self):
        # another entry, of any user, or nft itself: refusing this one
        # refused every new entry of every user until that was found
        config = _config()
        with (
            patch("omr_admin.read_omr_config", side_effect=lambda: config),
            patch("omr_admin.modif_config_user", side_effect=lambda u, c: config["users"][0][u].update(c)),
            patch("omr_admin._nft_sync_ports", return_value=False) as sync,
            patch("omr_admin._nft_base_table_exists", return_value=True),
        ):
            assert omr_admin._fw_port_add("readonly", "8080", "tcp", "x", "ACCEPT", 4, "", "", "default", "") is None
        assert len(config["users"][0]["readonly"]["fw_ports"]) == 1
        assert sync.call_count == 2

    def test_kept_while_nftables_is_not_loaded(self):
        config = _config()
        with (
            patch("omr_admin.read_omr_config", side_effect=lambda: config),
            patch("omr_admin.modif_config_user", side_effect=lambda u, c: config["users"][0][u].update(c)),
            patch("omr_admin._nft_sync_ports", return_value=False),
            patch("omr_admin._nft_base_table_exists", return_value=False),
        ):
            assert omr_admin._fw_port_add("readonly", "8080", "tcp", "x", "ACCEPT", 4, "", "", "default", "") is None
        assert len(config["users"][0]["readonly"]["fw_ports"]) == 1

    def test_address_of_the_other_family_refused(self, other_client):
        with patch("omr_admin.modif_config_user") as modif:
            r = other_client.post("/firewallopen", json={"name": "x", "port": "80", "proto": "tcp", "fwtype": "ACCEPT",
                                                        "ipproto": "ipv4", "source_dip": "2001:db8::1"})
        assert r.json()["reason"] == "Address of the other IP family"
        assert not modif.called


class TestGlorytunPorts:
    def test_udp_listening_port_is_bind_port(self):
        files = {"/etc/glorytun-udp/tun2": "BIND=::\nBIND_PORT=65002\nHOST=::\nPORT=5000\nDEV=tun2\n",
                 "/etc/glorytun-tcp/tun2": "PORT=65002\nHOST=::\n"}
        with patch("builtins.open", side_effect=_open_with(files)):
            assert omr_admin._tunnel_file_ports("/etc/glorytun-udp/tun2") == {65002}
            assert omr_admin._tunnel_file_ports("/etc/glorytun-tcp/tun2") == {65002}

    def test_user_without_a_tunnel_opens_nothing(self, other_client):
        with (
            patch("os.path.isfile", side_effect=lambda p: p in ("/etc/glorytun-tcp/tun0",)),
            patch("omr_admin.shorewall_add_port") as add,
        ):
            r = other_client.post("/glorytun", json={"key": "k" * 64, "port": 65002, "chacha": True})
        assert r.json()["reason"] == "No Glorytun tunnel for this user"
        assert not add.called


class TestWanAcl:
    def test_acl_written_under_the_lock_with_every_users_ips(self, other_client):
        config = _config()
        config["users"][0]["openmptcprouter"]["wanips"] = ["198.51.100.7"]
        written, depth = {}, []
        lock = _TrackLock()

        def write(p, t, **k):
            written[p] = t
            depth.append(lock.depth)

        with (
            patch("os.path.isfile", return_value=True),
            patch("omr_admin._omr_config_lock", side_effect=lock),
            patch("omr_admin.read_omr_config", side_effect=lambda: config),
            patch("omr_admin.modif_config_user", side_effect=lambda u, c: config["users"][0][u].update(c)),
            patch("omr_admin._atomic_write_text", side_effect=write),
        ):
            r = other_client.post("/wan", json={"ips": "203.0.113.4"})
        assert r.json()["result"] == "done"
        assert written["/etc/shadowsocks-libev/local.acl"] == "[white_list]\n198.51.100.7\n203.0.113.4\n"
        assert depth == [1]

    def test_removed_users_ips_leave_the_acl(self):
        config = _config()
        config["users"][0]["openmptcprouter"]["wanips"] = ["198.51.100.7"]
        written = {}
        with (
            patch("omr_admin.read_omr_config", side_effect=lambda: config),
            patch("omr_admin._atomic_write_text", side_effect=lambda p, t, **k: written.update({p: t})),
        ):
            omr_admin._write_ss_acl()
        assert written["/etc/shadowsocks-libev/local.acl"] == "[white_list]\n198.51.100.7\n"
        del config["users"][0]["openmptcprouter"]["wanips"]
        written.clear()
        with (
            patch("omr_admin.read_omr_config", side_effect=lambda: config),
            patch("omr_admin._atomic_write_text", side_effect=lambda p, t, **k: written.update({p: t})),
        ):
            omr_admin._write_ss_acl()
        assert written == {}   # no IP left: the ACL as it was


# ---------------------------------------------------------------------------
# Values checked before they are written
# ---------------------------------------------------------------------------

class TestLowValidation:
    def test_dsvpn_key_with_a_newline_refused(self, primary_client):
        with patch("os.path.isfile", return_value=True), patch("omr_admin._atomic_write_text") as write:
            r = primary_client.post("/dsvpn", json={"key": "abc\nPORT=1", "port": 65401})
        assert r.json()["reason"] == "Invalid key"
        assert not write.called

    @pytest.mark.parametrize("mtu", [100, 1279, 9001])
    def test_vxlan_mtu_out_of_range(self, other_client, mtu):
        r = other_client.post("/vxlan", json={"mtu": mtu})
        assert r.status_code == 422

    def test_vxlan_bridge_name_fits_an_interface_name(self):
        assert omr_admin._vxlan_bridge_name(42) == "br-vxlan42"
        assert omr_admin._vxlan_bridge_name(9999999) == "br-vxlan9999999"
        assert omr_admin._vxlan_bridge_name(16777215) == "br-vxffffff"
        assert all(len(omr_admin._vxlan_bridge_name(v)) <= 15 for v in (0, 10000000, 16777215))

    def test_port_65535_accepted(self):
        assert omr_admin.DSVPN(key="k", port=65535).port == 65535
        assert omr_admin.MQVPN(port=65535).port == 65535

    @pytest.mark.parametrize("fixed_ip,reason", [
        ("10.255.221.5", "Invalid fixed_ip"),       # out of the subnet
        ("10.255.220.1", "Invalid fixed_ip"),       # MQVPN's own
        ("10.255.220.255", "Invalid fixed_ip"),
        ("not-an-ip", "Invalid fixed_ip"),
        ("10.255.220.9", "fixed_ip already used by another user"),
    ])
    def test_mqvpn_fixed_ip_checked(self, admin_client, fixed_ip, reason):
        server = {"subnet": "10.255.220.0/24", "users": [{"name": "openmptcprouter", "key": "a"},
                                                        {"name": "readonly", "key": "b", "fixed_ip": "10.255.220.9"}]}
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open_with({"/etc/mqvpn/server.json": json.dumps(server)})),
            patch("omr_admin._atomic_write_json") as write,
        ):
            r = admin_client.post("/mqvpn_user", json={"username": "openmptcprouter", "fixed_ip": fixed_ip})
        assert r.json()["reason"] == reason
        assert not write.called

    def test_mqvpn_fixed_ip_of_the_subnet_saved(self, admin_client):
        server = {"subnet": "10.255.220.0/24", "users": [{"name": "openmptcprouter", "key": "a"}]}
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open_with({"/etc/mqvpn/server.json": json.dumps(server)})),
            patch("omr_admin.file_as_bytes", side_effect=[b"a", b"b"]),
            patch("omr_admin._atomic_write_json") as write,
        ):
            r = admin_client.post("/mqvpn_user", json={"username": "openmptcprouter", "fixed_ip": "10.255.220.20"})
        assert r.json()["result"] == "done"
        assert write.call_args.args[1]["users"][0]["fixed_ip"] == "10.255.220.20"

    def test_vxlan_routes_serialised(self):
        # the conflict checks and the save as one step
        assert omr_admin.vxlan.__wrapped__ and omr_admin.vxlan_user_set_config.__wrapped__
        assert omr_admin.lan.__wrapped__ and omr_admin.openvpn.__wrapped__


class TestMqvpnPathPolicyQuota:
    def _post(self, client, route, body, policy):
        server = {"users": [], "path_policy": policy}
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open_with({"/etc/mqvpn/server.json": json.dumps(server)})),
            patch("omr_admin._atomic_write_json") as write,
            patch("omr_admin._mqvpn_push", return_value=[]) as push,
        ):
            r = client.post(route, json=body)
        return r.json(), write, push

    def test_dscp_and_weight_interfaces_counted_together(self, other_client):
        policy = [{"user": "readonly", "iface": f"wan{i}", "weight": 1} for i in range(16)]
        body, write, push = self._post(other_client, "/mqvpn_dscp", {"pins": [{"iface": "lte1", "dscp": ["cs1"]}]}, policy)
        assert body["reason"] == "Too many interfaces"
        assert not write.called and not push.called

    def test_table_full(self, other_client):
        policy = [{"user": f"u{i}", "iface": "wan", "weight": 1} for i in range(128)]
        body, write, _ = self._post(other_client, "/mqvpn_weight", {"weights": [{"iface": "wan1", "weight": 2}]}, policy)
        assert body["reason"] == "MQVPN path policy table full"
        assert not write.called

    def test_table_over_the_limit_can_shrink(self, other_client):
        # left over it by an older release: every sync was refused, the ones
        # that removed entries too
        policy = [{"user": f"u{i}", "iface": "wan", "weight": 1} for i in range(140)] + \
                 [{"user": "readonly", "iface": f"wan{i}", "dscp_mask": 1} for i in range(3)]
        body, write, _ = self._post(other_client, "/mqvpn_dscp", {"pins": [{"iface": "wan0", "dscp": ["cs1"]}]}, policy)
        assert body["result"] == "done"
        assert write.called
        # growing it is still refused
        body, write, _ = self._post(other_client, "/mqvpn_dscp", {"pins": [{"iface": f"wan{i}", "dscp": ["cs1"]}
                                                                           for i in range(4)]}, policy)
        assert body["reason"] == "MQVPN path policy table full"
        assert not write.called

    def test_changing_its_own_entries_in_a_full_table(self, other_client):
        policy = [{"user": f"u{i}", "iface": "wan", "weight": 1} for i in range(127)] + \
                 [{"user": "readonly", "iface": "wan1", "weight": 1}]
        body, write, _ = self._post(other_client, "/mqvpn_weight", {"weights": [{"iface": "wan1", "weight": 2}]}, policy)
        assert body["result"] == "done"
        assert write.called

    def test_wireguard_peers_per_user_capped(self, other_client):
        key = __import__("base64").b64encode(b"k" * 32).decode()
        peers = [{"ip": f"10.255.247.{i}", "key": key} for i in range(2, 2 + omr_admin.WIREGUARD_MAX_USER_PEERS + 1)]
        with patch("os.path.isfile", return_value=True), patch("omr_admin.modif_config_user") as modif:
            r = other_client.post("/wireguard", json={"peers": peers})
        assert r.json()["reason"] == "Too many peers"
        assert not modif.called


class TestSpeedtestConcurrency:
    def test_caps_and_release(self, other_client):
        omr_admin._speedtests_running.clear()
        try:
            omr_admin._speedtests_running["readonly"] = omr_admin.SPEEDTEST_MAX_USER
            with patch("omr_admin._mptcp_status_for_ip", return_value="no"):
                r = other_client.get("/speedtest", params={"size": 1})
                assert r.status_code == 429
                r = other_client.post("/speedtest", content=b"x" * 10)
                assert r.status_code == 429
                omr_admin._speedtests_running.clear()
                omr_admin._speedtests_running["someone"] = omr_admin.SPEEDTEST_MAX
                assert other_client.get("/speedtest", params={"size": 1}).status_code == 429
                omr_admin._speedtests_running.clear()
                r = other_client.get("/speedtest", params={"size": 1})
                assert r.status_code == 200 and len(r.content) == 1024 * 1024
                r = other_client.post("/speedtest", content=b"x" * 10)
                assert r.json()["bytes"] == 10
            assert omr_admin._speedtests_running == {}   # counted out once done
        finally:
            omr_admin._speedtests_running.clear()

    def test_stalled_upload_gives_its_slot_back(self, monkeypatch):
        # a WAN dropped mid-upload (no FIN, no RST): nothing timed the body
        # out, and the slot was kept for the life of the worker
        monkeypatch.setattr(omr_admin, "SPEEDTEST_IDLE_TIMEOUT", 0.05)
        omr_admin._speedtests_running.clear()

        class _Request:
            client = type("C", (), {"host": "192.0.2.1"})()

            async def stream(self):
                yield b"x" * 10
                await asyncio.sleep(10)
                yield b"never"
        try:
            with patch("omr_admin._mptcp_status_for_ip", return_value="no"):
                r = asyncio.run(omr_admin.speedtestul(_Request(), current_user=OTHER))
            assert r.status_code == 408
            assert omr_admin._speedtests_running == {}
            # over the longest: measured over what came by then
            monkeypatch.setattr(omr_admin, "SPEEDTEST_MAX_DURATION", 0.03)
            with patch("omr_admin._mptcp_status_for_ip", return_value="no"):
                r = asyncio.run(omr_admin.speedtestul(_Request(), current_user=OTHER))
            assert r["bytes"] == 10
            assert omr_admin._speedtests_running == {}
        finally:
            omr_admin._speedtests_running.clear()

    def test_released_when_the_body_never_streams(self):
        # the generator's finally only runs once it started: a client gone
        # before that kept the slot for the life of the worker
        omr_admin._speedtests_running.clear()
        try:
            assert omr_admin._speedtest_start("readonly")
            released = []

            def release():
                released.append(1)
                omr_admin._speedtest_end("readonly")

            async def body():
                yield b"x"

            async def send(message):
                raise OSError("client gone")

            async def receive():
                return {"type": "http.disconnect"}

            response = omr_admin._SpeedtestResponse(body(), release)
            with pytest.raises(Exception):
                asyncio.run(response({"type": "http", "asgi": {"spec_version": "2.4"}}, receive, send))
            assert released == [1]
            assert omr_admin._speedtests_running == {}
        finally:
            omr_admin._speedtests_running.clear()


class TestJwtExpRequired:
    def test_token_without_exp_refused(self):
        import jwt as pyjwt
        user = omr_admin.get_user(MOCK_CONFIG["users"][0], "admin")
        token = pyjwt.encode({"sub": "admin", "pwd": omr_admin._password_fingerprint(user.user_password)},
                             omr_admin.SECRET_KEY, algorithm=omr_admin.ALGORITHM)
        request = MagicMock(client=MagicMock(host="198.51.100.7"), headers={"Authorization": f"Bearer {token}"})
        with pytest.raises(omr_admin.HTTPException):
            omr_admin.get_current_user(request, token)


class TestLifespanGuards:
    def test_a_failing_step_does_not_stop_the_start(self):
        ran = []
        with (
            patch("omr_admin.load_mptcp_bpf_schedulers", side_effect=OSError("bpffs")),
            patch("omr_admin.normalize_persisted_mptcp_path_manager", side_effect=lambda: ran.append("pm")),
            patch("omr_admin.sync_ss_go_users", side_effect=ValueError("bad json")),
            patch("omr_admin.resume_proxy_restarts", side_effect=lambda: ran.append("resume")),
            patch("omr_admin.proxy_isolate_reverse_tunnels", side_effect=lambda: ran.append("isolate")),
            patch("omr_admin._tighten_tunnel_keys"),
            patch("omr_admin._tighten_router_backups", side_effect=lambda: ran.append("backups")),
        ):
            async def run():
                async with omr_admin._lifespan(omr_admin.app):
                    ran.append("serving")
            asyncio.run(run())
        assert ran == ["pm", "resume", "isolate", "backups", "serving"]


# ---------------------------------------------------------------------------
# Every route but the public ones requires a login
# ---------------------------------------------------------------------------

# The router asks / and /mptcpsupport before it has a token, logs in with
# /token, a browser with /login_basic; /clienthost and /logout give nothing.
PUBLIC_ROUTES = {"/", "/token", "/login_basic", "/logout", "/clienthost", "/mptcpsupport"}


def _depends_on_login(dependant):
    calls = {omr_admin.get_current_user, omr_admin.get_current_active_user}
    return any(dep.call in calls or _depends_on_login(dep) for dep in dependant.dependencies)


class TestEveryRouteRequiresLogin:
    def test_route_dependencies(self):
        from fastapi.routing import APIRoute
        unprotected = sorted(route.path for route in omr_admin.app.routes
                             if isinstance(route, APIRoute) and route.path not in PUBLIC_ROUTES
                             and not _depends_on_login(route.dependant))
        assert unprotected == []

    def test_public_routes_still_exist(self):
        paths = {getattr(route, "path", None) for route in omr_admin.app.routes}
        assert PUBLIC_ROUTES <= paths

    def test_unauthenticated_request_refused_everywhere(self, unauth_client):
        from fastapi.routing import APIRoute
        for route in omr_admin.app.routes:
            if not isinstance(route, APIRoute) or route.path in PUBLIC_ROUTES or "{" in route.path:
                continue
            method = sorted(route.methods)[0].lower()
            r = getattr(unauth_client, method)(route.path)
            assert r.status_code in (401, 403), (route.path, r.status_code)


# ---------------------------------------------------------------------------
# A disabled user: its access cut, and put back when enabled
# ---------------------------------------------------------------------------

class TestDisabledUserAccess:
    @pytest.fixture
    def xray(self, tmp_path, monkeypatch):
        path = tmp_path / "xray-server.json"
        path.write_text(json.dumps({"inbounds": [
            {"tag": "omrin-tunnel", "settings": {"clients": [
                {"id": "u0", "email": "openmptcprouter"}, {"id": "u2", "email": "readonly"},
                {"id": "u2g", "email": "readonlygre-user2-ip0"},
                {"id": "r2", "email": "omr-reverse@readonly", "reverse": {"tag": "OMRLan-readonly"}}]}},
            {"tag": "omrin-socks-tunnel", "settings": {"accounts": [{"user": "readonly", "pass": "p"}]}},
        ], "routing": {"rules": []}}))
        monkeypatch.setattr(omr_admin, "PROXY_REDIRECT_CONFIGS", {"xray": str(path)})
        monkeypatch.setattr(omr_admin, "OMR_CONFIG_LOCK_FILE", str(tmp_path / ".lock"))
        return path

    @pytest.mark.real_env
    def test_proxy_clients_taken_out_and_put_back(self, xray):
        before = json.loads(xray.read_text())
        udata = {"userid": 2, "username": "readonly", "gre_tunnels": {"gre-user2-ip0": {}}}
        real_isfile = os.path.isfile
        with (
            patch("os.path.isfile", side_effect=lambda p: str(p) == str(xray) or (real_isfile(p) and str(p).startswith(str(xray.parent)))),
            patch("omr_admin._schedule_proxy_restart") as restart,
            patch("omr_admin.modif_config_user") as modif,
        ):
            suspended = omr_admin._suspend_user_access("readonly", udata)
            during = json.loads(xray.read_text())
            emails = [c["email"] for c in during["inbounds"][0]["settings"]["clients"]]
            # its reverse tunnel too: its router's bridge logs in with it, its
            # redirected ports went on reaching its LAN
            assert emails == ["openmptcprouter"]
            # saved as soon as taken, marked partial until the caller saves it
            assert modif.call_args.args == ("readonly", {"access_suspended": dict(suspended, _partial=True)})
            assert during["inbounds"][1]["settings"]["accounts"] == []
            json.dumps(suspended)   # kept in the config
            omr_admin._resume_user_access("readonly", udata, suspended)
        after = json.loads(xray.read_text())
        for ib_before, ib_after in zip(before["inbounds"], after["inbounds"]):
            for field in ("clients", "accounts"):
                assert sorted(map(json.dumps, ib_before["settings"].get(field, []))) == \
                    sorted(map(json.dumps, ib_after["settings"].get(field, [])))
        assert restart.call_count == 2

    def test_partial_suspension_completed_not_redone(self):
        # stopped after its openvpn step: run again, that step would revoke
        # with easyrsa and drop the certificate it kept
        udata = {"userid": 2, "disabled": "true",
                 "access_suspended": {"_partial": True, "openvpn": {"serials": ["02"]}}}
        assert omr_admin._suspension_incomplete(udata)
        assert not omr_admin._suspension_incomplete({"access_suspended": {"openvpn": True}})
        assert omr_admin._suspension_incomplete({})
        with (
            patch("os.path.isfile", side_effect=lambda p: p in ("/etc/openvpn/tun0.conf", "/etc/glorytun-tcp/tun2")),
            patch("omr_admin._ccd_disable") as ccd,
            patch("omr_admin._pki_retire_user_certs") as retire,
            patch("omr_admin._openvpn_revoke") as revoke,
            patch("omr_admin._openvpn_kill"),
            patch("omr_admin.modif_config_user") as modif,
            patch("subprocess.run"),
        ):
            suspended = omr_admin._suspend_user_access("readonly", udata)
        assert not ccd.called and not retire.called and not revoke.called
        assert suspended == {"openvpn": {"serials": ["02"]}, "units": ["glorytun-tcp@tun2"]}
        assert modif.call_args.args[1]["access_suspended"]["_partial"] is True

    def test_tunnels_stopped_openvpn_refused_and_back(self):
        present = {"/etc/glorytun-tcp/tun2", "/etc/dsvpn/dsvpn2", "/etc/openvpn/tun0.conf"}
        written = {}
        with (
            patch("os.path.isfile", side_effect=lambda p: p in present or p in written),
            patch("builtins.open", side_effect=_open_with({"/etc/openvpn/ccd/readonly": "iroute 192.168.2.0 255.255.255.0\n"})),
            patch("omr_admin._atomic_write_text", side_effect=lambda p, t, **k: written.update({p: t})),
            patch("omr_admin._openvpn_kill") as kill,
            patch("omr_admin._openvpn_revoke") as revoke,
            patch("omr_admin._pki_retire_user_certs", return_value=["02"]) as retire,
            patch("omr_admin._pki_restore_user_certs", return_value="02") as restore,
            patch("omr_admin._openvpn_drop_cert_files") as drop,
            patch("subprocess.run") as run,
            patch("omr_admin._restart_service") as restart,
        ):
            suspended = omr_admin._suspend_user_access("readonly", {"userid": 2})
            assert written["/etc/openvpn/ccd/readonly"] == "iroute 192.168.2.0 255.255.255.0\ndisable\n"
            kill.assert_called_once_with("readonly")
            # tun1 (UDP) has no ccd: only the CRL keeps it out there; the
            # files are kept, for the router's certificate to be put back
            retire.assert_called_once_with("readonly")
            assert not revoke.called
            assert suspended["openvpn"] == {"serials": ["02"]}
            assert [c.args[0] for c in run.call_args_list] == [
                ["systemctl", "-q", "disable", "glorytun-tcp@tun2"],
                ["systemctl", "-q", "stop", "glorytun-tcp@tun2"],
                ["systemctl", "-q", "disable", "dsvpn-server@dsvpn2"],
                ["systemctl", "-q", "stop", "dsvpn-server@dsvpn2"]]
            run.reset_mock()
            omr_admin._resume_user_access("readonly", {"userid": 2}, suspended)
            restore.assert_called_once_with("readonly", ["02"])
            assert not drop.called
            assert written["/etc/openvpn/ccd/readonly"] == "iroute 192.168.2.0 255.255.255.0\n"
            # not put back: a new one at /config
            restore.return_value = None
            with patch("omr_admin._pki_user_has_valid_cert", return_value=False):
                omr_admin._resume_user_access("readonly", {"userid": 2}, suspended)
            drop.assert_called_once_with("readonly")
            # but not the files of a certificate issued meanwhile
            drop.reset_mock()
            with patch("omr_admin._pki_user_has_valid_cert", return_value=True):
                omr_admin._resume_user_access("readonly", {"userid": 2}, suspended)
            assert not drop.called
            # no valid certificate to revoke in the index: easyrsa, as before
            retire.return_value = []
            suspended = omr_admin._suspend_user_access("readonly", {"userid": 2})
            revoke.assert_called_once_with("readonly")
            assert suspended["openvpn"] is True
        assert [c.args[0] for c in restart.call_args_list][:2] == ["glorytun-tcp@tun2", "dsvpn-server@dsvpn2"]

    def test_modify_user_suspends_then_resumes(self, admin_client):
        config = _config()
        with (
            patch("omr_admin.read_omr_config", side_effect=lambda: config),
            patch("omr_admin.modif_config_user", side_effect=lambda u, c: config["users"][0][u].update(c)),
            patch("omr_admin._mutate_omr_config", side_effect=lambda f: f(config)),
            patch("omr_admin._suspend_user_access", return_value={"units": ["glorytun-tcp@tun2"]}) as suspend,
            patch("omr_admin._resume_user_access") as resume,
        ):
            r = admin_client.post("/modify_user", json={"username": "readonly", "disabled": True})
            assert r.json()["result"] == "done"
            assert config["users"][0]["readonly"]["access_suspended"] == {"units": ["glorytun-tcp@tun2"]}
            # disabled again: nothing more taken
            admin_client.post("/modify_user", json={"username": "readonly", "disabled": True})
            assert suspend.call_count == 1
            r = admin_client.post("/modify_user", json={"username": "readonly", "disabled": False})
        assert r.json()["result"] == "done"
        assert resume.call_args.args[2] == {"units": ["glorytun-tcp@tun2"]}
        assert "access_suspended" not in config["users"][0]["readonly"]

    def test_user_disabled_before_suspension_existed(self, admin_client):
        # disabled, never suspended: disabling it again changed nothing, its
        # router kept its VPN and proxies
        config = _config()
        config["users"][0]["readonly"]["disabled"] = "true"
        with (
            patch("omr_admin.read_omr_config", side_effect=lambda: config),
            patch("omr_admin.modif_config_user", side_effect=lambda u, c: config["users"][0][u].update(c)),
            patch("omr_admin._mutate_omr_config", side_effect=lambda f: f(config)),
            patch("omr_admin._suspend_user_access", return_value={"units": ["glorytun-tcp@tun2"]}) as suspend,
        ):
            r = admin_client.post("/modify_user", json={"username": "readonly", "disabled": True})
        assert r.json()["result"] == "done"
        assert suspend.call_count == 1
        assert config["users"][0]["readonly"]["access_suspended"] == {"units": ["glorytun-tcp@tun2"]}

    def test_disabled_users_suspended_at_startup(self):
        config = _config()
        config["users"][0]["readonly"]["disabled"] = "true"
        config["users"][0]["openmptcprouter"]["disabled"] = False
        with (
            patch("omr_admin.read_omr_config", side_effect=lambda: config),
            patch("omr_admin.modif_config_user", side_effect=lambda u, c: config["users"][0][u].update(c)),
            patch("omr_admin._suspend_user_access", return_value={"units": ["glorytun-tcp@tun2"]}) as suspend,
        ):
            omr_admin._suspend_disabled_users()
            omr_admin._suspend_disabled_users()   # the next worker: done already
        assert [c.args[0] for c in suspend.call_args_list] == ["readonly"]
        assert config["users"][0]["readonly"]["access_suspended"] == {"units": ["glorytun-tcp@tun2"]}
        assert "access_suspended" not in config["users"][0]["openmptcprouter"]

    def test_resume_sets_up_its_gre_tunnels_again(self, admin_client):
        # left alone while suspended: a public IP given meanwhile had none
        config = _config()
        config["gre_tunnels"] = True
        config["users"][0]["readonly"].update(disabled="true", access_suspended={}, public_ips=["203.0.113.9"])
        seen = []
        with (
            patch("omr_admin.read_omr_config", side_effect=lambda: config),
            patch("omr_admin._mutate_omr_config", side_effect=lambda f: f(config)),
            patch("omr_admin._resume_user_access"),
            patch("omr_admin.add_gre_tunnels",
                  side_effect=lambda u: seen.append((u, omr_admin._user_access_cut(config["users"][0][u])))),
        ):
            r = admin_client.post("/modify_user", json={"username": "readonly", "disabled": False})
        assert r.json()["result"] == "done"
        assert seen == [("readonly", False)]   # once no longer marked suspended

    def test_port_of_a_suspended_user_not_given_to_another(self, tmp_path, monkeypatch):
        manager = tmp_path / "manager.json"
        manager.write_text(json.dumps({"port_conf": {"65101": {"key": "k1", "userid": 1}}}))
        config = _config()
        config["users"][0]["readonly"]["access_suspended"] = {
            "shadowsocks": {"65105": {"key": "carol", "userid": 2}}}
        real_open = open
        with (
            patch("builtins.open", side_effect=lambda p, *a, **k: real_open(str(manager) if p == "/etc/shadowsocks-libev/manager.json" else p, *a, **k)),
            patch("omr_admin._atomic_write_json", side_effect=lambda p, d, **k: manager.write_text(json.dumps(d))),
            patch("omr_admin.read_omr_config", side_effect=lambda: config),
            patch("omr_admin.OMR_CONFIG_LOCK_FILE", str(tmp_path / ".lock")),
            patch("socket.socket"),
            patch("omr_admin._listening_ports", return_value=[]),
            patch("omr_admin._configured_server_ports", return_value=[]),
        ):
            # the lowest free one: 65101 manager.json's, 65102 a user's,
            # 65105 the suspended user's
            assert str(omr_admin.add_ss_user("", "dave", 3)) == "65103"

    def test_free_shadowsocks_port_skips_listeners_and_stops_at_65535(self, tmp_path):
        manager = tmp_path / "manager.json"
        manager.write_text(json.dumps({"port_conf": {"65101": {"key": "k1", "userid": 1}}}))
        config = {"users": [{}]}
        real_open = open
        with (
            patch("builtins.open", side_effect=lambda p, *a, **k: real_open(str(manager) if p == "/etc/shadowsocks-libev/manager.json" else p, *a, **k)),
            patch("omr_admin.read_omr_config", side_effect=lambda: config),
            patch("omr_admin._listening_ports", side_effect=lambda proto: [(65102, 65102)] if proto == "tcp" else []) as listening,
            patch("omr_admin._configured_server_ports", side_effect=lambda proto: [(65103, 65200)]),
        ):
            assert omr_admin._ss_free_port({"65101": {}}) == 65201
        # the sockets listed once per protocol, not twice
        assert listening.call_count == 2
        with (
            patch("omr_admin.read_omr_config", side_effect=lambda: config),
            patch("omr_admin._ss_ports_in_use", return_value=set()),
            patch("omr_admin._configured_server_ports", return_value=[(65101, 65535)]),
        ):
            with pytest.raises(ValueError):
                omr_admin._ss_free_port({})

    def test_suspension_keeps_what_was_taken_when_a_step_fails(self):
        with (
            patch("os.path.isfile", side_effect=lambda p: p in ("/etc/shadowsocks-go/upsks.json", "/etc/openvpn/tun0.conf")),
            patch("builtins.open", side_effect=_open_with({"/etc/shadowsocks-go/upsks.json": json.dumps({"readonly": "upsk"})})),
            patch("omr_admin.remove_ss_go_user"),
            patch("omr_admin._ccd_disable", side_effect=OSError("disk full")),
            patch("omr_admin._openvpn_revoke"),
            patch("omr_admin._openvpn_kill"),
            patch("subprocess.run"),
        ):
            suspended = omr_admin._suspend_user_access("readonly", {"userid": 2})
        assert suspended["shadowsocks_go"] == "upsk"

    def test_softether_password_of_both_forms(self):
        assert omr_admin._softether_password({"softethervpn": "pw"}) == "pw"
        assert omr_admin._softether_password({"softethervpn": {"password": "pw"}}) == "pw"
        assert omr_admin._softether_password({"softethervpn": {}}) is None
        assert omr_admin._softether_password({}) is None
        with (
            patch("os.path.isfile", side_effect=lambda p: p == "/var/lib/softether/vpn_server.config"),
            patch("omr_admin.remove_softether_user") as remove,
            patch("subprocess.run"),
        ):
            suspended = omr_admin._suspend_user_access("openmptcprouter", {"userid": 0, "softethervpn": "pw"})
        remove.assert_called_once_with("openmptcprouter")
        assert suspended["softether"] is True

    def test_resume_leaves_a_port_given_to_another_user(self, tmp_path):
        manager = tmp_path / "manager.json"
        manager.write_text(json.dumps({"port_conf": {"65105": {"key": "dave", "userid": 3},
                                                     "65106": {"key": "x", "userid": 4}}}))
        real_open = open
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=lambda p, *a, **k: real_open(str(manager) if p == "/etc/shadowsocks-libev/manager.json" else p, *a, **k)),
            patch("omr_admin._atomic_write_json", side_effect=lambda p, d, **k: manager.write_text(json.dumps(d))),
            patch("omr_admin.OMR_CONFIG_LOCK_FILE", str(tmp_path / ".lock")),
            patch("omr_admin._ss_manager_readd") as readd,
        ):
            omr_admin._ss_resume({"65105": {"key": "carol", "userid": 2}, "65107": {"key": "carol", "userid": 2}})
        table = json.loads(manager.read_text())["port_conf"]
        assert table["65105"] == {"key": "dave", "userid": 3}
        assert table["65107"] == {"key": "carol", "userid": 2}
        assert [c.args[0] for c in readd.call_args_list] == ["65107"]

    def test_resume_into_a_file_turned_to_port_conf(self, tmp_path):
        # taken from port_key, the file turned to port_conf meanwhile
        manager = tmp_path / "manager.json"
        manager.write_text(json.dumps({"port_conf": {"65101": {"key": "main"}}}))
        real_open = open
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=lambda p, *a, **k: real_open(str(manager) if p == "/etc/shadowsocks-libev/manager.json" else p, *a, **k)),
            patch("omr_admin._atomic_write_json", side_effect=lambda p, d, **k: manager.write_text(json.dumps(d))),
            patch("omr_admin.OMR_CONFIG_LOCK_FILE", str(tmp_path / ".lock")),
            patch("omr_admin._ss_manager_readd"),
        ):
            omr_admin._ss_resume({"65105": "carolkey"}, 2)
        assert json.loads(manager.read_text())["port_conf"]["65105"] == {"key": "carolkey", "userid": 2}
        # and the other way round
        manager.write_text(json.dumps({"port_key": {"65101": "main"}}))
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=lambda p, *a, **k: real_open(str(manager) if p == "/etc/shadowsocks-libev/manager.json" else p, *a, **k)),
            patch("omr_admin._atomic_write_json", side_effect=lambda p, d, **k: manager.write_text(json.dumps(d))),
            patch("omr_admin.OMR_CONFIG_LOCK_FILE", str(tmp_path / ".lock")),
            patch("omr_admin._ss_manager_readd"),
        ):
            omr_admin._ss_resume({"65105": {"key": "carolkey", "userid": 2}}, 2)
        assert json.loads(manager.read_text())["port_key"]["65105"] == "carolkey"

    def test_wireguard_peers_of_a_disabled_user_left_out(self):
        key = __import__("base64").b64encode(b"k" * 32).decode()
        config = _config()
        config["users"][0]["readonly"].update(disabled="true", wireguard_peers=[{"ip": "10.255.247.9", "key": key}])
        config["users"][0]["openmptcprouter"]["wireguard_peers"] = [{"ip": "10.255.247.2", "key": key}]
        written = {}
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open_with({"/etc/wireguard/wg0.conf": "[Interface]\nListenPort = 65311\n"})),
            patch("omr_admin.file_as_bytes", side_effect=[b"a", b"b"]),
            patch("omr_admin._atomic_write_text", side_effect=lambda p, t, **k: written.update({p: t})),
            patch("omr_admin._wg_syncconf"),
        ):
            omr_admin._write_wireguard_conf(config)
        text = written["/etc/wireguard/wg0.conf"]
        assert "10.255.247.2" in text and "10.255.247.9" not in text

    def test_mqvpn_user_put_back_as_it_was(self):
        server = {"users": [{"name": "openmptcprouter", "key": "a"}]}
        written = {}
        with (
            patch("os.path.isfile", side_effect=lambda p: p == "/etc/mqvpn/server.json"),
            patch("builtins.open", side_effect=_open_with({"/etc/mqvpn/server.json": json.dumps(server)})),
            patch("omr_admin._atomic_write_json", side_effect=lambda p, d, **k: written.update({p: d})),
            patch("omr_admin.mqvpn_api", return_value={"ok": True}) as api,
        ):
            omr_admin._resume_user_access("readonly", {}, {"mqvpn": {"user": {"name": "readonly", "key": "k"}, "path_policy": []}})
        assert written["/etc/mqvpn/server.json"] == {"users": [{"name": "openmptcprouter", "key": "a"},
                                                               {"name": "readonly", "key": "k"}]}
        api.assert_called_once_with({"cmd": "add_user", "name": "readonly", "key": "k"})

    def test_mqvpn_fixed_ip_taken_meanwhile_not_put_back(self):
        server = {"users": [{"name": "alice", "key": "a", "fixed_ip": "10.255.220.10"}]}
        written = {}
        with (
            patch("os.path.isfile", side_effect=lambda p: p == "/etc/mqvpn/server.json"),
            patch("builtins.open", side_effect=_open_with({"/etc/mqvpn/server.json": json.dumps(server)})),
            patch("omr_admin._atomic_write_json", side_effect=lambda p, d, **k: written.update({p: d})),
            patch("omr_admin.mqvpn_api", return_value={"ok": True}),
        ):
            omr_admin._resume_user_access("readonly", {}, {"mqvpn": {
                "user": {"name": "readonly", "key": "k", "fixed_ip": "10.255.220.10"},
                "path_policy": [{"user": "readonly", "iface": f"wan{i}"} for i in range(20)]}})
        cfg = written["/etc/mqvpn/server.json"]
        assert cfg["users"][1] == {"name": "readonly", "key": "k"}
        assert len(cfg["path_policy"]) == omr_admin.MQVPN_MAX_USER_PATHS

    def test_suspended_mqvpn_fixed_ip_reserved(self):
        config = _config()
        config["users"][0]["readonly"]["access_suspended"] = {
            "mqvpn": {"user": {"name": "readonly", "key": "k", "fixed_ip": "10.255.220.10"}}}
        with (
            patch("omr_admin.read_omr_config", side_effect=lambda: config),
            patch("builtins.open", side_effect=_open_with({"/etc/mqvpn/server.json": json.dumps({"users": []})})),
        ):
            assert omr_admin._mqvpn_fixed_ips() == {"10.255.220.10": "readonly"}


class TestReviewFixes20261014:
    """Whole-codebase review of 2026-10-14."""

    _MPTCP = {"checksum": "0", "path_manager": "default", "scheduler": "default",
              "syn_retries": 3, "congestion_control": "bbr", "version": 0}

    def _mptcp(self, client, payload, sysctl_d="", v1=True):
        written, calls = {}, []

        def _run(cmd, *a, **kw):
            calls.append(" ".join(cmd) if cmd else "")
            return MagicMock(returncode=0)
        v1_files = {"/proc/sys/net/mptcp/enabled", "/proc/sys/net/mptcp/pm_type", "/proc/sys/net/mptcp/scheduler",
                    "/proc/sys/net/mptcp/path_manager", "/proc/sys/net/mptcp/syn_retries"}
        with (
            patch("os.path.exists", side_effect=lambda p: str(p) in v1_files if v1 else str(p) == "/proc/sys/net/mptcp/mptcp_enabled"),
            patch("os.path.isfile", return_value=False),
            patch("builtins.open", side_effect=_open_with({"/etc/sysctl.d/90-shadowsocks.conf": sysctl_d})),
            patch("omr_admin._atomic_write_text", side_effect=lambda p, t, **k: written.update({p: t})),
            patch("omr_admin.file_as_bytes", side_effect=[b"before", b"after"]),
            patch("subprocess.run", side_effect=_run),
        ):
            assert client.post("/mptcp", json=payload).json()["result"] == "done"
        return written["/etc/sysctl.d/90-shadowsocks.conf"], calls

    def test_mptcp_pm_type_0_applied(self, primary_client):
        text, calls = self._mptcp(primary_client, {**self._MPTCP, "pm_type": 0}, "net.mptcp.pm_type=1\n")
        assert "sysctl -qw net.mptcp.pm_type=0" in calls
        assert "net.mptcp.pm_type=0" in text and "pm_type=1" not in text

    def test_mptcp_pm_type_unset_left_alone(self, primary_client):
        for payload in ({**self._MPTCP, "pm_type": ""}, self._MPTCP):
            text, calls = self._mptcp(primary_client, payload, "net.mptcp.pm_type=1\n")
            assert not any("pm_type" in c for c in calls)
            assert "net.mptcp.pm_type=1" in text

    def test_mptcp_v1_knob_0_replaces_a_written_value(self, primary_client):
        text, calls = self._mptcp(primary_client, {**self._MPTCP, "close_timeout": 0, "stale_loss_cnt": ""},
                                  "net.mptcp.close_timeout=120\nnet.mptcp.stale_loss_cnt=8\n")
        assert "sysctl -qw net.mptcp.close_timeout=0" in calls
        assert "net.mptcp.close_timeout=0" in text and "close_timeout=120" not in text
        assert "net.mptcp.stale_loss_cnt=8" in text     # unset: kept

    def test_mptcp_keeps_the_installer_sysctls(self, primary_client):
        installer = ("net.mptcp.enabled=1\nnet.mptcp.blackhole_timeout = 0\nnet.mptcp.close_timeout=60\n"
                     "net.mptcp.mptcp_scheduler=redundant\nnet.mptcp.scheduler=blest\n")
        text, _calls = self._mptcp(primary_client, self._MPTCP, installer)
        assert "net.mptcp.blackhole_timeout = 0" in text and "net.mptcp.enabled=1" in text
        assert "net.mptcp.close_timeout=60" in text     # not sent: kept
        assert "mptcp_scheduler" not in text            # the other kernel kind's name
        assert "net.mptcp.scheduler=blest" not in text  # replaced
        text, _calls = self._mptcp(primary_client, self._MPTCP, installer, v1=False)
        assert "net.mptcp.blackhole_timeout = 0" in text
        assert "net.mptcp.scheduler=blest" not in text and "net.mptcp.close_timeout" not in text
        assert "net.mptcp.mptcp_scheduler=default" in text

    def test_glorytun_udp_without_glorytun_tcp(self):
        written = {}
        with (
            patch("os.path.isfile", side_effect=lambda p: p == "/etc/glorytun-udp/tun0"),
            patch("builtins.open", side_effect=_open_with({"/etc/glorytun-udp/tun0": "PORT=65001\nDEV=tun0\n"})),
            patch("omr_admin._atomic_write_text", side_effect=lambda p, t, **k: written.update({p: (t, k)})),
            patch("subprocess.run"),
            patch("omr_admin._restart_service"),
        ):
            omr_admin.add_glorytun_udp(3)
        key, kwargs = written["/etc/glorytun-udp/tun3.key"]
        assert len(key) == 64 and key == key.upper() and kwargs == {"new_mode": 0o600}

    def test_glorytun_udp_shares_the_tcp_key(self):
        written = {}
        with (
            patch("os.path.isfile", side_effect=lambda p: p in ("/etc/glorytun-udp/tun0", "/etc/glorytun-tcp/tun3.key")),
            patch("builtins.open", side_effect=_open_with({"/etc/glorytun-udp/tun0": "PORT=65001\n",
                                                           "/etc/glorytun-tcp/tun3.key": "ABCD"})),
            patch("omr_admin._atomic_write_text", side_effect=lambda p, t, **k: written.update({p: t})),
            patch("subprocess.run"),
            patch("omr_admin._restart_service"),
        ):
            omr_admin.add_glorytun_udp(3)
        assert written["/etc/glorytun-udp/tun3.key"] == "ABCD"

    @pytest.mark.real_env
    def test_openvpn_revoke_drops_the_files(self, tmp_path, monkeypatch):
        for directory, name in (("reqs", "bob.req"), ("issued", "bob.crt"), ("private", "bob.key"), ("private", "bobby.key")):
            (tmp_path / directory).mkdir(exist_ok=True)
            (tmp_path / directory / name).write_text("x")
        monkeypatch.setattr(omr_admin, "PKI_DIR", str(tmp_path))
        monkeypatch.setattr(omr_admin, "OMR_CONFIG_LOCK_FILE", str(tmp_path / ".lock"))
        with (
            patch("subprocess.run") as run,
            patch("omr_admin._pki_retire_user_certs", return_value=False),
            patch("omr_admin._openvpn_gen_crl") as crl,
        ):
            omr_admin._openvpn_revoke("bob")
        assert run.call_args_list[0].args[0] == ["./easyrsa", "--batch", "revoke", "bob"]
        crl.assert_called_once()
        assert sorted(p.name for p in tmp_path.rglob("*") if p.is_file() and p.name != ".lock") == ["bobby.key"]

    def test_startup_suspension_one_failure_and_wireguard(self):
        config = _config()
        users = config["users"][0]
        users["readonly"].update(disabled="true", wireguard_peers=[{"ip": "10.255.247.9", "key": "k"}])
        users["openmptcprouter"].update(disabled="true")
        done = []

        def suspend(username, udata):
            if username == "openmptcprouter":
                raise OSError("disk full")
            return {"units": ["x"]}
        with (
            patch("omr_admin.read_omr_config", side_effect=lambda: config),
            patch("omr_admin._suspend_user_access", side_effect=suspend),
            patch("omr_admin.modif_config_user", side_effect=lambda u, c: done.append(u)),
            patch("omr_admin._write_wireguard_conf") as wireguard,
            patch("omr_admin._omr_config_lock"),
        ):
            omr_admin._suspend_disabled_users()
        assert done == ["readonly"]
        wireguard.assert_called_once()

    def test_mqvpn_bytes_are_the_users_sessions(self):
        status = {"ok": True, "clients": [
            {"user": "bob", "bytes_rx": 10, "bytes_tx": 20},
            {"user": "bob", "bytes_rx": 1, "bytes_tx": 2},
            {"user": "alice", "bytes_rx": 100, "bytes_tx": 200},
            {"user": "(global)", "bytes_rx": 1000, "bytes_tx": 2000}]}
        with (
            patch("os.path.isfile", return_value=True),
            patch("omr_admin.mqvpn_api", return_value=status) as api,
        ):
            assert omr_admin._mqvpn_user_bytes("bob") == (11, 22)
            # one get_status for every user of the polling cycle
            assert omr_admin._mqvpn_user_bytes("alice") == (100, 200)
            assert api.call_count == 1
        omr_admin._mqvpn_status_cache.update(at=0.0, status=None)
        with (
            patch("os.path.isfile", return_value=True),
            patch("omr_admin.mqvpn_api", return_value={"ok": False, "error": "response too large"}) as api,
            patch.object(omr_admin.LOG, "warning") as warning,
        ):
            assert omr_admin._mqvpn_user_bytes("bob") == (0, 0)
            # the failure shared as well: one timeout, one warning
            assert omr_admin._mqvpn_user_bytes("alice") == (0, 0)
        assert "response too large" in str(warning.call_args)
        assert api.call_count == 1 and warning.call_count == 1

    def test_remove_user_purges_its_metrics(self, admin_client):
        metrics = MagicMock()
        with (
            patch("omr_admin._teardown_user"),
            patch.object(omr_admin, "_omr_metrics_router", metrics),
        ):
            r = admin_client.post("/remove_user", json={"username": "readonly"})
        assert r.json()["result"] == "done"
        metrics.purge_user.assert_called_once_with("readonly")

    def test_remove_user_purges_out_of_the_config_lock(self, admin_client):
        depths = []
        metrics = MagicMock()
        metrics.purge_user.side_effect = lambda u: depths.append(getattr(omr_admin._omr_config_lock_state, "depth", 0))
        with (
            patch("omr_admin._teardown_user"),
            patch.object(omr_admin, "_omr_metrics_router", metrics),
        ):
            admin_client.post("/remove_user", json={"username": "readonly"})
            # refused: nothing purged
            admin_client.post("/remove_user", json={"username": "ghost"})
        assert depths == [0]

    def test_softethervpn_keeps_the_installers_string(self, primary_client):
        config = _config()
        config["users"][0]["openmptcprouter"]["softethervpn"] = "old"
        changes = {}
        with (
            patch("os.path.isfile", return_value=True),
            patch("omr_admin.read_omr_config", side_effect=lambda: config),
            patch("omr_admin.modif_config_user", side_effect=lambda u, c: changes.update(c)),
            patch("requests.post"),
        ):
            r = primary_client.post("/softethervpn", json={"password": "newpassword"})
        assert r.json()["result"] == "done", r.json()
        assert changes == {"softethervpn": "newpassword"}

    def test_reality_port_closed_whoever_opened_it(self, primary_client):
        xray = {"inbounds": [{"tag": "omrin-vless-reality", "port": 443}, {"tag": "omrin-tunnel", "port": 65228}]}
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open_with({"/etc/xray/xray-server.json": json.dumps(xray)})),
            patch("omr_admin._atomic_write_json"),
            patch("omr_admin.modif_config_user"),
            patch("omr_admin.xray_ensure_reverse_client", return_value="r"),
            patch("omr_admin._xray_user_conf", return_value={}),
            patch("omr_admin._restart_service"),
            patch("omr_admin._fw_service_port_del") as close,
            patch("omr_admin.shorewall_del_port") as del_port,
        ):
            r = primary_client.post("/xray", json={"userid": "0", "vless_reality": False, "transport": "tcp", "ss_method": ""})
        assert r.json()["result"] == "done", r.json()
        close.assert_called_once_with("443", "tcp", "xray vless-reality")
        del_port.assert_not_called()

    def test_xray_ss_method_checked(self, primary_client):
        # the PSK and uPSKs are 32 bytes: an aes-128 or unknown method made
        # xray refuse its config, every user's proxy down
        xray = {"inbounds": [{"tag": "omrin-shadowsocks-tunnel", "settings": {"method": "2022-blake3-aes-256-gcm"}}]}
        written = {}
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open_with({"/etc/xray/xray-server.json": json.dumps(xray)})),
            patch("omr_admin._atomic_write_json", side_effect=lambda p, d, **k: written.update({p: d})),
            patch("omr_admin.modif_config_user"),
            patch("omr_admin.xray_ensure_reverse_client", return_value="r"),
            patch("omr_admin._xray_user_conf", return_value={}),
            patch("omr_admin._restart_service") as restart,
        ):
            r = primary_client.post("/xray", json={"userid": "0", "ss_method": "rc4-md5"})
            assert r.json() == {"result": "error", "reason": "Invalid ss_method", "route": "xray"}
            assert not written and not restart.called
            r = primary_client.post("/xray", json={"userid": "0", "ss_method": "2022-blake3-aes-128-gcm"})
            assert r.json()["result"] == "done"
        assert written["/etc/xray/xray-server.json"]["inbounds"][0]["settings"]["method"] == "2022-blake3-aes-256-gcm"

    def test_reality_refused_on_a_port_something_listens_on(self, primary_client):
        xray = {"inbounds": [{"tag": "omrin-tunnel", "port": 65228}]}
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open_with({"/etc/xray/xray-server.json": json.dumps(xray)})),
            patch("omr_admin._proxy_port_elsewhere", return_value=None),
            patch("omr_admin._listening_ports", return_value=[(443, 443)]),
            patch("omr_admin._atomic_write_json") as write,
        ):
            r = primary_client.post("/xray", json={"userid": "0", "vless_reality": True})
        assert r.json()["reason"] == "Port 443 already in use on the server"
        assert not write.called

    def test_reality_port_not_opened_without_its_config(self, primary_client):
        xray = {"inbounds": [{"tag": "omrin-tunnel", "port": 65228, "streamSettings": {"network": "tcp"}}]}
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open_with({"/etc/xray/xray-server.json": json.dumps(xray)})),
            patch("omr_admin._atomic_write_json"),
            patch("omr_admin.modif_config_user"),
            patch("omr_admin.xray_ensure_reverse_client", return_value="r"),
            patch("omr_admin._xray_user_conf", return_value={}),
            patch("omr_admin.xray_fix_reality_keys", return_value=None),
            patch("omr_admin._proxy_port_elsewhere", return_value=None),
            patch("omr_admin._restart_service"),
            patch("omr_admin.shorewall_add_port") as add_port,
        ):
            r = primary_client.post("/xray", json={"userid": "0", "vless_reality": True, "transport": "grpc", "ss_method": ""})
        assert r.status_code == 200 and r.json()["result"] == "done", r.text
        add_port.assert_not_called()


# ---------------------------------------------------------------------------
# Full review of 2026-10-23
# ---------------------------------------------------------------------------

class TestReview20261023:
    def test_username_server_refused(self, admin_client):
        # the CN of OpenVPN's own certificate: revoked and replaced by a
        # client one, OpenVPN down for every router
        with patch("omr_admin._mutate_omr_config") as mutate:
            r = admin_client.post("/add_user", json={"username": "server"})
        assert r.json()["reason"] == "Invalid username"
        mutate.assert_not_called()

    def test_vxlan_port_of_a_server_service_refused(self, user_client):
        with patch("omr_admin._vxlan_service_ports", return_value=[(65101, 65101)]), \
             patch("omr_admin._listening_ports", return_value=[]), \
             patch("omr_admin.write_vxlan_conf"), patch("omr_admin.modif_config_user") as modif:
            r = user_client.post("/vxlan", json={"enable": True, "port": 65101})
        assert r.json()["reason"] == "Port used by the server"
        modif.assert_not_called()

    def test_vxlan_port_of_a_server_service_refused_to_the_admin_too(self, admin_client):
        with patch("omr_admin._vxlan_service_ports", return_value=[(65101, 65101)]), \
             patch("omr_admin._listening_ports", return_value=[]), \
             patch("omr_admin.write_vxlan_conf"), patch("omr_admin.modif_config_user") as modif:
            r = admin_client.post("/vxlan", json={"enable": True, "port": 65101})
            assert r.json()["reason"] == "Port used by the server"
            r = admin_client.post("/vxlan_user", json={"username": "readonly", "port": 65101})
            assert r.json() == {"result": "error", "reason": "Port used by the server", "route": "vxlan_user"}
        modif.assert_not_called()

    def test_vxlan_port_another_user_has_shared_unless_a_process_has_it(self, user_client):
        config = _config()
        config["users"][0]["readonly"]["vxlan"] = {"enabled": True, "port": 65200}
        with patch("omr_admin.read_omr_config", return_value=config), \
             patch("omr_admin._listening_ports",   # the kernel's VXLAN socket
                   side_effect=lambda proto, skip_processes=(), skip_kernel=False: [] if skip_kernel else [(65200, 65200)]), \
             patch("omr_admin._configured_server_ports", return_value=[]):
            assert omr_admin._vxlan_port_error("openmptcprouter", 0, 65200, "vxlan") is None
            with patch("omr_admin._vxlan_service_ports", return_value=[(65200, 65200)]):
                assert omr_admin._vxlan_port_error("openmptcprouter", 0, 65200, "vxlan")["reason"] == \
                    "Port used by the server"

    def test_vxlan_input_synced_on_a_port_change_only(self, user_client):
        with patch("omr_admin.write_vxlan_conf"), patch("omr_admin.modif_config_user"), \
             patch("omr_admin._nft_sync_vxlan_input") as sync:
            r = user_client.post("/vxlan", json={"enable": False})
        assert r.json()["result"] == "done"
        sync.assert_not_called()

    def test_vxlan_default_slice_of_a_userid_not_given_refused(self, user_client):
        # userid 5 has no user yet: given at /add_user, its default address
        # was on two devices
        localip = omr_admin._vxlan_default_v4(5)[0]
        with patch("omr_admin.write_vxlan_conf"), patch("omr_admin.modif_config_user") as modif:
            r = user_client.post("/vxlan", json={"enable": True, "localip": localip})
        assert r.json()["reason"] == "localip is the default of another userid"
        modif.assert_not_called()

    def test_port_redirected_by(self):
        config = _config()
        config["users"][0]["readonly"]["fw_ports"] = [
            {"fwtype": "DNAT", "proto": "tcp", "port": "400-500", "family": 4, "source_dip": ""},
            {"fwtype": "ACCEPT", "proto": "udp", "port": "443", "family": 4, "source_dip": ""}]
        assert omr_admin._port_redirected_by(config, 443, "tcp") == ["readonly"]
        assert omr_admin._port_redirected_by(config, 443, "udp") == []
        assert omr_admin._port_redirected_by(config, 501, "tcp") == []

    def test_mqvpn_not_moved_onto_a_redirected_port(self, user_client):
        config = _config()
        config["users"][0]["readonly"]["fw_ports"] = [
            {"fwtype": "DNAT", "proto": "udp", "port": "65443", "family": 4, "source_dip": ""}]
        with patch("os.path.isfile", return_value=True), \
             patch("omr_admin.read_omr_config", return_value=config), \
             patch("omr_admin.shorewall_add_port") as add, patch("omr_admin._restart_service") as restart:
            r = user_client.post("/mqvpn", json={**TestReview20261023._MQVPN, "port": 65443})
        assert r.json() == {"result": "error", "reason": "Port redirected by: readonly", "route": "mqvpn"}
        add.assert_not_called()
        restart.assert_not_called()

    _MQVPN = {"key": "k", "scheduler": "wlb", "port": 443, "fec_enable": True, "fec_scheme": "reed_solomon",
              "reinjection_control": True, "reinjection_mode": "deadline", "cc": "bbr2"}

    def test_restart_deferred_until_the_lock_is_released(self):
        seen = []
        with patch("omr_admin._restart_service_now", side_effect=lambda unit: seen.append(
                (unit, getattr(omr_admin._omr_config_lock_state, 'depth', 0)))):
            with omr_admin._omr_config_lock():
                with omr_admin._omr_config_lock():
                    omr_admin._restart_service("xray")
                    omr_admin._restart_service("xray")
                assert seen == []
            omr_admin._restart_service("v2ray")
        assert seen == [("xray", 0), ("v2ray", 0)]

    def test_deferred_restart_that_raises_spares_the_others_and_the_result(self):
        seen = []
        def restart(unit):
            seen.append(unit)
            if unit == "glorytun-tcp@tun3":
                raise OSError("fork failed")
        with patch("omr_admin._restart_service_now", side_effect=restart):
            @omr_admin._serialise_config_write
            def body():
                omr_admin._restart_service("glorytun-tcp@tun3")
                omr_admin._restart_service("glorytun-udp@tun3")
                return "done"
            assert body() == "done"
        assert seen == ["glorytun-tcp@tun3", "glorytun-udp@tun3"]

    def test_restart_dropped_when_the_unit_is_stopped_under_the_lock(self):
        with patch("omr_admin._restart_service_now") as restart, \
             patch("omr_admin.subprocess.run", return_value=MagicMock(returncode=0)) as run:
            with omr_admin._omr_config_lock():
                omr_admin._restart_service("glorytun-tcp@tun3")
                omr_admin._stop_service("glorytun-tcp@tun3", disable=True)
                assert [c.args[0] for c in run.call_args_list] == [["systemctl", "-q", "disable", "glorytun-tcp@tun3"]]
            assert run.call_args_list[-1].args[0] == ["systemctl", "-q", "stop", "glorytun-tcp@tun3"]
        restart.assert_not_called()

    def test_oneshot_stopped_at_once_its_restart_dropped(self):
        # omr-vxlan@'s ExecStop reads the file removed right after the stop
        with patch("omr_admin._restart_service_now") as restart, \
             patch("omr_admin.subprocess.run", return_value=MagicMock(returncode=0)) as run:
            with omr_admin._omr_config_lock():
                omr_admin._restart_service("omr-vxlan@user3")
                omr_admin._stop_service("omr-vxlan@user3", defer=False)
                assert [c.args[0] for c in run.call_args_list] == [["systemctl", "-q", "stop", "omr-vxlan@user3"]]
        restart.assert_not_called()

    def test_one_restart_for_both_spellings_of_a_unit(self):
        with patch("omr_admin._restart_service_now") as restart:
            with omr_admin._omr_config_lock():
                omr_admin._restart_service("shadowsocks-libev-manager@manager.service")
                omr_admin._restart_service("shadowsocks-libev-manager@manager")
        restart.assert_called_once_with("shadowsocks-libev-manager@manager")

    def test_vxlan_port_check_parses_the_config_once(self):
        # once per user per helper, under the config lock
        config = _config()
        with patch("omr_admin.read_omr_config", return_value=config) as read, \
             patch("omr_admin._vxlan_service_ports", return_value=[]), \
             patch("omr_admin._listening_ports", return_value=[]):
            assert omr_admin._vxlan_port_error("openmptcprouter", 0, 65200, "vxlan") is None
        assert read.call_count == 1

    def test_previous_lan_parsed_leniently(self):
        assert str(omr_admin._lan_parse("192.168.1.1/24/", lenient=True)) == "192.168.1.0/24"
        assert str(omr_admin._lan_parse("192.168.1.1/255.255.255.0", lenient=True)) == "192.168.1.0/24"
        assert omr_admin._lan_parse("not a lan", lenient=True) is None
        assert omr_admin._lan_parse(" 192.168.1.1/24") is None

    def test_removed_glorytun_udp_stopped_before_its_link_and_files_go(self):
        # deferred, Restart=always brought it back in between and recreated
        # the persist link, its EnvironmentFile gone
        calls = []
        present = {"/etc/glorytun-udp/tun9.key", "/etc/glorytun-udp/tun9"}
        with patch("omr_admin.subprocess.run", side_effect=lambda cmd, **k: calls.append(cmd) or MagicMock(returncode=0)), \
             patch("os.path.isfile", side_effect=lambda p: p in present), \
             patch("os.remove", side_effect=lambda p: calls.append(["rm", p])):
            with omr_admin._omr_config_lock():
                omr_admin._restart_service("glorytun-udp@tun9")
                omr_admin.remove_glorytun_udp(9)
                assert calls.index(["systemctl", "-q", "stop", "glorytun-udp@tun9"]) < \
                    calls.index(["ip", "link", "del", "gt-udp-tun9"]) < \
                    calls.index(["rm", "/etc/glorytun-udp/tun9.key"])
        assert ["systemctl", "-q", "restart", "glorytun-udp@tun9"] not in calls

    def test_service_not_moved_onto_an_enabled_vxlan_port(self):
        # vxlan_input drops it, and the tunnel's socket takes it once up
        config = _config()
        config["users"][0]["readonly"]["vxlan"] = {"enabled": True, "port": 5000}
        with patch("omr_admin.read_omr_config", return_value=config):
            assert omr_admin._vxlan_port_users(5000) == ["readonly"]
            assert omr_admin._vxlan_port_users(5001) == []
            assert omr_admin._tunnel_port_error(PRIMARY, 5000, ("tcp", "udp"), []) == \
                "Port used by the VXLAN of: readonly"
            assert omr_admin._tunnel_port_error(PRIMARY, 5000, ("tcp",), []) is None   # dsvpn: TCP
            # the port it has already stays accepted
            with patch("omr_admin._tunnel_file_ports", return_value={5000}):
                assert omr_admin._tunnel_port_error(PRIMARY, 5000, ("tcp", "udp"), ["/etc/glorytun-udp/tun0"]) is None
            assert omr_admin._shadowsocks_port_error({"port_key": {}}, PRIMARY, 5000) == \
                "Port used by the VXLAN of: readonly"
            assert omr_admin._shadowsocks_port_error({"port_key": {}}, PRIMARY, 65101) is None

    def test_mqvpn_not_moved_onto_an_enabled_vxlan_port(self, primary_client):
        config = _config()
        config["users"][0]["readonly"]["vxlan"] = {"enabled": True, "port": 5000}
        with patch("os.path.isfile", return_value=True), \
             patch("omr_admin.read_omr_config", return_value=config), \
             patch("builtins.open", side_effect=_open_with({"/etc/mqvpn/server.json": json.dumps(TestMqvpnRestart._SERVER)})), \
             patch("omr_admin._atomic_write_json") as write, patch("omr_admin._restart_service") as restart:
            r = primary_client.post("/mqvpn", json={**TestReview20261023._MQVPN, "port": 5000})
        assert r.json() == {"result": "error", "reason": "Port used by the VXLAN of: readonly", "route": "mqvpn"}
        write.assert_not_called()
        restart.assert_not_called()

    def test_vxlan_file_replaced_only_when_it_changes(self):
        config = _config()
        config["users"][0]["openmptcprouter"].update(vxlan={"enabled": True}, vpnlocalip="10.255.255.1",
                                                     vpnremoteip="10.255.255.2")
        written = {}
        with patch("omr_admin.read_omr_config", return_value=config), \
             patch("os.makedirs"), patch("os.path.isfile", side_effect=lambda p: p in written), \
             patch("omr_admin.file_as_bytes", side_effect=lambda p: written[p].encode()), \
             patch("omr_admin._atomic_write_text", side_effect=lambda p, t, **k: written.update({p: t})) as write, \
             patch("omr_admin.subprocess.run"), patch("omr_admin._restart_service") as restart:
            omr_admin.write_vxlan_conf("openmptcprouter", 0)
            omr_admin.write_vxlan_conf("openmptcprouter", 0)   # each router sync
        assert write.call_count == 1 and restart.call_count == 1
        assert "VNI=1\n" in written["/etc/openmptcprouter-vps-admin/omr-vxlan/user0"]

    def test_openvpn_defaults_reserved_clients_and_tcp_not(self):
        files = {"/etc/openvpn/plain.conf": "dev tun5\nserver 10.9.0.0 255.255.255.0\n",
                 "/etc/openvpn/tcp.conf": "proto tcp-server\nport 65301\n",
                 "/etc/openvpn/client.conf": "client\nremote 1.2.3.4 1195\nport 1196\n",
                 "/etc/mlvpn/mlvpn0.conf": "[wan1]\nbindport = 65201\n"}
        with patch("omr_admin.glob.glob", side_effect=lambda pattern: fnmatch.filter(files, pattern)), \
             patch("builtins.open", side_effect=_open_with(files)):
            assert sorted(omr_admin._tunnel_udp_config_ports()) == [(1194, 1194), (65201, 65201)]

    def test_vxlan_route_parses_the_config_once(self, user_client):
        with patch("omr_admin.read_omr_config", side_effect=lambda: _config()) as read, \
             patch("omr_admin._listening_ports", return_value=[]), \
             patch("omr_admin._vxlan_service_ports", return_value=[]), \
             patch("omr_admin.modif_config_user"), patch("omr_admin.write_vxlan_conf"), \
             patch("omr_admin._nft_sync_vxlan_input"):
            r = user_client.post("/vxlan", json={"enable": True, "port": 4790})
        assert r.json()["result"] == "done"
        assert read.call_count == 1

    def test_mqvpn_try_restart_after_the_lock(self):
        with patch("omr_admin.subprocess.run", return_value=MagicMock(returncode=0)) as run:
            with omr_admin._omr_config_lock():
                omr_admin._systemctl_after_lock("try-restart", "mqvpn")
                run.assert_not_called()
        assert run.call_args.args[0] == ["systemctl", "-q", "try-restart", "mqvpn"]

    def test_sockets_listed_once_per_hold_of_the_lock(self):
        with patch("omr_admin.psutil.net_connections", return_value=[]) as listing:
            with omr_admin._omr_config_lock():
                omr_admin._listening_ports("udp")
                omr_admin._listening_ports("udp", skip_kernel=True)
            assert listing.call_count == 1
            omr_admin._listening_ports("udp")
            assert listing.call_count == 2

    def test_vxlan_service_ports_not_listening_are_reserved(self):
        # WireGuard is a kernel socket, a daemon may not be started yet, a
        # userid not given yet has its glorytun-udp 650NN: a stored VXLAN
        # port on one of them was dropped from the internet for every router
        config = _config()
        config["users"][0]["readonly"]["shadowsocks_port"] = 65102
        files = {"/etc/wireguard/wg0.conf": "[Interface]\nListenPort = 65311\n",
                 "/etc/glorytun-udp/tun1": "BIND_PORT=65150\nPORT=5000\n",
                 "/etc/openvpn/tun0.conf": "proto tcp\nport 65301\n",
                 "/etc/openvpn/tun1.conf": "dev tun1\nproto udp\nport 65302\n",
                 "/etc/mlvpn/mlvpn0.conf": "[wan1]\nbindport = 65201\n"}
        with patch("omr_admin.glob.glob", side_effect=lambda pattern: fnmatch.filter(files, pattern)), \
             patch("builtins.open", side_effect=_open_with(files)), \
             patch("omr_admin._configured_server_ports", return_value=[]):
            spans = omr_admin._vxlan_service_ports(config, listening=[])
            for port in (65311, 65102, 65150, 65302, 65201, 65000 + 5, 65000 + omr_admin.USERID_MAX):
                assert any(a <= port <= b for a, b in spans), port
            for port in (4789, 65301):   # OpenVPN TCP's is not a UDP port
                assert not any(a <= port <= b for a, b in spans), port
            config["users"][0]["readonly"]["vxlan"] = {"enabled": True, "port": 65311}
            assert omr_admin._render_vxlan_input(config, spans) == []

    def test_vxlan_stored_default_of_another_userid_still_accepted(self, user_client):
        # stored before the check: every /vxlan of that router refused,
        # disabling it included
        localip = omr_admin._vxlan_default_v4(5)[0]
        config = _config()
        config["users"][0]["openmptcprouter"]["vxlan"] = {"enabled": True, "localip": localip}
        with patch("omr_admin.read_omr_config", return_value=config), \
             patch("omr_admin.write_vxlan_conf"), patch("omr_admin.modif_config_user") as modif:
            r = user_client.post("/vxlan", json={"enable": False, "localip": localip})
        assert r.json()["result"] == "done"
        modif.assert_called_once()

    def test_main_router_suspension_stops_mlvpn(self):
        with patch("os.path.isfile", side_effect=lambda p: p == "/etc/mlvpn/mlvpn0.conf"):
            assert omr_admin._user_tunnel_units(0) == ["mlvpn@mlvpn0"]
            assert omr_admin._user_tunnel_units(2) == []

    def test_unredirect_without_destip_spares_a_user_named_like_the_prefix(self):
        data = {"inbounds": [
            {"tag": "a_redir_tcp_80_to_192.168.1.2:80", "port": 80},
            {"tag": "a_redir_tcp_80_to_x_redir_tcp_443_to_1.2.3.4:443", "port": 443}],
            "routing": {"rules": []}}
        written = {}
        user = omr_admin.User(username="a", userid=3, permissions="rw")
        with patch("os.path.isfile", return_value=True), \
             patch("builtins.open", side_effect=_open_with({omr_admin.PROXY_REDIRECT_CONFIGS["xray"]: json.dumps(data)})), \
             patch("omr_admin._atomic_write_json", side_effect=lambda p, d, **k: written.update({p: d})), \
             patch("omr_admin._schedule_proxy_restart"), patch("omr_admin._restart_service"):
            omr_admin._proxy_del_port("xray", user, "80", "tcp", "", "")
        tags = [ib["tag"] for ib in written[omr_admin.PROXY_REDIRECT_CONFIGS["xray"]]["inbounds"]]
        assert tags == ["a_redir_tcp_80_to_x_redir_tcp_443_to_1.2.3.4:443"]

    def test_user_dnat_rebuilt_when_user_accept_is_refused(self):
        with patch("omr_admin.read_omr_config", return_value=_config()), \
             patch("omr_admin._nft_flush_chain", side_effect=lambda chain, rules: chain != "user_accept") as flush:
            assert omr_admin._nft_sync_ports() is False
        assert [c.args[0] for c in flush.call_args_list] == ["user_accept", "user_dnat"]

    def test_firewall_open_any_takes_the_ipv4_rule_back_when_ipv6_fails(self, user_client):
        config = _config()
        store = {"fw_ports": []}
        def add4(*a, **k):
            store["fw_ports"] = [{"name": "x", "family": 4}]
        def modif(user, changes):
            store.update(changes)
        config["users"][0]["openmptcprouter"]["fw_ports"] = []
        with patch("omr_admin.read_omr_config", side_effect=lambda: {**config, "users": [{
                    **config["users"][0], "openmptcprouter": {**config["users"][0]["openmptcprouter"], **store}}]}), \
             patch("omr_admin.shorewall_add_port", side_effect=add4), \
             patch("omr_admin.shorewall6_add_port", return_value="No more than 1024 firewall entries per user"), \
             patch("omr_admin.modif_config_user", side_effect=modif), \
             patch("omr_admin._nft_sync_ports") as sync:
            r = user_client.post("/firewallopen", json={"name": "x", "port": "8080", "proto": "tcp",
                                                        "fwtype": "ACCEPT", "ipproto": "any"})
        assert r.json()["result"] == "error"
        assert store["fw_ports"] == []
        sync.assert_called_once()

    def test_vpnips_same_addresses_again_rewrite_the_6in4_file(self, user_client):
        config = _config()
        config["users"][0]["openmptcprouter"].update(vpnremoteip="10.255.255.2", vpnlocalip="10.255.255.1",
                                                     ula="fd12::/48")
        with patch("omr_admin.read_omr_config", return_value=config), \
             patch("omr_admin._vpnips_error", return_value=None), \
             patch("omr_admin._openvpn_leases", return_value={}), \
             patch("omr_admin.modif_config_user"), \
             patch("omr_admin._apply_6in4_conf") as apply:
            r = user_client.post("/vpnips", json={"remoteip": "10.255.255.2", "localip": "10.255.255.1",
                                                  "ula": "fd12::/48"})
        assert r.json()["result"] == "done"
        apply.assert_called_once()
        assert "fd12::/48" in apply.call_args.args[1]

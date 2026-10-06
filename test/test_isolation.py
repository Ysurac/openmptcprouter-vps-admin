"""
What one user of a shared VPS can no longer do to the others, or to the VPS:
take another user's ports, traffic or files, or change what every user shares
(the server settings only the administrator and the main router, userid 0,
may change), plus the hardening that came with it (tokens tied to the
password, the /backuppost size limit, the /mptcpsupport cache...).
"""

import base64
import io
import json
import os
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import jwt
import pytest

from conftest import (ALGORITHM, MOCK_CONFIG, SECRET_KEY, _ASGITestClient, _mock_open,  # noqa: F401
                      app, omr_admin)

PRIMARY = omr_admin.User(username="openmptcprouter", userid=0, permissions="rw", shadowsocks_port=65101)
# Another router of the VPS: the 'readonly' entry of MOCK_CONFIG (userid 2,
# shadowsocks port 65102), here with read-write rights.
OTHER = omr_admin.User(username="readonly", userid=2, permissions="rw", shadowsocks_port=65102)


@pytest.fixture
def other_client():
    app.dependency_overrides[omr_admin.get_current_user] = lambda: OTHER
    yield _ASGITestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.pop(omr_admin.get_current_user, None)


def _config():
    return json.loads(json.dumps(MOCK_CONFIG))


# ---------------------------------------------------------------------------
# Server-wide settings
# ---------------------------------------------------------------------------

class TestServerWideSettings:
    @pytest.mark.parametrize("method,route,payload", [
        ("post", "/sipalg", {"enable": True}),
        ("post", "/firewall", {"redirect_ports": "enable"}),
        ("post", "/shorewall", {"redirect_ports": "enable"}),
        ("post", "/dscp_classify", {"entries": []}),
        ("post", "/mptcp_dscp", {"pins": []}),
        ("post", "/mptcp_weight", {"weights": []}),
        ("post", "/bypass", {"intf": "vpn1", "ipv4s": ["0.0.0.0/0"]}),
        ("post", "/openvpn", {"port": 65301, "cipher": "AES-256-GCM"}),
        ("post", "/mlvpn", {"timeout": 30, "reorder_buffer_size": 64, "loss_tolerence": 50,
                            "cleartext_data": 0, "password": "abc"}),
        ("post", "/shadowsocks-go", {"port": 65280, "method": "2022-blake3-aes-256-gcm",
                                     "fast_open": True, "reuse_port": True}),
        ("get", "/update", None),
    ])
    def test_other_router_refused(self, other_client, method, route, payload):
        with (
            patch("os.path.isfile", return_value=True),
            patch("omr_admin.set_global_param") as set_param,
            patch("omr_admin._atomic_write") as write,
            patch("subprocess.run") as run,
        ):
            r = getattr(other_client, method)(route, **({"json": payload} if payload is not None else {}))
        body = r.json()
        assert body["result"] == "permission", body
        assert not set_param.called and not write.called and not run.called

    def test_main_router_and_admin_allowed(self, user_client):
        assert omr_admin._is_server_admin(PRIMARY)
        assert omr_admin._is_server_admin(omr_admin.User(username="admin", permissions="admin"))
        assert not omr_admin._is_server_admin(OTHER)
        assert not omr_admin._is_server_admin(omr_admin.User(username="x", permissions="rw"))
        r = user_client.post("/sipalg", json={"enable": False})
        assert r.json()["result"] != "permission"

    def test_vpn_of_another_router_is_its_own_only(self, other_client):
        with (
            patch("omr_admin._atomic_write_text") as write,
            patch("omr_admin.modif_config_user") as modif,
        ):
            r = other_client.post("/vpn", json={"vpn": "openvpn"})
        assert r.json()["result"] == "done"
        modif.assert_called_once_with("readonly", {"vpn": "openvpn"})
        write.assert_not_called()   # current-vpn is the main router's

    def test_vpn_of_main_router_written(self, user_client):
        with patch("omr_admin._atomic_write_text") as write, patch("omr_admin.modif_config_user"):
            user_client.post("/vpn", json={"vpn": "openvpn"})
        write.assert_called_once_with("/etc/openmptcprouter-vps-admin/current-vpn", "openvpn\n")


class TestMlvpnPassword:
    @pytest.mark.parametrize("password", ["x\nstatuscommand = /sbin/reboot", "a%b", 'a"b', "a b", "", "A" * 129])
    def test_refused(self, user_client, password):
        with patch("os.path.isfile", return_value=True), patch("omr_admin._atomic_write") as write:
            r = user_client.post("/mlvpn", json={"timeout": 30, "reorder_buffer_size": 64, "loss_tolerence": 50,
                                                 "cleartext_data": 0, "password": password})
        assert r.json() == {"result": "error", "reason": "Invalid password", "route": "mlvpn"}
        write.assert_not_called()

    def test_base64_accepted(self, user_client):
        with patch("os.path.isfile", return_value=True), patch("omr_admin.file_as_bytes", return_value=b""):
            r = user_client.post("/mlvpn", json={"timeout": 30, "reorder_buffer_size": 64, "loss_tolerence": 50,
                                                 "cleartext_data": 0, "password": "Zm9v+Ym/Fy="})
        assert r.json()["result"] == "done"


# ---------------------------------------------------------------------------
# /shadowsocks
# ---------------------------------------------------------------------------

class TestShadowsocksPorts:
    _MANAGER = {"server": "0.0.0.0", "port_key": {"65101": "primarykey", "65102": "otherkey"},
                "method": "chacha20-ietf-poly1305", "timeout": 600, "fast_open": True}

    def _post(self, client, port, **extra):
        written = {}
        manager = json.dumps(self._MANAGER)

        def _open(path, mode="r", *a, **k):
            if str(path) == "/etc/shadowsocks-libev/manager.json" and "w" not in mode:
                return io.BytesIO(manager.encode()) if "b" in mode else io.StringIO(manager)
            return _mock_open(path, mode, *a, **k)

        def _write(path, data, *a, **k):
            written[path] = data

        payload = {"port": port, "method": "aes-256-gcm", "fast_open": False, "reuse_port": True,
                   "no_delay": True, "key": "newkey", **extra}
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open),
            patch("omr_admin._atomic_write_json", side_effect=_write),
            patch("omr_admin.file_as_bytes", side_effect=[b"a", b"b"]),
            patch("omr_admin.modif_config_user") as modif,
            patch("omr_admin.shorewall_add_port", return_value=None),
            patch("omr_admin.set_global_param"),
        ):
            r = client.post("/shadowsocks", json=payload)
        return r.json(), written, modif

    # One client per test: both fixtures set the same dependency override.
    def test_port_of_the_main_router_refused(self, other_client):
        body, written, modif = self._post(other_client, 65101)
        assert body == {"result": "error", "reason": "Port already used by another user", "route": "shadowsocks"}
        assert written == {} and not modif.called

    def test_port_of_another_router_refused(self, user_client):
        body, written, modif = self._post(user_client, 65102)
        assert body == {"result": "error", "reason": "Port already used by another user", "route": "shadowsocks"}
        assert written == {} and not modif.called

    def test_other_router_cannot_pick_a_new_port(self, other_client):
        body, written, _ = self._post(other_client, 65200)
        assert body["result"] == "error" and "can change the Shadowsocks port" in body["reason"]
        assert written == {}

    def test_other_router_changes_its_key_only(self, other_client):
        body, written, modif = self._post(other_client, 65102)
        assert body["result"] == "done"
        manager = written["/etc/shadowsocks-libev/manager.json"]
        assert manager["port_key"] == {"65101": "primarykey", "65102": "newkey"}
        # the method and options every user shares are left as they were
        assert manager["method"] == "chacha20-ietf-poly1305" and manager["fast_open"] is True
        assert not modif.called

    def test_main_router_still_sets_the_server(self, user_client):
        body, written, modif = self._post(user_client, 65101)
        assert body["result"] == "done"
        manager = written["/etc/shadowsocks-libev/manager.json"]
        assert manager["method"] == "aes-256-gcm" and manager["port_key"]["65101"] == "newkey"
        modif.assert_called_with("openmptcprouter", {"shadowsocks_port": 65101})

    def test_port_conf_entry_of_another_userid_refused(self):
        data = {"port_conf": {"65300": {"key": "k", "userid": 7}}}
        with patch("omr_admin.read_omr_config", return_value=_config()):
            assert omr_admin._shadowsocks_port_error(data, PRIMARY, 65300) == "Port already used by another user"
            assert omr_admin._shadowsocks_port_error(data, PRIMARY, 65301) is None

    def test_manager_command_is_json(self):
        manager = json.dumps({"port_key": {"65101": "k"}})
        sent = []
        sock = MagicMock()
        sock.sendto.side_effect = lambda data, addr: sent.append(data)

        def _open(path, mode="r", *a, **k):
            if str(path) == "/etc/shadowsocks-libev/manager.json":
                return io.StringIO(manager)
            return _mock_open(path, mode, *a, **k)

        with (
            patch("builtins.open", side_effect=_open),
            patch("omr_admin._atomic_write_json"),
            patch("socket.socket", return_value=sock),
        ):
            omr_admin.add_ss_user("65110", 'k", "plugin": "/bin/sh')
        assert sent[0].startswith(b"add: ")
        assert json.loads(sent[0][5:]) == {"server_port": 65110, "key": 'k", "plugin": "/bin/sh'}


# ---------------------------------------------------------------------------
# V2Ray/XRay redirects and reverse tunnels
# ---------------------------------------------------------------------------

_USERS = {
    "openmptcprouter": {"userid": 0, "username": "openmptcprouter"},
    "readonly": {"userid": "2", "username": "readonly"},
    "admin": {"username": "admin", "permissions": "admin"},
}


def _clients(reverse=True):
    clients = [{"id": "u0", "email": "openmptcprouter"}, {"id": "u2", "email": "readonly"}]
    if reverse:
        clients.append({"id": "rev0", "level": 0, "email": "omr-reverse", "reverse": {"tag": "OMRLan"}})
    return clients


class TestProxyRedirectIsolation:
    @pytest.fixture
    def configs(self, tmp_path, monkeypatch):
        paths = {}
        xray = {"inbounds": [{"tag": "omrin-tunnel", "port": 65248, "protocol": "vless",
                              "settings": {"clients": _clients()}},
                             {"tag": "omrin-vless-reality", "port": 443, "protocol": "vless"},
                             {"tag": "api", "port": 10086, "protocol": "dokodemo-door",
                              "settings": {"network": "tcp"}}],
                "routing": {"rules": [{"type": "field", "inboundTag": ["api"], "outboundTag": "api"}]}}
        v2ray = {"inbounds": [{"tag": "omrin-tunnel", "port": 65228, "protocol": "vless",
                               "settings": {"clients": _clients(reverse=False)}}],
                 "reverse": {"portals": [{"tag": "OMRLan", "domain": "omr.lan"}]},
                 "routing": {"rules": [{"type": "field", "inboundTag": ["omrin-tunnel"],
                                        "outboundTag": "OMRLan", "domain": ["full:omr.lan"]}]}}
        for service, data in (("xray", xray), ("v2ray", v2ray)):
            p = tmp_path / f"{service}-server.json"
            p.write_text(json.dumps(data))
            paths[service] = str(p)
        monkeypatch.setattr(omr_admin, "PROXY_REDIRECT_CONFIGS", paths)
        monkeypatch.setattr(omr_admin, "OMR_CONFIG_LOCK_FILE", str(tmp_path / ".lock"))
        with patch("omr_admin._schedule_proxy_restart") as restart:
            yield paths, restart

    @staticmethod
    def _load(path):
        return json.loads(open(path).read())

    @pytest.mark.real_env
    @pytest.mark.parametrize("service", ["v2ray", "xray"])
    def test_port_of_another_user_refused(self, configs, service):
        paths, _ = configs
        add = getattr(omr_admin, f"{service}_add_port")
        assert add(PRIMARY, "8080", "tcp", "x", "192.168.1.2", "80") is None
        before = open(paths[service]).read()
        assert add(OTHER, "8080", "tcp", "x", "192.168.2.2", "80") == "Port already in use on the server"
        assert add(OTHER, "8000-8100", "tcp", "x", "192.168.2.2", "") == "Port already in use on the server"
        assert open(paths[service]).read() == before
        # the same port in the other protocol is another listener
        assert add(OTHER, "8080", "udp", "x", "192.168.2.2", "80") is None

    @pytest.mark.real_env
    @pytest.mark.parametrize("port", ["443", "10086"])
    def test_server_listener_refused(self, configs, port):
        # VLESS Reality on 443, the API inbound: the daemon could not start.
        assert omr_admin.xray_add_port(PRIMARY, port, "tcp", "x", "192.168.1.2", port) == \
            "Port already in use on the server"

    @pytest.mark.real_env
    @pytest.mark.parametrize("service", ["v2ray", "xray"])
    def test_same_user_new_destination_replaces_the_redirect(self, configs, service):
        paths, _ = configs
        add = getattr(omr_admin, f"{service}_add_port")
        add(PRIMARY, "1000-1002", "tcp", "x", "192.168.1.2", "2000-2002")
        assert add(PRIMARY, "1001", "tcp", "x", "192.168.1.3", "80") is None
        data = self._load(paths[service])
        redirects = [i for i in data["inbounds"] if "_redir_" in i["tag"]]
        assert [(i["port"], i["settings"]["address"]) for i in redirects] == [(1001, "192.168.1.3")]
        rules = [r for r in data["routing"]["rules"] if "_redir_" in (r.get("inboundTag") or [""])[0]]
        assert [r["inboundTag"] for r in rules] == [[redirects[0]["tag"]]]

    @pytest.mark.real_env
    def test_ports_per_user_capped(self, configs, monkeypatch):
        monkeypatch.setattr(omr_admin, "PROXY_REDIRECT_MAX_USER_PORTS", 5)
        assert omr_admin.xray_add_port(PRIMARY, "1000-1003", "tcp", "x", "192.168.1.2", "") is None
        assert "No more than 5 ports" in omr_admin.xray_add_port(PRIMARY, "2000-2001", "tcp", "x", "192.168.1.2", "")
        # another user has its own allowance
        assert omr_admin.xray_add_port(OTHER, "3000-3004", "tcp", "x", "192.168.2.2", "") is None

    @pytest.mark.real_env
    def test_xray_redirect_goes_to_the_users_own_reverse_tunnel(self, configs):
        paths, _ = configs
        omr_admin.xray_add_port(PRIMARY, "8080", "tcp", "x", "192.168.1.2", "80")
        omr_admin.xray_add_port(OTHER, "8081", "tcp", "x", "192.168.2.2", "80")
        data = self._load(paths["xray"])
        targets = {r["inboundTag"][0]: r["outboundTag"] for r in data["routing"]["rules"] if r["outboundTag"] != "api"}
        assert targets == {"openmptcprouter_redir_tcp_8080_to_192.168.1.2:80": "OMRLan",
                           "readonly_redir_tcp_8081_to_192.168.2.2:80": "OMRLan-readonly"}
        clients = data["inbounds"][0]["settings"]["clients"]
        reverse = [c for c in clients if "reverse" in c]
        assert [(c["email"], c["reverse"]["tag"]) for c in reverse] == \
            [("omr-reverse", "OMRLan"), ("omr-reverse@readonly", "OMRLan-readonly")]
        assert reverse[0]["id"] != reverse[1]["id"]

    @pytest.mark.real_env
    def test_v2ray_redirect_goes_to_the_users_own_portal(self, configs):
        paths, _ = configs
        omr_admin.v2ray_add_port(OTHER, "8081", "tcp", "x", "192.168.2.2", "80")
        data = self._load(paths["v2ray"])
        assert {"tag": "OMRLan-readonly", "domain": "omr.lan"} in data["reverse"]["portals"]
        bridge = data["routing"]["rules"][0]
        assert bridge == {"type": "field", "inboundTag": ["omrin-tunnel"], "domain": ["full:omr.lan"],
                          "user": ["readonly"], "outboundTag": "OMRLan-readonly"}

    @pytest.mark.real_env
    def test_v2ray_isolation_moves_redirects_and_keeps_the_shared_portal_to_the_primary(self, configs):
        paths, _ = configs
        data = self._load(paths["v2ray"])
        data["inbounds"].append({"tag": "readonly_redir_tcp_8081_to_192.168.2.2:80", "port": 8081})
        data["routing"]["rules"].append({"type": "field", "inboundTag": ["readonly_redir_tcp_8081_to_192.168.2.2:80"],
                                         "outboundTag": "OMRLan"})
        assert omr_admin._proxy_isolate_reverse("v2ray", data, _USERS)
        rules = data["routing"]["rules"]
        assert next(r for r in rules if r["inboundTag"][0].startswith("readonly_redir"))["outboundTag"] == "OMRLan-readonly"
        shared = next(r for r in rules if r["outboundTag"] == "OMRLan")
        assert shared["user"] == ["openmptcprouter"]
        # idempotent
        assert not omr_admin._proxy_isolate_reverse("v2ray", data, _USERS)

    @pytest.mark.real_env
    def test_xray_isolation_replaces_the_shared_uuid_once(self, configs):
        paths, _ = configs
        data = self._load(paths["xray"])
        with patch("omr_admin.read_omr_config", return_value={}), patch("omr_admin.set_global_param") as set_param:
            assert omr_admin._proxy_isolate_reverse("xray", data, _USERS)
        set_param.assert_called_once_with("xray_reverse_per_user", True)
        assert omr_admin.xray_reverse_client_id(data) not in ("", "rev0")
        assert omr_admin.xray_reverse_client_id(data, "OMRLan-readonly")
        rotated = omr_admin.xray_reverse_client_id(data)
        with patch("omr_admin.read_omr_config", return_value={"xray_reverse_per_user": True}), \
             patch("omr_admin.set_global_param"):
            assert not omr_admin._proxy_isolate_reverse("xray", data, _USERS)
        assert omr_admin.xray_reverse_client_id(data) == rotated

    @pytest.mark.real_env
    def test_single_user_vps_unchanged(self, configs):
        paths, _ = configs
        for service in ("xray", "v2ray"):
            data = self._load(paths[service])
            for ib in data["inbounds"]:
                if ib["tag"] == "omrin-tunnel":
                    ib["settings"]["clients"] = [c for c in ib["settings"]["clients"] if c["email"] != "readonly"]
            before = json.dumps(data)
            with patch("omr_admin.set_global_param") as set_param:
                assert not omr_admin._proxy_isolate_reverse(service, data, _USERS)
            assert json.dumps(data) == before and not set_param.called

    @pytest.mark.real_env
    def test_removed_user_takes_its_tunnel_and_redirects_along(self, configs):
        paths, _ = configs
        omr_admin.xray_add_port(OTHER, "8081", "tcp", "x", "192.168.2.2", "80")
        omr_admin.xray_add_port(PRIMARY, "8080", "tcp", "x", "192.168.1.2", "80")
        data = self._load(paths["xray"])
        assert omr_admin._proxy_drop_user("xray", data, "readonly")
        assert [i["tag"] for i in data["inbounds"] if "_redir_" in i["tag"]] == \
            ["openmptcprouter_redir_tcp_8080_to_192.168.1.2:80"]
        assert not omr_admin.xray_reverse_client_id(data, "OMRLan-readonly")
        assert omr_admin.xray_reverse_client_id(data) == "rev0"
        assert all(r["outboundTag"] != "OMRLan-readonly" for r in data["routing"]["rules"])

    @pytest.mark.real_env
    def test_no_reverse_client_for_a_user_without_xray(self, configs):
        # The admin user calling /config must not get (and restart xray for)
        # a reverse client of its own.
        paths, restart = configs
        before = open(paths["xray"]).read()
        with patch("omr_admin.set_global_param"):
            assert omr_admin.xray_user_reverse_key("admin", None) == ""
            assert open(paths["xray"]).read() == before
            key = omr_admin.xray_user_reverse_key("readonly", "2")
        assert key and key != "rev0"
        restart.assert_called_once_with("xray")

    @pytest.mark.real_env
    def test_router_logged_in_as_admin_uses_the_main_tunnel(self, configs):
        paths, _ = configs
        admin = omr_admin.User(username="admin", permissions="admin")
        assert omr_admin.xray_add_port(admin, "8090", "tcp", "x", "192.168.1.2", "80") is None
        data = self._load(paths["xray"])
        assert next(r for r in data["routing"]["rules"] if r["inboundTag"][0].startswith("admin_redir"))["outboundTag"] == "OMRLan"

    def test_owner_of_a_tag(self):
        owner = omr_admin._proxy_redirect_owner
        assert owner("bob_redir_tcp_80_to_192.168.1.2:80") == "bob"
        assert owner("a_redir_tcp_1_redir_udp_1000-1002_to_:1000-1002#1001") == "a_redir_tcp_1"
        assert owner("omrin-tunnel") is None and owner("api") is None

    def test_redirect_endpoint_reports_the_conflict(self, user_client):
        with patch("os.path.isfile", return_value=True), \
             patch("omr_admin.xray_add_port", return_value="Port already in use on the server"):
            r = user_client.post("/xrayredirect", json={"name": "x", "port": "8080", "proto": "tcp",
                                                        "destip": "192.168.1.2", "destport": "80"})
        assert r.json() == {"result": "error", "reason": "Port already in use on the server", "route": "xrayredirect"}

    @pytest.mark.parametrize("field,value,reason", [
        ("proto", "tcp_80_redir_tcp", "Invalid protocol"),
        ("port", "80_redir_tcp_80", "Invalid port"),
        ("destip", "x_redir_tcp_80_to_1.2.3.4", "Invalid address"),
        ("destport", "80#1", "Invalid destination port"),
    ])
    @pytest.mark.parametrize("route", ["/xrayunredirect", "/v2rayunredirect"])
    def test_unredirect_can_only_name_the_users_own_redirect(self, user_client, route, field, value, reason):
        payload = {"name": "x", "port": "80", "proto": "tcp", "destip": "192.168.1.2", "destport": "80", field: value}
        with patch("os.path.isfile", return_value=True), \
             patch("omr_admin.xray_del_port") as xdel, patch("omr_admin.v2ray_del_port") as vdel:
            r = user_client.post(route, json=payload)
        assert r.json()["reason"] == reason
        assert not xdel.called and not vdel.called


# ---------------------------------------------------------------------------
# Tunnel addresses: /vxlan, /vpnips, /wireguard, /lan
# ---------------------------------------------------------------------------

class TestVxlanTunnelAddresses:
    @pytest.mark.parametrize("field,value", [
        ("localip", "1.0.0.1/1"), ("localip", "10.255.249.1/24"), ("localip", "10.255.249.4/30"),
        ("localip", "10.255.249.7/30"), ("localip", "10.255.252.1/30"), ("localip", "10.255.249.1"),
        ("remoteip", "0.0.0.0/0"), ("localip6", "2000::1/3"), ("localip6", "fd00::a00:1/126"),
        ("localip6", "fd00::b00:1/64"), ("remoteip6", "::/0"),
    ])
    def test_refused(self, user_client, field, value):
        with patch("omr_admin.write_vxlan_conf") as write, patch("omr_admin.modif_config_user") as modif:
            r = user_client.post("/vxlan", json={"enable": True, field: value})
        assert r.json() == {"result": "error", "reason": f"Invalid {field}", "route": "vxlan"}
        assert not write.called and not modif.called

    def test_slice_of_another_user_refused(self, user_client):
        # 'readonly' (userid 2) has 10.255.249.8/30 by default.
        with patch("omr_admin.write_vxlan_conf"), patch("omr_admin.modif_config_user") as modif:
            r = user_client.post("/vxlan", json={"enable": True, "localip": "10.255.249.10/30"})
        assert r.json()["reason"] == "localip already used by another user"
        assert not modif.called

    @pytest.mark.parametrize("userid", [0, 15, 16, 255, 256, 1087])
    def test_every_default_slice_is_accepted(self, userid):
        v4 = omr_admin._vxlan_default_v4(userid)
        v6 = omr_admin._vxlan_default_v6(userid)
        for value in v4:
            assert omr_admin._vxlan_tunnel_net(value, 4) is not None, value
        for value in v6:
            assert omr_admin._vxlan_tunnel_net(value, 6) is not None, value

    def test_stored_bad_address_not_written(self):
        written = {}

        class _File(io.StringIO):
            def close(self):
                written["data"] = self.getvalue()

        config = _config()
        config["users"][0]["openmptcprouter"].update(
            vpnlocalip="10.255.255.1", vpnremoteip="10.255.255.2",
            vxlan={"enabled": True, "mode": "l3", "localip": "1.0.0.1/1", "localip6": "::1/0"})
        text = json.dumps(config)

        def _open(path, mode="r", *a, **k):
            if str(path).endswith("omr-vxlan/user0") and "w" in mode:
                return _File()
            if str(path).endswith("omr-admin-config.json"):
                return io.StringIO(text)
            return _mock_open(path, mode, *a, **k)

        with (
            patch("builtins.open", side_effect=_open),
            patch("os.path.isfile", return_value=False),
            patch("os.makedirs"),
            patch("omr_admin.file_as_bytes", return_value=b"x"),
        ):
            omr_admin.write_vxlan_conf("openmptcprouter", 0)
        assert "LOCALTUNIP" not in written["data"]


class TestVpnIpsOwnership:
    _PAYLOAD = {"remoteip": "10.255.255.2", "localip": "10.255.255.1"}

    def _post(self, client, config=None, **fields):
        text = json.dumps(config or _config())

        def _open(path, mode="r", *a, **k):
            if str(path).endswith("omr-admin-config.json") and "w" not in mode:
                return io.StringIO(text)
            return _mock_open(path, mode, *a, **k)

        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=_open),
            patch("omr_admin.modif_config_user") as modif,
            patch("subprocess.run"),
            patch("omr_admin._nft_sync_ports"),
        ):
            r = client.post("/vpnips", json={**self._PAYLOAD, **fields})
        return r.json(), modif

    @pytest.mark.parametrize("ula", ["::/0", "2000::/3", "fd00::/48", "fd00::/8", "fd12:3456:789a::/32",
                                     "fd12:3456:789a::/96", "2001:db8::/48"])
    def test_ula_refused(self, user_client, ula):
        body, modif = self._post(user_client, ula=ula)
        assert body == {"result": "error", "reason": "Invalid ula", "route": "vpnips"}
        assert not modif.called

    def test_router_ula_accepted(self, user_client):
        body, _ = self._post(user_client, ula="fd12:3456:789a::/48")
        assert body["result"] == "done"

    @pytest.mark.parametrize("field,value", [("localip6", "fd00::a02:1/126"), ("remoteip6", "fd00::a00:1/126"),
                                             ("remoteip6", "2001:db8::2/126")])
    def test_only_its_own_6in4_pair(self, user_client, field, value):
        body, _ = self._post(user_client, **{field: value})
        assert body == {"result": "error", "reason": f"Invalid {field}", "route": "vpnips"}

    def test_address_of_another_router_refused(self, other_client):
        config = _config()
        config["users"][0]["openmptcprouter"].update(vpnremoteip="10.255.255.2", vpnlocalip="10.255.255.1",
                                                    ula="fd12:3456:789a::/48")
        body, modif = self._post(other_client, config, remoteip="10.255.255.2", localip="10.255.255.5")
        assert body["reason"] == "remoteip already used by another user" and not modif.called
        body, _ = self._post(other_client, config, remoteip="10.255.255.1", localip="10.255.255.5")
        assert body["reason"] == "remoteip already used by another user"
        body, _ = self._post(other_client, config, remoteip="10.255.255.6", localip="10.255.255.5",
                             ula="fd12:3456:789a::/56")
        assert body["reason"] == "ula already used by another user"
        # the VPS end of a tunnel is shared (every OpenVPN client's localip)
        body, _ = self._post(other_client, config, remoteip="10.255.255.6", localip="10.255.255.1")
        assert body["result"] == "done"


def _open_with_config(config):
    text = json.dumps(config)

    def _open(path, mode="r", *a, **k):
        if str(path).endswith("omr-admin-config.json") and "w" not in mode:
            return io.StringIO(text)
        return _mock_open(path, mode, *a, **k)
    return _open


class TestLanNetworks:
    @pytest.mark.parametrize("lan", ["192.168.1.1//", "fd00::/64", "192.168.1.1/24\npush x", "1.2.3.4/33",
                                     "example.com"])
    def test_not_a_network_refused(self, user_client, lan):
        with patch("omr_admin.modif_config_user") as modif:
            r = user_client.post("/lan", json={"lanips": ["192.168.100.1/255.255.255.0", lan]})
        assert r.json() == {"result": "error", "reason": "Invalid lanips", "route": "lan"}
        assert not modif.called

    @pytest.mark.parametrize("lan", ["0.0.0.0/0", "8.8.8.0/24", "10.255.255.0/24", "10.0.0.0/8", "127.0.0.1/8"])
    def test_unroutable_lan_refused_with_client2client(self, user_client, lan):
        config = _config()
        config["client2client"] = True
        with patch("builtins.open", side_effect=_open_with_config(config)), \
             patch("omr_admin.modif_config_user") as modif:
            r = user_client.post("/lan", json={"lanips": [lan]})
        assert r.json() == {"result": "error", "reason": "Invalid lanips", "route": "lan"}
        assert not modif.called

    def test_any_network_stored_without_client2client(self, user_client):
        # Nothing is routed then: a 10/8 or public LAN is kept as before.
        with patch("omr_admin.modif_config_user") as modif:
            r = user_client.post("/lan", json={"lanips": ["10.0.0.1/255.0.0.0", "203.0.113.1/29"]})
        assert r.json()["result"] == "done"
        modif.assert_called_once_with("openmptcprouter", {"lanips": ["10.0.0.1/255.0.0.0", "203.0.113.1/29"]})

    @pytest.mark.parametrize("lan", ["192.168.100.1/255.255.255.0", "192.168.1.1/24", "172.16.5.0/24",
                                     "100.64.1.0/24", "10.1.0.0/16", "192.168.1.1/24/"])
    def test_router_lan_accepted(self, lan):
        assert omr_admin._lan_network(lan) is not None

    def test_lan_of_another_router_refused_with_client2client(self, user_client):
        config = _config()
        config["client2client"] = True
        config["users"][0]["readonly"]["lanips"] = ["192.168.100.1/255.255.255.0"]
        text = json.dumps(config)

        def _open(path, mode="r", *a, **k):
            if str(path).endswith("omr-admin-config.json") and "w" not in mode:
                return io.StringIO(text)
            return _mock_open(path, mode, *a, **k)

        with patch("builtins.open", side_effect=_open), patch("omr_admin.modif_config_user") as modif:
            r = user_client.post("/lan", json={"lanips": ["192.168.100.1/24"]})
            assert r.json()["result"] == "conflict" and not modif.called
            r = user_client.post("/lan", json={"lanips": ["192.168.101.1/24"]})
            assert r.json()["result"] == "done"


# ---------------------------------------------------------------------------
# Firewall: another user's public IP
# ---------------------------------------------------------------------------

class TestFirewallPublicIps:
    def test_dedicated_ip_belongs_to_its_user_not_to_the_gre_tunnels(self):
        # The main router has a GRE tunnel on every public IP, those
        # dedicated to the other users included.
        config = _config()
        config["users"][0]["openmptcprouter"]["gre_tunnels"] = {
            "gre1": {"public_ip": "203.0.113.9"}, "gre2": {"public_ip": "203.0.113.11"}}
        config["users"][0]["readonly"]["public_ips"] = ["203.0.113.11"]
        assert omr_admin._public_ip_owner(config, "203.0.113.11") == "readonly"
        assert omr_admin._public_ip_owner(config, "203.0.113.9") is None

    def test_public_ip_of_another_user_refused(self, user_client):
        config = _config()
        config["users"][0]["readonly"]["public_ips"] = ["203.0.113.9"]
        text = json.dumps(config)

        def _open(path, mode="r", *a, **k):
            if str(path).endswith("omr-admin-config.json") and "w" not in mode:
                return io.StringIO(text)
            return _mock_open(path, mode, *a, **k)

        with patch("builtins.open", side_effect=_open), patch("omr_admin.shorewall_add_port", return_value=None) as add:
            r = user_client.post("/firewallopen", json={"name": "x", "port": "80", "proto": "tcp", "fwtype": "DNAT",
                                                        "source_dip": "203.0.113.9"})
            assert r.json() == {"result": "error", "reason": "Address used by another user", "route": "firewallopen"}
            assert not add.called
            r = user_client.post("/firewallopen", json={"name": "x", "port": "80", "proto": "tcp", "fwtype": "DNAT",
                                                        "source_dip": "203.0.113.10"})
            assert r.json()["result"] == "done"


# ---------------------------------------------------------------------------
# Backups
# ---------------------------------------------------------------------------

class TestBackupNames:
    @pytest.mark.parametrize("name,ok", [
        ("openmptcprouter-backup.tar.gz", True), ("openmptcprouter-1700000000-backup.tar.gz", True),
        ("openmptcprouter-bar-backup.tar.gz", False), ("openmptcprouter-bar-1700000000-backup.tar.gz", False),
        ("openmptcprouterx-backup.tar.gz", False),
    ])
    def test_backupget_only_the_users_own(self, user_client, name, ok):
        with patch("os.path.isfile", return_value=True):
            r = user_client.get("/backupget", params={"filename": name})
        assert ("data" in r.json()) is ok

    def test_backup_of_a_user_named_after_a_dated_copy(self):
        # bob-1-backup.tar.gz: a dated copy of bob's, or user bob-1's backup.
        config = {"users": [{"bob": {}, "bob-1": {}}]}
        with patch("omr_admin.read_omr_config", return_value=config):
            assert not omr_admin._is_own_backup("bob-1-backup.tar.gz", "bob")
            assert omr_admin._is_own_backup("bob-1-backup.tar.gz", "bob-1")
            assert omr_admin._is_own_backup("bob-1700000000-backup.tar.gz", "bob")
            assert omr_admin._is_own_backup("bob-1-1700000000-backup.tar.gz", "bob-1")
            assert not omr_admin._is_own_backup("bob-1-1700000000-backup.tar.gz", "bob")

    def test_backuplist_only_the_users_own(self, user_client):
        files = ["/var/opt/openmptcprouter/openmptcprouter-1700000000-backup.tar.gz",
                 "/var/opt/openmptcprouter/openmptcprouter-bar-1700000000-backup.tar.gz"]
        with (
            patch("glob.glob", return_value=files),
            patch("os.path.isfile", return_value=True),
            patch("os.path.getmtime", return_value=1700000000.0),
            patch("os.stat") as mock_stat,
        ):
            mock_stat.return_value.st_mtime = 1700000000.0
            r = user_client.get("/backuplist")
        assert [f for f, _ in r.json()["sorted"]] == ["openmptcprouter-1700000000-backup.tar.gz"]

    @pytest.mark.real_env
    def test_rotation_leaves_the_other_users_backups(self, tmp_path):
        import re
        for i in range(12):
            (tmp_path / f"foo-{1700000000 + i}-backup.tar.gz").write_text("x")
            (tmp_path / f"foo-bar-{1700000000 + i}-backup.tar.gz").write_text("x")
        own = re.compile(r"foo-\d+-backup\.tar\.gz")
        omr_admin.delete_oldest_files(str(tmp_path / "foo-*-backup.tar.gz"), match=own.fullmatch)
        assert len(list(tmp_path.glob("foo-bar-*"))) == 12
        assert len([p for p in tmp_path.iterdir() if own.fullmatch(p.name)]) == 10

    def test_decoded_size_capped(self, user_client, monkeypatch):
        monkeypatch.setattr(omr_admin, "BACKUP_MAX_SIZE", 8)
        r = user_client.post("/backuppost", json={"data": base64.b64encode(b"0123456789").decode()})
        assert r.json() == {"result": "error", "reason": "Backup too large", "route": "backuppost"}

    def test_body_size_limit(self):
        import asyncio
        calls = []

        async def inner(scope, receive, send):
            while True:
                message = await receive()
                calls.append(message)
                if not message.get("more_body"):
                    break

        limit = omr_admin._BodySizeLimit(inner, {"/backuppost": 10})

        def run(headers, chunks, path="/backuppost"):
            sent = []
            queue = list(chunks)

            async def receive():
                body = queue.pop(0)
                return {"type": "http.request", "body": body, "more_body": bool(queue)}

            async def send(message):
                sent.append(message)

            scope = {"type": "http", "path": path, "headers": headers}
            try:
                asyncio.run(limit(scope, receive, send))
            except omr_admin.HTTPException as e:
                return e.status_code
            return sent[0]["status"] if sent else None

        assert run([(b"content-length", b"11")], [b"x" * 11]) == 413
        assert run([], [b"x" * 6, b"x" * 6]) == 413          # chunked, no length
        assert run([(b"content-length", b"10")], [b"x" * 10]) is None
        assert run([(b"content-length", b"999")], [b"x" * 999], path="/speedtest") is None

    @pytest.mark.real_env
    def test_backup_files_are_0600(self, tmp_path):
        import stat
        path = tmp_path / "b.tar.gz"
        old = os.umask(0o022)
        try:
            with open(path, "wb", opener=omr_admin._owner_only_opener) as f:
                f.write(b"x")
        finally:
            os.umask(old)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

class TestTokensTiedToThePassword:
    @staticmethod
    def _token(pwd=None):
        claims = {"sub": "openmptcprouter", "exp": datetime.utcnow() + timedelta(hours=1)}
        if pwd is not None:
            claims["pwd"] = pwd
        return jwt.encode(claims, SECRET_KEY, algorithm=ALGORITHM)

    def test_token_of_the_current_password_accepted(self, unauth_client):
        token = self._token(omr_admin._password_fingerprint("userpassword"))
        r = unauth_client.get("/vpn_list", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    @pytest.mark.parametrize("pwd", [None, "", "0" * 32])
    def test_token_of_another_password_refused(self, unauth_client, pwd):
        if pwd == "0" * 32:
            pwd = omr_admin._password_fingerprint("oldpassword")
        r = unauth_client.get("/vpn_list", headers={"Authorization": f"Bearer {self._token(pwd)}"})
        assert r.status_code == 403

    def test_login_token_carries_the_fingerprint(self, unauth_client):
        r = unauth_client.post("/token", data={"username": "openmptcprouter", "password": "userpassword"})
        claims = jwt.decode(r.json()["access_token"], SECRET_KEY, algorithms=[ALGORITHM])
        assert claims["pwd"] == omr_admin._password_fingerprint("userpassword")
        assert "userpassword" not in json.dumps(claims)

    def test_non_ascii_password_is_a_wrong_password_not_a_500(self, unauth_client):
        r = unauth_client.post("/token", data={"username": "openmptcprouter", "password": "pàssword"})
        assert r.status_code == 400


# ---------------------------------------------------------------------------
# Exact name matches
# ---------------------------------------------------------------------------

class TestExactNames:
    def test_pki_index_line(self):
        line = "V\t330101000000Z\t\tABCD\tunknown\t/CN={}\n"
        assert omr_admin._pki_index_line_is(line.format("foo"), "foo")
        assert omr_admin._pki_index_line_is(line.format("foo/emailAddress=x"), "foo")
        assert not omr_admin._pki_index_line_is(line.format("foobar"), "foo")
        assert not omr_admin._pki_index_line_is(line.format("foo-bar"), "foo")

    def test_openvpn_counters_of_the_user_only(self):
        status = (b">INFO:OpenVPN Management Interface\r\n"
                  b"OpenVPN CLIENT LIST\r\nUpdated,2026-10-05\r\n"
                  b"Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since\r\n"
                  b"foobar,1.2.3.4:5,111,222,2026-10-05\r\nfoo,1.2.3.5:6,333,444,2026-10-05\r\nEND\r\n")
        sock = MagicMock()
        sock.makefile.return_value = io.BytesIO(status)
        with patch("socket.socket", return_value=sock):
            assert omr_admin.get_bytes_openvpn("foo") == {"downlinkBytes": 333, "uplinkBytes": 444}
        sock.makefile.return_value = io.BytesIO(status)
        with patch("socket.socket", return_value=sock):
            assert omr_admin.get_bytes_openvpn("Bytes") == {"downlinkBytes": 0, "uplinkBytes": 0}


# ---------------------------------------------------------------------------
# /mptcpsupport
# ---------------------------------------------------------------------------

class TestMptcpSupportCache:
    def test_one_ss_run_for_a_burst_of_requests(self):
        omr_admin._mptcp_support_cache["time"] = None
        proc = MagicMock()
        proc.communicate.return_value = (b"ESTAB 192.0.2.7:443\n", b"")
        try:
            with patch("omr_admin.path.exists", return_value=False), \
                 patch("subprocess.Popen", return_value=proc) as popen:
                for _ in range(20):
                    assert omr_admin._mptcp_connections() == (None, b"ESTAB 192.0.2.7:443\n")
            assert popen.call_count == 1
        finally:
            omr_admin._mptcp_support_cache["time"] = None

    def test_endpoint_is_not_async(self):
        # A coroutine would run `ss -M` on the event loop of every request.
        import inspect
        assert not inspect.iscoroutinefunction(omr_admin.mptcpsupport)


# ---------------------------------------------------------------------------
# A user without a userid
# ---------------------------------------------------------------------------

NO_USERID = omr_admin.User(username="readonly", permissions="rw")


@pytest.fixture
def no_userid_client():
    app.dependency_overrides[omr_admin.get_current_user] = lambda: NO_USERID
    yield _ASGITestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.pop(omr_admin.get_current_user, None)


class TestUserWithoutUserid:
    """Was taken for userid 0: it read the main router's config and keys
    and wrote its tunnel files."""

    @pytest.mark.parametrize("method,route,payload", [
        ("get", "/config", None),
        ("get", "/status", None),
        ("post", "/vxlan", {"enable": True}),
        ("post", "/glorytun", {"key": "k", "port": 65001, "chacha": True}),
        ("post", "/dsvpn", {"key": "k", "port": 65401}),
        ("post", "/vpnips", {"remoteip": "10.255.255.6", "localip": "10.255.255.5"}),
    ])
    def test_refused(self, no_userid_client, method, route, payload):
        with (
            patch("os.path.isfile", return_value=True),
            patch("omr_admin.modif_config_user") as modif,
            patch("omr_admin.write_vxlan_conf") as vxlan,
            patch("omr_admin._atomic_write") as write,
        ):
            r = getattr(no_userid_client, method)(route, **({"json": payload} if payload is not None else {}))
        assert r.json().get("reason", r.json().get("error")) == "User has no userid", r.json()
        assert not modif.called and not vxlan.called and not write.called

    def test_admin_still_acts_as_the_main_router(self, admin_client):
        with patch("omr_admin.write_vxlan_conf") as vxlan, patch("omr_admin.modif_config_user"):
            r = admin_client.post("/vxlan", json={"enable": True, "vni": 777})
        assert r.json()["result"] == "done"
        assert vxlan.call_args.args == ("admin", 0)


# ---------------------------------------------------------------------------
# The config template's passwords
# ---------------------------------------------------------------------------

def _mock_config_json(config_json):
    def _open(path, mode="r", *a, **k):
        if str(path) == "/etc/openmptcprouter-vps-admin/omr-admin-config.json" and "w" not in mode:
            return io.BytesIO(config_json.encode()) if "b" in mode else io.StringIO(config_json)
        return _mock_open(path, mode, *a, **k)
    return _open


class TestTemplatePasswords:
    """A user the installer left with MySecretKey / AdminMySecretKey has a
    password anyone can read in the repository: it can't log in."""

    @staticmethod
    def _config(password):
        config = _config()
        config["users"][0]["openmptcprouter"]["user_password"] = password
        config["users"][0]["admin"]["user_password"] = "AdminMySecretKey"
        return json.dumps(config)

    @pytest.mark.parametrize("username,password", [("openmptcprouter", "MySecretKey"),
                                                   ("admin", "AdminMySecretKey")])
    def test_login_refused(self, unauth_client, username, password):
        with patch("builtins.open", side_effect=_mock_config_json(self._config("MySecretKey"))):
            r = unauth_client.post("/token", data={"username": username, "password": password})
        assert r.status_code == 400

    def test_token_refused(self, unauth_client):
        claims = {"sub": "openmptcprouter", "exp": datetime.utcnow() + timedelta(hours=1),
                  "pwd": omr_admin._password_fingerprint("MySecretKey")}
        token = jwt.encode(claims, SECRET_KEY, algorithm=ALGORITHM)
        with patch("builtins.open", side_effect=_mock_config_json(self._config("MySecretKey"))):
            r = unauth_client.get("/vpn_list", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

    def test_other_users_still_log_in(self, unauth_client):
        with patch("builtins.open", side_effect=_mock_config_json(self._config("userpassword"))):
            r = unauth_client.post("/token", data={"username": "openmptcprouter", "password": "userpassword"})
        assert r.status_code == 200

    def test_startup_warning(self):
        with patch.object(omr_admin.LOG, "warning") as warning:
            omr_admin.warn_template_passwords(json.loads(self._config("MySecretKey")))
        assert sorted(call.args[1] for call in warning.call_args_list) == ["admin", "openmptcprouter"]

"""
Unit tests for the VXLAN L2/L3 mode support:

  - get_vxlan_config(): defaults mode to "l3", coerces invalid values back
    to "l3", passes through a valid "l2"
  - write_vxlan_conf(): L3 (default) writes LOCALTUNIP/LOCALTUNIP6 with no
    BRIDGE line; L2 writes MODE=l2 + a VNI-derived BRIDGE and skips the P2P
    tunnel IPs entirely
  - POST /vxlan: mode passthrough into modif_config_user(), invalid mode
    values silently dropped rather than stored
"""

import io
import ipaddress
import json
from unittest.mock import patch

import pytest

from conftest import omr_admin, user_headers  # noqa: F401  (fixtures)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FileEnv:
    """builtins.open side_effect mapping paths to contents, recording writes."""

    def __init__(self, files):
        self.files = dict(files)
        self.written = {}

    def __call__(self, path, mode="r", *args, **kwargs):
        sp = str(path)
        binary = "b" in str(mode)
        if "w" in str(mode) or "a" in str(mode):
            env = self

            class _Recorder(io.BytesIO if binary else io.StringIO):
                def close(recorder):
                    value = recorder.getvalue()
                    env.written[sp] = value
                    # Feed the write back so later reads in the same test see it
                    env.files[sp] = value.decode() if binary else value
                    super().close()

            return _Recorder()
        if sp in self.files:
            data = self.files[sp]
            return io.BytesIO(data.encode()) if binary else io.StringIO(data)
        return io.BytesIO() if binary else io.StringIO()


_CONFIG_PATH = "/etc/openmptcprouter-vps-admin/omr-admin-config.json"
_VXLAN_FILE = "/etc/openmptcprouter-vps-admin/omr-vxlan/user0"


def _config(username="openmptcprouter", userid=0, vxlan=None, vpnips=True):
    user = {"userid": userid, "username": username}
    if vpnips:
        user["vpnlocalip"] = "10.255.252.1"
        user["vpnremoteip"] = "10.255.252.2"
    if vxlan is not None:
        user["vxlan"] = vxlan
    return json.dumps({"users": [{username: user}]})


def _two_users(my_port=4789, other_port=4789, my_vni=5, other_vni=5, enabled=True):
    """Config with the test user (userid 0) and a second user (userid 2), both
    carrying an explicit VXLAN VNI/port, to exercise the collision checks."""
    return json.dumps({"users": [{
        "openmptcprouter": {"userid": 0, "username": "openmptcprouter",
                            "vpnlocalip": "10.255.252.1", "vpnremoteip": "10.255.252.2",
                            "vxlan": {"enabled": enabled, "vni": my_vni, "port": my_port}},
        "otheruser": {"userid": 2, "username": "otheruser",
                      "vpnlocalip": "10.255.253.1", "vpnremoteip": "10.255.253.2",
                      "vxlan": {"enabled": True, "vni": other_vni, "port": other_port}},
    }]})


# ===========================================================================
# get_vxlan_config()
# ===========================================================================


class TestGetVxlanConfig:
    def test_mode_defaults_to_l3_when_absent(self):
        env = _FileEnv({_CONFIG_PATH: _config(vxlan={"enabled": True})})
        with patch("builtins.open", side_effect=env):
            cfg = omr_admin.get_vxlan_config("openmptcprouter", 0)
        assert cfg["mode"] == "l3"

    def test_valid_l2_mode_passed_through(self):
        env = _FileEnv({_CONFIG_PATH: _config(vxlan={"enabled": True, "mode": "l2"})})
        with patch("builtins.open", side_effect=env):
            cfg = omr_admin.get_vxlan_config("openmptcprouter", 0)
        assert cfg["mode"] == "l2"

    def test_invalid_mode_coerced_to_l3(self):
        env = _FileEnv({_CONFIG_PATH: _config(vxlan={"enabled": True, "mode": "bogus"})})
        with patch("builtins.open", side_effect=env):
            cfg = omr_admin.get_vxlan_config("openmptcprouter", 0)
        assert cfg["mode"] == "l3"

    @pytest.mark.parametrize("userid, localip, remoteip", [
        (0, "10.255.249.1/30", "10.255.249.2/30"),
        (63, "10.255.249.253/30", "10.255.249.254/30"),
        (64, "10.255.224.1/30", "10.255.224.2/30"),
        (1087, "10.255.239.253/30", "10.255.239.254/30"),
        (1088, None, None),
    ])
    def test_default_v4_slices_stay_valid_past_userid_63(self, userid, localip, remoteip):
        """10.255.249.<userid*4+1> overflowed past .255 from userid 64 on."""
        env = _FileEnv({_CONFIG_PATH: _config(userid=userid, vxlan={"enabled": True})})
        with patch("builtins.open", side_effect=env):
            cfg = omr_admin.get_vxlan_config("openmptcprouter", userid)
        assert (cfg["localip"], cfg["remoteip"]) == (localip, remoteip)
        if localip is not None:
            ipaddress.ip_interface(cfg["localip"])
            ipaddress.ip_interface(cfg["remoteip"])

    @pytest.mark.parametrize("userid, localip6, remoteip6", [
        (0, "fd00::b00:1/126", "fd00::b00:2/126"),
        (10, "fd00::b0a:1/126", "fd00::b0a:2/126"),
        (255, "fd00::b0ff:1/126", "fd00::b0ff:2/126"),
        (256, "fd00::b100:1/126", "fd00::b100:2/126"),
        (4095, "fd00::bfff:1/126", "fd00::bfff:2/126"),
        (4096, None, None),
    ])
    def test_default_v6_slices_stay_valid_past_userid_255(self, userid, localip6, remoteip6):
        """fd00::b0<hex(userid)> grew a fifth hex digit from userid 256 on."""
        env = _FileEnv({_CONFIG_PATH: _config(userid=userid, vxlan={"enabled": True})})
        with patch("builtins.open", side_effect=env):
            cfg = omr_admin.get_vxlan_config("openmptcprouter", userid)
        assert (cfg["localip6"], cfg["remoteip6"]) == (localip6, remoteip6)
        if localip6 is not None:
            ipaddress.ip_interface(cfg["localip6"])
            ipaddress.ip_interface(cfg["remoteip6"])

    def test_default_slices_never_collide_across_userids(self):
        seen4 = set()
        for userid in range(0, 1088):
            local, _ = omr_admin._vxlan_default_v4(userid)
            net = ipaddress.ip_interface(local).network
            assert net not in seen4
            seen4.add(net)
        seen6 = set()
        for userid in range(0, 4096):
            local, _ = omr_admin._vxlan_default_v6(userid)
            net = ipaddress.ip_interface(local).network
            assert net not in seen6
            seen6.add(net)

    def test_explicit_addresses_still_win_over_defaults(self):
        env = _FileEnv({_CONFIG_PATH: _config(userid=64, vxlan={
            "enabled": True, "localip": "10.9.9.1/30", "localip6": "fd00::9:1/126"})})
        with patch("builtins.open", side_effect=env):
            cfg = omr_admin.get_vxlan_config("openmptcprouter", 64)
        assert cfg["localip"] == "10.9.9.1/30"
        assert cfg["localip6"] == "fd00::9:1/126"


# ===========================================================================
# write_vxlan_conf()
# ===========================================================================


class TestWriteVxlanConf:
    def _run(self, vxlan, isfile=False):
        env = _FileEnv({_CONFIG_PATH: _config(vxlan=vxlan)})
        with (
            patch("builtins.open", side_effect=env),
            patch("os.path.isfile", return_value=isfile),
            patch("os.makedirs"),
            patch("os.remove") as remove,
            patch("subprocess.run") as run,
        ):
            omr_admin.write_vxlan_conf("openmptcprouter", 0)
        return env, remove, run

    def test_l3_mode_writes_routed_ips_no_bridge(self):
        env, _, _ = self._run({"enabled": True, "mode": "l3", "vni": 5})
        written = env.written[_VXLAN_FILE]
        assert "MODE=l3" in written
        assert "LOCALTUNIP=" in written
        assert "LOCALTUNIP6=" in written
        assert "BRIDGE=" not in written

    def test_default_mode_behaves_like_l3(self):
        env, _, _ = self._run({"enabled": True, "vni": 5})
        written = env.written[_VXLAN_FILE]
        assert "MODE=l3" in written
        assert "LOCALTUNIP=" in written
        assert "BRIDGE=" not in written

    def test_l2_mode_writes_vni_derived_bridge_no_tunnel_ip(self):
        env, _, _ = self._run({"enabled": True, "mode": "l2", "vni": 5})
        written = env.written[_VXLAN_FILE]
        assert "MODE=l2" in written
        assert "BRIDGE=br-vxlan5" in written
        assert "LOCALTUNIP=" not in written
        assert "LOCALTUNIP6=" not in written

    def test_l2_mode_bridge_name_tracks_vni(self):
        env, _, _ = self._run({"enabled": True, "mode": "l2", "vni": 42})
        written = env.written[_VXLAN_FILE]
        assert "BRIDGE=br-vxlan42" in written

    def test_disabled_removes_existing_file(self):
        env, remove, _ = self._run({"enabled": False}, isfile=True)
        remove.assert_called_once_with(_VXLAN_FILE)
        assert _VXLAN_FILE not in env.written

    def test_missing_vpn_ips_skips_write(self):
        env = _FileEnv({
            _CONFIG_PATH: _config(vxlan={"enabled": True, "mode": "l2"}, vpnips=False)
        })
        with (
            patch("builtins.open", side_effect=env),
            patch("os.path.isfile", return_value=False),
            patch("os.makedirs"),
        ):
            omr_admin.write_vxlan_conf("openmptcprouter", 0)
        assert _VXLAN_FILE not in env.written

    def test_l3_past_derived_pools_omits_tunnel_ips_but_still_writes(self):
        env = _FileEnv({_CONFIG_PATH: _config(userid=5000, vxlan={"enabled": True, "mode": "l3"})})
        with (
            patch("builtins.open", side_effect=env),
            patch("os.path.isfile", return_value=False),
            patch("os.makedirs"),
            patch("subprocess.run"),
        ):
            omr_admin.write_vxlan_conf("openmptcprouter", 5000)
        written = env.written["/etc/openmptcprouter-vps-admin/omr-vxlan/user5000"]
        assert "MODE=l3" in written
        assert "VNI=5001" in written
        assert "LOCALTUNIP" not in written


# ===========================================================================
# POST /vxlan
# ===========================================================================


class TestVxlanEndpoint:
    _PAYLOAD = {"enable": True, "mode": "l2"}

    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/vxlan", json=self._PAYLOAD)
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/vxlan", json=self._PAYLOAD)
        assert r.json()["result"] == "permission"

    def test_success_passes_mode_through(self, user_client):
        with (
            patch("omr_admin.write_vxlan_conf"),
            patch("omr_admin.modif_config_user") as modif,
        ):
            r = user_client.post("/vxlan", json=self._PAYLOAD)
        assert r.json()["result"] == "done"
        modif.assert_called_once()
        _, changes = modif.call_args[0]
        assert changes["vxlan"]["mode"] == "l2"
        assert changes["vxlan"]["enabled"] is True

    def test_invalid_mode_falls_back_to_current(self, user_client):
        with (
            patch("omr_admin.write_vxlan_conf"),
            patch("omr_admin.modif_config_user") as modif,
        ):
            r = user_client.post("/vxlan", json={"enable": True, "mode": "bogus"})
        assert r.json()["result"] == "done"
        _, changes = modif.call_args[0]
        assert changes["vxlan"]["mode"] == "l3"

    def test_mode_omitted_keeps_current_default(self, user_client):
        with (
            patch("omr_admin.write_vxlan_conf"),
            patch("omr_admin.modif_config_user") as modif,
        ):
            r = user_client.post("/vxlan", json={"enable": True})
        assert r.json()["result"] == "done"
        _, changes = modif.call_args[0]
        assert changes["vxlan"]["mode"] == "l3"

    def test_disable_still_writes_conf(self, user_client):
        with (
            patch("omr_admin.write_vxlan_conf") as write_conf,
            patch("omr_admin.modif_config_user"),
        ):
            r = user_client.post("/vxlan", json={"enable": False})
        assert r.json()["result"] == "done"
        write_conf.assert_called_once()

    def test_non_admin_cannot_set_vni(self, user_client):
        r = user_client.post("/vxlan", json={"enable": True, "vni": 999})
        assert r.json()["result"] == "permission"

    def test_admin_can_set_own_vni(self, admin_client):
        with (
            patch("omr_admin.write_vxlan_conf"),
            patch("omr_admin.modif_config_user") as modif,
        ):
            r = admin_client.post("/vxlan", json={"enable": True, "vni": 777})
        assert r.json()["result"] == "done"
        _, changes = modif.call_args[0]
        assert changes["vxlan"]["vni"] == 777

    def test_partial_update_preserves_previously_set_vni(self, user_client):
        """A bare {enable, mode} POST (what the router actually sends) must not
        wipe an admin-assigned vni back down to the auto-derived default."""
        env = _FileEnv({
            _CONFIG_PATH: _config(vxlan={"enabled": True, "mode": "l2", "vni": 555})
        })
        with (
            patch("builtins.open", side_effect=env),
            patch("omr_admin.write_vxlan_conf"),
            patch("omr_admin.modif_config_user") as modif,
        ):
            r = user_client.post("/vxlan", json={"enable": True, "mode": "l2"})
        assert r.json()["result"] == "done"
        _, changes = modif.call_args[0]
        assert changes["vxlan"]["vni"] == 555

    def test_port_colliding_with_other_user_on_same_vni_rejected(self, user_client):
        """The kernel accepts one VXLAN device per (VNI, dstport) whatever the
        local/remote addresses, so a user may not move onto a pair another
        user already holds: their omr-vxlan@ unit would fail at ip link add."""
        env = _FileEnv({_CONFIG_PATH: _two_users(my_port=4789, other_port=4790)})
        with (
            patch("builtins.open", side_effect=env),
            patch("omr_admin.write_vxlan_conf") as write_conf,
            patch("omr_admin.modif_config_user") as modif,
        ):
            r = user_client.post("/vxlan", json={"enable": True, "port": 4790})
        assert r.json()["result"] == "conflict"
        assert "otheruser" in r.json()["reason"]
        assert "port" in r.json()["reason"]
        modif.assert_not_called()
        write_conf.assert_not_called()

    def test_port_distinct_from_other_user_on_same_vni_accepted(self, user_client):
        env = _FileEnv({_CONFIG_PATH: _two_users(my_port=4789, other_port=4790)})
        with (
            patch("builtins.open", side_effect=env),
            patch("omr_admin.write_vxlan_conf"),
            patch("omr_admin.modif_config_user") as modif,
        ):
            r = user_client.post("/vxlan", json={"enable": True, "port": 4791})
        assert r.json()["result"] == "done"
        _, changes = modif.call_args[0]
        assert changes["vxlan"]["port"] == 4791

    def test_disable_skips_pair_check(self, user_client):
        env = _FileEnv({_CONFIG_PATH: _two_users(my_port=4789, other_port=4789)})
        with (
            patch("builtins.open", side_effect=env),
            patch("omr_admin.write_vxlan_conf") as write_conf,
            patch("omr_admin.modif_config_user"),
        ):
            r = user_client.post("/vxlan", json={"enable": False})
        assert r.json()["result"] == "done"
        write_conf.assert_called_once()

    @pytest.mark.parametrize("payload", [{"port": 0}, {"port": 70000}])
    def test_out_of_range_port_rejected(self, user_client, payload):
        r = user_client.post("/vxlan", json={"enable": True, **payload})
        assert r.status_code == 422


# ===========================================================================
# GET /vxlan_vnis, POST /vxlan_user (admin-only VNI control)
# ===========================================================================


class TestVxlanVnis:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.get("/vxlan_vnis")
        assert r.status_code == 403

    def test_non_admin_denied(self, user_client):
        r = user_client.get("/vxlan_vnis")
        assert r.json()["result"] == "permission"

    def test_admin_lists_every_user_vni(self, admin_client):
        env = _FileEnv({_CONFIG_PATH: _config(vxlan={"enabled": True, "mode": "l2", "vni": 9})})
        with patch("builtins.open", side_effect=env):
            r = admin_client.get("/vxlan_vnis")
        body = r.json()
        assert body["result"] == "done"
        assert body["users"]["openmptcprouter"]["vni"] == 9
        assert body["users"]["openmptcprouter"]["mode"] == "l2"
        assert body["users"]["openmptcprouter"]["port"] == 4789


class TestVxlanUser:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/vxlan_user", json={"username": "openmptcprouter", "vni": 5})
        assert r.status_code == 403

    def test_non_admin_denied(self, user_client):
        r = user_client.post("/vxlan_user", json={"username": "openmptcprouter", "vni": 5})
        assert r.json()["result"] == "permission"

    def test_unknown_user_errors(self, admin_client):
        r = admin_client.post("/vxlan_user", json={"username": "nosuchuser", "vni": 5})
        assert r.json()["result"] == "error"

    def test_invalid_mode_errors(self, admin_client):
        r = admin_client.post("/vxlan_user", json={"username": "openmptcprouter", "mode": "bogus"})
        assert r.json()["result"] == "error"

    def test_conflicting_vni_blocked_without_force(self, admin_client):
        env = _FileEnv({
            _CONFIG_PATH: json.dumps({"users": [{
                "openmptcprouter": {"userid": 0, "username": "openmptcprouter", "vxlan": {"enabled": True, "vni": 5}},
                "otheruser": {"userid": 2, "username": "otheruser", "vxlan": {"enabled": True, "vni": 5}},
            }]})
        })
        with patch("builtins.open", side_effect=env):
            r = admin_client.post("/vxlan_user", json={"username": "openmptcprouter", "vni": 5})
        assert r.json()["result"] == "conflict"
        assert "otheruser" in r.json()["reason"]

    def test_conflicting_vni_allowed_with_force_when_ports_differ(self, admin_client):
        env = _FileEnv({_CONFIG_PATH: _two_users(my_port=4789, other_port=4790)})
        with (
            patch("builtins.open", side_effect=env),
            patch("omr_admin.write_vxlan_conf"),
        ):
            r = admin_client.post(
                "/vxlan_user",
                json={"username": "openmptcprouter", "vni": 5, "force": True},
            )
        assert r.json()["result"] == "done"

    def test_same_vni_same_port_rejected_even_with_force(self, admin_client):
        """force merges L2 segments, but it can't make the kernel accept two
        devices with the same VNI on the same dstport (EEXIST): the second
        omr-vxlan@ unit would fail at ip link add and that user would have no
        tunnel at all."""
        env = _FileEnv({_CONFIG_PATH: _two_users(my_port=4789, other_port=4789)})
        with (
            patch("builtins.open", side_effect=env),
            patch("omr_admin.write_vxlan_conf") as write_conf,
            patch("omr_admin.modif_config_user") as modif,
        ):
            r = admin_client.post(
                "/vxlan_user",
                json={"username": "openmptcprouter", "vni": 5, "force": True},
            )
        assert r.json()["result"] == "conflict"
        assert "otheruser" in r.json()["reason"]
        assert "port" in r.json()["reason"]
        modif.assert_not_called()
        write_conf.assert_not_called()

    def test_moving_port_onto_used_pair_rejected(self, admin_client):
        env = _FileEnv({_CONFIG_PATH: _two_users(my_port=4790, other_port=4789)})
        with (
            patch("builtins.open", side_effect=env),
            patch("omr_admin.write_vxlan_conf") as write_conf,
        ):
            r = admin_client.post("/vxlan_user", json={"username": "openmptcprouter", "port": 4789})
        assert r.json()["result"] == "conflict"
        write_conf.assert_not_called()

    def test_enabling_colliding_user_rejected(self, admin_client):
        env = _FileEnv({_CONFIG_PATH: _two_users(my_port=4789, other_port=4789, enabled=False)})
        with (
            patch("builtins.open", side_effect=env),
            patch("omr_admin.write_vxlan_conf") as write_conf,
        ):
            r = admin_client.post("/vxlan_user", json={"username": "openmptcprouter", "enable": True})
        assert r.json()["result"] == "conflict"
        write_conf.assert_not_called()

    def test_disabling_colliding_user_still_allowed(self, admin_client):
        """Legacy state from before the pair check: disabling removes a device
        rather than creating one, so it must go through."""
        env = _FileEnv({_CONFIG_PATH: _two_users(my_port=4789, other_port=4789)})
        with (
            patch("builtins.open", side_effect=env),
            patch("omr_admin.write_vxlan_conf") as write_conf,
        ):
            r = admin_client.post("/vxlan_user", json={"username": "openmptcprouter", "enable": False})
        body = r.json()
        assert body["result"] == "done"
        assert body["vxlan"]["enabled"] is False
        write_conf.assert_called_once_with("openmptcprouter", 0)

    def test_success_sets_port_and_keeps_vni(self, admin_client):
        env = _FileEnv({_CONFIG_PATH: _config(vxlan={"enabled": True})})
        with (
            patch("builtins.open", side_effect=env),
            patch("omr_admin.write_vxlan_conf"),
        ):
            r = admin_client.post("/vxlan_user", json={"username": "openmptcprouter", "port": 4800})
        body = r.json()
        assert body["result"] == "done"
        assert body["vxlan"]["port"] == 4800
        assert body["vxlan"]["vni"] == 1

    @pytest.mark.parametrize("payload", [{"port": 0}, {"port": 65536}, {"vni": -1}, {"vni": 16777216}])
    def test_out_of_range_ids_rejected(self, admin_client, payload):
        r = admin_client.post("/vxlan_user", json={"username": "openmptcprouter", **payload})
        assert r.status_code == 422

    def test_success_sets_vni_and_mode(self, admin_client):
        env = _FileEnv({_CONFIG_PATH: _config(vxlan={"enabled": True})})
        with (
            patch("builtins.open", side_effect=env),
            patch("omr_admin.write_vxlan_conf") as write_conf,
        ):
            r = admin_client.post(
                "/vxlan_user",
                json={"username": "openmptcprouter", "vni": 42, "mode": "l2"},
            )
        body = r.json()
        assert body["result"] == "done"
        assert body["vxlan"]["vni"] == 42
        assert body["vxlan"]["mode"] == "l2"
        write_conf.assert_called_once_with("openmptcprouter", 0)

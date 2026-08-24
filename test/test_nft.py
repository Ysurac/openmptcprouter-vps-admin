"""
Unit tests for the nftables engine that replaced Shorewall as omr-admin's
firewall enforcement mechanism (see the block above shorewall_add_port in
omradmin.py, and the plan/context in docs/api.md).

Split to match the engine's own three layers:
  - _render_*   pure functions of a plain config dict -> nft rule-body
                strings. No system access, so these are tested directly
                with hand-built dicts, no fixtures/mocking needed.
  - _nft_sync_*/_nft_ensure_*  apply a rendered script via one atomic
                `nft -f -` call (subprocess.run(..., input=script)) --
                tested here by mocking subprocess.run and asserting on the
                script text, same pattern test_dscp_sync.py uses for the
                DSCP-classify sync functions (dscp_mark chain, nft sets).

The four remaining chains (user_accept/user_dnat, gre_snat, client2client,
ct_helpers) plus the port-state read/write helpers (_fw_port_add/_del) are
exercised end-to-end through the existing endpoint tests in test_api.py
(TestShorewallOpen/Close, TestMqvpn's port-change test, TestClientToClient,
TestSipAlg, ...) -- this file covers what those don't: the exact rendered
rule text for each state shape.
"""

import io
import json
from unittest.mock import patch

from conftest import omr_admin  # noqa: F401  (fixture import side effect)


def _applied_script(run_mock):
    """The nft script text passed to a mocked `nft -f -` call."""
    return run_mock.call_args.kwargs["input"].decode()


def _config(users):
    return {"users": [users]}


def _open_config(data):
    def _open(path, mode="r", *args, **kwargs):
        if str(path) == "/etc/openmptcprouter-vps-admin/omr-admin-config.json":
            return io.StringIO(json.dumps(data))
        raise FileNotFoundError(path)
    return _open


# ===========================================================================
# _render_fw_ports
# ===========================================================================


class TestRenderFwPorts:
    def test_accept_v4_and_v6_use_meta_nfproto(self):
        config = _config({
            "openmptcprouter": {"userid": 0, "fw_ports": [
                {"name": "shadowsocks", "port": "65101", "proto": "tcp", "fwtype": "ACCEPT", "family": 4},
                {"name": "mqvpn", "port": "65443", "proto": "udp", "fwtype": "ACCEPT", "family": 6},
            ]},
        })
        accept, dnat = omr_admin._render_fw_ports(config)
        assert dnat == []
        assert len(accept) == 2
        v4 = next(l for l in accept if "shadowsocks" in l)
        assert v4.startswith("meta nfproto ipv4 tcp dport 65101 accept")
        v6 = next(l for l in accept if "mqvpn" in l)
        assert v6.startswith("meta nfproto ipv6 udp dport 65443 accept")

    def test_dnat_v4_userid0_targets_vpnremoteip(self):
        config = _config({
            "openmptcprouter": {
                "userid": 0, "vpnremoteip": "10.255.220.6",
                "fw_ports": [{"name": "http", "port": "80", "proto": "tcp", "fwtype": "DNAT", "family": 4}],
            },
        })
        _accept, dnat = omr_admin._render_fw_ports(config)
        assert len(dnat) == 1
        assert dnat[0].startswith("meta nfproto ipv4 tcp dport 80 dnat ip to 10.255.220.6")

    def test_dnat_v6_synthesizes_ula_from_userid(self):
        config = _config({
            "alice": {
                "userid": 5,
                "fw_ports": [{"name": "http", "port": "80", "proto": "tcp", "fwtype": "DNAT", "family": 6}],
            },
        })
        _accept, dnat = omr_admin._render_fw_ports(config)
        assert dnat == ['meta nfproto ipv6 tcp dport 80 dnat ip6 to fd00::a05:2 comment "OMR alice redirect http tcp"']

    def test_dnat_without_known_target_is_skipped(self):
        # No vpnremoteip yet (router hasn't announced its tunnel IP) --
        # nothing sane to redirect to, so the entry is dropped rather than
        # rendering a broken "dnat to " rule.
        config = _config({
            "openmptcprouter": {
                "userid": 0,
                "fw_ports": [{"name": "http", "port": "80", "proto": "tcp", "fwtype": "DNAT", "family": 4}],
            },
        })
        _accept, dnat = omr_admin._render_fw_ports(config)
        assert dnat == []

    def test_explicit_vpn_override_wins_over_vpnremoteip(self):
        config = _config({
            "alice": {
                "userid": 3, "vpnremoteip": "10.255.220.6",
                "fw_ports": [{
                    "name": "gre-port", "port": "443", "proto": "tcp", "fwtype": "DNAT",
                    "family": 4, "vpn": "10.255.249.2",
                }],
            },
        })
        _accept, dnat = omr_admin._render_fw_ports(config)
        assert "dnat ip to 10.255.249.2" in dnat[0]

    def test_source_dip_and_dest_ip_add_daddr_saddr_matches(self):
        config = _config({
            "openmptcprouter": {
                "userid": 0,
                "fw_ports": [{
                    "name": "multi-ip", "port": "80", "proto": "tcp", "fwtype": "ACCEPT",
                    "family": 4, "source_dip": "203.0.113.5", "dest_ip": "198.51.100.9",
                }],
            },
        })
        accept, _dnat = omr_admin._render_fw_ports(config)
        assert "ip daddr 203.0.113.5" in accept[0]
        assert "ip saddr 198.51.100.9" in accept[0]

    def test_comment_tags_include_username_and_verb(self):
        config = _config({
            "bob": {"userid": 1, "fw_ports": [
                {"name": "openvpn", "port": "1194", "proto": "udp", "fwtype": "ACCEPT", "family": 4},
            ]},
        })
        accept, _dnat = omr_admin._render_fw_ports(config)
        assert 'comment "OMR bob open openvpn udp"' in accept[0]


# ===========================================================================
# _fw_port_add / _fw_port_del
# ===========================================================================


class TestFwPortState:
    def test_add_preserves_sibling_port_for_same_service(self):
        config = _config({
            "openmptcprouter": {"fw_ports": [
                {"name": "http", "port": "80", "proto": "tcp", "fwtype": "ACCEPT", "family": 4,
                 "source_dip": "", "dest_ip": "", "vpn": "default", "comment": ""},
            ]},
        })
        with (
            patch("builtins.open", side_effect=_open_config(config)),
            patch("omr_admin.modif_config_user") as modif,
            patch("omr_admin._nft_sync_ports"),
        ):
            omr_admin._fw_port_add("openmptcprouter", "443", "tcp", "http", "ACCEPT", 4, "", "", "default", "")

        ports = modif.call_args.args[1]["fw_ports"]
        assert [p["port"] for p in ports] == ["80", "443"]

    def test_add_replaces_only_the_same_port(self):
        config = _config({
            "openmptcprouter": {"fw_ports": [
                {"name": "http", "port": "80", "proto": "tcp", "fwtype": "ACCEPT", "family": 4,
                 "source_dip": "", "dest_ip": "", "vpn": "default", "comment": "old"},
                {"name": "http", "port": "443", "proto": "tcp", "fwtype": "ACCEPT", "family": 4,
                 "source_dip": "", "dest_ip": "", "vpn": "default", "comment": ""},
            ]},
        })
        with (
            patch("builtins.open", side_effect=_open_config(config)),
            patch("omr_admin.modif_config_user") as modif,
            patch("omr_admin._nft_sync_ports"),
        ):
            omr_admin._fw_port_add("openmptcprouter", "80", "tcp", "http", "ACCEPT", 4, "", "", "default", "new")

        ports = modif.call_args.args[1]["fw_ports"]
        assert [p["port"] for p in ports] == ["443", "80"]
        assert ports[-1]["comment"] == "new"

    def test_delete_preserves_sibling_port_for_same_service(self):
        config = _config({
            "openmptcprouter": {"fw_ports": [
                {"name": "http", "port": "80", "proto": "tcp", "fwtype": "ACCEPT", "family": 4,
                 "source_dip": "", "dest_ip": "", "vpn": "default", "comment": ""},
                {"name": "http", "port": "443", "proto": "tcp", "fwtype": "ACCEPT", "family": 4,
                 "source_dip": "", "dest_ip": "", "vpn": "default", "comment": ""},
            ]},
        })
        with (
            patch("builtins.open", side_effect=_open_config(config)),
            patch("omr_admin.modif_config_user") as modif,
            patch("omr_admin._nft_sync_ports"),
        ):
            omr_admin._fw_port_del("openmptcprouter", "443", "tcp", "http", "ACCEPT", 4)

        ports = modif.call_args.args[1]["fw_ports"]
        assert [p["port"] for p in ports] == ["80"]


# ===========================================================================
# shorewall_list
# ===========================================================================


class TestShorewallListRendering:
    def test_includes_protocol_and_port(self):
        config = _config({
            "openmptcprouter": {"fw_ports": [
                {"name": "http", "port": "80", "proto": "tcp", "fwtype": "ACCEPT", "family": 4,
                 "comment": " --- web"},
            ]},
        })
        params = omr_admin.ShorewallListparams(name="open", ipproto="ipv4")
        user = omr_admin.User(username="openmptcprouter", userid=0)
        with patch("omr_admin.read_omr_config", return_value=config):
            result = omr_admin.shorewall_list(params=params, current_user=user)
        assert result["list"] == ["# OMR openmptcprouter open http port tcp 80 --- web\n"]


# ===========================================================================
# _render_bulk_redirect
# ===========================================================================


class TestRenderBulkRedirect:
    def test_disabled_by_default(self):
        config = _config({"openmptcprouter": {"userid": 0, "vpnremoteip": "10.255.220.6"}})
        assert omr_admin._render_bulk_redirect(config) == []

    def test_v4_enabled_targets_default_user(self):
        config = _config({"openmptcprouter": {"userid": 0, "vpnremoteip": "10.255.220.6"}})
        config["bulk_redirect_v4"] = True
        lines = omr_admin._render_bulk_redirect(config)
        assert len(lines) == 2
        assert any("meta nfproto ipv4 tcp dport 1-64999 dnat ip to 10.255.220.6" in l for l in lines)
        assert any("meta nfproto ipv4 udp dport 1-64999 dnat ip to 10.255.220.6" in l for l in lines)

    def test_v4_enabled_without_known_address_yields_nothing(self):
        config = _config({"openmptcprouter": {"userid": 0}})
        config["bulk_redirect_v4"] = True
        assert omr_admin._render_bulk_redirect(config) == []

    def test_v6_enabled_synthesizes_ula(self):
        config = _config({"openmptcprouter": {"userid": 0}})
        config["bulk_redirect_v6"] = True
        lines = omr_admin._render_bulk_redirect(config)
        assert any("dnat ip6 to fd00::a00:2" in l for l in lines)


# ===========================================================================
# _render_gre_snat
# ===========================================================================


class TestRenderGreSnat:
    def test_renders_both_snat_lines_per_tunnel(self):
        config = _config({
            "alice": {"gre_tunnels": {"gre-user3-ip0": {
                "public_ip": "203.0.113.5", "network": "10.255.249.0/30",
                "iface": "eth1", "local_ip": "10.255.249.1",
            }}},
        })
        lines = omr_admin._render_gre_snat(config)
        assert len(lines) == 2
        assert 'ip saddr 10.255.249.0/30 oifname "eth1" snat ip to 203.0.113.5' in lines[0]
        assert 'oifname "gre-user3-ip0" snat ip to 10.255.249.1' in lines[1]

    def test_incomplete_legacy_entry_is_skipped(self):
        # Entries created before the iface/network fields existed only have
        # local_ip/remote_ip/public_ip -- nothing to render yet rather than
        # a broken rule.
        config = _config({"alice": {"gre_tunnels": {"gre-user3-ip0": {
            "public_ip": "203.0.113.5", "local_ip": "10.255.249.1", "remote_ip": "10.255.249.2",
        }}}})
        assert omr_admin._render_gre_snat(config) == []


# ===========================================================================
# _render_client2client / _render_ct_helpers
# ===========================================================================


class TestRenderClient2Client:
    def test_disabled_is_empty(self):
        assert omr_admin._render_client2client(False) == []

    def test_enabled_matches_vpn_ifaces_both_directions(self):
        lines = omr_admin._render_client2client(True)
        assert len(lines) == 1
        assert lines[0].startswith("iifname { ")
        assert "oifname { " in lines[0]
        for pattern in omr_admin.NFT_VPN_IFACES:
            assert f'"{pattern}"' in lines[0]


class _NoCloseStringIO(io.StringIO):
    """A StringIO whose content survives the `with open(...) as n:` block
    that writes to it (that block calls .close() on exit)."""
    def close(self):
        pass


class TestSyncOpenvpnClientToClient:
    """_sync_openvpn_client2client() -- reapplies the persisted client2client
    choice to /etc/openvpn/tun0.conf's own `client-to-client` directive.

    Needed for the same reason _nft_sync_client2client() exists: the sibling
    openmptcprouter-vps repo's debian9-x86_64.sh regenerates tun0.conf from
    its shipped template on every VPS install *and* update run, silently
    dropping this line -- this is what the /client2client endpoint and
    _nft_resync_all() (at every omr-admin startup) call to put it back.
    """

    def _run(self, existing_content, enabled):
        captured = _NoCloseStringIO()
        # Mirrors what move(tmpfile, path) really does on disk: content read
        # back from `path` after the move reflects what was written to the
        # tmpfile, not the pre-edit content.
        state = {"content": existing_content}

        def _open(path, mode="r", *a, **kw):
            if "tun0.conf" in str(path):
                content = state["content"]
                return io.BytesIO(content.encode()) if "b" in mode else io.StringIO(content)
            return io.BytesIO() if "b" in mode else captured  # the mkstemp() tmpfile

        def _move(_src, _dst):
            state["content"] = captured.getvalue()

        with patch("omr_admin.os.path.isfile", return_value=True), \
             patch("builtins.open", side_effect=_open), \
             patch("omr_admin.move", side_effect=_move) as move_mock, \
             patch("subprocess.run") as run_mock:
            changed = omr_admin._sync_openvpn_client2client(enabled)
        return changed, captured.getvalue(), move_mock, run_mock

    def test_missing_file_is_a_noop(self):
        with patch("omr_admin.os.path.isfile", return_value=False), \
             patch("subprocess.run") as run_mock:
            assert omr_admin._sync_openvpn_client2client(True) is False
        run_mock.assert_not_called()

    def test_enable_appends_line_and_restarts(self):
        changed, written, move_mock, run_mock = self._run("proto tcp6-server\n", True)
        assert changed is True
        assert "client-to-client" in written
        move_mock.assert_called_once()
        run_mock.assert_called_once_with(["systemctl", "-q", "restart", "openvpn@tun0"], check=False)

    def test_disable_removes_line_and_restarts(self):
        changed, written, move_mock, run_mock = self._run("proto tcp6-server\nclient-to-client\n", False)
        assert changed is True
        assert "client-to-client" not in written
        run_mock.assert_called_once()

    def test_already_matching_state_is_idempotent(self):
        changed, written, _move_mock, run_mock = self._run("proto tcp6-server\nclient-to-client\n", True)
        assert changed is False
        run_mock.assert_not_called()


class TestRenderCtHelpers:
    def test_disabled_is_empty(self):
        assert omr_admin._render_ct_helpers(False) == []

    def test_enabled_assigns_udp_and_tcp_sip_helpers(self):
        lines = omr_admin._render_ct_helpers(True)
        assert any('udp dport 5060 ct helper set "sip_udp"' in l for l in lines)
        assert any('tcp dport 5060 ct helper set "sip_tcp"' in l for l in lines)


# ===========================================================================
# _nft_flush_chain / _nft_run -- the shared apply mechanism
# ===========================================================================


class TestNftFlushChain:
    def test_builds_one_flush_plus_one_add_per_rule(self):
        with patch("subprocess.run") as run:
            run.return_value.returncode = 0
            omr_admin._nft_flush_chain("user_accept", ["tcp dport 80 accept", "tcp dport 443 accept"])
        script = _applied_script(run)
        lines = [l for l in script.splitlines() if l]
        assert lines[0] == "flush chain inet omr user_accept"
        assert lines[1] == "add rule inet omr user_accept tcp dport 80 accept"
        assert lines[2] == "add rule inet omr user_accept tcp dport 443 accept"

    def test_empty_rule_list_still_flushes(self):
        with patch("subprocess.run") as run:
            run.return_value.returncode = 0
            omr_admin._nft_flush_chain("client2client", [])
        script = _applied_script(run)
        assert script.strip() == "flush chain inet omr client2client"


class TestNftRun:
    def test_missing_nft_binary_returns_false_without_raising(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert omr_admin._nft_run("add table inet omr") is False

    def test_nonzero_returncode_returns_false(self):
        with patch("subprocess.run") as run:
            run.return_value.returncode = 1
            run.return_value.stderr = b"Error: syntax error"
            assert omr_admin._nft_run("garbage") is False

    def test_success_returns_true(self):
        with patch("subprocess.run") as run:
            run.return_value.returncode = 0
            assert omr_admin._nft_run("add table inet omr") is True

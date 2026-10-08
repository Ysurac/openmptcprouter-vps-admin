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
from unittest.mock import MagicMock, patch

import pytest

from conftest import _mock_open, omr_admin  # noqa: F401  (fixture import side effect)


def _applied_script(run_mock):
    """The nft script text passed to a mocked `nft -f -` call."""
    return run_mock.call_args.kwargs["input"].decode()


def _config(users):
    return {"users": [users]}


def _open_config(data):
    def _open(path, mode="r", *args, **kwargs):
        if str(path) == "/etc/openmptcprouter-vps-admin/omr-admin-config.json":
            return io.StringIO(json.dumps(data))
        if str(path) == omr_admin.OMR_CONFIG_LOCK_FILE:
            return io.StringIO()
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
        assert dnat[0].startswith(omr_admin._NFT_FROM_NET + " meta nfproto ipv4 tcp dport 80 dnat ip to 10.255.220.6")

    def test_dnat_v6_synthesizes_ula_from_userid(self):
        config = _config({
            "alice": {
                "userid": 5,
                "fw_ports": [{"name": "http", "port": "80", "proto": "tcp", "fwtype": "DNAT", "family": 6}],
            },
        })
        _accept, dnat = omr_admin._render_fw_ports(config)
        assert dnat == [omr_admin._NFT_FROM_NET + ' meta nfproto ipv6 tcp dport 80 dnat ip6 to fd00::a05:2 comment "OMR alice redirect http tcp"']

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

    def test_entry_restricted_to_the_other_family_is_skipped(self):
        # A v4 literal on a v6 rule would render `meta nfproto ipv6 ip6
        # daddr 1.2.3.4`, which nft refuses -- and the chain is flushed in a
        # single transaction, so it would take every other port with it.
        config = _config({
            "openmptcprouter": {"userid": 0, "fw_ports": [
                {"name": "http", "port": "80", "proto": "tcp", "fwtype": "ACCEPT", "family": 6,
                 "source_dip": "1.2.3.4"},
                {"name": "https", "port": "443", "proto": "tcp", "fwtype": "ACCEPT", "family": 6},
            ]},
        })
        accept, _ = omr_admin._render_fw_ports(config)
        assert [l for l in accept if "dport 443" in l]
        assert not [l for l in accept if "dport 80" in l]

    def test_comment_tags_include_username_and_verb(self):
        config = _config({
            "bob": {"userid": 1, "fw_ports": [
                {"name": "openvpn", "port": "1194", "proto": "udp", "fwtype": "ACCEPT", "family": 4},
            ]},
        })
        accept, _dnat = omr_admin._render_fw_ports(config)
        assert 'comment "OMR bob open openvpn udp"' in accept[0]

    def test_invalid_stored_entries_are_skipped(self):
        # Entries stored before omr-admin validated them: a newline in the
        # port would add nft commands of its own, a DNAT on a server port
        # would send SSH/the API to the router. Only the sane entry renders.
        config = _config({
            "openmptcprouter": {"userid": 0, "vpnremoteip": "10.255.220.6", "fw_ports": [
                {"name": "evil", "port": "80 accept\nflush ruleset", "proto": "tcp", "fwtype": "ACCEPT", "family": 4},
                # GHSA-p7h3-26vj-4wg3 proof of concept, as stored by an earlier release
                {"name": "poc", "port": '22 accept comment "poc"\nadd chain inet omr OMRPOC\n#',
                 "proto": "tcp", "fwtype": "ACCEPT", "family": 4},
                {"name": "ssh", "port": "65222", "proto": "tcp", "fwtype": "DNAT", "family": 4},
                {"name": "bad", "port": "81", "proto": "tcp accept", "fwtype": "ACCEPT", "family": 4},
                {"name": "https", "port": "443", "proto": "tcp", "fwtype": "DNAT", "family": 4},
            ]},
        })
        accept, dnat = omr_admin._render_fw_ports(config)
        assert accept == []
        assert len(dnat) == 1 and "dport 443 " in dnat[0]

    def test_shorewall_colon_range_renders_as_nft_range(self):
        config = _config({
            "openmptcprouter": {"userid": 0, "fw_ports": [
                {"name": "range", "port": "1000:2000", "proto": "udp", "fwtype": "ACCEPT", "family": 4},
            ]},
        })
        accept, _dnat = omr_admin._render_fw_ports(config)
        assert accept[0].startswith("meta nfproto ipv4 udp dport 1000-2000 accept")

    def test_comment_cannot_break_out_of_the_line(self):
        config = _config({
            "bob": {"userid": 1, "fw_ports": [
                {"name": 'x\nflush ruleset\\"', "port": "80", "proto": "tcp", "fwtype": "ACCEPT", "family": 4},
            ]},
        })
        accept, _dnat = omr_admin._render_fw_ports(config)
        assert len(accept) == 1
        assert "\n" not in accept[0] and "\\" not in accept[0]
        assert accept[0].endswith('comment "OMR bob open x flush ruleset \' tcp"')


# ===========================================================================
# _fw_entry_error
# ===========================================================================


class TestFwEntryError:
    def test_valid_entries(self):
        for port in ("80", "1", "2-64999", "1000:2000", "65535"):
            assert omr_admin._fw_entry_error(port, "tcp", "ACCEPT") is None
        assert omr_admin._fw_entry_error("64999", "udp", "DNAT") is None
        assert omr_admin._fw_entry_error("80", "tcp", "DNAT", "203.0.113.5", "2001:db8::/32") is None

    def test_invalid_port(self):
        for port in ("", "0", "65536", "abc", "80,443", "90-80", "80\n", "80 accept", "-1"):
            assert omr_admin._fw_entry_error(port, "tcp", "ACCEPT") == "Invalid port", port

    def test_dnat_refused_from_65000(self):
        for port in ("65000", "65222", "65500", "2-65000", "64000:65535"):
            assert "65000" in omr_admin._fw_entry_error(port, "tcp", "DNAT"), port
        # opening them stays allowed: that is how the services are opened
        assert omr_admin._fw_entry_error("65222", "tcp", "ACCEPT") is None

    def test_invalid_proto(self):
        for proto in ("", "all", "tcp udp", "icmp", "tcp\n"):
            assert omr_admin._fw_entry_error("80", proto, "ACCEPT") == "Invalid protocol", proto

    def test_invalid_address(self):
        for addr in ("eth0", "1.2.3.4 5.6.7.8", "!1.2.3.4", "1.2.3.4\nflush ruleset",
                     # ipaddress takes an IPv6 scope ID, and anything after '%'
                     "fe80::1%eth0", "fe80::1%x\nflush ruleset"):
            assert omr_admin._fw_entry_error("80", "tcp", "ACCEPT", addr, "") == "Invalid address", addr
            assert omr_admin._fw_entry_error("80", "tcp", "ACCEPT", "", addr) == "Invalid address", addr


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

    def test_add_ignores_unsupported_fwtype(self):
        # Routers push fwtype "REDIRECT" for a traffic rule saved without a
        # target; the Shorewall implementation wrote nothing for it and so
        # must we -- no config rewrite, no chain resync.
        config = _config({"openmptcprouter": {"fw_ports": []}})
        with (
            patch("builtins.open", side_effect=_open_config(config)),
            patch("omr_admin.modif_config_user") as modif,
            patch("omr_admin._nft_sync_ports") as sync,
        ):
            omr_admin._fw_port_add("openmptcprouter", "21", "tcp", "router 21", "REDIRECT", 4, "", "", "default", "")
        assert not modif.called
        assert not sync.called

    def test_add_refuses_dnat_of_a_server_port(self):
        config = _config({"openmptcprouter": {"fw_ports": []}})
        with (
            patch("builtins.open", side_effect=_open_config(config)),
            patch("omr_admin.modif_config_user") as modif,
            patch("omr_admin._nft_sync_ports") as sync,
        ):
            omr_admin._fw_port_add("openmptcprouter", "65222", "tcp", "router 65222", "DNAT", 4, "", "", "default", "")
        assert not modif.called
        assert not sync.called

    def test_add_prunes_legacy_unsupported_entries(self):
        config = _config({
            "openmptcprouter": {"fw_ports": [
                {"name": "router 21", "port": "21", "proto": "tcp", "fwtype": "REDIRECT", "family": 4,
                 "source_dip": "", "dest_ip": "", "vpn": "default", "comment": ""},
                {"name": "router 21", "port": "21", "proto": "tcp", "fwtype": "DNAT", "family": 4,
                 "source_dip": "", "dest_ip": "", "vpn": "default", "comment": ""},
            ]},
        })
        with (
            patch("builtins.open", side_effect=_open_config(config)),
            patch("omr_admin.modif_config_user") as modif,
            patch("omr_admin._nft_sync_ports"),
        ):
            omr_admin._fw_port_add("openmptcprouter", "443", "tcp", "router 443", "DNAT", 4, "", "", "default", "")
        ports = modif.call_args.args[1]["fw_ports"]
        assert [(p["port"], p["fwtype"]) for p in ports] == [("21", "DNAT"), ("443", "DNAT")]

    def test_add_identical_entry_is_a_noop(self):
        existing = {"name": "router 21", "port": "21", "proto": "tcp", "fwtype": "DNAT", "family": 4,
                    "source_dip": "", "dest_ip": "", "vpn": "default", "comment": ""}
        config = _config({"openmptcprouter": {"fw_ports": [existing]}})
        with (
            patch("builtins.open", side_effect=_open_config(config)),
            patch("omr_admin.modif_config_user") as modif,
            patch("omr_admin._nft_sync_ports") as sync,
        ):
            omr_admin._fw_port_add("openmptcprouter", "21", "tcp", "router 21", "DNAT", 4, "", "", "default", "")
        assert not modif.called
        assert not sync.called

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
    """/shorewalllist (and /firewalllist) must keep returning the Shorewall-era
    rules-file line layout: the router's openmptcprouter-vps init script
    greps "<port>\t# OMR <user> redirect router <port> port <proto>" to know a
    port is already handled and awk-splits the columns to decide what to
    close. A free-form summary line made it re-open every port on every pass
    and never close removed ones."""

    @staticmethod
    def _list(config, name, ipproto="ipv4"):
        params = omr_admin.ShorewallListparams(name=name, ipproto=ipproto)
        user = omr_admin.User(username="openmptcprouter", userid=0)
        with patch("omr_admin.read_omr_config", return_value=config):
            return omr_admin.shorewall_list(params=params, current_user=user)["list"]

    def test_accept_line_uses_legacy_shorewall_layout(self):
        config = _config({
            "openmptcprouter": {"fw_ports": [
                {"name": "http", "port": "80", "proto": "tcp", "fwtype": "ACCEPT", "family": 4,
                 "comment": " --- web"},
            ]},
        })
        assert self._list(config, "open") == [
            "ACCEPT\t\tnet\t\t$FW\t\ttcp\t80\t# OMR openmptcprouter open http port tcp --- web\n"
        ]

    def test_dnat_line_matches_router_side_grep(self):
        config = _config({
            "openmptcprouter": {"fw_ports": [
                {"name": "router 21", "port": "21", "proto": "tcp", "fwtype": "DNAT", "family": 4,
                 "source_dip": "", "dest_ip": "", "vpn": "default", "comment": ""},
            ]},
        })
        lines = self._list(config, "redirect router")
        assert lines == ["DNAT\t\tnet\t\tvpn:$OMR_ADDR\ttcp\t21\t# OMR openmptcprouter redirect router 21 port tcp\n"]
        # exact substring _vps_firewall_redirect_port greps for
        assert "21\t# OMR openmptcprouter redirect router 21 port tcp" in lines[0]
        # awk columns _vps_firewall_close_port reads: $1 type, $4 proto, $5 port, $6 "#" (no ORIGDEST column)
        cols = lines[0].split()
        assert (cols[0], cols[3], cols[4], cols[5]) == ("DNAT", "tcp", "21", "#")

    def test_origdest_and_source_host_columns(self):
        config = _config({
            "openmptcprouter": {"fw_ports": [
                {"name": "router 8080", "port": "8080", "proto": "tcp", "fwtype": "DNAT", "family": 4,
                 "source_dip": "1.2.3.4", "dest_ip": "5.6.7.8", "vpn": "10.255.250.2", "comment": ""},
            ]},
        })
        lines = self._list(config, "redirect router")
        assert lines == [
            "DNAT\t\tnet:5.6.7.8\t\tvpn:10.255.250.2\ttcp\t8080\t-\t1.2.3.4\t"
            "# OMR openmptcprouter redirect router 8080 port tcp to 1.2.3.4 from 5.6.7.8\n"
        ]
        cols = lines[0].split()
        assert (cols[1], cols[5], cols[6]) == ("net:5.6.7.8", "-", "1.2.3.4")

    def test_name_filter_and_family_filter(self):
        config = _config({
            "openmptcprouter": {"fw_ports": [
                {"name": "router 21", "port": "21", "proto": "tcp", "fwtype": "DNAT", "family": 4},
                {"name": "router 22", "port": "22", "proto": "tcp", "fwtype": "ACCEPT", "family": 4},
                {"name": "shadowsocks", "port": "65101", "proto": "tcp", "fwtype": "DNAT", "family": 4},
                {"name": "router 23", "port": "23", "proto": "tcp", "fwtype": "DNAT", "family": 6},
                {"name": "router 21", "port": "21", "proto": "udp", "fwtype": "REDIRECT", "family": 4},
            ]},
        })
        redirect = self._list(config, "redirect router")
        assert [l.split()[4] for l in redirect] == ["21"]
        assert self._list(config, "open router")[0].split()[4] == "22"
        assert [l.split()[4] for l in self._list(config, "redirect router", "ipv6")] == ["23"]
        # unsupported fwtype (a rule pushed without target) is never listed
        assert all("udp" not in l for l in redirect)

    def test_family_any_lists_both_families_without_duplicates(self):
        # LuCI's "Restrict to address family = IPv4 and IPv6" sends
        # ipproto='any'; the legacy line layout has no family column, so a
        # port opened for both families must still appear once or the router
        # would close it on the line it did not match.
        config = _config({
            "openmptcprouter": {"fw_ports": [
                {"name": "router 21", "port": "21", "proto": "tcp", "fwtype": "DNAT", "family": 4},
                {"name": "router 21", "port": "21", "proto": "tcp", "fwtype": "DNAT", "family": 6},
                {"name": "router 23", "port": "23", "proto": "tcp", "fwtype": "DNAT", "family": 6},
            ]},
        })
        assert [l.split()[4] for l in self._list(config, "redirect router", "any")] == ["21", "23"]


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


class TestRenderGreForward:
    def test_tunnel_reaches_its_interface_and_dnat_comes_back(self):
        config = _config({"alice": {"gre_tunnels": {"gre-user3-ip0": {
            "public_ip": "203.0.113.5", "network": "10.255.249.0/30",
            "iface": "eth1", "local_ip": "10.255.249.1",
        }}}})
        lines = omr_admin._render_gre_forward(config)
        assert len(lines) == 2
        assert lines[0].startswith('iifname "gre-user3-ip0" oifname "eth1" accept')
        assert lines[1].startswith('meta nfproto ipv4 iifname "eth1" oifname "gre-user3-ip0" ct status dnat accept')

    def test_entry_without_iface_is_skipped(self):
        config = _config({"alice": {"gre_tunnels": {"gre-user3-ip0": {
            "public_ip": "203.0.113.5", "local_ip": "10.255.249.1",
        }}}})
        assert omr_admin._render_gre_forward(config) == []

    def test_iface_name_that_is_not_one_is_skipped(self):
        config = _config({"alice": {"gre_tunnels": {"gre-user3-ip0": {
            "public_ip": "203.0.113.5", "iface": 'eth1" accept; drop "',
        }}}})
        assert omr_admin._render_gre_forward(config) == []

    def test_sync_creates_and_fills_gre_forward(self):
        config = _config({"alice": {"gre_tunnels": {"gre-user3-ip0": {
            "public_ip": "203.0.113.5", "network": "10.255.249.0/30",
            "iface": "eth1", "local_ip": "10.255.249.1",
        }}}})
        with patch("omr_admin.read_omr_config", return_value=config), \
             patch("omr_admin._nft_flush_chain", return_value=True) as flush, \
             patch("omr_admin._nft_run", return_value=True) as run:
            assert omr_admin._nft_sync_gre_snat() is True
        flush.assert_called_once()
        assert flush.call_args.args[0] == "gre_snat"
        script = run.call_args.args[0]
        # created first: a VPS whose omr.nft predates the chain has none
        assert script.index("add chain inet omr gre_forward") < script.index("flush chain inet omr gre_forward")
        assert 'add rule inet omr gre_forward iifname "gre-user3-ip0" oifname "eth1" accept' in script


# ===========================================================================
# _proxy_gre_user_sync
# ===========================================================================


class TestXrayGreUserSync:
    @staticmethod
    def _data():
        return {
            "inbounds": [
                {"tag": "omrin-tunnel", "settings": {"clients": []}},
                {"tag": "omrin-vless-reality", "settings": {"clients": [{"id": "main", "flow": "xtls-rprx-vision"}]}},
            ],
            "routing": {"rules": [
                # what xray_add_routing wrote before: VLESS only
                {"type": "field", "inboundTag": "omrin-tunnel", "user": "omrgre-user0-ip1", "outboundTag": "output-203.0.113.5"},
                {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
            ]},
        }

    def test_rule_covers_every_tunnel_inbound_and_reality_gets_the_user(self):
        data = self._data()
        assert omr_admin._proxy_gre_user_sync(data, "omrgre-user0-ip1", "uuid-1", "output-203.0.113.5") is True
        rules = [r for r in data["routing"]["rules"] if r["outboundTag"] == "output-203.0.113.5"]
        assert rules == [{"type": "field", "inboundTag": list(omr_admin.XRAY_TUNNEL_INBOUNDS),
                          "user": ["omrgre-user0-ip1"], "outboundTag": "output-203.0.113.5"}]
        assert "omrin-shadowsocks-tunnel" in rules[0]["inboundTag"]
        reality = data["inbounds"][1]["settings"]["clients"]
        assert {"id": "uuid-1", "flow": "xtls-rprx-vision", "email": "omrgre-user0-ip1"} in reality
        assert {"id": "main", "flow": "xtls-rprx-vision"} in reality
        assert {"type": "field", "inboundTag": ["api"], "outboundTag": "api"} in data["routing"]["rules"]

    def test_second_run_changes_nothing(self):
        data = self._data()
        omr_admin._proxy_gre_user_sync(data, "omrgre-user0-ip1", "uuid-1", "output-203.0.113.5")
        assert omr_admin._proxy_gre_user_sync(data, "omrgre-user0-ip1", "uuid-1", "output-203.0.113.5") is False

    def test_new_uuid_replaces_the_reality_client(self):
        data = self._data()
        omr_admin._proxy_gre_user_sync(data, "omrgre-user0-ip1", "uuid-1", "output-203.0.113.5")
        assert omr_admin._proxy_gre_user_sync(data, "omrgre-user0-ip1", "uuid-2", "output-203.0.113.5") is True
        ids = [c["id"] for c in data["inbounds"][1]["settings"]["clients"] if c.get("email") == "omrgre-user0-ip1"]
        assert ids == ["uuid-2"]

    def test_reality_client_dropped_with_the_user(self):
        data = self._data()
        omr_admin._proxy_gre_user_sync(data, "omrgre-user0-ip1", "uuid-1", "output-203.0.113.5")
        assert omr_admin._xray_drop_reality_client(data, "omrgre-user0-ip1") is True
        assert data["inbounds"][1]["settings"]["clients"] == [{"id": "main", "flow": "xtls-rprx-vision"}]
        assert omr_admin._xray_drop_reality_client(data, "omrgre-user0-ip1") is False


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
        # The file is replaced atomically, which the test mocks turn into
        # open(path, 'w'): content read back from `path` afterwards is what
        # was written, not the pre-edit content.
        state = {"content": existing_content, "writes": 0}

        class _Replacing(io.StringIO):
            def close(self):
                state["content"] = self.getvalue()
                state["writes"] += 1
                super().close()

        def _open(path, mode="r", *a, **kw):
            if "tun0.conf" in str(path):
                if "w" in mode:
                    return _Replacing()
                content = state["content"]
                return io.BytesIO(content.encode()) if "b" in mode else io.StringIO(content)
            return _mock_open(path, mode, *a, **kw)

        with patch("omr_admin.os.path.isfile", return_value=True), \
             patch("builtins.open", side_effect=_open), \
             patch("subprocess.run") as run_mock:
            changed = omr_admin._sync_openvpn_client2client(enabled)
        return changed, state["content"], state["writes"], run_mock

    def test_missing_file_is_a_noop(self):
        with patch("omr_admin.os.path.isfile", return_value=False), \
             patch("subprocess.run") as run_mock:
            assert omr_admin._sync_openvpn_client2client(True) is False
        run_mock.assert_not_called()

    def test_enable_appends_line_and_restarts(self):
        changed, written, writes, run_mock = self._run("proto tcp6-server\n", True)
        assert changed is True
        assert "client-to-client" in written
        assert writes == 1
        run_mock.assert_called_once_with(["systemctl", "-q", "restart", "openvpn@tun0"], check=False)

    def test_disable_removes_line_and_restarts(self):
        changed, written, _writes, run_mock = self._run("proto tcp6-server\nclient-to-client\n", False)
        assert changed is True
        assert "client-to-client" not in written
        run_mock.assert_called_once()

    def test_already_matching_state_is_idempotent(self):
        changed, written, _writes, run_mock = self._run("proto tcp6-server\nclient-to-client\n", True)
        assert changed is False
        run_mock.assert_not_called()


class TestRenderCtHelpers:
    def test_disabled_is_empty(self):
        assert omr_admin._render_ct_helpers(False) == []

    def test_enabled_assigns_udp_and_tcp_sip_helpers(self):
        lines = omr_admin._render_ct_helpers(True)
        assert any('udp dport 5060 ct helper set "sip_udp"' in l for l in lines)
        assert any('tcp dport 5060 ct helper set "sip_tcp"' in l for l in lines)


class TestSyncSipAlg:
    def test_disable_only_flushes_the_chain(self):
        # Disable must not modprobe or `add ct helper`: on the shipped
        # default (nf_conntrack_sip blacklisted, SIP ALG off) those can only
        # fail, and the router re-POSTs /sipalg every sync cycle -- the
        # recurring journal errors of openmptcprouter#4361.
        with patch("subprocess.run") as run:
            run.return_value.returncode = 0
            assert omr_admin._nft_sync_sipalg(False) is True
        assert run.call_count == 1
        assert _applied_script(run).strip() == "flush chain inet omr ct_helpers"

    def test_enable_modprobes_then_creates_helpers_and_rules(self):
        with patch("subprocess.run") as run:
            run.return_value.returncode = 0
            assert omr_admin._nft_sync_sipalg(True) is True
        calls = run.call_args_list
        # a modprobe blacklist only blocks alias autoloading, so the module
        # must be loaded explicitly before the helper objects are created
        assert calls[0].args[0] == ["modprobe", "nf_conntrack_sip"]
        # and its NAT half, which nothing autoloads
        assert calls[1].args[0] == ["modprobe", "nf_nat_sip"]
        helper_script = calls[2].kwargs["input"].decode()
        assert 'add ct helper inet omr sip_udp { type "sip" protocol udp; }' in helper_script
        assert 'add ct helper inet omr sip_tcp { type "sip" protocol tcp; }' in helper_script
        chain_script = calls[3].kwargs["input"].decode()
        assert chain_script.splitlines()[0] == "flush chain inet omr ct_helpers"
        assert 'ct helper set "sip_udp"' in chain_script
        assert 'ct helper set "sip_tcp"' in chain_script

    def test_enable_returns_false_when_nft_rejects_the_rules(self):
        # e.g. the module really is unavailable: the helper objects were
        # never created, so the rule batch referencing them fails
        def _run(cmd, **kwargs):
            result = MagicMock()
            result.returncode = 1 if cmd[0] == omr_admin.NFT_BIN else 0
            result.stderr = b"Error: Could not process rule: No such file or directory"
            return result
        with patch("subprocess.run", side_effect=_run):
            assert omr_admin._nft_sync_sipalg(True) is False

    def test_enable_goes_on_without_nf_nat_sip(self):
        # nf_nat_sip missing: the helper still tracks calls, it just can't
        # rewrite them, so warn and assign it anyway
        def _run(cmd, **kwargs):
            result = MagicMock()
            result.returncode = 1 if cmd == ["modprobe", "nf_nat_sip"] else 0
            result.stderr = b"modprobe: FATAL: Module nf_nat_sip not found"
            return result
        with patch("subprocess.run", side_effect=_run) as run, \
             patch.object(omr_admin.LOG, "warning") as warning:
            assert omr_admin._nft_sync_sipalg(True) is True
        assert run.call_count == 4
        assert "nf_nat_sip" in warning.call_args.args[-1]

    def test_enable_stops_when_modprobe_fails(self):
        # omr-admin.service without CAP_SYS_MODULE: modprobe gets EPERM. Report
        # that, rather than running nft batches that can only fail with ENOENT
        def _run(cmd, **kwargs):
            result = MagicMock()
            result.returncode = 1 if cmd[0] == "modprobe" else 0
            result.stderr = b"modprobe: ERROR: could not insert 'nf_conntrack_sip': Operation not permitted"
            return result
        with patch("subprocess.run", side_effect=_run) as run, \
             patch.object(omr_admin.LOG, "warning") as warning:
            assert omr_admin._nft_sync_sipalg(True) is False
        assert [c.args[0][0] for c in run.call_args_list] == ["modprobe"]
        assert "Operation not permitted" in warning.call_args.args[-1]


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


# ===========================================================================
# missing base ruleset (the `inet omr` table from openmptcprouter-vps's
# nftables/omr.nft) -- expected transient, must stay quiet
# ===========================================================================


def _nft_run_mock(apply_rc, table_rc, stderr=b""):
    """Mock subprocess.run distinguishing the `nft -f -` apply from the
    `nft list table inet omr` probe _nft_run() falls back on."""
    def _run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = table_rc if 'list' in cmd else apply_rc
        result.stderr = stderr
        return result
    return _run


class TestNftMissingBaseTable:
    """During a VPS install/update our own deb (re)starts omr-admin before
    the new base ruleset is loaded, so every apply fails with ENOENT until
    nftables.service's omr-admin-resync drop-in restarts us. That pass is
    what lands the state; this one must not fill the journal with errors it
    can do nothing about (openmptcprouter#4361 territory)."""

    _ENOENT = b"/dev/stdin:1:18-20: Error: Could not process rule: No such file or directory"

    def test_table_probe_decides_between_warning_and_debug(self):
        with patch("subprocess.run", side_effect=_nft_run_mock(1, 1, self._ENOENT)), \
             patch("omr_admin.LOG") as log:
            assert omr_admin._nft_run("flush chain inet omr user_accept") is False
        log.warning.assert_not_called()
        log.debug.assert_called_once()

    def test_real_failure_with_table_present_still_warns(self):
        with patch("subprocess.run", side_effect=_nft_run_mock(1, 0, b"Error: syntax error")), \
             patch("omr_admin.LOG") as log:
            assert omr_admin._nft_run("garbage") is False
        log.warning.assert_called_once()

    def test_successful_apply_never_probes_the_table(self):
        with patch("subprocess.run", side_effect=_nft_run_mock(0, 0)) as run:
            assert omr_admin._nft_run("flush chain inet omr user_accept") is True
        assert all('list' not in c.args[0] for c in run.call_args_list)

    def test_resync_all_skips_nft_work_but_still_syncs_openvpn(self):
        with patch("omr_admin._nft_base_table_exists", return_value=False), \
             patch("omr_admin.read_omr_config", return_value={"client2client": True}), \
             patch("omr_admin._nft_sync_ports") as ports, \
             patch("omr_admin._nft_sync_gre_snat") as gre, \
             patch("omr_admin._nft_sync_client2client") as c2c, \
             patch("omr_admin._nft_resync_dscp_classify") as dscp, \
             patch("omr_admin._nft_sync_sipalg") as sipalg, \
             patch("omr_admin._sync_openvpn_client2client") as openvpn:
            omr_admin._nft_resync_all()
        for mock in (ports, gre, c2c, dscp, sipalg):
            mock.assert_not_called()
        openvpn.assert_called_once_with(True)

    def test_resync_all_runs_everything_with_the_table_present(self):
        with patch("omr_admin._nft_base_table_exists", return_value=True), \
             patch("omr_admin.read_omr_config", return_value={"sipalg": True}), \
             patch("omr_admin._nft_sync_ports") as ports, \
             patch("omr_admin._nft_sync_gre_snat") as gre, \
             patch("omr_admin._nft_sync_client2client") as c2c, \
             patch("omr_admin._nft_resync_dscp_classify") as dscp, \
             patch("omr_admin._nft_sync_sipalg") as sipalg, \
             patch("omr_admin._sync_openvpn_client2client") as openvpn:
            omr_admin._nft_resync_all()
        for mock in (ports, gre, c2c, dscp):
            mock.assert_called_once()
        sipalg.assert_called_once_with(True)
        openvpn.assert_called_once_with(False)


class TestNftErrorSummary:
    def test_repeated_identical_errors_collapse_with_a_count(self):
        stderr = "".join(
            f"/dev/stdin:{i}:14-16: Error: No such file or directory\n"
            f"add set inet omr omr_dscp_classify_cs{i}_4 {{ type ipv4_addr; }}\n"
            "             ^^^\n"
            for i in range(1, 11)
        )
        summary = omr_admin._nft_error_summary(stderr)
        assert summary == "Error: No such file or directory (x10)"
        assert "\n" not in summary

    def test_distinct_errors_are_all_kept_on_one_line(self):
        stderr = ("/dev/stdin:1:1-3: Error: syntax error, unexpected junk\n"
                  "/dev/stdin:2:1-3: Error: No such file or directory\n")
        summary = omr_admin._nft_error_summary(stderr)
        assert summary == ("Error: syntax error, unexpected junk; "
                           "Error: No such file or directory")

    def test_unprefixed_stderr_is_passed_through(self):
        assert omr_admin._nft_error_summary("Error: syntax error") == "Error: syntax error"

    def test_empty_stderr_never_logs_a_blank_message(self):
        assert omr_admin._nft_error_summary("") == "unknown error"


# ===========================================================================
# What one user's entry can do to the single user_accept/user_dnat flush
# ===========================================================================


class TestRenderHardening:
    def test_userid_stored_as_a_string_renders(self):
        # /add_user stores "userid": str(userid); '{:x}' refused it, which
        # failed every sync of every user, and omr-admin's startup.
        config = _config({"alice": {"userid": "5", "fw_ports": [
            {"name": "http", "port": "80", "proto": "tcp", "fwtype": "DNAT", "family": 6}]}})
        _accept, dnat = omr_admin._render_fw_ports(config)
        assert len(dnat) == 1 and "dnat ip6 to fd00::a05:2" in dnat[0]

    def test_userid_without_an_ipv6_tunnel_address_is_skipped(self):
        config = _config({"alice": {"userid": 256, "vpnremoteip": "10.255.220.6", "fw_ports": [
            {"name": "http", "port": "80", "proto": "tcp", "fwtype": "DNAT", "family": 6},
            {"name": "http", "port": "80", "proto": "tcp", "fwtype": "DNAT", "family": 4}]}})
        _accept, dnat = omr_admin._render_fw_ports(config)
        assert len(dnat) == 1 and "dnat ip to 10.255.220.6" in dnat[0]

    def test_bulk_v6_with_a_string_userid(self):
        config = _config({"openmptcprouter": {"userid": "0"}})
        config["bulk_redirect_v6"] = True
        assert any("dnat ip6 to fd00::a00:2" in l for l in omr_admin._render_bulk_redirect(config))

    def test_redirects_only_what_comes_from_the_internet(self):
        # nat_prerouting sees the tunnels too: a redirect of udp/53 took the
        # DNS of every other router.
        config = _config({"openmptcprouter": {"userid": 0, "vpnremoteip": "10.255.220.6", "fw_ports": [
            {"name": "dns", "port": "53", "proto": "udp", "fwtype": "DNAT", "family": 4},
            {"name": "web", "port": "80", "proto": "tcp", "fwtype": "ACCEPT", "family": 4}]}})
        config["bulk_redirect_v4"] = True
        accept, dnat = omr_admin._render_fw_ports(config)
        dnat += omr_admin._render_bulk_redirect(config)
        assert dnat and all(l.startswith(omr_admin._NFT_FROM_NET + " ") for l in dnat)
        assert not accept[0].startswith("iifname")
        for iface in omr_admin.NFT_VPN_IFACES + ("client-wg*",):
            assert f'"{iface}"' in omr_admin._NFT_FROM_NET

    def test_invalid_redirect_target_is_skipped(self):
        for target in ("10.255.220.6/8", "10.255.220.6 accept", "fd00::1"):
            config = _config({"openmptcprouter": {"userid": 0, "vpnremoteip": target, "fw_ports": [
                {"name": "http", "port": "80", "proto": "tcp", "fwtype": "DNAT", "family": 4}]}})
            assert omr_admin._render_fw_ports(config) == ([], []), target

    def test_entry_failing_to_render_skips_only_itself(self):
        config = _config({
            "alice": {"userid": 3, "fw_ports": [{"name": "a", "port": "80", "proto": "tcp", "fwtype": "ACCEPT", "family": 4}]},
            "bob": {"userid": 4, "fw_ports": [{"name": "b", "port": "81", "proto": "tcp", "fwtype": "ACCEPT", "family": 4}]},
        })
        real = omr_admin._render_fw_entry

        def flaky(username, udata, entry, exclude=()):
            if username == "alice":
                raise ValueError("boom")
            return real(username, udata, entry, exclude)

        with patch("omr_admin._render_fw_entry", side_effect=flaky):
            accept, _dnat = omr_admin._render_fw_ports(config)
        assert len(accept) == 1 and "dport 81" in accept[0]

    def test_comment_is_printable_ascii_of_128_bytes_at_most(self):
        # nft counts bytes (120 x "é" is 240) and a lone surrogate from the
        # JSON body made script.encode() raise.
        for text in ("é" * 120, "\ud800 x", "a\nb\"c\\d" + "z" * 300):
            comment = omr_admin._nft_comment(text)
            encoded = comment.encode("ascii")
            assert len(encoded) <= 128 and '"' not in comment and "\\" not in comment and "\n" not in comment

    def test_script_with_a_surrogate_does_not_raise(self):
        with patch("subprocess.run", return_value=MagicMock(returncode=0)) as run:
            assert omr_admin._nft_run('add rule inet omr user_accept accept comment "\ud800"\n')
        assert run.called

    def test_netmask_forms_and_leading_zeros_refused(self):
        # ipaddress takes them, nft does not (or reads /024 as octal).
        for addr in ("1.2.3.4/255.255.255.0", "1.2.3.4/0.0.0.255", "1.2.3.0/024", "10.0.0.0/08", "::/0128"):
            assert omr_admin._fw_entry_error("80", "tcp", "ACCEPT", addr) == "Invalid address", addr
        for addr in ("1.2.3.0/24", "1.2.3.4", "2001:db8::/32", "0.0.0.0/0", "::ffff:1.2.3.4"):
            assert omr_admin._fw_entry_error("80", "tcp", "ACCEPT", addr) is None, addr



class TestXrayGreSyncAll:
    @staticmethod
    def _run(data, users):
        written = {}
        with patch("os.path.isfile", return_value=True), \
             patch("omr_admin.file_as_bytes", return_value=b"x"), \
             patch("builtins.open", side_effect=lambda *a, **k: io.StringIO(json.dumps(data))), \
             patch("omr_admin._atomic_write_json", side_effect=lambda p, d: written.update(data=d)):
            omr_admin._proxy_gre_sync_all("xray", users, "md5")
        return written.get("data")

    def test_rule_and_outbound_of_a_removed_user_dropped(self):
        data = {"outbounds": [{"tag": "direct"}, {"protocol": "freedom", "settings": {"userLevel": 0},
                                                  "tag": "output-203.0.113.9", "sendThrough": "203.0.113.9"}],
                "routing": {"rules": [
                    {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
                    {"type": "field", "inboundTag": list(omr_admin.XRAY_TUNNEL_INBOUNDS),
                     "user": ["gretestgre-user3-ip0"], "outboundTag": "output-203.0.113.9"},
                    # not one of the GRE tunnels': left alone
                    {"type": "field", "user": ["alice"], "outboundTag": "output-198.51.100.7"},
                ]}}
        new = self._run(data, {"openmptcprouter": {"userid": 0}})
        assert [r["outboundTag"] for r in new["routing"]["rules"]] == ["api", "output-198.51.100.7"]
        assert [o["tag"] for o in new["outbounds"]] == ["direct"]

    def test_tunnel_of_a_user_kept(self):
        users = {"openmptcprouter": {"userid": 0, "gre_tunnels": {"gre-user0-ip1": {
            "public_ip": "203.0.113.9", "xray": {"uuid": "u1"}}}}}
        data = {"outbounds": [], "routing": {"rules": []}}
        new = self._run(data, users)
        assert [o["tag"] for o in new["outbounds"]] == ["output-203.0.113.9"]
        assert new["routing"]["rules"][0]["user"] == ["openmptcproutergre-user0-ip1"]
        assert self._run(new, users) is None   # nothing more to change


class TestProxyGreRulePlacement:
    @staticmethod
    def _data():
        return {"inbounds": [], "routing": {"rules": [
            {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
            {"type": "field", "inboundTag": ["omrin-tunnel"], "ip": ["127.0.0.0/8"], "outboundTag": "blocked"},
            {"type": "field", "inboundTag": ["omrin-tunnel"], "domain": ["domain:localhost"], "outboundTag": "blocked"},
        ]}}

    def test_after_the_blocked_rules(self):
        # first, it reached the VPS's own localhost services through the proxy
        data = self._data()
        omr_admin._proxy_gre_user_sync(data, "openmptcproutergre-user0-ip1", "u1", "output-203.0.113.5")
        assert data["routing"]["rules"][-1]["user"] == ["openmptcproutergre-user0-ip1"]

    def test_rule_of_an_earlier_release_moved_after_them(self):
        data = self._data()
        data["routing"]["rules"].insert(0, {"type": "field", "inboundTag": list(omr_admin.XRAY_TUNNEL_INBOUNDS),
                                            "user": ["openmptcproutergre-user0-ip1"], "outboundTag": "output-203.0.113.5"})
        assert omr_admin._proxy_gre_user_sync(data, "openmptcproutergre-user0-ip1", "u1", "output-203.0.113.5") is True
        assert [r["outboundTag"] for r in data["routing"]["rules"]] == ["api", "blocked", "blocked", "output-203.0.113.5"]

    def test_stable_with_several_users(self):
        data = self._data()
        for _ in range(2):
            omr_admin._proxy_gre_user_sync(data, "a-gre-user0-ip0", "u1", "output-203.0.113.5")
            omr_admin._proxy_gre_user_sync(data, "b-gre-user3-ip0", "u3", "output-203.0.113.5")
        assert omr_admin._proxy_gre_user_sync(data, "a-gre-user0-ip0", "u1", "output-203.0.113.5") is False
        assert omr_admin._proxy_gre_user_sync(data, "b-gre-user3-ip0", "u3", "output-203.0.113.5") is False

    def test_v2ray_tunnel_inbounds(self):
        data = self._data()
        omr_admin._proxy_gre_user_sync(data, "openmptcproutergre-user0-ip1", "u1", "output-203.0.113.5",
                                       omr_admin.V2RAY_TUNNEL_INBOUNDS)
        assert data["routing"]["rules"][-1]["inboundTag"] == list(omr_admin.V2RAY_TUNNEL_INBOUNDS)

    def test_no_reality_client_without_a_uuid(self):
        data = {"inbounds": [{"tag": "omrin-vless-reality", "settings": {"clients": []}}], "routing": {"rules": []}}
        omr_admin._proxy_gre_user_sync(data, "alice", "", "output-203.0.113.5")
        assert data["inbounds"][0]["settings"]["clients"] == []


class TestXrayGreSharedIp:
    _data = staticmethod(TestXrayGreUserSync._data)

    def test_users_of_a_same_public_ip_keep_their_own_rule(self):
        data = self._data()
        data["routing"]["rules"] = [r for r in data["routing"]["rules"] if r["outboundTag"] == "api"]
        omr_admin._proxy_gre_user_sync(data, "openmptcproutergre-user0-ip1", "uuid-1", "output-203.0.113.5")
        omr_admin._proxy_gre_user_sync(data, "alicegre-user3-ip0", "uuid-3", "output-203.0.113.5")
        users = [r["user"] for r in data["routing"]["rules"] if r["outboundTag"] == "output-203.0.113.5"]
        assert sorted(users) == [["alicegre-user3-ip0"], ["openmptcproutergre-user0-ip1"]]
        # nothing left to change for either: no restart ping-pong
        assert omr_admin._proxy_gre_user_sync(data, "openmptcproutergre-user0-ip1", "uuid-1", "output-203.0.113.5") is False
        assert omr_admin._proxy_gre_user_sync(data, "alicegre-user3-ip0", "uuid-3", "output-203.0.113.5") is False

    def test_shared_outbound_of_a_public_ip(self):
        data = {"outbounds": [{"protocol": "freedom", "tag": "direct"}]}
        assert omr_admin._proxy_gre_outbound_sync(data, "output-203.0.113.5", "203.0.113.5") is True
        assert omr_admin._proxy_gre_outbound_sync(data, "output-203.0.113.5", "203.0.113.5") is False
        assert [o["tag"] for o in data["outbounds"]] == ["direct", "output-203.0.113.5"]


# ===========================================================================
# add_gre_tunnels
# ===========================================================================


_PUBLIC = [("eth0", "198.51.100.1", "255.255.255.0"), ("eth0", "203.0.113.5", "255.255.255.255"),
           ("eth1", "203.0.113.9", "255.255.255.0")]


class TestAddGreTunnels:
    @staticmethod
    def _run(config, public=_PUBLIC, only_user=None, isfile=lambda p: False):
        writes = []

        def modif(user, changes):
            config["users"][0][user].update(changes)

        with patch("omr_admin._vps_public_ipv4s", return_value=public), \
             patch("omr_admin.read_omr_config", side_effect=lambda: config), \
             patch("omr_admin.modif_config_user", side_effect=modif) as modified, \
             patch("omr_admin._gre_write_intf", side_effect=lambda *a: writes.append(a)), \
             patch("os.path.isfile", side_effect=isfile), \
             patch("os.path.exists", return_value=False), \
             patch("omr_admin._nft_sync_gre_snat"), \
             patch("omr_admin._gre_drop_stale_intf"), \
             patch("omr_admin.set_global_param"):
            omr_admin.add_gre_tunnels(only_user)
        return modified, writes

    @staticmethod
    def _config():
        return {"gre_tunnels": True, "users": [{
            "admin": {"username": "admin", "permissions": "admin"},
            "openmptcprouter": {"userid": 0, "username": "openmptcprouter"},
            "alice": {"userid": 3, "username": "alice", "public_ips": ["203.0.113.9"]},
            "bob": {"userid": 4, "username": "bob"},
        }]}

    def test_default_user_every_ip_others_their_public_ips(self):
        config = self._config()
        self._run(config)
        users = config["users"][0]
        assert {t["public_ip"] for t in users["openmptcprouter"]["gre_tunnels"].values()} == \
            {"198.51.100.1", "203.0.113.5", "203.0.113.9"}
        # "(user == addtouser and str(ip) == addwithip)" compared the /24 of
        # the tunnels with a public IP: no other user ever had one
        assert {name: t["public_ip"] for name, t in users["alice"]["gre_tunnels"].items()} == \
            {"gre-user3-ip0": "203.0.113.9"}
        assert "gre_tunnels" not in users["bob"]
        assert "gre_tunnels" not in users["admin"]

    def test_tunnels_out_of_the_vxlan_slices_and_distinct(self):
        config = self._config()
        self._run(config)
        nets = [t["network"] for u in config["users"][0].values() for t in (u.get("gre_tunnels") or {}).values()]
        assert len(nets) == len(set(nets)) == 4
        for net in nets:
            assert omr_admin.IPNetwork(net) in omr_admin.GRE_V4_POOL
            assert omr_admin.IPNetwork(net) not in omr_admin.VXLAN_V4_POOL_LEGACY

    def test_second_run_changes_nothing(self):
        config = self._config()
        self._run(config)
        before = json.loads(json.dumps(config))
        modified, _ = self._run(config)
        modified.assert_not_called()
        assert config == before

    def test_new_address_keeps_the_others_names_and_networks(self):
        config = self._config()
        self._run(config, public=_PUBLIC[1:])
        before = dict(config["users"][0]["openmptcprouter"]["gre_tunnels"])
        # an address listed ahead of the others: it renamed and renumbered them
        self._run(config)
        after = config["users"][0]["openmptcprouter"]["gre_tunnels"]
        for name, tunnel in before.items():
            assert after[name]["public_ip"] == tunnel["public_ip"]
            assert after[name]["network"] == tunnel["network"]
        new = [name for name in after if name not in before]
        assert len(new) == 1 and after[new[0]]["public_ip"] == "198.51.100.1"
        # the router maps the tunnels in order: a new one comes last
        assert list(after)[-1] == new[0]

    def test_tunnel_in_the_vxlan_slices_is_moved_keeping_the_rest(self):
        config = self._config()
        config["users"][0]["openmptcprouter"]["gre_tunnels"] = {"gre-user0-ip1": {
            "local_ip": "10.255.249.1", "remote_ip": "10.255.249.2", "public_ip": "203.0.113.5",
            "shadowsocks_port": "65150", "xray": {"uuid": "u", "ss2022": "k"}}}
        _, writes = self._run(config, public=_PUBLIC[1:])
        tunnel = config["users"][0]["openmptcprouter"]["gre_tunnels"]["gre-user0-ip1"]
        assert omr_admin.IPNetwork(tunnel["network"]) in omr_admin.GRE_V4_POOL
        assert tunnel["remote_ip"] == str(omr_admin.IPNetwork(tunnel["network"])[2])
        assert tunnel["shadowsocks_port"] == "65150"
        assert tunnel["xray"]["uuid"] == "u"
        assert any(w[0] == "gre-user0-ip1" for w in writes)

    def test_only_user(self):
        config = self._config()
        self._run(config, only_user="alice")
        assert "gre_tunnels" in config["users"][0]["alice"]
        assert "gre_tunnels" not in config["users"][0]["openmptcprouter"]

    def test_startup_call_after_what_it_uses(self):
        # At import time: above a function it reaches, it failed with a NameError
        import inspect
        src = inspect.getsource(omr_admin)
        call = src.index("\n        add_gre_tunnels()\n")
        for name in ("def _proxy_drop_user(", "def xray_del_user(", "def xray_add_user(",
                     "def _nft_sync_gre_snat(", "def _proxy_gre_user_sync("):
            assert src.index(name) < call, name

    def test_v2ray_user_of_each_tunnel(self):
        config = self._config()
        v2ray = "/etc/v2ray/v2ray-server.json"
        with patch("omr_admin.v2ray_add_user") as add, patch("omr_admin.v2ray_del_user"), \
             patch("omr_admin.file_as_bytes", return_value=b"x"), \
             patch("omr_admin._proxy_gre_sync_all") as sync:
            self._run(config, only_user="alice", isfile=lambda p: p == v2ray)
        tunnel = config["users"][0]["alice"]["gre_tunnels"]["gre-user3-ip0"]
        assert tunnel["v2ray"]["email"] == "alicegre-user3-ip0"
        assert add.call_args.args[:2] == ("alicegre-user3-ip0", tunnel["v2ray"]["uuid"])
        assert add.call_args.kwargs == {"restart": 0}   # one restart, in the sync
        assert [c.args[0] for c in sync.call_args_list] == ["v2ray"]

    def test_a_single_public_ip_has_no_tunnel(self):
        config = self._config()
        modified, _ = self._run(config, public=_PUBLIC[:1])
        modified.assert_not_called()


def _open_manager(data):
    def _open(path, mode="r", *args, **kwargs):
        if str(path) == "/etc/shadowsocks-libev/manager.json":
            return io.StringIO(json.dumps(data))
        raise FileNotFoundError(path)
    return _open


class TestGreSsPort:
    def test_own_port_on_the_address_reused(self):
        manager = {"port_conf": {"65101": {"key": "k0", "userid": 0}, "65150": {"key": "k0", "userid": 0, "local_address": "203.0.113.5"}}}
        with patch("builtins.open", side_effect=_open_manager(manager)), patch("omr_admin.add_ss_user") as add:
            assert omr_admin._gre_ss_port("203.0.113.5", 0, {"shadowsocks_port": 65101}) == ("65150", False)
        add.assert_not_called()

    def test_port_of_another_user_on_the_address_not_taken(self):
        manager = {"port_conf": {"65102": {"key": "k2", "userid": 2}, "65160": {"key": "k0", "userid": 0, "local_address": "203.0.113.5"}}}
        with patch("builtins.open", side_effect=_open_manager(manager)), patch("omr_admin.add_ss_user", return_value=65161) as add:
            assert omr_admin._gre_ss_port("203.0.113.5", 2, {"shadowsocks_port": 65102}) == ("65161", True)
        add.assert_called_once_with('', "k2", 2, "203.0.113.5")

    def test_user_without_a_port_gets_none(self):
        manager = {"port_conf": {"65101": {"key": "k0", "userid": 0}}}
        with patch("builtins.open", side_effect=_open_manager(manager)), patch("omr_admin.add_ss_user") as add:
            assert omr_admin._gre_ss_port("203.0.113.5", 4, {}) == (None, False)
        add.assert_not_called()


@pytest.mark.real_env
class TestGreWriteIntf:
    def test_written_once_and_a_renumbered_tunnel_recreated(self, tmp_path):
        net = omr_admin.IPNetwork("10.255.240.4/30")
        with patch("omr_admin.GRE_INTF_DIR", str(tmp_path)), patch("subprocess.run") as run:
            omr_admin._gre_write_intf("gre-user0-ip1", "eth0", "203.0.113.5", "255.255.255.0", net, "openmptcprouter", 0)
            text = (tmp_path / "gre-user0-ip1").read_text()
            assert "NETWORK=10.255.240.4/30\nLOCALIP=10.255.240.5\nREMOTEIP=10.255.240.6\n" in text
            assert "USERNAME=openmptcprouter\nUSERID=0\n" in text
            run.assert_not_called()
            omr_admin._gre_write_intf("gre-user0-ip1", "eth0", "203.0.113.5", "255.255.255.0", net, "openmptcprouter", 0)
            run.assert_not_called()
            # omr-service only recreates a tunnel whose remote changed
            omr_admin._gre_write_intf("gre-user0-ip1", "eth0", "203.0.113.5", "255.255.255.0",
                                      omr_admin.IPNetwork("10.255.240.8/30"), "openmptcprouter", 0)
            run.assert_called_once()
            assert run.call_args.args[0] == ["ip", "link", "del", "gre-user0-ip1"]

    def test_files_of_no_tunnel_of_the_user_removed(self, tmp_path):
        for name in ("gre-user0-ip0", "gre-user0-ip1", "gre-user0-ip3", "gre-user3-ip0", "notes"):
            (tmp_path / name).write_text("x")
        with patch("omr_admin.GRE_INTF_DIR", str(tmp_path)), patch("subprocess.run") as run:
            omr_admin._gre_drop_stale_intf(0, {"gre-user0-ip0": {}, "gre-user0-ip1": {}})
        assert sorted(p.name for p in tmp_path.iterdir()) == ["gre-user0-ip0", "gre-user0-ip1", "gre-user3-ip0", "notes"]
        run.assert_called_once()
        assert run.call_args.args[0] == ["ip", "link", "del", "gre-user0-ip3"]

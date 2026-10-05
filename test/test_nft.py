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
        helper_script = calls[1].kwargs["input"].decode()
        assert 'add ct helper inet omr sip_udp { type "sip" protocol udp; }' in helper_script
        assert 'add ct helper inet omr sip_tcp { type "sip" protocol tcp; }' in helper_script
        chain_script = calls[2].kwargs["input"].decode()
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

        def flaky(username, udata, entry):
            if username == "alice":
                raise ValueError("boom")
            return real(username, udata, entry)

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

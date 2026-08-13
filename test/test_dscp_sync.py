"""
Unit tests for the VPS-side DSCP/weight sync endpoints (server side of the
router's per-WAN DSCP pinning, per-WAN weighting, and destination -> DSCP
classification):

  - POST /mptcp_dscp:    converges the bpf_dscp dscp_remote_id map to the
    router's dscp_iface -> WAN pins, keyed by MPTCP remote endpoint id
    instead of local IP (every subflow shares one local IP on the VPS).
  - POST /mptcp_weight:  converges the bpf_weight(_rr) weight_remote_id map
    the same way, tracking previously-pushed remote ids in a small state
    file so stale ones get cleaned up (remote ids have no fixed
    enumeration, unlike the small fixed set of DSCP classes).
  - POST /dscp_classify: mirrors the router's own destination -> DSCP
    classification (omr-dscp/omr-dscp-nft) into per-class ipsets plus an
    idempotent Shorewall mangle block, so the VPS's own outbound traffic to
    a proxied session's real destination carries the same DSCP as the
    router->VPS leg for that session.
  - POST /mqvpn_dscp:    the MQVPN analogue of /mptcp_dscp -- pushes a
    per-path dscp_mask both live (mqvpn_api() control socket,
    127.0.0.1:9090) and persisted (server.json's "path_policy" array),
    keyed by (user, iface) since mqvpn has no MPTCP-style remote_id.
    server.json is also the source of truth for convergence: an iface
    dropped from the request has its dscp_mask cleared both live and in
    the persisted entry.
  - POST /mqvpn_weight:  the MQVPN analogue of /mptcp_weight -- same
    live+persisted push, for the per-path `weight` field instead of
    `dscp_mask`.
"""

import io
import json
import subprocess
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
                    env.files[sp] = value.decode() if binary else value
                    super().close()

            return _Recorder()
        if sp in self.files:
            data = self.files[sp]
            return io.BytesIO(data.encode()) if binary else io.StringIO(data)
        return io.BytesIO() if binary else io.StringIO()


_DSCP_SCRIPT = "/usr/sbin/mptcp-scheduler-dscp.sh"
_WEIGHT_SCRIPT = "/usr/sbin/mptcp-scheduler-weight.sh"
_WEIGHT_STATE_FILE = omr_admin.MPTCP_WEIGHT_STATE_FILE

_MQVPN_USERNAME = "openmptcprouter"  # RW_USER.username in conftest.py
_MQVPN_SERVER_JSON = "/etc/mqvpn/server.json"


def _exists_only(*present):
    """os.path.exists side_effect that's True only for the given paths."""
    present = set(present)
    return lambda p: str(p) in present


# ===========================================================================
# POST /mptcp_dscp
# ===========================================================================


class TestMptcpDscpEndpoint:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/mptcp_dscp", json={"pins": []})
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/mptcp_dscp", json={"pins": []})
        assert r.json()["result"] == "permission"

    def test_script_not_installed_warns(self, user_client):
        with patch("os.path.exists", return_value=False):
            r = user_client.post("/mptcp_dscp", json={"pins": []})
        assert r.json()["result"] == "warning"

    def test_invalid_dscp_class_errors(self, user_client):
        with patch("os.path.exists", side_effect=_exists_only(_DSCP_SCRIPT)):
            r = user_client.post(
                "/mptcp_dscp", json={"pins": [{"dscp": "bogus", "remote_id": 1}]}
            )
        assert r.json()["result"] == "error"

    @pytest.mark.parametrize("remote_id", [-1, 256])
    def test_out_of_range_remote_id_errors(self, user_client, remote_id):
        with patch("os.path.exists", side_effect=_exists_only(_DSCP_SCRIPT)):
            r = user_client.post(
                "/mptcp_dscp",
                json={"pins": [{"dscp": "cs4", "remote_id": remote_id}]},
            )
        assert r.json()["result"] == "error"

    def test_success_sets_pinned_and_deletes_the_rest(self, user_client):
        with (
            patch("os.path.exists", side_effect=_exists_only(_DSCP_SCRIPT)),
            patch("subprocess.run") as run,
        ):
            r = user_client.post(
                "/mptcp_dscp", json={"pins": [{"dscp": "cs4", "remote_id": 5}]}
            )
        assert r.json()["result"] == "done"
        calls = [c.args[0] for c in run.call_args_list]
        assert [_DSCP_SCRIPT, "set", "cs4", "id", "5"] in calls
        assert len(calls) == len(omr_admin.DSCP_CLASSES)
        deleted = {c[2] for c in calls if c[1] == "del"}
        assert deleted == set(omr_admin.DSCP_CLASSES) - {"cs4"}

    def test_empty_pins_deletes_every_class(self, user_client):
        with (
            patch("os.path.exists", side_effect=_exists_only(_DSCP_SCRIPT)),
            patch("subprocess.run") as run,
        ):
            r = user_client.post("/mptcp_dscp", json={"pins": []})
        assert r.json()["result"] == "done"
        calls = [c.args[0] for c in run.call_args_list]
        assert all(c[1] == "del" for c in calls)
        assert {c[2] for c in calls} == set(omr_admin.DSCP_CLASSES)

    def test_pins_field_defaults_when_omitted(self, user_client):
        with (
            patch("os.path.exists", side_effect=_exists_only(_DSCP_SCRIPT)),
            patch("subprocess.run") as run,
        ):
            r = user_client.post("/mptcp_dscp", json={})
        assert r.json()["result"] == "done"
        assert run.call_count == len(omr_admin.DSCP_CLASSES)


# ===========================================================================
# POST /mptcp_weight
# ===========================================================================


class TestMptcpWeightEndpoint:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/mptcp_weight", json={"weights": []})
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/mptcp_weight", json={"weights": []})
        assert r.json()["result"] == "permission"

    def test_script_not_installed_warns(self, user_client):
        with patch("os.path.exists", return_value=False):
            r = user_client.post("/mptcp_weight", json={"weights": []})
        assert r.json()["result"] == "warning"

    @pytest.mark.parametrize(
        "remote_id,weight", [(-1, 10), (256, 10), (1, 0), (1, -5)]
    )
    def test_invalid_pin_errors(self, user_client, remote_id, weight):
        with patch("os.path.exists", side_effect=_exists_only(_WEIGHT_SCRIPT)):
            r = user_client.post(
                "/mptcp_weight",
                json={"weights": [{"remote_id": remote_id, "weight": weight}]},
            )
        assert r.json()["result"] == "error"

    def test_first_sync_with_no_state_file(self, user_client):
        env = _FileEnv({})
        with (
            patch("os.path.exists", side_effect=_exists_only(_WEIGHT_SCRIPT)),
            patch("builtins.open", side_effect=env),
            patch("subprocess.run") as run,
        ):
            r = user_client.post(
                "/mptcp_weight",
                json={
                    "weights": [
                        {"remote_id": 1, "weight": 10},
                        {"remote_id": 2, "weight": 20},
                    ]
                },
            )
        assert r.json()["result"] == "done"
        calls = [c.args[0] for c in run.call_args_list]
        assert [_WEIGHT_SCRIPT, "set", "id", "1", "10"] in calls
        assert [_WEIGHT_SCRIPT, "set", "id", "2", "20"] in calls
        assert not any(c[1] == "del" for c in calls)
        assert env.written[_WEIGHT_STATE_FILE] == "1 2"

    def test_stale_ids_removed_and_state_file_rewritten(self, user_client):
        env = _FileEnv({_WEIGHT_STATE_FILE: "1 2 3"})
        with (
            patch(
                "os.path.exists",
                side_effect=_exists_only(_WEIGHT_SCRIPT, _WEIGHT_STATE_FILE),
            ),
            patch("builtins.open", side_effect=env),
            patch("subprocess.run") as run,
        ):
            r = user_client.post(
                "/mptcp_weight", json={"weights": [{"remote_id": 1, "weight": 50}]}
            )
        assert r.json()["result"] == "done"
        calls = [c.args[0] for c in run.call_args_list]
        assert [_WEIGHT_SCRIPT, "set", "id", "1", "50"] in calls
        deleted = {c[3] for c in calls if c[1] == "del"}
        assert deleted == {"2", "3"}
        assert env.written[_WEIGHT_STATE_FILE] == "1"

    def test_no_desired_weights_clears_everything(self, user_client):
        env = _FileEnv({_WEIGHT_STATE_FILE: "1 2"})
        with (
            patch(
                "os.path.exists",
                side_effect=_exists_only(_WEIGHT_SCRIPT, _WEIGHT_STATE_FILE),
            ),
            patch("builtins.open", side_effect=env),
            patch("subprocess.run") as run,
        ):
            r = user_client.post("/mptcp_weight", json={"weights": []})
        assert r.json()["result"] == "done"
        calls = [c.args[0] for c in run.call_args_list]
        assert all(c[1] == "del" for c in calls)
        assert env.written[_WEIGHT_STATE_FILE] == ""

    def test_weights_field_defaults_when_omitted(self, user_client):
        env = _FileEnv({})
        with (
            patch("os.path.exists", side_effect=_exists_only(_WEIGHT_SCRIPT)),
            patch("builtins.open", side_effect=env),
            patch("subprocess.run") as run,
        ):
            r = user_client.post("/mptcp_weight", json={})
        assert r.json()["result"] == "done"
        assert run.call_count == 0
        assert env.written[_WEIGHT_STATE_FILE] == ""


# ===========================================================================
# POST /dscp_classify
# ===========================================================================


class TestDscpClassifyEndpoint:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/dscp_classify", json={"entries": []})
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/dscp_classify", json={"entries": []})
        assert r.json()["result"] == "permission"

    def test_ipset_missing_warns(self, user_client):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            r = user_client.post("/dscp_classify", json={"entries": []})
        assert r.json()["result"] == "warning"

    def test_ipset_version_check_failure_warns(self, user_client):
        with patch(
            "subprocess.run",
            side_effect=subprocess.CalledProcessError(1, ["ipset", "version"]),
        ):
            r = user_client.post("/dscp_classify", json={"entries": []})
        assert r.json()["result"] == "warning"

    def test_invalid_dscp_class_errors(self, user_client):
        # 'af11' is a valid mptcp_dscp class but not in the narrower
        # DSCP_CLASSIFY_CLASSES set (Shorewall's %dscpmap has no af*/le entries).
        r = user_client.post(
            "/dscp_classify",
            json={"entries": [{"dscp": "af11", "cidr": "10.0.0.0/24"}]},
        )
        assert r.json()["result"] == "error"

    def test_invalid_cidr_errors(self, user_client):
        r = user_client.post(
            "/dscp_classify",
            json={"entries": [{"dscp": "cs4", "cidr": "not-an-ip"}]},
        )
        assert r.json()["result"] == "error"

    def test_success_dispatches_normalized_cidrs_per_class_and_family(self, user_client):
        with (
            patch("omr_admin._refresh_dscp_classify_ipset") as refresh,
            patch("omr_admin._ensure_dscp_classify_mangle") as ensure_mangle,
        ):
            r = user_client.post(
                "/dscp_classify",
                json={
                    "entries": [
                        {"dscp": "cs4", "cidr": "10.0.0.5/24"},  # host bits set
                        {"dscp": "cs4", "cidr": "2001:db8::1/32"},
                    ]
                },
            )
        assert r.json()["result"] == "done"
        assert refresh.call_count == len(omr_admin.DSCP_CLASSIFY_CLASSES) * 2
        cs4_calls = {
            c.args[1]: c.args[2] for c in refresh.call_args_list if "_cs4_" in c.args[0]
        }
        assert cs4_calls[4] == ["10.0.0.0/24"]
        assert cs4_calls[6] == ["2001:db8::/32"]
        ensure_mangle.assert_any_call(4)
        ensure_mangle.assert_any_call(6)

    def test_unmentioned_classes_get_empty_lists(self, user_client):
        with (
            patch("omr_admin._refresh_dscp_classify_ipset") as refresh,
            patch("omr_admin._ensure_dscp_classify_mangle"),
        ):
            user_client.post(
                "/dscp_classify",
                json={"entries": [{"dscp": "cs4", "cidr": "10.0.0.0/24"}]},
            )
        ef_calls = [c for c in refresh.call_args_list if "_ef_" in c.args[0]]
        assert ef_calls and all(c.args[2] == [] for c in ef_calls)

    def test_entries_field_defaults_when_omitted(self, user_client):
        with (
            patch("omr_admin._refresh_dscp_classify_ipset") as refresh,
            patch("omr_admin._ensure_dscp_classify_mangle"),
        ):
            r = user_client.post("/dscp_classify", json={})
        assert r.json()["result"] == "done"
        assert refresh.call_count == len(omr_admin.DSCP_CLASSIFY_CLASSES) * 2
        assert all(c.args[2] == [] for c in refresh.call_args_list)


# ===========================================================================
# Helper: _dscp_classify_ipset_name
# ===========================================================================


class TestDscpClassifyIpsetName:
    def test_name_format(self):
        assert omr_admin._dscp_classify_ipset_name("cs4", 4) == "omr_dscp_classify_cs4_4"
        assert omr_admin._dscp_classify_ipset_name("ef", 6) == "omr_dscp_classify_ef_6"


# ===========================================================================
# Helper: _refresh_dscp_classify_ipset
# ===========================================================================


class TestRefreshDscpClassifyIpset:
    def test_ipv4_atomic_swap_sequence(self):
        with patch("subprocess.run") as run:
            omr_admin._refresh_dscp_classify_ipset(
                "myset", 4, ["10.0.0.0/24", "10.0.1.0/24"]
            )
        calls = [c.args[0] for c in run.call_args_list]
        assert calls == [
            ["ipset", "destroy", "myset_tmp"],
            ["ipset", "create", "myset_tmp", "hash:net", "family", "inet"],
            ["ipset", "add", "myset_tmp", "10.0.0.0/24", "-exist"],
            ["ipset", "add", "myset_tmp", "10.0.1.0/24", "-exist"],
            ["ipset", "create", "myset", "hash:net", "family", "inet", "-exist"],
            ["ipset", "swap", "myset_tmp", "myset"],
            ["ipset", "destroy", "myset_tmp"],
        ]

    def test_ipv6_uses_inet6_family(self):
        with patch("subprocess.run") as run:
            omr_admin._refresh_dscp_classify_ipset("myset6", 6, [])
        calls = [c.args[0] for c in run.call_args_list]
        assert ["ipset", "create", "myset6_tmp", "hash:net", "family", "inet6"] in calls
        assert not any(c[1] == "add" for c in calls)


# ===========================================================================
# Helper: _dscp_classify_mangle_line
# ===========================================================================


class TestDscpClassifyMangleLine:
    def test_ipv4_column_count_and_action(self):
        line = omr_admin._dscp_classify_mangle_line("cs4", 4, "someset")
        cols = line.rstrip("\n").split("\t")
        assert cols[0] == "DSCP(CS4)"
        assert cols[1] == "-"
        assert cols[2] == "+someset"
        assert len(cols) == 14
        assert all(c == "-" for c in cols[3:])

    def test_ipv6_has_one_extra_column(self):
        line = omr_admin._dscp_classify_mangle_line("ef", 6, "someset6")
        cols = line.rstrip("\n").split("\t")
        assert cols[0] == "DSCP(EF)"
        assert len(cols) == 15

    def test_ends_with_newline(self):
        line = omr_admin._dscp_classify_mangle_line("cs0", 4, "s")
        assert line.endswith("\n")


# ===========================================================================
# Helper: _ensure_dscp_classify_mangle
# ===========================================================================


_TMPFILE = "/tmp/fake-mangle-tmp"


class TestEnsureDscpClassifyMangle:
    def _run(self, family=4, existing=None, isfile=True):
        mangle_path = "/etc/shorewall/mangle" if family == 4 else "/etc/shorewall6/mangle"
        files = {} if existing is None else {mangle_path: existing}
        env = _FileEnv(files)

        def _fake_move(src, dst):
            env.files[dst] = env.files.get(src, "")

        with (
            patch("builtins.open", side_effect=env),
            patch("os.path.isfile", return_value=isfile),
            patch("omr_admin.mkstemp", return_value=(999, _TMPFILE)),
            patch("os.close"),
            patch("omr_admin.move", side_effect=_fake_move),
            patch("subprocess.run") as run,
        ):
            omr_admin._ensure_dscp_classify_mangle(family)
        return mangle_path, env, run

    def test_creates_missing_file_with_full_block(self):
        mangle_path, env, run = self._run(family=4, existing=None, isfile=False)
        content = env.files[mangle_path]
        assert content.count(omr_admin.DSCP_CLASSIFY_MANGLE_BEGIN) == 1
        assert content.count(omr_admin.DSCP_CLASSIFY_MANGLE_END) == 1
        for dscp in omr_admin.DSCP_CLASSIFY_CLASSES:
            assert f"omr_dscp_classify_{dscp}_4" in content
        run.assert_called_once_with(["systemctl", "-q", "reload", "shorewall"], check=False)

    def test_ipv6_reloads_shorewall6(self):
        _, _, run = self._run(family=6, existing=None, isfile=False)
        run.assert_called_once_with(["systemctl", "-q", "reload", "shorewall6"], check=False)

    def test_preserves_content_outside_markers_and_replaces_stale_block(self):
        begin = omr_admin.DSCP_CLASSIFY_MANGLE_BEGIN
        end = omr_admin.DSCP_CLASSIFY_MANGLE_END
        existing = f"# custom rule\nSomeRule\n{begin}\nstale-row\n{end}\n# trailer\n"
        mangle_path, env, _run_result = self._run(family=4, existing=existing, isfile=True)
        content = env.files[mangle_path]
        assert "# custom rule" in content
        assert "# trailer" in content
        assert "stale-row" not in content
        assert content.count(begin) == 1
        assert content.count(end) == 1

    def test_rerun_with_unchanged_content_skips_reload(self):
        # First pass produces the canonical generated content.
        mangle_path, env, _ = self._run(family=4, existing=None, isfile=False)
        generated = env.files[mangle_path]
        # A second pass seeded with that exact content is a no-op: same
        # bytes back out, so no reload should fire.
        _, env2, run2 = self._run(family=4, existing=generated, isfile=True)
        assert env2.files[mangle_path] == generated
        run2.assert_not_called()


# ===========================================================================
# POST /mqvpn_dscp
# ===========================================================================


class TestMqvpnDscpEndpoint:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/mqvpn_dscp", json={"pins": []})
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/mqvpn_dscp", json={"pins": []})
        assert r.json()["result"] == "permission"

    def test_not_installed_warns(self, user_client):
        with patch("os.path.isfile", return_value=False):
            r = user_client.post("/mqvpn_dscp", json={"pins": []})
        assert r.json()["result"] == "warning"

    def test_invalid_dscp_class_errors(self, user_client):
        with patch("os.path.isfile", return_value=True):
            r = user_client.post(
                "/mqvpn_dscp",
                json={"pins": [{"iface": "wan1", "dscp": ["bogus"]}]},
            )
        assert r.json()["result"] == "error"

    @pytest.mark.parametrize("iface", ["", "a" * 16])
    def test_invalid_iface_errors(self, user_client, iface):
        with patch("os.path.isfile", return_value=True):
            r = user_client.post(
                "/mqvpn_dscp", json={"pins": [{"iface": iface, "dscp": ["ef"]}]}
            )
        assert r.json()["result"] == "error"

    def test_success_builds_mask_live_and_persisted(self, user_client):
        env = _FileEnv({_MQVPN_SERVER_JSON: "{}"})
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=env),
            patch("omr_admin.mqvpn_api", return_value={"ok": True}) as api,
        ):
            r = user_client.post(
                "/mqvpn_dscp",
                json={"pins": [{"iface": "wan1", "dscp": ["cs4", "ef"]}]},
            )
        assert r.json()["result"] == "done"
        mask = (1 << 32) | (1 << 46)
        api.assert_called_once_with({
            "cmd": "set_path_dscp_mask",
            "user": _MQVPN_USERNAME,
            "iface": "wan1",
            "dscp_mask": mask,
        })
        written = json.loads(env.written[_MQVPN_SERVER_JSON])
        assert written["path_policy"] == [
            {"user": _MQVPN_USERNAME, "iface": "wan1", "dscp_mask": mask}
        ]

    def test_stale_ifaces_cleared_live_and_persisted(self, user_client):
        seed = {"path_policy": [
            {"user": _MQVPN_USERNAME, "iface": "wan1", "dscp_mask": 1},
            {"user": _MQVPN_USERNAME, "iface": "wan2", "dscp_mask": 2},
        ]}
        env = _FileEnv({_MQVPN_SERVER_JSON: json.dumps(seed)})
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=env),
            patch("omr_admin.mqvpn_api", return_value={"ok": True}) as api,
        ):
            r = user_client.post(
                "/mqvpn_dscp", json={"pins": [{"iface": "wan1", "dscp": ["ef"]}]}
            )
        assert r.json()["result"] == "done"
        calls = {c.args[0]["iface"]: c.args[0]["dscp_mask"] for c in api.call_args_list}
        assert calls["wan1"] == 1 << 46
        assert calls["wan2"] == 0  # cleared, not re-pinned
        written = json.loads(env.written[_MQVPN_SERVER_JSON])
        # wan2's entry had only dscp_mask, so clearing it drops the whole entry.
        assert written["path_policy"] == [
            {"user": _MQVPN_USERNAME, "iface": "wan1", "dscp_mask": 1 << 46}
        ]

    def test_clearing_dscp_preserves_a_sibling_weight_entry(self, user_client):
        # wan1 has both a weight (set via /mqvpn_weight) and a dscp_mask;
        # clearing the dscp pin must not drop the weight field too.
        seed = {"path_policy": [
            {"user": _MQVPN_USERNAME, "iface": "wan1", "weight": 100, "dscp_mask": 1},
        ]}
        env = _FileEnv({_MQVPN_SERVER_JSON: json.dumps(seed)})
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=env),
            patch("omr_admin.mqvpn_api", return_value={"ok": True}),
        ):
            r = user_client.post("/mqvpn_dscp", json={"pins": []})
        assert r.json()["result"] == "done"
        written = json.loads(env.written[_MQVPN_SERVER_JSON])
        assert written["path_policy"] == [
            {"user": _MQVPN_USERNAME, "iface": "wan1", "weight": 100}
        ]

    def test_empty_pins_clears_previous_entries(self, user_client):
        seed = {"path_policy": [{"user": _MQVPN_USERNAME, "iface": "wan1", "dscp_mask": 1}]}
        env = _FileEnv({_MQVPN_SERVER_JSON: json.dumps(seed)})
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=env),
            patch("omr_admin.mqvpn_api", return_value={"ok": True}) as api,
        ):
            r = user_client.post("/mqvpn_dscp", json={"pins": []})
        assert r.json()["result"] == "done"
        api.assert_called_once_with({
            "cmd": "set_path_dscp_mask",
            "user": _MQVPN_USERNAME,
            "iface": "wan1",
            "dscp_mask": 0,
        })
        assert json.loads(env.written[_MQVPN_SERVER_JSON])["path_policy"] == []

    def test_other_users_entries_untouched(self, user_client):
        seed = {"path_policy": [{"user": "someone-else", "iface": "wan1", "dscp_mask": 9}]}
        env = _FileEnv({_MQVPN_SERVER_JSON: json.dumps(seed)})
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=env),
            patch("omr_admin.mqvpn_api", return_value={"ok": True}) as api,
        ):
            r = user_client.post("/mqvpn_dscp", json={"pins": []})
        assert r.json()["result"] == "done"
        api.assert_not_called()
        # Nothing changed for this user, so no write happens at all -- the
        # other user's entry is simply never touched.
        assert _MQVPN_SERVER_JSON not in env.written

    def test_control_socket_failure_surfaced_as_warning(self, user_client):
        env = _FileEnv({_MQVPN_SERVER_JSON: "{}"})
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=env),
            patch("omr_admin.mqvpn_api", return_value={"ok": False, "error": "user not found"}),
        ):
            r = user_client.post(
                "/mqvpn_dscp", json={"pins": [{"iface": "wan1", "dscp": ["ef"]}]}
            )
        assert r.json()["result"] == "warning"
        assert "user not found" in r.json()["reason"]
        # Still persisted even though the live push failed (e.g. user not
        # currently connected) -- it'll apply on their next connect.
        assert json.loads(env.written[_MQVPN_SERVER_JSON])["path_policy"] == [
            {"user": _MQVPN_USERNAME, "iface": "wan1", "dscp_mask": 1 << 46}
        ]

    def test_no_write_when_nothing_changes(self, user_client):
        env = _FileEnv({_MQVPN_SERVER_JSON: "{}"})
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=env),
            patch("omr_admin.mqvpn_api", return_value={"ok": True}),
        ):
            r = user_client.post("/mqvpn_dscp", json={"pins": []})
        assert r.json()["result"] == "done"
        assert _MQVPN_SERVER_JSON not in env.written

    def test_pins_field_defaults_when_omitted(self, user_client):
        env = _FileEnv({_MQVPN_SERVER_JSON: "{}"})
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=env),
            patch("omr_admin.mqvpn_api", return_value={"ok": True}) as api,
        ):
            r = user_client.post("/mqvpn_dscp", json={})
        assert r.json()["result"] == "done"
        api.assert_not_called()
        assert _MQVPN_SERVER_JSON not in env.written


# ===========================================================================
# POST /mqvpn_weight
# ===========================================================================


class TestMqvpnWeightEndpoint:
    def test_requires_auth(self, unauth_client):
        r = unauth_client.post("/mqvpn_weight", json={"weights": []})
        assert r.status_code == 403

    def test_ro_user_denied(self, ro_client):
        r = ro_client.post("/mqvpn_weight", json={"weights": []})
        assert r.json()["result"] == "permission"

    def test_not_installed_warns(self, user_client):
        with patch("os.path.isfile", return_value=False):
            r = user_client.post("/mqvpn_weight", json={"weights": []})
        assert r.json()["result"] == "warning"

    @pytest.mark.parametrize("weight", [-1, 65536])
    def test_out_of_range_weight_errors(self, user_client, weight):
        with patch("os.path.isfile", return_value=True):
            r = user_client.post(
                "/mqvpn_weight",
                json={"weights": [{"iface": "wan1", "weight": weight}]},
            )
        assert r.json()["result"] == "error"

    def test_zero_weight_is_valid(self, user_client):
        # 0 means "use the scheduler's default (1)" -- not out of range.
        env = _FileEnv({_MQVPN_SERVER_JSON: "{}"})
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=env),
            patch("omr_admin.mqvpn_api", return_value={"ok": True}) as api,
        ):
            r = user_client.post(
                "/mqvpn_weight", json={"weights": [{"iface": "wan1", "weight": 0}]}
            )
        assert r.json()["result"] == "done"
        api.assert_called_once_with({
            "cmd": "set_path_weight", "user": _MQVPN_USERNAME, "iface": "wan1", "weight": 0,
        })
        written = json.loads(env.written[_MQVPN_SERVER_JSON])
        assert written["path_policy"] == [
            {"user": _MQVPN_USERNAME, "iface": "wan1", "weight": 0}
        ]

    def test_invalid_iface_errors(self, user_client):
        with patch("os.path.isfile", return_value=True):
            r = user_client.post(
                "/mqvpn_weight", json={"weights": [{"iface": "", "weight": 10}]}
            )
        assert r.json()["result"] == "error"

    def test_success_pushes_weight_live_and_persisted(self, user_client):
        env = _FileEnv({_MQVPN_SERVER_JSON: "{}"})
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=env),
            patch("omr_admin.mqvpn_api", return_value={"ok": True}) as api,
        ):
            r = user_client.post(
                "/mqvpn_weight", json={"weights": [{"iface": "wan1", "weight": 200}]}
            )
        assert r.json()["result"] == "done"
        api.assert_called_once_with({
            "cmd": "set_path_weight", "user": _MQVPN_USERNAME, "iface": "wan1", "weight": 200,
        })
        written = json.loads(env.written[_MQVPN_SERVER_JSON])
        assert written["path_policy"] == [
            {"user": _MQVPN_USERNAME, "iface": "wan1", "weight": 200}
        ]

    def test_stale_ifaces_reset_to_zero_live_and_persisted(self, user_client):
        seed = {"path_policy": [
            {"user": _MQVPN_USERNAME, "iface": "wan1", "weight": 10},
            {"user": _MQVPN_USERNAME, "iface": "wan2", "weight": 20},
        ]}
        env = _FileEnv({_MQVPN_SERVER_JSON: json.dumps(seed)})
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=env),
            patch("omr_admin.mqvpn_api", return_value={"ok": True}) as api,
        ):
            r = user_client.post(
                "/mqvpn_weight", json={"weights": [{"iface": "wan1", "weight": 50}]}
            )
        assert r.json()["result"] == "done"
        calls = {c.args[0]["iface"]: c.args[0]["weight"] for c in api.call_args_list}
        assert calls == {"wan1": 50, "wan2": 0}
        written = json.loads(env.written[_MQVPN_SERVER_JSON])
        assert written["path_policy"] == [
            {"user": _MQVPN_USERNAME, "iface": "wan1", "weight": 50}
        ]

    def test_clearing_weight_preserves_a_sibling_dscp_entry(self, user_client):
        seed = {"path_policy": [
            {"user": _MQVPN_USERNAME, "iface": "wan1", "weight": 10, "dscp_mask": 5},
        ]}
        env = _FileEnv({_MQVPN_SERVER_JSON: json.dumps(seed)})
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=env),
            patch("omr_admin.mqvpn_api", return_value={"ok": True}),
        ):
            r = user_client.post("/mqvpn_weight", json={"weights": []})
        assert r.json()["result"] == "done"
        written = json.loads(env.written[_MQVPN_SERVER_JSON])
        assert written["path_policy"] == [
            {"user": _MQVPN_USERNAME, "iface": "wan1", "dscp_mask": 5}
        ]

    def test_control_socket_failure_surfaced_as_warning(self, user_client):
        env = _FileEnv({_MQVPN_SERVER_JSON: "{}"})
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=env),
            patch("omr_admin.mqvpn_api", return_value={"ok": False, "error": "path not found"}),
        ):
            r = user_client.post(
                "/mqvpn_weight", json={"weights": [{"iface": "wan1", "weight": 50}]}
            )
        assert r.json()["result"] == "warning"
        assert "path not found" in r.json()["reason"]
        # Still persisted for whenever the user next connects.
        assert json.loads(env.written[_MQVPN_SERVER_JSON])["path_policy"] == [
            {"user": _MQVPN_USERNAME, "iface": "wan1", "weight": 50}
        ]

    def test_no_write_when_nothing_changes(self, user_client):
        env = _FileEnv({_MQVPN_SERVER_JSON: "{}"})
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=env),
            patch("omr_admin.mqvpn_api", return_value={"ok": True}),
        ):
            r = user_client.post("/mqvpn_weight", json={"weights": []})
        assert r.json()["result"] == "done"
        assert _MQVPN_SERVER_JSON not in env.written

    def test_weights_field_defaults_when_omitted(self, user_client):
        env = _FileEnv({_MQVPN_SERVER_JSON: "{}"})
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=env),
            patch("omr_admin.mqvpn_api", return_value={"ok": True}) as api,
        ):
            r = user_client.post("/mqvpn_weight", json={})
        assert r.json()["result"] == "done"
        api.assert_not_called()
        assert _MQVPN_SERVER_JSON not in env.written

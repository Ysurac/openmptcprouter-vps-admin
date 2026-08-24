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

    def test_nft_missing_warns(self, user_client):
        with patch("os.path.exists", side_effect=_exists_only()):
            r = user_client.post("/dscp_classify", json={"entries": []})
        assert r.json()["result"] == "warning"

    def test_invalid_dscp_class_errors(self, user_client):
        # 'af11' is a valid mptcp_dscp class but not in the narrower
        # DSCP_CLASSIFY_CLASSES set (kept for continuity with what the
        # router's omr-dscp/omr-dscp-nft classifiers actually produce).
        with patch("os.path.exists", side_effect=_exists_only(omr_admin.NFT_BIN)):
            r = user_client.post(
                "/dscp_classify",
                json={"entries": [{"dscp": "af11", "cidr": "10.0.0.0/24"}]},
            )
        assert r.json()["result"] == "error"

    def test_invalid_cidr_errors(self, user_client):
        with patch("os.path.exists", side_effect=_exists_only(omr_admin.NFT_BIN)):
            r = user_client.post(
                "/dscp_classify",
                json={"entries": [{"dscp": "cs4", "cidr": "not-an-ip"}]},
            )
        assert r.json()["result"] == "error"

    def test_success_dispatches_normalized_cidrs_per_class_and_family(self, user_client):
        with (
            patch("os.path.exists", side_effect=_exists_only(omr_admin.NFT_BIN)),
            patch("omr_admin._nft_ensure_dscp_sets") as ensure_sets,
            patch("omr_admin._nft_refresh_dscp_set") as refresh,
            patch("omr_admin._nft_sync_dscp_mark") as sync_mark,
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
        ensure_sets.assert_called_once()
        assert refresh.call_count == len(omr_admin.DSCP_CLASSIFY_CLASSES) * 2
        cs4_calls = {c.args[1]: c.args[2] for c in refresh.call_args_list if c.args[0] == "cs4"}
        assert cs4_calls[4] == ["10.0.0.0/24"]
        assert cs4_calls[6] == ["2001:db8::/32"]
        sync_mark.assert_called_once()

    def test_unmentioned_classes_get_empty_lists(self, user_client):
        with (
            patch("os.path.exists", side_effect=_exists_only(omr_admin.NFT_BIN)),
            patch("omr_admin._nft_ensure_dscp_sets"),
            patch("omr_admin._nft_refresh_dscp_set") as refresh,
            patch("omr_admin._nft_sync_dscp_mark"),
        ):
            user_client.post(
                "/dscp_classify",
                json={"entries": [{"dscp": "cs4", "cidr": "10.0.0.0/24"}]},
            )
        ef_calls = [c for c in refresh.call_args_list if c.args[0] == "ef"]
        assert ef_calls and all(c.args[2] == [] for c in ef_calls)

    def test_entries_field_defaults_when_omitted(self, user_client):
        with (
            patch("os.path.exists", side_effect=_exists_only(omr_admin.NFT_BIN)),
            patch("omr_admin._nft_ensure_dscp_sets"),
            patch("omr_admin._nft_refresh_dscp_set") as refresh,
            patch("omr_admin._nft_sync_dscp_mark"),
        ):
            r = user_client.post("/dscp_classify", json={})
        assert r.json()["result"] == "done"
        assert refresh.call_count == len(omr_admin.DSCP_CLASSIFY_CLASSES) * 2
        assert all(c.args[2] == [] for c in refresh.call_args_list)

    def test_success_persists_entries_for_resync(self, user_client):
        """The router's push must survive an omr-admin restart (e.g. the
        nftables reload a VPS update triggers) via omr-admin-config.json,
        not just get applied live -- see _nft_resync_dscp_classify()."""
        with (
            patch("os.path.exists", side_effect=_exists_only(omr_admin.NFT_BIN)),
            patch("omr_admin._nft_ensure_dscp_sets"),
            patch("omr_admin._nft_refresh_dscp_set"),
            patch("omr_admin._nft_sync_dscp_mark"),
            patch("omr_admin.set_global_param") as set_param,
        ):
            user_client.post(
                "/dscp_classify",
                json={"entries": [{"dscp": "cs4", "cidr": "10.0.0.5/24"}]},
            )
        set_param.assert_called_once_with(
            "dscp_classify", [{"dscp": "cs4", "cidr": "10.0.0.5/24"}]
        )

    def test_invalid_entry_persists_nothing(self, user_client):
        with (
            patch("os.path.exists", side_effect=_exists_only(omr_admin.NFT_BIN)),
            patch("omr_admin.set_global_param") as set_param,
        ):
            user_client.post(
                "/dscp_classify",
                json={"entries": [{"dscp": "af11", "cidr": "10.0.0.0/24"}]},
            )
        set_param.assert_not_called()


# ===========================================================================
# _nft_resync_dscp_classify / _dscp_classify_by_class -- replaying the
# router's last push after an nftables restart (e.g. a VPS update) empties
# the sets, independent of the router ever re-pushing on its own.
# ===========================================================================


class TestNftResyncDscpClassify:
    def test_replays_persisted_entries_per_class_and_family(self):
        config = {"dscp_classify": [
            {"dscp": "cs4", "cidr": "10.0.0.5/24"},  # host bits set
            {"dscp": "cs4", "cidr": "2001:db8::1/32"},
        ]}
        with (
            patch("omr_admin.read_omr_config", return_value=config),
            patch("omr_admin._nft_ensure_dscp_sets") as ensure_sets,
            patch("omr_admin._nft_refresh_dscp_set") as refresh,
            patch("omr_admin._nft_sync_dscp_mark") as sync_mark,
        ):
            omr_admin._nft_resync_dscp_classify()
        ensure_sets.assert_called_once()
        assert refresh.call_count == len(omr_admin.DSCP_CLASSIFY_CLASSES) * 2
        cs4_calls = {c.args[1]: c.args[2] for c in refresh.call_args_list if c.args[0] == "cs4"}
        assert cs4_calls[4] == ["10.0.0.0/24"]
        assert cs4_calls[6] == ["2001:db8::/32"]
        sync_mark.assert_called_once()

    def test_missing_config_key_clears_every_set(self):
        with (
            patch("omr_admin.read_omr_config", return_value={}),
            patch("omr_admin._nft_ensure_dscp_sets"),
            patch("omr_admin._nft_refresh_dscp_set") as refresh,
            patch("omr_admin._nft_sync_dscp_mark"),
        ):
            omr_admin._nft_resync_dscp_classify()
        assert refresh.call_count == len(omr_admin.DSCP_CLASSIFY_CLASSES) * 2
        assert all(c.args[2] == [] for c in refresh.call_args_list)

    def test_unreadable_config_is_a_noop_not_a_crash(self):
        with (
            patch("omr_admin.read_omr_config", return_value=None),
            patch("omr_admin._nft_ensure_dscp_sets"),
            patch("omr_admin._nft_refresh_dscp_set") as refresh,
            patch("omr_admin._nft_sync_dscp_mark"),
        ):
            omr_admin._nft_resync_dscp_classify()
        assert all(c.args[2] == [] for c in refresh.call_args_list)

    def test_by_class_skips_invalid_entries_silently(self):
        entries = [
            {"dscp": "af11", "cidr": "10.0.0.0/24"},  # not in DSCP_CLASSIFY_CLASSES
            {"dscp": "cs4", "cidr": "not-an-ip"},
            {"dscp": "cs4", "cidr": "10.0.0.0/24"},
        ]
        by_class = omr_admin._dscp_classify_by_class(entries)
        assert by_class["cs4"][4] == ["10.0.0.0/24"]


# ===========================================================================
# Helper: _nft_dscp_set_name
# ===========================================================================


class TestNftDscpSetName:
    def test_name_format(self):
        assert omr_admin._nft_dscp_set_name("cs4", 4) == "omr_dscp_classify_cs4_4"
        assert omr_admin._nft_dscp_set_name("ef", 6) == "omr_dscp_classify_ef_6"


# ===========================================================================
# Helper: _nft_refresh_dscp_set / _nft_ensure_dscp_sets
# (these, plus every other _nft_sync_*/_nft_ensure_* helper, apply their
# script via one `nft -f -` call -- subprocess.run's `input` kwarg is the
# exact transaction that would be committed, so that's what these assert on
# rather than a real nft binary.)
# ===========================================================================


def _applied_script(run_mock):
    """The nft script text passed to the mocked `nft -f -` call."""
    return run_mock.call_args.kwargs["input"].decode()


class TestNftRefreshDscpSet:
    def test_flush_and_add_element_are_one_atomic_call(self):
        with patch("subprocess.run") as run:
            run.return_value.returncode = 0
            omr_admin._nft_refresh_dscp_set("cs4", 4, ["10.0.0.0/24", "10.0.1.0/24"])
        run.assert_called_once()
        script = _applied_script(run)
        assert "flush set inet omr omr_dscp_classify_cs4_4" in script
        assert "add element inet omr omr_dscp_classify_cs4_4 { 10.0.0.0/24, 10.0.1.0/24 }" in script

    def test_empty_cidrs_only_flushes(self):
        with patch("subprocess.run") as run:
            run.return_value.returncode = 0
            omr_admin._nft_refresh_dscp_set("ef", 6, [])
        script = _applied_script(run)
        assert "flush set inet omr omr_dscp_classify_ef_6" in script
        assert "add element" not in script


class TestNftEnsureDscpSets:
    def test_declares_v4_and_v6_sets_for_every_class(self):
        with patch("subprocess.run") as run:
            run.return_value.returncode = 0
            omr_admin._nft_ensure_dscp_sets()
        script = _applied_script(run)
        for dscp in omr_admin.DSCP_CLASSIFY_CLASSES:
            assert f"add set inet omr omr_dscp_classify_{dscp}_4 {{ type ipv4_addr; flags interval; }}" in script
            assert f"add set inet omr omr_dscp_classify_{dscp}_6 {{ type ipv6_addr; flags interval; }}" in script


# ===========================================================================
# Helper: _render_dscp_mark (pure -- no mocking needed)
# ===========================================================================


class TestRenderDscpMark:
    def test_one_v4_and_one_v6_rule_per_class(self):
        lines = omr_admin._render_dscp_mark()
        assert len(lines) == len(omr_admin.DSCP_CLASSIFY_CLASSES) * 2
        v4 = next(l for l in lines if "omr_dscp_classify_cs4_4" in l)
        assert v4.startswith("ip daddr @omr_dscp_classify_cs4_4 ip dscp set cs4")
        v6 = next(l for l in lines if "omr_dscp_classify_cs4_6" in l)
        assert v6.startswith("ip6 daddr @omr_dscp_classify_cs4_6 ip6 dscp set cs4")


# ===========================================================================
# Helper: _nft_sync_dscp_mark
# ===========================================================================


class TestNftSyncDscpMark:
    def test_flushes_and_repopulates_the_chain_atomically(self):
        with patch("subprocess.run") as run:
            run.return_value.returncode = 0
            omr_admin._nft_sync_dscp_mark()
        run.assert_called_once()
        script = _applied_script(run)
        assert "flush chain inet omr dscp_mark" in script
        for dscp in omr_admin.DSCP_CLASSIFY_CLASSES:
            assert f"omr_dscp_classify_{dscp}_4" in script
            assert f"omr_dscp_classify_{dscp}_6" in script


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

"""
Unit tests for sync_ss_go_users().

The function reads /etc/shadowsocks-go/upsks.json and ensures every user
present there also exists in xray and mqvpn, adding them when missing.

Strategy
--------
- os.path.isfile is patched per-test to control which config files "exist".
- builtins.open is patched per-test (overriding the autouse patch_env patch)
  to serve in-memory JSON for each config path.
- xray_add_user and add_mqvpn are patched on the module to intercept calls
  without touching the filesystem.
"""

import io
import json
from unittest.mock import call, patch

import pytest

from conftest import _mock_open, omr_admin

# ---------------------------------------------------------------------------
# Fixture data
# ---------------------------------------------------------------------------

_UPSKS_ONE = {"alice": "alicekey=="}
_UPSKS_TWO = {"alice": "alicekey==", "bob": "bobkey=="}

_XRAY_EMPTY = {
    "inbounds": [
        {"tag": "omrin-tunnel", "settings": {"clients": []}},
        {"tag": "omrin-vmess-tunnel", "settings": {"clients": []}},
        {"tag": "omrin-shadowsocks-tunnel", "settings": {"clients": []}},
        {"tag": "omrin-socks-tunnel", "settings": {"accounts": []}},
    ]
}

_XRAY_WITH_ALICE_CLIENT = {
    "inbounds": [
        {
            "tag": "omrin-tunnel",
            "settings": {
                "clients": [{"email": "alice", "id": "some-uuid", "level": 0, "alterId": 0}]
            },
        }
    ]
}

_XRAY_WITH_ALICE_SOCKS = {
    "inbounds": [
        {
            "tag": "omrin-socks-tunnel",
            "settings": {"accounts": [{"user": "alice", "pass": "secret"}]},
        }
    ]
}

_MQVPN_EMPTY = {"users": []}
_MQVPN_WITH_ALICE = {"users": [{"name": "alice", "key": "mqvpnkey"}]}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SS_GO_CFG = "/etc/shadowsocks-go/upsks.json"
XRAY_CFG = "/etc/xray/xray-server.json"
MQVPN_CFG = "/etc/mqvpn/server.json"


def _isfile_for(*paths):
    return lambda p: str(p) in paths


def _open_with(upsks=None, xray=None, mqvpn=None):
    """Return an open() side_effect serving in-memory JSON for known paths."""
    mapping = {}
    if upsks is not None:
        mapping[SS_GO_CFG] = json.dumps(upsks)
    if xray is not None:
        mapping[XRAY_CFG] = json.dumps(xray)
    if mqvpn is not None:
        mapping[MQVPN_CFG] = json.dumps(mqvpn)

    def _open(path, mode="r", *args, **kwargs):
        sp = str(path)
        binary = "b" in str(mode)
        if sp in mapping:
            data = mapping[sp]
            return io.BytesIO(data.encode()) if binary else io.StringIO(data)
        return _mock_open(path, mode, *args, **kwargs)

    return _open


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSyncSsGoUsers:

    def test_no_upsks_file_is_noop(self):
        with (
            patch("os.path.isfile", return_value=False),
            patch.object(omr_admin, "xray_add_user") as mock_xray,
            patch.object(omr_admin, "add_mqvpn") as mock_mqvpn,
        ):
            omr_admin.sync_ss_go_users()

        mock_xray.assert_not_called()
        mock_mqvpn.assert_not_called()

    def test_no_xray_no_mqvpn_skips_both(self):
        with (
            patch("os.path.isfile", side_effect=_isfile_for(SS_GO_CFG)),
            patch("builtins.open", side_effect=_open_with(upsks=_UPSKS_ONE)),
            patch.object(omr_admin, "xray_add_user") as mock_xray,
            patch.object(omr_admin, "add_mqvpn") as mock_mqvpn,
        ):
            omr_admin.sync_ss_go_users()

        mock_xray.assert_not_called()
        mock_mqvpn.assert_not_called()

    def test_user_missing_from_xray_is_added(self):
        with (
            patch("os.path.isfile", side_effect=_isfile_for(SS_GO_CFG, XRAY_CFG)),
            patch("builtins.open", side_effect=_open_with(upsks=_UPSKS_ONE, xray=_XRAY_EMPTY)),
            patch.object(omr_admin, "xray_add_user") as mock_xray,
            patch.object(omr_admin, "add_mqvpn") as mock_mqvpn,
        ):
            omr_admin.sync_ss_go_users()

        mock_xray.assert_called_once_with("alice", "", "alicekey==")
        mock_mqvpn.assert_not_called()

    def test_existing_xray_client_not_re_added(self):
        with (
            patch("os.path.isfile", side_effect=_isfile_for(SS_GO_CFG, XRAY_CFG)),
            patch("builtins.open", side_effect=_open_with(upsks=_UPSKS_ONE, xray=_XRAY_WITH_ALICE_CLIENT)),
            patch.object(omr_admin, "xray_add_user") as mock_xray,
        ):
            omr_admin.sync_ss_go_users()

        mock_xray.assert_not_called()

    def test_existing_xray_socks_user_not_re_added(self):
        """Users stored in accounts[].user (socks inbound) are detected as present."""
        with (
            patch("os.path.isfile", side_effect=_isfile_for(SS_GO_CFG, XRAY_CFG)),
            patch("builtins.open", side_effect=_open_with(upsks=_UPSKS_ONE, xray=_XRAY_WITH_ALICE_SOCKS)),
            patch.object(omr_admin, "xray_add_user") as mock_xray,
        ):
            omr_admin.sync_ss_go_users()

        mock_xray.assert_not_called()

    def test_user_missing_from_mqvpn_is_added(self):
        with (
            patch("os.path.isfile", side_effect=_isfile_for(SS_GO_CFG, MQVPN_CFG)),
            patch("builtins.open", side_effect=_open_with(upsks=_UPSKS_ONE, mqvpn=_MQVPN_EMPTY)),
            patch.object(omr_admin, "xray_add_user") as mock_xray,
            patch.object(omr_admin, "add_mqvpn") as mock_mqvpn,
        ):
            omr_admin.sync_ss_go_users()

        mock_mqvpn.assert_called_once_with("alice")
        mock_xray.assert_not_called()

    def test_existing_mqvpn_user_not_re_added(self):
        with (
            patch("os.path.isfile", side_effect=_isfile_for(SS_GO_CFG, MQVPN_CFG)),
            patch("builtins.open", side_effect=_open_with(upsks=_UPSKS_ONE, mqvpn=_MQVPN_WITH_ALICE)),
            patch.object(omr_admin, "add_mqvpn") as mock_mqvpn,
        ):
            omr_admin.sync_ss_go_users()

        mock_mqvpn.assert_not_called()

    def test_user_added_to_both_when_missing_from_both(self):
        with (
            patch("os.path.isfile", side_effect=_isfile_for(SS_GO_CFG, XRAY_CFG, MQVPN_CFG)),
            patch("builtins.open", side_effect=_open_with(upsks=_UPSKS_ONE, xray=_XRAY_EMPTY, mqvpn=_MQVPN_EMPTY)),
            patch.object(omr_admin, "xray_add_user") as mock_xray,
            patch.object(omr_admin, "add_mqvpn") as mock_mqvpn,
        ):
            omr_admin.sync_ss_go_users()

        mock_xray.assert_called_once_with("alice", "", "alicekey==")
        mock_mqvpn.assert_called_once_with("alice")

    def test_multiple_users_partial_sync(self):
        """Alice is present in both; bob is missing from both → only bob is added."""
        with (
            patch("os.path.isfile", side_effect=_isfile_for(SS_GO_CFG, XRAY_CFG, MQVPN_CFG)),
            patch(
                "builtins.open",
                side_effect=_open_with(
                    upsks=_UPSKS_TWO,
                    xray=_XRAY_WITH_ALICE_CLIENT,
                    mqvpn=_MQVPN_WITH_ALICE,
                ),
            ),
            patch.object(omr_admin, "xray_add_user") as mock_xray,
            patch.object(omr_admin, "add_mqvpn") as mock_mqvpn,
        ):
            omr_admin.sync_ss_go_users()

        mock_xray.assert_called_once_with("bob", "", "bobkey==")
        mock_mqvpn.assert_called_once_with("bob")

    def test_xray_upsk_passed_correctly(self):
        """The upsk read from upsks.json is forwarded verbatim to xray_add_user."""
        upsks = {"testuser": "MySpecialKey123=="}
        with (
            patch("os.path.isfile", side_effect=_isfile_for(SS_GO_CFG, XRAY_CFG)),
            patch("builtins.open", side_effect=_open_with(upsks=upsks, xray=_XRAY_EMPTY)),
            patch.object(omr_admin, "xray_add_user") as mock_xray,
        ):
            omr_admin.sync_ss_go_users()

        mock_xray.assert_called_once_with("testuser", "", "MySpecialKey123==")

    def test_corrupt_upsks_json_does_not_raise(self):
        def _bad_open(path, mode="r", *args, **kwargs):
            if str(path) == SS_GO_CFG:
                return io.StringIO("{not valid json")
            return _mock_open(path, mode, *args, **kwargs)

        with (
            patch("os.path.isfile", side_effect=_isfile_for(SS_GO_CFG)),
            patch("builtins.open", side_effect=_bad_open),
            patch.object(omr_admin, "xray_add_user") as mock_xray,
            patch.object(omr_admin, "add_mqvpn") as mock_mqvpn,
        ):
            omr_admin.sync_ss_go_users()  # must not raise

        mock_xray.assert_not_called()
        mock_mqvpn.assert_not_called()

    def test_corrupt_xray_json_still_adds_to_mqvpn(self):
        """A broken xray config is silently skipped; mqvpn sync still runs."""
        def _bad_open(path, mode="r", *args, **kwargs):
            if str(path) == XRAY_CFG:
                return io.StringIO("{not valid json")
            return _open_with(upsks=_UPSKS_ONE, mqvpn=_MQVPN_EMPTY)(path, mode, *args, **kwargs)

        with (
            patch("os.path.isfile", side_effect=_isfile_for(SS_GO_CFG, XRAY_CFG, MQVPN_CFG)),
            patch("builtins.open", side_effect=_bad_open),
            patch.object(omr_admin, "xray_add_user") as mock_xray,
            patch.object(omr_admin, "add_mqvpn") as mock_mqvpn,
        ):
            omr_admin.sync_ss_go_users()

        mock_xray.assert_called_once_with("alice", "", "alicekey==")
        mock_mqvpn.assert_called_once_with("alice")

"""
mqvpn_auto_fixed_ip: MQVPN fixed IPs picked by omr-admin, for new users
(add_mqvpn) and, at startup, for the users without one.
"""

import builtins
import json
from unittest.mock import patch

import pytest

from conftest import omr_admin

_REAL_OPEN = builtins.open

_USERS = {"admin": {"permissions": "admin"},
          "r0": {"userid": 0, "vpnremoteip": "10.255.220.7"},       # connected now
          "r1": {"userid": 1, "vpnremoteip": "10.255.252.2"},       # on OpenVPN: not MQVPN's
          "r2": {"userid": 2},
          "r3": {"userid": 3, "vpnremoteip": "10.255.220.5"}}       # another router's address


@pytest.fixture
def mqvpn(tmp_path, monkeypatch):
    """server.json in tmp_path; yields (state, mqvpn_api calls)."""
    server = tmp_path / "server.json"
    state = {"config": {"mqvpn_auto_fixed_ip": True, "users": [_USERS]},
             "server": {"subnet": "10.255.220.0/24", "users": [{"name": "r2", "key": "k", "fixed_ip": "10.255.220.3"}]},
             "api": {"ok": True}}
    calls = []
    mocked_open = builtins.open   # conftest's: the config lock file and the rest

    def fake_open(path, *a, **kw):
        if str(path) == "/etc/mqvpn/server.json":
            server.write_text(json.dumps(state["server"]))
            return _REAL_OPEN(server, *a, **kw)
        return mocked_open(path, *a, **kw)

    def fake_api(cmd):
        calls.append(cmd)
        return state["api"](cmd) if callable(state["api"]) else state["api"]

    monkeypatch.setattr(omr_admin, "open", fake_open, raising=False)
    monkeypatch.setattr(omr_admin, "read_omr_config", lambda: state["config"])
    monkeypatch.setattr(omr_admin, "mqvpn_api", fake_api)
    monkeypatch.setattr(omr_admin, "_atomic_write_json", lambda p, data, **kw: state.__setitem__("server", data))
    with patch("os.path.isfile", lambda p: p == "/etc/mqvpn/server.json"):
        yield state, calls


def test_pick(mqvpn):
    state, _ = mqvpn
    cfg = state["server"]
    pick = omr_admin._mqvpn_pick_fixed_ip
    assert pick(cfg, "r0") == "10.255.220.7"      # keeps its address of now
    # r1's vpnremoteip isn't MQVPN's; userid 1 + 2 = .3 is r2's fixed IP:
    # the first free one, past .1 (mqvpn's) .3 (r2) .5 (r3) .7 (r0)
    assert pick(cfg, "r1") == "10.255.220.2"
    assert pick(cfg, "r3") == "10.255.220.5"
    assert pick(cfg, "nobody") == "10.255.220.2"
    # a suspended user's fixed IP is not given away
    state["config"]["users"][0] = dict(_USERS, r1=dict(_USERS["r1"], access_suspended={
        "mqvpn": {"user": {"name": "r1", "fixed_ip": "10.255.220.2"}}}))
    assert pick(cfg, "nobody") == "10.255.220.4"
    # full: .1 mqvpn, .2 suspended r1, .3 r2, .5 r3, .4 and .6 taken below
    small = {"subnet": "10.255.220.0/29", "users": cfg["users"] + [
        {"name": "x", "fixed_ip": "10.255.220.4"}, {"name": "y", "fixed_ip": "10.255.220.6"}]}
    assert pick(small, "r0") is None


def test_add_user(mqvpn):
    state, calls = mqvpn
    omr_admin.add_mqvpn("r0")
    assert calls[-1]["cmd"] == "add_user" and calls[-1]["fixed_ip"] == "10.255.220.7"
    assert state["server"]["users"][-1]["fixed_ip"] == "10.255.220.7"


def test_add_user_off_by_default(mqvpn):
    state, calls = mqvpn
    del state["config"]["mqvpn_auto_fixed_ip"]
    omr_admin.add_mqvpn("r0")
    assert "fixed_ip" not in calls[-1] and "fixed_ip" not in state["server"]["users"][-1]


def test_add_user_refused(mqvpn):
    state, calls = mqvpn
    state["api"] = lambda cmd: ({"ok": False, "error": "fixed_ip invalid or unavailable"}
                                if "fixed_ip" in cmd else {"ok": True})
    omr_admin.add_mqvpn("r0")
    assert len(calls) == 2 and "fixed_ip" not in calls[1]
    assert "fixed_ip" not in state["server"]["users"][-1]


def test_startup(mqvpn):
    state, calls = mqvpn
    state["server"]["users"] += [{"name": "r0", "key": "k"}, {"name": "r1", "key": "k"}]
    # r0's address is in use by its own session: mqvpn refuses it live
    state["api"] = lambda cmd: {"ok": cmd["name"] != "r0"}
    omr_admin.mqvpn_auto_fixed_ips()
    assert [(c["cmd"], c["name"], c["fixed_ip"]) for c in calls] == [
        ("set_user_fixed_ip", "r0", "10.255.220.7"), ("set_user_fixed_ip", "r1", "10.255.220.2")]
    assert {u["name"]: u["fixed_ip"] for u in state["server"]["users"]} == {
        "r2": "10.255.220.3", "r0": "10.255.220.7", "r1": "10.255.220.2"}
    calls.clear()
    omr_admin.mqvpn_auto_fixed_ips()
    assert calls == []


def test_startup_refused_for_another_session(mqvpn):
    """Refused for an address another router's dynamic session holds: not
    saved, or that router's /vpnips was refused as another user's address."""
    state, calls = mqvpn
    state["server"]["users"] += [{"name": "r0", "key": "k"}, {"name": "r1", "key": "k"}]
    state["api"] = {"ok": False, "error": "fixed_ip invalid or unavailable"}
    omr_admin.mqvpn_auto_fixed_ips()
    assert len(calls) == 2
    # r0 holds .7 itself: pinned from mqvpn's next start; r1's .2 is not its own
    assert {u["name"]: u.get("fixed_ip") for u in state["server"]["users"]} == {
        "r2": "10.255.220.3", "r0": "10.255.220.7", "r1": None}


def test_startup_off(mqvpn):
    state, calls = mqvpn
    state["config"]["mqvpn_auto_fixed_ip"] = False
    state["server"]["users"].append({"name": "r0", "key": "k"})
    omr_admin.mqvpn_auto_fixed_ips()
    assert calls == [] and "fixed_ip" not in state["server"]["users"][-1]

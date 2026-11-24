"""
omr_bgp optional module: config endpoints, the generated BIRD and nft
configs, and the sync that announces only the connected routers.
"""

import builtins
import json
from unittest.mock import MagicMock, patch

import pytest

_REAL_OPEN = builtins.open

import omr_bgp
from conftest import omr_admin, app  # noqa: F401  (loads omradmin with omr_bgp)

_BGP = {"local_as": 65001,
        "neighbors": [{"name": "up1", "address": "192.0.2.1", "as": 64500, "password": "s3cret", "multihop": 2},
                      {"name": "up6", "address": "2001:db8::ffff", "as": 64500}],
        "pools": ["203.0.113.0/30", "2001:db8:1::/126"]}

_INNER = {"r1": {"ipv4": ["10.255.220.5"], "ipv6": ["fd00::a00:6", "fda2:b17b:c16e::/48"]},
          "r2": {"ipv4": ["10.255.220.6"]}}
_INNER_FILES = dict(_INNER, nofixed={"ipv6": ["fd00::a00:a"]},
                    main={"ipv6": ["fd00::a00:2"]})


@pytest.fixture
def bgp(tmp_path, monkeypatch):
    monkeypatch.setattr(omr_bgp, "open", _REAL_OPEN, raising=False)
    monkeypatch.setattr(omr_bgp, "BGP_FILE", str(tmp_path / "omr-bgp.json"))
    monkeypatch.setattr(omr_bgp, "BIRD_CONF", str(tmp_path / "bird.conf"))
    monkeypatch.setattr(omr_bgp, "BIRD_INCLUDE", str(tmp_path / "omr-bgp.conf"))
    monkeypatch.setattr(omr_bgp, "MQVPN_FILE", str(tmp_path / "server.json"))
    monkeypatch.setattr(omr_bgp, "OMR_CONFIG_FILE", str(tmp_path / "omr-admin-config.json"))
    monkeypatch.setattr(omr_bgp, "OMR_6IN4_DIR", str(tmp_path / "omr-6in4"))
    monkeypatch.setattr(omr_bgp, "_applied", None)
    monkeypatch.setattr(omr_bgp, "_leader_fd", None)
    monkeypatch.setattr(omr_bgp, "_vps_addresses", lambda: set())
    (tmp_path / "server.json").write_text(json.dumps({"users": [
        {"name": "r1", "key": "k", "fixed_ip": "10.255.220.5"},
        {"name": "r2", "key": "k", "fixed_ip": "10.255.220.6"},
        {"name": "nofixed", "key": "k"},
        {"name": "bad", "key": "k", "fixed_ip": "10.0.0.1; flush ruleset"}]}))
    # trailing comma: omr-admin accepts it
    (tmp_path / "omr-admin-config.json").write_text(
        '{"users": [{"r1": {"userid": 1}, "r2": {"userid": 2}, "nofixed": {"userid": 3}, "bad": {"userid": 4},'
        ' "main": {"userid": 0},}]}')
    (tmp_path / "omr-6in4").mkdir()
    (tmp_path / "omr-6in4" / "user1").write_text(
        "LOCALIP=10.255.220.1\nREMOTEIP=10.255.220.5\nLOCALIP6=fd00::a00:5/126\nREMOTEIP6=fd00::a00:6/126\n"
        "ULA=fda2:b17b:c16e::/48\n")
    (tmp_path / "omr-6in4" / "user4").write_text("REMOTEIP6=fd00::1 } accept\n")
    # ULA=auto (the router picks it) keeps the endpoint
    (tmp_path / "omr-6in4" / "user3").write_text("REMOTEIP6=fd00::a00:a/126\nULA=auto\n")
    # the main router's global prefix is not NATed
    (tmp_path / "omr-6in4" / "user0").write_text("REMOTEIP6=fd00::a00:2/126\nULA=2001:db8:ab00::/56\n")
    (tmp_path / "bird.conf").write_text("router id 192.0.2.10;\n")
    yield tmp_path
    omr_bgp.stop()


def test_inner_addresses(bgp):
    # what can't be parsed never reaches nft
    assert omr_bgp._inner_addresses() == _INNER_FILES


def test_render():
    cfg = dict(_BGP, routers={"r1": {"ipv4": "203.0.113.1", "ipv6": "2001:db8:1::1"},
                              "r2": {"ipv4": "203.0.113.2", "ipv6": "2001:db8:1::2"}})
    active = omr_bgp.active_routes(cfg, {"r1"}, _INNER)
    assert active == {"203.0.113.1": ["10.255.220.5"], "2001:db8:1::1": ["fd00::a00:6", "fda2:b17b:c16e::/48"]}
    # r2 connected, but without a 6in4 tunnel: only its IPv4
    assert set(omr_bgp.active_routes(cfg, {"r2"}, _INNER)) == {"203.0.113.2"}
    bird = omr_bgp.render_bird(cfg, active)
    assert "route 203.0.113.1/32 blackhole;" in bird and "route 2001:db8:1::1/128 blackhole;" in bird
    assert "203.0.113.2" not in bird
    assert "neighbor 192.0.2.1 as 64500;" in bird and 'password "s3cret";' in bird and "multihop 2;" in bird
    up1, up6 = bird.split("protocol bgp omr_up1")[1].split("protocol bgp omr_up6")
    assert 'ipv4 {' in up1 and 'proto = "omr_routers"' in up1 and 'ipv6' not in up1
    assert 'ipv6 {' in up6 and 'proto = "omr_routers6"' in up6
    nft = omr_bgp.render_nft(active)
    assert "table inet omr_bgp" in nft
    assert "ip daddr 203.0.113.1 dnat ip to 10.255.220.5" in nft
    assert "ip saddr { 10.255.220.5 } snat ip to 203.0.113.1" in nft
    assert "ip6 daddr 2001:db8:1::1 dnat ip6 to fd00::a00:6" in nft
    assert "ip6 saddr { fd00::a00:6, fda2:b17b:c16e::/48 } snat ip6 to 2001:db8:1::1" in nft


def test_admin_only(bgp, user_client):
    assert user_client.post("/bgp", json=_BGP).json()["result"] == "permission"
    assert user_client.get("/bgp").json()["result"] == "permission"


def test_endpoints(bgp, admin_client):
    def router(**kw):
        return admin_client.post("/bgp/router", json=kw).json()
    bad = dict(_BGP, neighbors=[dict(_BGP["neighbors"][0], password='a"b')])
    assert admin_client.post("/bgp", json=bad).json()["result"] == "error"
    assert admin_client.post("/bgp", json=_BGP).json()["result"] == "done"
    assert router(username="nofixed")["result"] == "error"
    assert router(username="r1")["public_ip"] == "203.0.113.1"
    assert router(username="r1", family=6)["public_ip"] == "2001:db8:1::1"
    assert router(username="r2", family=6)["reason"] == "User has no 6in4 tunnel"
    assert router(username="r2", public_ip="203.0.113.1")["result"] == "error"      # taken
    assert router(username="r2", public_ip="2001:db8:1::2", family=4)["result"] == "error"
    assert router(username="r2", public_ip="2001:db9::1")["result"] == "error"      # out of the pools
    assert router(username="r2")["public_ip"] == "203.0.113.2"
    # /30 hosts: .1 and .2 only, and the routers must stay in the pools
    assert admin_client.post("/bgp", json=dict(_BGP, pools=["203.0.113.0/30"])).json()["result"] == "error"
    assert omr_bgp._read_cfg()["routers"] == {"r1": {"ipv4": "203.0.113.1", "ipv6": "2001:db8:1::1"},
                                              "r2": {"ipv4": "203.0.113.2"}}
    with patch("omr_bgp.shutil.which", return_value=None), \
            patch("omr_bgp._mqvpn_status", lambda: {"clients": [{"user": "r1"}]}):
        routers = admin_client.get("/bgp").json()["routers"]
    assert routers[0] == {"username": "r1", "ipv4": "203.0.113.1", "ipv6": "2001:db8:1::1",
                          "fixed_ip": "10.255.220.5", "ipv6_endpoint": "fd00::a00:6", "connected": True,
                          "announced": ["2001:db8:1::1", "203.0.113.1"]}
    assert admin_client.post("/bgp/router/remove", json={"username": "r1", "family": 6}).json()["result"] == "done"
    assert admin_client.post("/bgp/router/remove", json={"username": "r2"}).json()["result"] == "done"
    assert omr_bgp._read_cfg()["routers"] == {"r1": {"ipv4": "203.0.113.1"}}


def test_sync(bgp, monkeypatch):
    (bgp / "omr-bgp.json").write_text(json.dumps(dict(_BGP, routers={
        "r1": {"ipv4": "203.0.113.1", "ipv6": "2001:db8:1::1"}, "r2": {"ipv4": "203.0.113.2"}})))
    monkeypatch.setattr(omr_bgp, "_mqvpn_status", lambda: {"clients": [{"user": "r1"}]})
    run = MagicMock(return_value=MagicMock(returncode=0, stdout="Reconfigured\n", stderr=""))
    with patch("omr_bgp.subprocess.run", run), patch("omr_bgp.shutil.which", return_value="/usr/sbin/birdc"):
        omr_bgp.sync_once()
        assert run.call_count == 2   # birdc configure, nft -f
        conf = (bgp / "omr-bgp.conf").read_text()
        assert "203.0.113.1/32" in conf and "2001:db8:1::1/128" in conf
        assert 'include "%s";' % omr_bgp.BIRD_INCLUDE in (bgp / "bird.conf").read_text()
        omr_bgp.sync_once()
        assert run.call_count == 2   # nothing changed, nothing applied
        # control socket down: kept for a while, then every route withdrawn
        monkeypatch.setattr(omr_bgp, "_mqvpn_status", lambda: None)
        for _ in range(omr_bgp.MQVPN_FAILURES_MAX - 1):
            omr_bgp.sync_once()
        assert run.call_count == 2
        omr_bgp.sync_once()
        assert "203.0.113.1" not in (bgp / "omr-bgp.conf").read_text()


def test_password_newline_refused(bgp, admin_client):
    # match() took a trailing newline into BIRD's config, which then refused it
    bad = dict(_BGP, neighbors=[dict(_BGP["neighbors"][0], password="s3cret\n")])
    assert admin_client.post("/bgp", json=bad).json()["result"] == "error"
    bad = dict(_BGP, neighbors=[dict(_BGP["neighbors"][0], name="up1\n")])
    assert admin_client.post("/bgp", json=bad).json()["result"] == "error"
    bad = dict(_BGP, neighbors=[dict(_BGP["neighbors"][0], address="fe80::1")])
    assert admin_client.post("/bgp", json=bad).json()["result"] == "error"


def test_static_protocol_names_and_whole_internet_refused(bgp, admin_client):
    # omr_routers(6) are the static protocols: BIRD refused the whole config
    for name in ("routers", "routers6"):
        bad = dict(_BGP, neighbors=[dict(_BGP["neighbors"][0], name=name)])
        assert admin_client.post("/bgp", json=bad).json()["reason"] == "Invalid or duplicate neighbor name"
    for pool in ("0.0.0.0/0", "::/0"):
        assert admin_client.post("/bgp", json=dict(_BGP, pools=[pool])).json()["reason"] == "Invalid pool"


def test_vps_address_never_given(bgp, admin_client, monkeypatch):
    # its DNAT took SSH, the API and MQVPN itself to the router
    monkeypatch.setattr(omr_bgp, "_vps_addresses", lambda: {"203.0.113.1", "2001:db8:1:0::1"})
    assert admin_client.post("/bgp", json=_BGP).json()["result"] == "done"
    r = admin_client.post("/bgp/router", json={"username": "r1", "public_ip": "203.0.113.1"}).json()
    assert r["reason"] == "public_ip is an address of the VPS"
    assert admin_client.post("/bgp/router", json={"username": "r1"}).json()["public_ip"] == "203.0.113.2"
    assert admin_client.post("/bgp/router", json={"username": "r1", "family": 6}).json()["public_ip"] == "2001:db8:1::2"


def test_nat_applied_when_bird_refuses(bgp, monkeypatch):
    (bgp / "omr-bgp.json").write_text(json.dumps(dict(_BGP, routers={"r1": {"ipv4": "203.0.113.1"}})))
    monkeypatch.setattr(omr_bgp, "_mqvpn_status", lambda: {"clients": [{"user": "r1"}]})
    run = MagicMock(return_value=MagicMock(returncode=0, stdout="Unable to connect\n", stderr=""))
    with patch("omr_bgp.subprocess.run", run), patch("omr_bgp.shutil.which", return_value="/usr/sbin/birdc"):
        omr_bgp.sync_once()
    assert [c.args[0][0] for c in run.call_args_list] == ["birdc", "nft"]
    assert omr_bgp._applied is None   # retried next round


def test_corrupt_config_read_as_empty(bgp, admin_client):
    (bgp / "omr-bgp.json").write_text('{"local_as": 65001,')
    assert admin_client.get("/bgp").json()["config"] == {}
    assert admin_client.post("/bgp", json=_BGP).json()["result"] == "done"
    assert omr_bgp._read_cfg()["local_as"] == 65001

"""
/global_options: the server-wide options of omr-admin-config.json, admin only.
"""

from unittest.mock import patch

import pytest

from conftest import omr_admin


@pytest.fixture
def config():
    """The config as _mutate_omr_config changes it; yields it."""
    data = {"users": [{}], "gre_tunnels": False, "glorytun_udp_type": "dhcp"}

    def mutate(mutator, **kw):
        mutator(data)
    with patch("omr_admin.read_omr_config", lambda: data), \
            patch("omr_admin._mutate_omr_config", side_effect=mutate):
        yield data


def test_admin_only(config, user_client):
    assert user_client.get("/global_options").json()["result"] == "permission"
    assert user_client.post("/global_options", json={"debug": True}).json()["result"] == "permission"
    assert "debug" not in config


def test_get(config, admin_client):
    options = admin_client.get("/global_options").json()["options"]
    assert options == dict(omr_admin.GLOBAL_OPTIONS, gre_tunnels=False, glorytun_udp_type="dhcp")
    assert options["mqvpn_auto_fixed_ip"] is False and options["6in4"] is True


def test_set_only_what_is_sent(config, admin_client):
    with patch("omr_admin.mqvpn_auto_fixed_ips") as fill:
        r = admin_client.post("/global_options", json={"mqvpn_auto_fixed_ip": True, "6in4": False,
                                                       "glorytun_tcp_type": "dhcp"}).json()
    assert r["result"] == "done" and r["changed"] == ["6in4", "glorytun_tcp_type", "mqvpn_auto_fixed_ip"]
    assert config["mqvpn_auto_fixed_ip"] is True and config["6in4"] is False
    assert config["glorytun_tcp_type"] == "dhcp" and config["gre_tunnels"] is False
    fill.assert_called_once_with()   # the users without a fixed IP, right away


@pytest.mark.parametrize("payload", [{"unknown": True}, {"glorytun_tcp_type": "other"}, {"debug": "maybe"}])
def test_refused(config, admin_client, payload):
    assert admin_client.post("/global_options", json=payload).status_code == 422
    assert set(config) == {"users", "gre_tunnels", "glorytun_udp_type"}


def test_side_effects(config, admin_client):
    with patch("omr_admin._nft_sync_sipalg", return_value=True) as sip, \
            patch("omr_admin._sync_openvpn_client2client") as openvpn, \
            patch("omr_admin._nft_sync_client2client") as c2c, \
            patch("omr_admin.mqvpn_auto_fixed_ips") as fill:
        r = admin_client.post("/global_options", json={"sipalg": True, "client2client": True,
                                                       "mqvpn_auto_fixed_ip": False}).json()
    assert r["result"] == "done"
    sip.assert_called_once_with(True)
    openvpn.assert_called_once_with(True)
    c2c.assert_called_once_with()
    fill.assert_not_called()
    with patch("omr_admin._nft_sync_sipalg", return_value=False):
        r = admin_client.post("/global_options", json={"sipalg": True}).json()
    assert r["result"] == "error" and r["reason"] == omr_admin._SIPALG_NOT_APPLIED


def test_debug(config, admin_client):
    level = omr_admin.LOG.level
    try:
        admin_client.post("/global_options", json={"debug": True})
        assert omr_admin.LOG.level == omr_admin.logging.DEBUG
        admin_client.post("/global_options", json={"debug": False})
        assert omr_admin.LOG.level == omr_admin.logging.NOTSET
    finally:
        omr_admin.LOG.setLevel(level)

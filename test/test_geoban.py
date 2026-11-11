"""
omr-geoban endpoints: /geoban, /geoban_source, /geoban_check, /geoban_asn.

The script itself (openmptcprouter-vps) is mocked: these check what
omr-admin passes it, what it writes to omr-geoban.conf, and how it reads the
answers.
"""

import contextlib
from unittest.mock import MagicMock, patch

import pytest

from conftest import omr_admin, app

BIN = omr_admin.GEOBAN_BIN

_CONF = (
    '# comment kept\n'
    'MODE="allow"\n'
    'COUNTRIES="fr -as16276"\n'
    'EXEMPT="203.0.113.7"\n'
    'OPEN_PORTS=""\n'
    'SOURCE="dbip"\n'
    'MAXMIND_ACCOUNT_ID="123456"\n'
    'MAXMIND_LICENSE_KEY="secret_key"\n'
)


def _result(returncode=0, stdout="", stderr=""):
    return MagicMock(returncode=returncode, stdout=stdout, stderr=stderr)


@contextlib.contextmanager
def _geoban(conf=_CONF, run=None, installed=True):
    """omr-geoban installed with *conf* as its configuration; yields the
    subprocess.run and _atomic_write_text mocks."""
    run = run or MagicMock(return_value=_result())
    with (
        patch("os.path.isfile", return_value=installed),
        patch("omr_admin._geoban_file_lock", contextlib.nullcontext),
        patch("omr_admin._geoban_api_lock", contextlib.nullcontext),
        patch("omr_admin._geoban_conf_text", return_value=conf),
        patch("omr_admin._geoban_dropped", return_value=None),
        patch("omr_admin._atomic_write_text") as write,
        patch("os.chmod"),
        patch("omr_admin.subprocess.run", run),
    ):
        yield run, write


def _geoban_calls(run):
    return [c.args[0][1:] for c in run.call_args_list if c.args and c.args[0][0] == BIN]


@pytest.fixture
def other_client():
    """A read-write router that is not the main one (userid 1)."""
    from conftest import _ASGITestClient
    user = omr_admin.User(username="other", userid=1, permissions="rw", disabled=False)
    app.dependency_overrides[omr_admin.get_current_user] = lambda: user
    yield _ASGITestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.pop(omr_admin.get_current_user, None)


# ===========================================================================
# Configuration file
# ===========================================================================


class TestConf:
    def test_get_last_line_and_quotes(self):
        text = 'MODE="allow"\n  MODE="deny"\nEXEMPT=1.2.3.4\n'
        assert omr_admin._geoban_conf_get(text, "MODE") == "deny"
        assert omr_admin._geoban_conf_get(text, "EXEMPT") == "1.2.3.4"
        assert omr_admin._geoban_conf_get(text, "SOURCE", "dbip") == "dbip"
        assert omr_admin._geoban_conf_get(None, "MODE", "off") == "off"

    def test_set_replaces_first_drops_duplicates_keeps_comments(self):
        text = '# keep\nEXEMPT="a"\nMODE="off"\nEXEMPT="b"\n'
        out = omr_admin._geoban_conf_set(text, {"EXEMPT": "1.2.3.4", "OPEN_PORTS": "tcp/22"})
        assert out == '# keep\nEXEMPT="1.2.3.4"\nMODE="off"\nOPEN_PORTS="tcp/22"\n'

    def test_set_without_file(self):
        assert omr_admin._geoban_conf_set(None, {"MODE": "off"}) == 'MODE="off"\n'

    @pytest.mark.real_env
    def test_update_and_restore(self, tmp_path):
        conf = tmp_path / "omr-geoban.conf"
        conf.write_text('# c\nMODE="off"\n')
        conf.chmod(0o644)
        with (
            patch.object(omr_admin, "GEOBAN_CONF", str(conf)),
            patch.object(omr_admin, "GEOBAN_LOCK", str(tmp_path / "lock")),
        ):
            old = omr_admin._geoban_update_conf({"EXEMPT": "10.0.0.1"})
            assert conf.read_text() == '# c\nMODE="off"\nEXEMPT="10.0.0.1"\n'
            assert conf.stat().st_mode & 0o777 == 0o600
            omr_admin._geoban_restore_conf(old)
            assert conf.read_text() == '# c\nMODE="off"\n'
            conf.unlink()
            omr_admin._geoban_update_conf({"MODE": "off"})
            omr_admin._geoban_restore_conf(None)
            assert not conf.exists()


class TestValidation:
    def test_words(self):
        assert omr_admin._geoban_words(["fr, de", "-ru", "as3215", "!AS16276", "north-america"]) == [
            "fr", "de", "-ru", "as3215", "!AS16276", "north-america"]
        for bad in (["--force"], ["fr;id"], ["$(id)"], ["f"], ['fr"']):
            assert omr_admin._geoban_words(bad) is None, bad

    def test_exempt(self):
        assert omr_admin._geoban_exempt_entry("203.0.113.7") == "203.0.113.7"
        assert omr_admin._geoban_exempt_entry("203.0.113.7/24") == "203.0.113.0/24"
        assert omr_admin._geoban_exempt_entry("10.0.0.1-10.0.0.9") == "10.0.0.1-10.0.0.9"
        assert omr_admin._geoban_exempt_entry("2001:DB8::1") == "2001:db8::1"
        for bad in ("10.0.0.9-10.0.0.1", "10.0.0.1-::1", "1.2.3.4 5.6.7.8", 'x"', "1.2.3.4/33",
                    # a scope ID keeps any text, a new line and a key included
                    'fe80::1%x\nMODE="deny', 'fe80::1%eth0', 'fe80::%x\nA="b"/64',
                    'fe80::1%x\nA="b"-fe80::2', "10.0.0.1/24-10.0.0.9", "10.0.0.0/255.255.255.0"):
            assert omr_admin._geoban_exempt_entry(bad) is None, bad

    def test_open_port(self):
        assert omr_admin._geoban_open_port("TCP/65222") == "tcp/65222"
        assert omr_admin._geoban_open_port("udp/8000-8100") == "udp/8000-8100"
        assert omr_admin._geoban_open_port("udp/53-53") == "udp/53"
        for bad in ("sctp/1", "tcp/0", "tcp/70000", "tcp/9-8", "tcp/22,23"):
            assert omr_admin._geoban_open_port(bad) is None, bad


# ===========================================================================
# GET /geoban
# ===========================================================================


class TestGeobanGet:
    def test_requires_auth(self, unauth_client):
        assert unauth_client.get("/geoban").status_code == 403

    def test_other_router_refused(self, other_client):
        with _geoban():
            assert other_client.get("/geoban").json()["result"] == "permission"

    def test_not_installed(self, admin_client):
        with _geoban(installed=False):
            assert admin_client.get("/geoban").json()["result"] == "warning"

    def test_status_never_returns_the_license_key(self, user_client):
        applied = "mode=allow\nranges4=20000\n"
        with (
            _geoban(),
            patch("omr_admin._geoban_dropped", return_value=17),
            patch("builtins.open", side_effect=lambda *a, **k: __import__("io").StringIO(applied)),
        ):
            r = user_client.get("/geoban")
        body = r.json()
        assert body["result"] == "done"
        geoban = body["geoban"]
        assert geoban["mode"] == "allow"
        assert geoban["countries"] == ["fr", "-as16276"]
        assert geoban["exempt"] == ["203.0.113.7"]
        assert geoban["open_ports"] == []
        assert geoban["active"] is True and geoban["dropped"] == 17
        assert geoban["applied"] == {"mode": "allow", "ranges4": "20000"}
        assert geoban["maxmind_license_key_set"] is True
        assert "secret_key" not in r.text

    def test_ssh_open_without_an_open_ports_line(self, admin_client):
        # As omr-geoban: no line is tcp/65222, an empty one is nothing
        for conf, expected in (('MODE="allow"\n', ["tcp/65222"]), (None, ["tcp/65222"]),
                               ('OPEN_PORTS=""\n', []), ('OPEN_PORTS="udp/53"\n', ["udp/53"])):
            with _geoban(conf=conf):
                assert admin_client.get("/geoban").json()["geoban"]["open_ports"] == expected, conf


# ===========================================================================
# POST /geoban
# ===========================================================================


class TestGeobanSet:
    def test_requires_auth(self, unauth_client):
        assert unauth_client.post("/geoban", json={"mode": "off"}).status_code == 403

    def test_ro_user_denied(self, ro_client):
        assert ro_client.post("/geoban", json={"mode": "off"}).json()["result"] == "permission"

    def test_other_router_refused(self, other_client):
        with _geoban() as (run, _write):
            assert other_client.post("/geoban", json={"mode": "off"}).json()["result"] == "permission"
        assert not _geoban_calls(run)

    def test_invalid_mode_422(self, admin_client):
        with _geoban():
            assert admin_client.post("/geoban", json={"mode": "block"}).status_code == 422

    def test_allow(self, admin_client):
        with _geoban() as (run, write):
            r = admin_client.post("/geoban", json={"mode": "allow", "countries": ["europe -ru", "-as16276"]})
        assert r.json()["result"] == "done"
        assert _geoban_calls(run) == [["allow", "europe", "-ru", "-as16276"]]
        # omr-geoban saves MODE and COUNTRIES itself
        write.assert_not_called()

    def test_force(self, admin_client):
        with _geoban() as (run, _write):
            admin_client.post("/geoban", json={"mode": "deny", "countries": ["cn"], "force": True})
        assert _geoban_calls(run) == [["deny", "cn", "--force"]]

    def test_invalid_countries_run_nothing(self, admin_client):
        with _geoban() as (run, _write):
            r = admin_client.post("/geoban", json={"mode": "allow", "countries": ["--force"]})
        assert r.json() == {"result": "error", "reason": "Invalid countries", "route": "geoban"}
        assert not _geoban_calls(run)

    def test_exempt_written_then_reapplied_with_current_list(self, admin_client):
        with _geoban() as (run, write):
            r = admin_client.post("/geoban", json={"exempt": ["198.51.100.1", "2001:db8::/48"],
                                                   "open_ports": ["tcp/65222"]})
        assert r.json()["result"] == "done"
        text = write.call_args.args[1]
        assert 'EXEMPT="198.51.100.1 2001:db8::/48"' in text
        assert 'OPEN_PORTS="tcp/65222"' in text
        assert "# comment kept" in text
        assert _geoban_calls(run) == [["allow", "fr", "-as16276"]]

    def test_invalid_exempt(self, admin_client):
        with _geoban() as (run, write):
            r = admin_client.post("/geoban", json={"exempt": ["1.2.3.4\nMODE=off"]})
        assert r.json()["reason"] == "Invalid exempt address"
        write.assert_not_called()
        assert not _geoban_calls(run)

    def test_refused_for_a_connected_peer_restores_the_conf(self, admin_client):
        stderr = ("omr-geoban: these peers, connected now, would be blocked:\n"
                  "omr-geoban:   198.51.100.9 (IT, AS3269 Telecom Italia), to port 65101\n"
                  "omr-geoban: nothing applied. Add them to EXEMPT (omr-geoban exempt add <address>), or run again with --force\n")
        run = MagicMock(return_value=_result(1, stderr=stderr))
        with _geoban(run=run) as (_run, write):
            r = admin_client.post("/geoban", json={"mode": "allow", "countries": ["fr"], "exempt": []})
        body = r.json()
        assert body["result"] == "conflict"
        assert body["blocked"] == ["198.51.100.9 (IT, AS3269 Telecom Italia), to port 65101"]
        # EXEMPT written for the check, then put back as it was
        assert [c.args[1] for c in write.call_args_list][-1] == _CONF

    def test_error_reports_last_line(self, admin_client):
        run = MagicMock(return_value=_result(1, stderr="omr-geoban: unknown country code UK: the United Kingdom is GB\n"))
        with _geoban(run=run):
            r = admin_client.post("/geoban", json={"mode": "allow", "countries": ["uk"]})
        assert r.json() == {"result": "error", "reason": "unknown country code UK: the United Kingdom is GB",
                            "route": "geoban"}

    def test_allow_without_countries(self, admin_client):
        with _geoban(conf='MODE="off"\n') as (run, _write):
            r = admin_client.post("/geoban", json={"mode": "allow"})
        assert r.json()["result"] == "error"
        assert not _geoban_calls(run)

    def test_off(self, user_client):
        with _geoban() as (run, _write):
            r = user_client.post("/geoban", json={"mode": "off"})
        assert r.json()["result"] == "done"
        assert _geoban_calls(run) == [["off"]]

    def test_off_refused_restores_the_conf(self, admin_client):
        run = MagicMock(return_value=_result(1, stderr="omr-geoban: another omr-geoban is running\n"))
        with _geoban(run=run) as (_run, write):
            r = admin_client.post("/geoban", json={"mode": "off", "exempt": ["1.2.3.4"], "countries": ["de"]})
        assert r.json()["result"] == "error"
        assert 'EXEMPT="1.2.3.4"' in write.call_args_list[0].args[1]
        assert write.call_args_list[-1].args[1] == _CONF

    def test_countries_saved_while_off(self, admin_client):
        with _geoban(conf='MODE="off"\n') as (run, write):
            r = admin_client.post("/geoban", json={"countries": ["fr"]})
        assert r.json()["result"] == "done"
        assert 'COUNTRIES="fr"' in write.call_args.args[1]
        assert not _geoban_calls(run)


# ===========================================================================
# POST /geoban_source
# ===========================================================================


class TestGeobanSource:
    def test_ro_user_denied(self, ro_client):
        assert ro_client.post("/geoban_source", json={"source": "dbip"}).json()["result"] == "permission"

    def test_maxmind_credentials_never_on_the_command_line(self, admin_client):
        with _geoban() as (run, write):
            r = admin_client.post("/geoban_source", json={"source": "maxmind", "maxmind_account_id": "42",
                                                          "maxmind_license_key": "Key_123"})
        assert r.json()["result"] == "done"
        assert _geoban_calls(run) == [["source", "maxmind"]]
        text = write.call_args.args[1]
        assert 'MAXMIND_ACCOUNT_ID="42"' in text and 'MAXMIND_LICENSE_KEY="Key_123"' in text
        assert "Key_123" not in r.text

    def test_invalid_key_422(self, admin_client):
        with _geoban() as (run, _write):
            r = admin_client.post("/geoban_source", json={"source": "maxmind", "maxmind_account_id": "42",
                                                          "maxmind_license_key": "a\"b"})
        assert r.status_code == 422
        assert not _geoban_calls(run)

    def test_account_without_key(self, admin_client):
        with _geoban():
            r = admin_client.post("/geoban_source", json={"source": "maxmind", "maxmind_account_id": "42"})
        assert r.json()["result"] == "error"

    def test_failed_switch_restores_the_credentials(self, admin_client):
        run = MagicMock(return_value=_result(1, stderr="omr-geoban: no country list from maxmind: still using dbip\n"))
        with _geoban(run=run) as (_run, write):
            r = admin_client.post("/geoban_source", json={"source": "maxmind", "maxmind_account_id": "42",
                                                          "maxmind_license_key": "Key_123", "force": True})
        assert r.json()["reason"] == "no country list from maxmind: still using dbip"
        assert _geoban_calls(run) == [["source", "maxmind", "--force"]]
        assert write.call_args_list[-1].args[1] == _CONF


# ===========================================================================
# POST /geoban_check, GET /geoban_asn
# ===========================================================================


class TestGeobanCheck:
    def test_other_router_refused(self, other_client):
        with _geoban():
            r = other_client.post("/geoban_check", json={"addresses": ["8.8.8.8"]})
        assert r.json()["result"] == "permission"

    def test_parsed(self, admin_client):
        out = ("8.8.8.8 US AS15169 (Google LLC) blocked\n"
               "203.0.113.7 ?? AS?? allowed (exempt)\n"
               "2a01:cb00::1 FR AS3215 (Orange (France)) allowed\n")
        with _geoban(run=MagicMock(return_value=_result(0, stdout=out))) as (run, _write):
            r = admin_client.post("/geoban_check", json={"addresses": ["8.8.8.8", "203.0.113.7", "2A01:CB00::1"]})
        assert _geoban_calls(run) == [["check", "8.8.8.8", "203.0.113.7", "2a01:cb00::1"]]
        assert r.json()["addresses"] == [
            {"address": "8.8.8.8", "country": "US", "asn": "15169", "organisation": "Google LLC", "verdict": "blocked"},
            {"address": "203.0.113.7", "country": "??", "asn": "??", "organisation": "", "verdict": "allowed (exempt)"},
            {"address": "2a01:cb00::1", "country": "FR", "asn": "3215", "organisation": "Orange (France)",
             "verdict": "allowed"},
        ]

    def test_invalid_address(self, admin_client):
        with _geoban() as (run, _write):
            r = admin_client.post("/geoban_check", json={"addresses": ["-h"]})
        assert r.json()["result"] == "error"
        assert not _geoban_calls(run)

    def test_scope_id_refused(self, admin_client):
        with _geoban() as (run, _write):
            r = admin_client.post("/geoban_check", json={"addresses": ["fe80::1%x\n1.2.3.4"]})
        assert r.json()["result"] == "error"
        assert not _geoban_calls(run)


class TestGeobanAsn:
    def test_parsed(self, admin_client):
        out = ("AS3215     FR      21000000 IPv4  Orange S.A.\n"
               "AS5511     FR       1200000 IPv4  Orange S.A.\n"
               "AS64999    ??           256 IPv4  \n")
        with _geoban(run=MagicMock(return_value=_result(0, stdout=out))) as (run, _write):
            r = admin_client.get("/geoban_asn", params={"name": "orange"})
        assert _geoban_calls(run) == [["asn", "orange"]]
        networks = r.json()["networks"]
        assert networks[0] == {"asn": 3215, "country": "FR", "ipv4_addresses": 21000000,
                               "organisation": "Orange S.A."}
        # no organisation name: kept, not left out
        assert networks[2] == {"asn": 64999, "country": "??", "ipv4_addresses": 256, "organisation": ""}

    def test_no_match(self, admin_client):
        run = MagicMock(return_value=_result(1, stderr="omr-geoban: no network matches: zzz\n"))
        with _geoban(run=run):
            r = admin_client.get("/geoban_asn", params={"name": "zzz"})
        assert r.json() == {"result": "done", "networks": [], "route": "geoban_asn"}

    def test_never_an_option(self, admin_client):
        with _geoban() as (run, _write):
            r = admin_client.get("/geoban_asn", params={"name": "--"})
        assert r.json()["result"] == "error"
        assert not _geoban_calls(run)
        with _geoban() as (run, _write):
            assert admin_client.get("/geoban_asn", params={"name": "a;b"}).status_code == 422

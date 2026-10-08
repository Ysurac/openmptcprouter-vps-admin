"""
Unit tests for the VLESS Reverse Proxy helpers (VPS->LAN port forwarding on
xray 26+) and the reality x25519 key heal.

Covers:
  - xray_reverse_client_id():  lookup of the dedicated reverse client uuid
  - xray_ensure_reverse_client(): idempotent creation of the reverse client
  - xray_fix_reality_keys(): regeneration of empty/placeholder x25519 pairs,
    parsing both the old and the 26+ "xray x25519" output formats
  - POST /xray: heals a missing reverse client into xray-server.json and
    reports its uuid as reverse_key
"""

import io
import json
from unittest.mock import MagicMock, patch

import pytest

from conftest import _REAL_OPEN, omr_admin  # noqa: F401  (fixtures)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REVERSE_UUID = "aee990cb-0eee-4db6-bd47-8f70f6427401"


def _tunnel_cfg(clients, tag="omrin-tunnel"):
    return {"inbounds": [{"tag": tag, "settings": {"clients": clients}}]}


def _reverse_client(uuid=REVERSE_UUID, tag="OMRLan"):
    return {"id": uuid, "level": 0, "email": "omr-reverse", "reverse": {"tag": tag}}


def _vr_file(priv, pub="OLDPUB"):
    return json.dumps({
        "inbounds": [{
            "tag": "omrin-vless-reality",
            "protocol": "vless",
            "settings": {"clients": [{"id": REVERSE_UUID}], "decryption": "none"},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": "1.1.1.1:443",
                    "serverNames": [""],
                    "privateKey": priv,
                    "publicKey": pub,
                    "shortIds": [""],
                },
            },
        }],
    })


NEW_STYLE_X25519 = (
    "PrivateKey: MMP71tonUkrIictBP6QUgsKZtx7xHWQtZnHCvTmHSng\n"
    "Password (PublicKey): 5evrKRToEkafEmD3tBMKTiePUMEbFn5aOZA-_PH85BQ\n"
    "Hash32: 9AzW5GgJVATjKRZksgM4Hzh52jK1vzS32EAkMKin72E\n"
)

OLD_STYLE_X25519 = (
    "Private key: OLDSTYLEPRIVATEKEY\n"
    "Public key: OLDSTYLEPUBLICKEY\n"
)


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
                def close(self):
                    env.written[sp] = self.getvalue()
                    super().close()

            return _Recorder()
        if sp in self.files:
            data = self.files[sp]
            return io.BytesIO(data.encode()) if binary else io.StringIO(data)
        # anything else: behave like a missing file
        return io.BytesIO() if binary else io.StringIO()


def _x25519_result(stdout):
    return MagicMock(returncode=0, stdout=stdout, stderr="")


# ===========================================================================
# xray_reverse_client_id
# ===========================================================================


class TestXrayReverseClientId:
    def test_returns_uuid_when_reverse_client_present(self):
        cfg = _tunnel_cfg([{"id": "user-uuid", "email": "openmptcprouter"},
                           _reverse_client()])
        assert omr_admin.xray_reverse_client_id(cfg) == REVERSE_UUID

    def test_empty_when_no_reverse_client(self):
        cfg = _tunnel_cfg([{"id": "user-uuid", "email": "openmptcprouter"}])
        assert omr_admin.xray_reverse_client_id(cfg) == ""

    def test_empty_when_inbound_missing(self):
        cfg = _tunnel_cfg([_reverse_client()], tag="other-inbound")
        assert omr_admin.xray_reverse_client_id(cfg) == ""

    def test_ignores_other_reverse_tags(self):
        cfg = _tunnel_cfg([_reverse_client(tag="SomethingElse")])
        assert omr_admin.xray_reverse_client_id(cfg) == ""


# ===========================================================================
# xray_ensure_reverse_client
# ===========================================================================


class TestXrayEnsureReverseClient:
    def test_returns_existing_uuid_without_duplicating(self):
        cfg = _tunnel_cfg([_reverse_client()])
        assert omr_admin.xray_ensure_reverse_client(cfg) == REVERSE_UUID
        assert len(cfg["inbounds"][0]["settings"]["clients"]) == 1

    def test_appends_reverse_client_when_missing(self):
        cfg = _tunnel_cfg([{"id": "user-uuid", "email": "openmptcprouter"}])
        new_id = omr_admin.xray_ensure_reverse_client(cfg)
        clients = cfg["inbounds"][0]["settings"]["clients"]
        assert len(clients) == 2
        added = clients[1]
        assert added["id"] == new_id
        assert new_id != ""
        assert added["reverse"] == {"tag": "OMRLan"}
        assert added["email"] == "omr-reverse"

    def test_generated_uuids_are_unique(self):
        ids = set()
        for _ in range(3):
            cfg = _tunnel_cfg([])
            ids.add(omr_admin.xray_ensure_reverse_client(cfg))
        assert len(ids) == 3

    def test_returns_empty_and_leaves_config_when_inbound_missing(self):
        cfg = {"inbounds": [{"tag": "other", "settings": {"clients": []}}]}
        before = json.dumps(cfg)
        assert omr_admin.xray_ensure_reverse_client(cfg) == ""
        assert json.dumps(cfg) == before


# ===========================================================================
# xray_fix_reality_keys
# ===========================================================================


class TestXrayFixRealityKeys:
    def _run(self, file_content, x25519_stdout=NEW_STYLE_X25519, isfile=True):
        env = _FileEnv({"/etc/xray/xray-vless-reality.json": file_content})
        with (
            patch("os.path.isfile", return_value=isfile),
            patch("builtins.open", side_effect=env),
            patch("subprocess.run", return_value=_x25519_result(x25519_stdout)) as run,
        ):
            inbound = omr_admin.xray_fix_reality_keys()
        return inbound, env, run

    def test_none_when_file_missing(self):
        inbound, env, _ = self._run("", isfile=False)
        assert inbound is None
        assert env.written == {}

    def test_valid_key_left_untouched(self):
        inbound, env, run = self._run(_vr_file("GOODPRIVATEKEY"))
        rs = inbound["streamSettings"]["realitySettings"]
        assert rs["privateKey"] == "GOODPRIVATEKEY"
        assert env.written == {}
        run.assert_not_called()

    @pytest.mark.parametrize("broken", ["", "XRAY_X25519_PRIVATE_KEY"])
    def test_heals_empty_or_placeholder_key(self, broken):
        inbound, env, _ = self._run(_vr_file(broken))
        rs = inbound["streamSettings"]["realitySettings"]
        assert rs["privateKey"] == "MMP71tonUkrIictBP6QUgsKZtx7xHWQtZnHCvTmHSng"
        assert rs["publicKey"] == "5evrKRToEkafEmD3tBMKTiePUMEbFn5aOZA-_PH85BQ"
        written = json.loads(env.written["/etc/xray/xray-vless-reality.json"])
        wrs = written["inbounds"][0]["streamSettings"]["realitySettings"]
        assert wrs["privateKey"] == rs["privateKey"]
        assert wrs["publicKey"] == rs["publicKey"]

    def test_parses_old_x25519_output_format(self):
        inbound, env, _ = self._run(_vr_file(""), x25519_stdout=OLD_STYLE_X25519)
        rs = inbound["streamSettings"]["realitySettings"]
        assert rs["privateKey"] == "OLDSTYLEPRIVATEKEY"
        assert rs["publicKey"] == "OLDSTYLEPUBLICKEY"

    def test_generation_failure_writes_nothing(self):
        inbound, env, _ = self._run(_vr_file(""), x25519_stdout="")
        rs = inbound["streamSettings"]["realitySettings"]
        assert rs["privateKey"] == ""
        assert env.written == {}


# ===========================================================================
# POST /xray: reverse client heal + reverse_key reporting
# ===========================================================================


class TestXrayEndpointReverse:
    _SERVER_JSON = json.dumps({
        "inbounds": [
            {
                "tag": "omrin-tunnel",
                "port": 65248,
                "protocol": "vless",
                "settings": {"clients": [
                    {"id": "user-uuid", "email": "openmptcprouter"},
                ]},
                "streamSettings": {"network": "tcp"},
            },
            {
                "tag": "omrin-shadowsocks-tunnel",
                "settings": {"password": "srvkey", "clients": [
                    {"email": "openmptcprouter", "password": "usrkey"},
                ]},
                "streamSettings": {"network": "tcp"},
            },
        ],
        "routing": {"rules": []},
    })

    _PAYLOAD = {
        "userid": "user-uuid",
        "vless_reality": False,
        "ss_method": "2022-blake3-aes-256-gcm",
        "transport": "tcp",
    }

    def _post(self, user_client):
        env = _FileEnv({
            "/etc/openmptcprouter-vps-admin/omr-admin-config.json":
                json.dumps({"users": [{}]}),
            "/etc/xray/xray-server.json": self._SERVER_JSON,
        })

        def _isfile(p):
            return str(p) == "/etc/xray/xray-server.json"

        with (
            patch("os.path.isfile", side_effect=_isfile),
            patch("builtins.open", side_effect=env),
            patch.object(omr_admin, "modif_config_user") as modif,
        ):
            r = user_client.post("/xray", json=self._PAYLOAD)
        return r, env, modif

    def test_heals_missing_reverse_client_into_server_json(self, user_client):
        r, env, _ = self._post(user_client)
        assert r.json()["result"] == "done"
        written = json.loads(env.written["/etc/xray/xray-server.json"])
        clients = written["inbounds"][0]["settings"]["clients"]
        reverse = [c for c in clients if c.get("reverse", {}).get("tag") == "OMRLan"]
        assert len(reverse) == 1
        assert reverse[0]["id"]

    def test_reports_reverse_key_in_user_conf(self, user_client):
        r, env, modif = self._post(user_client)
        written = json.loads(env.written["/etc/xray/xray-server.json"])
        clients = written["inbounds"][0]["settings"]["clients"]
        reverse_id = next(c["id"] for c in clients
                          if c.get("reverse", {}).get("tag") == "OMRLan")
        modif.assert_called_once()
        conf = modif.call_args[0][1]["xray"]
        assert conf["reverse_key"] == reverse_id
        assert conf["transport"] == "tcp"


# ===========================================================================
# xray_add_user / xray_del_user: users pushed to the running xray
# ===========================================================================


def _xray_server():
    return {"inbounds": [
        {"tag": "omrin-tunnel", "protocol": "vless", "port": 65248,
         "settings": {"clients": [{"id": "u-main", "email": "openmptcprouter"},
                                  {"id": "u-rev", "email": "omr-reverse", "reverse": {"tag": "OMRLan"}}],
                      "decryption": "none"}},
        {"tag": "omrin-vmess-tunnel", "protocol": "vmess", "settings": {"clients": []}},
        {"tag": "omrin-trojan-tunnel", "protocol": "trojan", "settings": {"clients": []}},
        {"tag": "omrin-socks-tunnel", "protocol": "socks", "settings": {"accounts": []}},
        {"tag": "omrin-shadowsocks-tunnel", "protocol": "shadowsocks",
         "settings": {"password": "spsk", "method": "2022-blake3-aes-256-gcm", "clients": []}},
        {"tag": "api", "protocol": "dokodemo-door", "settings": {}},
    ], "routing": {"rules": []}, "outbounds": []}


class TestXrayLiveUsers:
    @staticmethod
    def _run(func, data, *args):
        written, calls = {}, []

        def run(cmd, **kwargs):
            entry = list(cmd)
            if entry[-1].endswith(".json"):
                with _REAL_OPEN(entry[-1]) as f:
                    entry[-1] = json.load(f)
            calls.append(entry)
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("shutil.which", return_value="/usr/bin/xray"), \
             patch("os.path.isfile", return_value=True), \
             patch("builtins.open", side_effect=lambda p, *a, **k: io.StringIO(json.dumps(data))
                   if str(p) == "/etc/xray/xray-server.json" else _REAL_OPEN(p, *a, **k)), \
             patch("omr_admin._atomic_write_json", side_effect=lambda p, d: written.update(data=d)), \
             patch("omr_admin._schedule_proxy_restart"), \
             patch("subprocess.run", side_effect=run):
            func(*args)
        return written.get("data"), calls

    def test_new_user_added_alone_to_each_running_inbound(self):
        data, calls = self._run(omr_admin.xray_add_user, _xray_server(), "alice", "u-alice", "k-alice")
        subs = [c[2] for c in calls]
        # "adi" of an inbound xray has: "existing tag found", every time
        assert subs.count("adi") == 1            # the SOCKS inbound only, no user manager
        assert subs.count("adu") == 4
        for c in calls:
            assert c[3] == "--server=127.0.0.1:10086"   # ahead of the arguments
        adu = [c[-1]["inbounds"][0] for c in calls if c[2] == "adu"]
        assert {i["tag"]: i["settings"]["clients"] for i in adu}["omrin-tunnel"] == \
            [{"id": "u-alice", "level": 0, "alterId": 0, "email": "alice"}]
        ss = next(i for i in adu if i["tag"] == "omrin-shadowsocks-tunnel")
        assert ss["settings"]["clients"] == [{"password": "k-alice", "email": "alice"}]
        assert ss["settings"]["method"] == "2022-blake3-aes-256-gcm"
        assert ["rmu", "-tag=omrin-tunnel", "alice"] == calls[subs.index("rmu")][2:3] + calls[subs.index("rmu")][4:]
        # written for a restart
        tunnel = data["inbounds"][0]["settings"]["clients"]
        assert tunnel[-1]["email"] == "alice"

    def test_user_added_again_replaced_not_listed_twice(self):
        data, _ = self._run(omr_admin.xray_add_user, _xray_server(), "openmptcprouter", "u-new", "k")
        clients = data["inbounds"][0]["settings"]["clients"]
        assert [c["id"] for c in clients if c.get("email") == "openmptcprouter"] == ["u-new"]
        # the reverse tunnel client stays
        assert any(c.get("reverse") for c in clients)

    def test_removed_user_only_from_its_inbounds_and_alone(self):
        data, calls = self._run(omr_admin.xray_del_user, _xray_server(), "openmptcprouter")
        assert [c[2] for c in calls] == ["rmu"]
        assert calls[0][4:] == ["-tag=omrin-tunnel", "openmptcprouter"]
        assert [c["email"] for c in data["inbounds"][0]["settings"]["clients"]] == ["omr-reverse"]

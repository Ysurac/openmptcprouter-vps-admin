"""
Tests for install_omr-ai.sh, the InfluxDB 3 Core + AI decision engine
installer, around the admin-token bootstrap that broke on current
influxdb3-core releases (Ysurac/openmptcprouter#4366).

The script is POSIX sh and drives apt/systemd for real, so it is not run
end-to-end here.  Instead each test:

  1. extracts the pieces under test from the *shipped* script text -- the
     tunable assignments, log/die/step, _wait_for_influx and the whole
     "3. Bootstrap admin token" section (everything up to "4. Create
     database") -- into a harness executed with `sh`, so what runs is the
     real shell code, not a copy kept in sync by hand;
  2. puts fake `influxdb3`, `systemctl` and `curl` executables first in PATH.
     The fake influxdb3 reproduces what influxdb3-core 3.10/3.11 does on a
     real server: it rejects "--host ... --admin" (flags placed before
     --admin are unexpected arguments for the bare "create token"), prints
     the token JSON on stdout for a fresh catalog, prints a non-JSON "token
     name already exists" line *and exits 0* when an operator token exists,
     and keeps that state under $INFLUX_DATA_DIR/$INFLUX_NODE_ID so the
     script's RESET_DATA wipe really resets it.  Every invocation is appended
     to $FAKE_LOG so tests can assert on the exact argv and on the order of
     operations (409 -> stop -> start -> health -> create).

Marked real_env: conftest's autouse patch_env fixture (mocked open/subprocess)
is skipped for this module since it drives real processes in tmp_path.
"""

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "install_omr-ai.sh"
SCRIPT_TEXT = SCRIPT.read_text()
HOST = "http://127.0.0.1:65501"
TUNABLES = ("RESET_DATA", "INSTALL_AI", "INFLUX_RETENTION", "INFLUX_RETENTION_DAYS")

pytestmark = [
    pytest.mark.real_env,
    pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX sh"),
]


# ---------------------------------------------------------------------------
# Harness built from the real script
# ---------------------------------------------------------------------------


def _assignment(name):
    """The `NAME=...` line of a tunable, verbatim."""
    m = re.search(rf"^{name}=.*$", SCRIPT_TEXT, re.M)
    assert m, f"{name}= assignment not found in install_omr-ai.sh"
    return m.group(0)


def _function(name):
    """Source of a shell function, whether a one-liner or a `{ ... }` block."""
    lines = SCRIPT_TEXT.splitlines()
    for i, line in enumerate(lines):
        if line.startswith(name + "()"):
            if line.rstrip().endswith("}"):
                return line
            j = i
            while lines[j] != "}":
                j += 1
            return "\n".join(lines[i:j + 1])
    raise AssertionError(f"function {name} not found in install_omr-ai.sh")


def _bootstrap_section():
    """Section 3 of the script: token bootstrap up to (not including) section 4."""
    start = SCRIPT_TEXT.index("# 3. Bootstrap admin token")
    end = SCRIPT_TEXT.index("# 4. Create database")
    lines = SCRIPT_TEXT[start:end].splitlines()
    while lines and (not lines[-1].strip() or lines[-1].startswith("# ---")):
        lines.pop()
    section = "\n".join(lines)
    assert "_create_admin_token" in section
    return section


def _bootstrap_harness():
    return "\n".join([
        "#!/bin/sh",
        "set -eu",
        *(_assignment(n) for n in TUNABLES),
        _function("log"),
        _function("die"),
        _function("step"),
        _function("_wait_for_influx"),
        _bootstrap_section(),
        "",
    ])


# ---------------------------------------------------------------------------
# Fake executables
# ---------------------------------------------------------------------------

FAKE_INFLUXDB3 = r'''#!/bin/sh
# Stand-in for the influxdb3 CLI, mimicking influxdb3-core 3.10/3.11.
# Only "create token" is implemented.
echo "influxdb3 $*" >> "$FAKE_LOG"
[ "$1 $2" = "create token" ] || { echo "fake influxdb3: unsupported command: $*" >&2; exit 99; }
shift 2
# clap treats --admin as a sub-command of "create token": any flag placed
# before it is an unexpected argument for the bare "create token".
if [ "${1:-}" != "--admin" ]; then
    printf "error: unexpected argument '%s' found\n\n  tip: '--admin %s' exists\n\nUsage: influxdb3 create token [COMMAND]\n\nFor more information, try '--help'.\n" "${1:-}" "${1:-}" >&2
    exit 2
fi
if [ "${FAKE_INFLUX_FAIL:-}" = "connrefused" ]; then
    echo "Failed to create token, error: RequestSend { method: POST, url: \"${INFLUX_HOST}/api/v3/configure/token/admin\", source: reqwest::Error { kind: Request, source: hyper_util::client::legacy::Error(Connect, ConnectError(\"tcp connect error\", Os { code: 111, kind: ConnectionRefused, message: \"Connection refused\" })) } }"
    exit 1
fi
marker="${INFLUX_DATA_DIR}/${INFLUX_NODE_ID}/catalog/_admin"
if [ -e "$marker" ]; then
    # Real CLI: non-JSON line on stdout, exit status 0.
    echo 'Failed to create token, error: ApiError { code: 409, message: "token name already exists, _admin", error_code: None }'
    exit 0
fi
seq_file="${INFLUX_DATA_DIR}/.fake-token-seq"   # outside the node dir: survives a wipe
n=$(( $(cat "$seq_file" 2>/dev/null || echo 0) + 1 ))
mkdir -p "$(dirname "$marker")" "$(dirname "$seq_file")"
echo "$n" > "$seq_file"
echo "apiv3_fake${n}" > "$marker"
case " $* " in
    *" --format json "*)
        cat <<JSON
{
  "help_msg": "Store this token securely, as it will not be shown again. HTTP requests require the following header: \"Authorization: Bearer apiv3_fake${n}\"",
  "token": "apiv3_fake${n}"
}
JSON
        ;;
    *)
        echo "New token created successfully!"
        echo "Token: apiv3_fake${n}"
        ;;
esac
'''

FAKE_SYSTEMCTL = '''#!/bin/sh
echo "systemctl $*" >> "$FAKE_LOG"
exit 0
'''

FAKE_CURL = '''#!/bin/sh
# Only ever called as: curl -s -o /dev/null -w "%{http_code}" URL
echo "curl $*" >> "$FAKE_LOG"
printf '%s' "${FAKE_CURL_CODE:-200}"
'''


class Sandbox:
    """One throwaway VPS: fake binaries, harness, data dir, creds path, call log."""

    def __init__(self, root):
        self.root = root
        self.fakebin = root / "bin"
        self.harness = root / "bootstrap.sh"
        self.data_dir = root / "var" / "lib" / "influxdb3" / "data"
        # Parent does not exist up front: _save_creds must mkdir -p it.
        self.creds = root / "etc" / "influxdb3" / "omr-influxdb.env"
        self.log = root / "calls.log"

        self.fakebin.mkdir()
        for name, body in (("influxdb3", FAKE_INFLUXDB3),
                           ("systemctl", FAKE_SYSTEMCTL),
                           ("curl", FAKE_CURL)):
            p = self.fakebin / name
            p.write_text(body)
            p.chmod(0o755)
        self.harness.write_text(_bootstrap_harness())

    @property
    def marker(self):
        """The fake catalog's operator-token record, under the real wipe path."""
        return self.data_dir / "omr-node" / "catalog" / "_admin"

    def env(self, **extra):
        env = {
            "PATH": f"{self.fakebin}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
            "LC_ALL": "C",
            "INFLUX_HOST": HOST,
            "INFLUX_ORG": "omr",
            "INFLUX_BUCKET": "omr_metrics",
            "INFLUX_NODE_ID": "omr-node",
            "INFLUX_DATA_DIR": str(self.data_dir),
            "CREDS_FILE": str(self.creds),
            "FAKE_LOG": str(self.log),
        }
        env.update({k: v for k, v in extra.items() if v is not None})
        return env

    def run(self, **extra):
        return subprocess.run(
            ["sh", str(self.harness)],
            env=self.env(**extra), capture_output=True, text=True, timeout=60,
        )

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def token_calls(self):
        return [c for c in self.calls() if c.startswith("influxdb3 create token")]

    def sequence(self):
        """Compact order of operations: influxdb3 / systemctl <verb> / curl."""
        out = []
        for c in self.calls():
            words = c.split()
            out.append(" ".join(words[:2]) if words[0] == "systemctl" else words[0])
        return out

    def simulate_lost_creds(self):
        """An earlier run created the operator token; the creds file is gone."""
        self.marker.parent.mkdir(parents=True)
        self.marker.write_text("apiv3_fromEarlierRun\n")

    def creds_token(self):
        for line in self.creds.read_text().splitlines():
            if line.startswith("INFLUX_ADMIN_TOKEN="):
                return line.split("=", 1)[1]
        return None


@pytest.fixture
def sandbox(tmp_path):
    return Sandbox(tmp_path)


def _tunables(**env_extra):
    """Evaluate the four tunable assignments under `sh` with the given environment."""
    script = "\n".join([
        "set -eu",
        *(_assignment(n) for n in TUNABLES),
        'printf "%s\\n" "RESET_DATA=$RESET_DATA" "INSTALL_AI=$INSTALL_AI" '
        '"INFLUX_RETENTION=$INFLUX_RETENTION" "INFLUX_RETENTION_DAYS=$INFLUX_RETENTION_DAYS"',
    ])
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **env_extra}
    r = subprocess.run(["sh", "-c", script], env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return dict(line.split("=", 1) for line in r.stdout.splitlines())


# ===========================================================================
# Static checks on the script text
# ===========================================================================


class TestScriptText:
    def test_parses_as_posix_sh(self):
        r = subprocess.run(["sh", "-n", str(SCRIPT)], capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stderr

    def test_creds_are_saved_before_the_database_step(self):
        # A failure in steps 4-8 (pip, PyTorch, download) must not lose a
        # token that is never shown again.
        assert "\n_save_creds\n" in SCRIPT_TEXT
        assert SCRIPT_TEXT.index("\n_save_creds\n") < SCRIPT_TEXT.index("# 4. Create database")


# ===========================================================================
# Tunables: defaults vs environment
# ===========================================================================


class TestTunables:
    def test_defaults_without_environment(self):
        assert _tunables() == {
            "RESET_DATA": "false",
            "INSTALL_AI": "true",
            "INFLUX_RETENTION": "60d",
            "INFLUX_RETENTION_DAYS": "60",
        }

    def test_environment_overrides_every_tunable(self):
        # `sudo RESET_DATA=true sh ./install_omr-ai.sh`, as the error text
        # suggests, used to be a no-op because the script reassigned "false".
        assert _tunables(RESET_DATA="true", INSTALL_AI="false",
                         INFLUX_RETENTION="30d", INFLUX_RETENTION_DAYS="30") == {
            "RESET_DATA": "true",
            "INSTALL_AI": "false",
            "INFLUX_RETENTION": "30d",
            "INFLUX_RETENTION_DAYS": "30",
        }

    def test_empty_retention_means_infinite_but_empty_flags_fall_back(self):
        got = _tunables(INFLUX_RETENTION="", RESET_DATA="", INSTALL_AI="")
        assert got["INFLUX_RETENTION"] == ""      # "" = infinite, must survive
        assert got["RESET_DATA"] == "false"        # never wipe by accident
        assert got["INSTALL_AI"] == "true"


# ===========================================================================
# Bootstrap: fresh catalog
# ===========================================================================


class TestFreshCatalog:
    def test_token_requested_with_admin_first_and_creds_saved_right_away(self, sandbox):
        r = sandbox.run()
        assert r.returncode == 0, r.stdout + r.stderr

        calls = sandbox.token_calls()
        assert len(calls) == 1
        argv = calls[0].split()
        # Regression for #4366: "--host ... --admin" is rejected by influxdb3
        # 3.10/3.11; --admin has to open the sub-command.
        assert argv[:4] == ["influxdb3", "create", "token", "--admin"]
        assert argv[argv.index("--host") + 1] == HOST
        assert argv[argv.index("--format") + 1] == "json"

        # Saved within section 3, mode 600, same layout as before.
        assert sandbox.creds_token() == "apiv3_fake1"
        assert stat.S_IMODE(sandbox.creds.stat().st_mode) == 0o600
        assert sandbox.creds.read_text().splitlines() == [
            f"INFLUX_HOST={HOST}",
            "INFLUX_ORG=omr",
            "INFLUX_BUCKET=omr_metrics",
            "INFLUX_ADMIN_TOKEN=apiv3_fake1",
        ]
        assert "Admin token ready." in r.stdout
        assert "Credentials saved" in r.stdout
        assert sandbox.sequence() == ["influxdb3"]   # no restart, no wipe

    def test_saved_creds_are_reused_without_touching_the_catalog(self, sandbox):
        sandbox.creds.parent.mkdir(parents=True)
        sandbox.creds.write_text("INFLUX_ADMIN_TOKEN=apiv3_saved\n")

        r = sandbox.run()
        assert r.returncode == 0, r.stdout + r.stderr
        assert "Using existing admin token" in r.stdout
        assert sandbox.calls() == []
        assert sandbox.creds_token() == "apiv3_saved"
        assert not sandbox.marker.exists()

    def test_creds_file_without_token_triggers_bootstrap(self, sandbox):
        sandbox.creds.parent.mkdir(parents=True)
        sandbox.creds.write_text("INFLUX_HOST=%s\nINFLUX_ADMIN_TOKEN=\n" % HOST)

        r = sandbox.run()
        assert r.returncode == 0, r.stdout + r.stderr
        assert len(sandbox.token_calls()) == 1
        assert sandbox.creds_token() == "apiv3_fake1"


# ===========================================================================
# Bootstrap: operator token exists, creds file lost
# ===========================================================================


class TestExistingTokenLostCreds:
    @pytest.mark.parametrize("reset_data", [None, "false", ""], ids=["unset", "false", "empty"])
    def test_refuses_with_explicit_message_and_keeps_the_catalog(self, sandbox, reset_data):
        sandbox.simulate_lost_creds()

        r = sandbox.run(RESET_DATA=reset_data)
        assert r.returncode == 1
        assert "An admin token exists in the InfluxDB 3 catalog" in r.stdout
        assert str(sandbox.creds) in r.stdout
        assert "sudo RESET_DATA=true sh " in r.stdout
        # Nothing destructive happened.
        assert sandbox.marker.read_text() == "apiv3_fromEarlierRun\n"
        assert not sandbox.creds.exists()
        assert sandbox.sequence() == ["influxdb3"]

    @pytest.mark.parametrize("health", ["200", "401"])
    def test_reset_data_from_environment_wipes_and_rebootstraps(self, sandbox, health):
        sandbox.simulate_lost_creds()

        r = sandbox.run(RESET_DATA="true", FAKE_CURL_CODE=health)
        assert r.returncode == 0, r.stdout + r.stderr
        assert "wiping catalog" in r.stdout
        assert sandbox.sequence() == [
            "influxdb3",          # 409: token exists
            "systemctl stop",
            "systemctl start",
            "curl",               # wait for /health (200 or 401 both mean "up")
            "influxdb3",          # fresh catalog: token created
        ]
        assert "systemctl stop influxdb3-core" in sandbox.calls()
        assert "systemctl start influxdb3-core" in sandbox.calls()
        for call in sandbox.token_calls():
            assert call.split()[3] == "--admin"

        # The wipe removed the old record; the fake re-created it for the new token.
        assert sandbox.marker.read_text() == "apiv3_fake1\n"
        assert sandbox.creds_token() == "apiv3_fake1"
        assert stat.S_IMODE(sandbox.creds.stat().st_mode) == 0o600


# ===========================================================================
# Bootstrap: CLI failures
# ===========================================================================


class TestCliFailures:
    def test_other_failures_are_shown_not_mistaken_for_an_existing_token(self, sandbox):
        # Pre-fix, any non-JSON output (including the flag-order usage error)
        # was read as "an admin token exists" and offered RESET_DATA.
        r = sandbox.run(FAKE_INFLUX_FAIL="connrefused")
        assert r.returncode == 1
        assert "An admin token exists" not in r.stdout
        assert "RESET_DATA" not in r.stdout + r.stderr
        assert f"influxdb3 create token --admin --host {HOST}" in r.stderr
        assert "Connection refused" in r.stderr
        assert not sandbox.creds.exists()
        assert sandbox.sequence() == ["influxdb3"]

    def test_fake_cli_rejects_the_legacy_flag_order(self, sandbox):
        # Guard for the guard: the fake must fail the pre-fix argv exactly like
        # influxdb3-core 3.10/3.11, otherwise the argv assertions above prove
        # nothing.
        r = subprocess.run(
            [str(sandbox.fakebin / "influxdb3"), "create", "token",
             "--host", HOST, "--admin", "--format", "json"],
            env=sandbox.env(), capture_output=True, text=True, timeout=30,
        )
        assert r.returncode == 2
        assert r.stdout == ""
        assert "unexpected argument '--host' found" in r.stderr
        assert not sandbox.marker.exists()

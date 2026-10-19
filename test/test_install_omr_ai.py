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

import json
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


def _database_section():
    start = SCRIPT_TEXT.index("# 4. Create database")
    end = SCRIPT_TEXT.index("# 5. Python influxdb3-python client")
    return SCRIPT_TEXT[start:end]


def _database_harness():
    return "\n".join([
        "#!/bin/sh",
        "set -eu",
        _function("log"),
        _function("die"),
        _function("step"),
        'INFLUX_BUCKET="omr_metrics"',
        'INFLUX_HOST="http://127.0.0.1:65501"',
        'ADMIN_TOKEN="test-token"',
        'INFLUX_RETENTION="60d"',
        _database_section(),
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
        + '"INFLUX_RETENTION=$INFLUX_RETENTION" "INFLUX_RETENTION_DAYS=$INFLUX_RETENTION_DAYS"',
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

    def test_config_update_uses_same_process_lock_as_api(self):
        assert '".omr-admin-config.lock"' in SCRIPT_TEXT
        assert "fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)" in SCRIPT_TEXT


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


class TestDatabaseCreation:
    @staticmethod
    def _run(tmp_path, fake_body):
        fakebin = tmp_path / "bin"
        fakebin.mkdir()
        influxdb3 = fakebin / "influxdb3"
        influxdb3.write_text("#!/bin/sh\n" + fake_body + "\n")
        influxdb3.chmod(0o755)
        harness = tmp_path / "database.sh"
        harness.write_text(_database_harness())
        env = {
            **os.environ,
            "PATH": f"{fakebin}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
            "LC_ALL": "C",
        }
        return subprocess.run(
            ["sh", str(harness)], env=env, capture_output=True, text=True, timeout=30,
        )

    def test_database_failure_aborts_installer(self, tmp_path):
        r = self._run(tmp_path, 'echo "connection refused" >&2; exit 9')
        assert r.returncode == 1
        assert "connection refused" in r.stderr
        assert "Failed to create database 'omr_metrics'" in r.stderr
        assert "Database ready." not in r.stdout

    def test_already_existing_database_is_success(self, tmp_path):
        r = self._run(tmp_path, 'echo "database already exists" >&2; exit 1')
        assert r.returncode == 0, r.stdout + r.stderr
        assert "Database already exists." in r.stdout
        assert "Database ready." in r.stdout

    def test_token_passed_in_environment_not_argv(self, tmp_path):
        # --token "$ADMIN_TOKEN" was readable by any local user in /proc/*/cmdline
        r = self._run(tmp_path, 'echo "argv: $*"; echo "env: ${INFLUXDB3_AUTH_TOKEN:-}"')
        assert r.returncode == 0, r.stdout + r.stderr
        assert "env: test-token" in r.stdout
        argv = next(line for line in r.stdout.splitlines() if line.startswith("argv: "))
        assert "test-token" not in argv and "--token" not in argv
        assert "--retention-period 60d" in argv


# ===========================================================================
# 8. omr-admin-config.json update
# ===========================================================================


def _config_section():
    start = SCRIPT_TEXT.index("# 8. Inject influxdb block")
    end = SCRIPT_TEXT.index("# Done")
    return SCRIPT_TEXT[start:end]


class TestConfigUpdate:
    @staticmethod
    def _run(tmp_path, content):
        config = tmp_path / "omr-admin-config.json"
        if content is not None:
            config.write_text(content)
            config.chmod(0o644)
        fakebin = tmp_path / "bin"
        fakebin.mkdir()
        log = tmp_path / "calls.log"
        systemctl = fakebin / "systemctl"
        # the restart sees the config as it is then
        systemctl.write_text('#!/bin/sh\necho "systemctl $* $(cat "$OMR_CONFIG_FILE" | tr -d "\\n ")" >> "$FAKE_LOG"\n')
        systemctl.chmod(0o755)
        harness = tmp_path / "config.sh"
        harness.write_text("\n".join([
            "#!/bin/sh",
            "set -eu",
            _function("log"),
            _function("die"),
            _function("step"),
            f'OMR_CONFIG_FILE="{config}"',
            'INFLUX_HOST="http://127.0.0.1:65501"',
            'INFLUX_ORG="omr"',
            'INFLUX_BUCKET="omr_metrics"',
            'ADMIN_TOKEN="test-token"',
            'INFLUX_RETENTION_DAYS="60"',
            _config_section(),
            "",
        ]))
        env = {**os.environ, "PATH": f"{fakebin}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
               "LC_ALL": "C", "FAKE_LOG": str(log), "OMR_CONFIG_FILE": str(config)}
        r = subprocess.run(["sh", str(harness)], env=env, capture_output=True, text=True, timeout=30)
        calls = log.read_text().splitlines() if log.exists() else []
        return r, config, calls

    def test_trailing_comma_kept_users_restart_after_the_write(self, tmp_path):
        r, config, calls = self._run(tmp_path, '{"users": [{"openmptcprouter": {"userid": 0,}}], "port": 65500,}')
        assert r.returncode == 0, r.stdout + r.stderr
        data = json.loads(config.read_text())
        assert data["users"] == [{"openmptcprouter": {"userid": 0}}]
        assert data["influxdb"]["token"] == "test-token"
        assert stat.S_IMODE(config.stat().st_mode) == 0o600
        # restarted once, with the influxdb block already there
        assert len(calls) == 1 and calls[0].startswith("systemctl restart omr-admin")
        assert '"influxdb"' in calls[0]

    def test_unreadable_config_left_as_it_is(self, tmp_path):
        broken = '{"users": [{"openmptcprouter": {"userid": 0'
        r, config, calls = self._run(tmp_path, broken)
        assert r.returncode == 1
        assert "could not parse" in r.stderr
        assert config.read_text() == broken
        assert not list(tmp_path.glob("omr-admin-config.json.*"))
        assert calls == []

    def test_token_not_on_the_python_command_line(self):
        section = _config_section()
        python_line = next(line for line in section.splitlines() if "python3 - " in line)
        assert "$ADMIN_TOKEN" not in python_line.split("python3 - ", 1)[1]
        assert python_line.startswith('OMR_INFLUX_TOKEN="$ADMIN_TOKEN" python3 - ')
        assert 'token = os.environ["OMR_INFLUX_TOKEN"]' in section

    def test_temp_file_never_world_readable(self):
        # created 0600, not chmod-ed after the replace
        section = _config_section()
        assert "os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)" in section
        assert 'open(tmp, "w")' not in section


class TestDecisionModel:
    def test_model_made_by_omr_metrics_not_a_copy(self):
        # A copy of the network kept here drifted (19 features, other
        # layers): omr-admin refused it and each worker made its own.
        assert "InterfaceScorer" not in SCRIPT_TEXT
        assert "N_FEATURES" not in SCRIPT_TEXT
        assert "omr_metrics.ensure_decision_model()" in SCRIPT_TEXT
        # once omr_metrics.py is there
        assert SCRIPT_TEXT.index("omr_metrics.ensure_decision_model()") > SCRIPT_TEXT.index('mv -f "$METRICS_TMP" "$dest"')


class TestPipPinned:
    def test_pip_fallback_installs_pinned_versions(self):
        assert ('apt_or_pip python3-influxdb3 "influxdb3-python==${INFLUXDB3_PYTHON_VERSION}"'
                ' "reactivex==${REACTIVEX_VERSION}"') in SCRIPT_TEXT
        assert 'apt_or_pip python3-torch "torch==${TORCH_VERSION}"' in SCRIPT_TEXT
        r = subprocess.run(["sh", "-c", "\n".join(line for line in SCRIPT_TEXT.splitlines()
                                                  if line.startswith(("INFLUXDB3_PYTHON_VERSION=", "TORCH_VERSION=",
                                                                      "REACTIVEX_VERSION=")))
                            + '\necho "$INFLUXDB3_PYTHON_VERSION $TORCH_VERSION $REACTIVEX_VERSION"'],
                           capture_output=True, text=True, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")})
        # reactivex 5 wants typing-extensions >= 4.15, which pip cannot put in
        # place of the Debian 13 one (Ysurac/openmptcprouter#4398)
        assert r.stdout.split() == ["0.21.0", "2.8.0", "4.0.4"]


FAKE_PIP3 = r'''#!/bin/sh
# Stand-in for pip3: --help lists --break-system-packages unless
# FAKE_PIP_OLD=1; an install is logged to $FAKE_LOG and fails when
# FAKE_PIP_FAIL=1, with the error on stderr, as Debian's pip does
echo "pip3 $*" >> "$FAKE_LOG"
if [ "$2" = "--help" ]; then
    echo "  --user"
    [ "${FAKE_PIP_OLD:-0}" = "1" ] || echo "  --break-system-packages  Allow pip to modify an EXTERNALLY-MANAGED Python"
    exit 0
fi
case " $* " in
    *" --break-system-packages "*) ;;
    *) [ "${FAKE_PIP_OLD:-0}" = "1" ] || { echo "error: externally-managed-environment" >&2; exit 1; } ;;
esac
if [ "${FAKE_PIP_FAIL:-0}" = "1" ]; then
    echo "error: uninstall-no-record-file" >&2
    exit 1
fi
exit 0
'''


class TestAptOrPip:
    """apt_or_pip, run from the script with fake apt-cache and pip3."""

    def _run(self, tmp_path, **env):
        bindir = tmp_path / "bin"
        bindir.mkdir()
        for name, body in (("pip3", FAKE_PIP3), ("apt-cache", "#!/bin/sh\nexit 100\n")):
            exe = bindir / name
            exe.write_text(body)
            exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
        log = tmp_path / "fake.log"
        log.write_text("")
        harness = "\n".join([
            "#!/bin/sh", "set -eu",
            _function("log"), _function("die"), _function("apt_or_pip"),
            'apt_or_pip python3-influxdb3 "influxdb3-python==0.21.0" "reactivex==4.0.4"',
            'echo DONE', "",
        ])
        r = subprocess.run(["sh", "-c", harness], capture_output=True, text=True,
                           env={"PATH": f"{bindir}:{os.environ.get('PATH', '/usr/bin:/bin')}",
                                "FAKE_LOG": str(log), **env})
        installs = [line for line in log.read_text().splitlines() if "--help" not in line]
        return r, installs

    def test_pep668_pip_installs_with_break_system_packages(self, tmp_path):
        r, installs = self._run(tmp_path)
        assert r.returncode == 0, r.stderr
        assert "DONE" in r.stdout
        assert installs == ["pip3 install --quiet --break-system-packages "
                            "influxdb3-python==0.21.0 reactivex==4.0.4"]

    def test_failure_shows_the_real_error_not_pep668(self, tmp_path):
        # It was hidden, and the retry without the option printed the
        # PEP 668 refusal instead (Ysurac/openmptcprouter#4398)
        r, installs = self._run(tmp_path, FAKE_PIP_FAIL="1")
        assert r.returncode != 0
        assert "DONE" not in r.stdout
        assert "uninstall-no-record-file" in r.stderr
        assert "externally-managed-environment" not in r.stderr
        assert len(installs) == 1

    def test_old_pip_without_the_option(self, tmp_path):
        r, installs = self._run(tmp_path, FAKE_PIP_OLD="1")
        assert r.returncode == 0, r.stderr
        assert installs == ["pip3 install --quiet influxdb3-python==0.21.0 reactivex==4.0.4"]


# ===========================================================================
# Temp files: removed on any exit, die included
# ===========================================================================


def _cleanup_prelude():
    """log/die/step, the temp-file variables, _cleanup and its traps, from the script."""
    traps = [line for line in SCRIPT_TEXT.splitlines() if line.startswith("trap ")]
    assert traps, "trap lines not found in install_omr-ai.sh"
    return [
        "#!/bin/sh", "set -eu",
        _function("log"), _function("die"), _function("step"),
        _assignment("GNUPG_TMP"), _assignment("METRICS_TMP"),
        _function("_cleanup"), *traps,
    ]


FAKE_CURL_DOWNLOAD = r'''#!/bin/sh
# curl -fsSL URL -o FILE: copies $FAKE_SRC to FILE, or fails like curl -f
echo "curl $*" >> "$FAKE_LOG"
out=""
while [ $# -gt 0 ]; do
    [ "$1" = "-o" ] && { out="$2"; shift; }
    shift
done
[ -n "${FAKE_SRC:-}" ] || { echo "curl: (22) The requested URL returned error: 404" >&2; exit 22; }
cp "$FAKE_SRC" "$out"
'''


def _write_fake(bindir, name, body):
    bindir.mkdir(exist_ok=True)
    exe = bindir / name
    exe.write_text(body)
    exe.chmod(0o755)


# ===========================================================================
# 1. InfluxData key: only the pinned key reaches the signed-by keyring
# ===========================================================================


def _gpg(home, *args, **kw):
    return subprocess.run(["gpg", "--batch", "--homedir", str(home), *args],
                          capture_output=True, timeout=60, check=True, **kw)


def _fingerprints(keyring):
    out = subprocess.run(["gpg", "--batch", "--show-keys", "--with-colons", str(keyring)],
                         capture_output=True, text=True, timeout=30, check=True).stdout
    lines = out.splitlines()
    # primary-key fingerprints only (the fpr line right after a pub line)
    return [lines[i + 1].split(":")[9] for i, line in enumerate(lines)
            if line.startswith("pub:") and lines[i + 1].startswith("fpr:")]


@pytest.fixture(scope="module")
def gpg_keys(tmp_path_factory):
    """Two throwaway keys: (pinned fpr, other fpr, armored file of both, armored file of other)."""
    if shutil.which("gpg") is None:
        pytest.skip("needs gpg")
    root = tmp_path_factory.mktemp("gpgkeys")
    home = root / "home"
    home.mkdir(mode=0o700)
    try:
        for uid in ("Pinned <pinned@example.invalid>", "Intruder <intruder@example.invalid>"):
            _gpg(home, "--passphrase", "", "--quick-gen-key", uid, "ed25519", "sign", "never")
        fprs = {}
        for uid in ("pinned@example.invalid", "intruder@example.invalid"):
            out = _gpg(home, "--with-colons", "--fingerprint", uid, text=True).stdout
            fprs[uid] = next(line.split(":")[9] for line in out.splitlines() if line.startswith("fpr:"))
        both = root / "both.key"
        both.write_bytes(_gpg(home, "--armor", "--export").stdout)
        other = root / "other.key"
        other.write_bytes(_gpg(home, "--armor", "--export", fprs["intruder@example.invalid"]).stdout)
    finally:
        subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "all"], capture_output=True)
    return fprs["pinned@example.invalid"], fprs["intruder@example.invalid"], both, other


def _key_section():
    start = SCRIPT_TEXT.index('step "Verifying and importing InfluxData GPG key..."')
    end = SCRIPT_TEXT.index('step "Adding InfluxData apt repository..."')
    return SCRIPT_TEXT[start:end]


class TestKeyImport:
    def _run(self, tmp_path, fingerprint, src):
        bindir = tmp_path / "bin"
        _write_fake(bindir, "curl", FAKE_CURL_DOWNLOAD)
        tmpdir = tmp_path / "tmp"
        tmpdir.mkdir()
        keyring = tmp_path / "influxdata-archive.gpg"
        harness = tmp_path / "key.sh"
        harness.write_text("\n".join([
            *_cleanup_prelude(),
            f'INFLUX_KEY_FINGERPRINT="{fingerprint}"',
            f'KEYRING_FILE="{keyring}"',
            _key_section(),
            'echo DONE', "",
        ]))
        env = {"PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
               "LC_ALL": "C", "TMPDIR": str(tmpdir), "FAKE_LOG": str(tmp_path / "calls.log"),
               "FAKE_SRC": str(src), "HOME": str(tmp_path)}
        r = subprocess.run(["sh", str(harness)], env=env, capture_output=True, text=True, timeout=60)
        return r, keyring, tmpdir

    def test_only_the_pinned_key_ends_up_in_the_keyring(self, tmp_path, gpg_keys):
        pinned, other, both, _ = gpg_keys
        r, keyring, tmpdir = self._run(tmp_path, pinned, both)
        assert r.returncode == 0, r.stdout + r.stderr
        assert "DONE" in r.stdout
        # the downloaded file had both keys: dearmored whole, both were trusted
        assert _fingerprints(keyring) == [pinned]
        assert stat.S_IMODE(keyring.stat().st_mode) == 0o644
        assert list(tmpdir.iterdir()) == []

    def test_fingerprint_mismatch_dies_and_cleans_up(self, tmp_path, gpg_keys):
        pinned, _, _, other_only = gpg_keys
        r, keyring, tmpdir = self._run(tmp_path, pinned, other_only)
        assert r.returncode == 1
        assert "Key fingerprint mismatch" in r.stderr
        assert "DONE" not in r.stdout
        assert not keyring.exists()
        # the throwaway GNUPGHOME and the downloaded key, removed by the trap
        assert list(tmpdir.iterdir()) == []


# ===========================================================================
# 7. omr_metrics.py download: never over the live module unchecked
# ===========================================================================


def _download_section(target_dir):
    start = SCRIPT_TEXT.index("# 7. Deploy omr_metrics.py")
    end = SCRIPT_TEXT.index("# 8. Inject influxdb block")
    section = SCRIPT_TEXT[start:end]
    assert "/usr/share/omr-admin" in section
    return section.replace("/usr/share/omr-admin", str(target_dir))


class TestMetricsDownload:
    LIVE = "LIVE = True\n"

    def _run(self, tmp_path, body):
        bindir = tmp_path / "bin"
        _write_fake(bindir, "curl", FAKE_CURL_DOWNLOAD)
        target = tmp_path / "omr-admin"
        target.mkdir()
        dest = target / "omr_metrics.py"
        dest.write_text(self.LIVE)
        src = None
        if body is not None:
            src = tmp_path / "download.py"
            src.write_text(body)
        harness = tmp_path / "download.sh"
        harness.write_text("\n".join([
            *_cleanup_prelude(),
            'INSTALL_AI="false"', 'OMR_ADMIN_VERSION="develop"',
            _download_section(target),
            'echo DONE', "",
        ]))
        env = {"PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
               "LC_ALL": "C", "FAKE_LOG": str(tmp_path / "calls.log")}
        if src is not None:
            env["FAKE_SRC"] = str(src)
        r = subprocess.run(["sh", str(harness)], env=env, capture_output=True, text=True, timeout=60)
        return r, target, dest

    def test_valid_module_replaces_the_live_one(self, tmp_path):
        r, target, dest = self._run(tmp_path, "def ensure_decision_model():\n    return True\n")
        assert r.returncode == 0, r.stdout + r.stderr
        assert "DONE" in r.stdout
        assert "ensure_decision_model" in dest.read_text()
        assert stat.S_IMODE(dest.stat().st_mode) == 0o644
        assert sorted(p.name for p in target.iterdir()) == ["omr_metrics.py"]

    def test_module_that_does_not_compile_leaves_the_live_one(self, tmp_path):
        # e.g. an HTML error page, or a truncated download
        r, target, dest = self._run(tmp_path, "<html><body>rate limited</body></html>\n")
        assert r.returncode == 1
        assert "does not compile" in r.stderr
        assert dest.read_text() == self.LIVE
        assert sorted(p.name for p in target.iterdir()) == ["omr_metrics.py"]

    def test_failed_download_leaves_the_live_one(self, tmp_path):
        r, target, dest = self._run(tmp_path, None)
        assert r.returncode != 0
        assert "DONE" not in r.stdout
        assert dest.read_text() == self.LIVE
        assert sorted(p.name for p in target.iterdir()) == ["omr_metrics.py"]


# ===========================================================================
# docker-compose.yml
# ===========================================================================

COMPOSE = SCRIPT.parent / "docker-compose.yml"


@pytest.fixture(scope="module")
def compose():
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load(COMPOSE.read_text())


class TestCompose:
    def test_torch_alone_from_the_cpu_index(self, compose):
        # download.pytorch.org/whl/cpu has no fastapi, uvicorn or influxdb3-python
        dockerfile = compose["x-torch-build"]["build"]["dockerfile_inline"]
        installs = [cmd.strip(" \\\n&") for cmd in dockerfile.split("pip install")[1:]]
        cpu = [cmd for cmd in installs if "download.pytorch.org/whl/cpu" in cmd]
        assert len(cpu) == 1
        assert cpu[0].split() == ["--no-cache-dir", "torch", "--index-url",
                                  "https://download.pytorch.org/whl/cpu"]
        assert any("fastapi" in cmd and "influxdb3-python" in cmd and "index-url" not in cmd
                   for cmd in installs)

    @staticmethod
    def _entrypoint_python(compose, path):
        script = compose["x-app-base"]["command"][0]
        code = script.split('python3 -c "', 1)[1].split('\n"', 1)[0]
        # sh double quotes: nothing in it may be expanded by sh or compose
        assert "$" not in code and '"' not in code and "`" not in code
        default = "/etc/openmptcprouter-vps-admin/omr-admin-config.json"
        assert default in code
        return code.replace(default, str(path))

    def _run(self, compose, tmp_path, content):
        path = tmp_path / "omr-admin-config.json"
        if content is not None:
            path.write_text(content)
            path.chmod(0o644)
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "INFLUXDB_URL": "http://influxdb:8181", "INFLUXDB_TOKEN": "influx-secret",
               "INFLUXDB_RETENTION": "30d"}
        r = subprocess.run(["python3", "-c", self._entrypoint_python(compose, path)],
                           env=env, capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stderr
        return path

    def test_existing_blocks_kept_and_file_0600(self, compose, tmp_path):
        # auto_learning set by POST /metrics/decision/auto was lost at each start
        # with a trailing comma, as omr-admin accepts it
        path = self._run(compose, tmp_path, '{"auto_learning": {"enabled": false, "interval": 600,},'
                                            ' "influxdb": {"url": "old", "token": "old"},}')
        data = json.loads(path.read_text())
        assert data["auto_learning"] == {"enabled": False, "interval": 600}
        assert data["influxdb"] == {"url": "http://influxdb:8181", "token": "influx-secret",
                                    "org": "omr", "bucket": "omr_metrics", "retention_days": 30}
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert sorted(p.name for p in tmp_path.iterdir()) == ["omr-admin-config.json"]

    @pytest.mark.parametrize("content", [None, "", "{not json", "[1, 2]"],
                             ids=["missing", "empty", "invalid", "not-a-dict"])
    def test_missing_or_invalid_config_tolerated(self, compose, tmp_path, content):
        path = self._run(compose, tmp_path, content)
        data = json.loads(path.read_text())
        assert list(data) == ["influxdb"]
        assert data["influxdb"]["token"] == "influx-secret"
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

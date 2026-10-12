#!/bin/sh
set -eu

# OpenMPTCProuter — InfluxDB 3 Core + AI decision engine setup for Debian 13 (Trixie).
# No interactive prompts.  Compatible with POSIX sh (dash, busybox sh, bash).
#
# Steps:
#   1. Installs InfluxDB 3 Core (InfluxData apt repo, fingerprint-verified)
#   2. Writes /etc/influxdb3/influxdb3-core.conf and starts the service
#   3. Bootstraps the admin token (first run only — token is never shown again)
#      and saves it to /etc/influxdb3/omr-influxdb.env straight away
#   4. Creates the omr_metrics database with 60-day retention (configurable)
#   5. python3-influxdb3  (apt when available, pip fallback)
#   6. PyTorch  [INSTALL_AI=true]
#      python3-torch from Debian when available, CPU-only pip wheel fallback
#   7. Deploys omr_metrics.py, which initialises the decision model [INSTALL_AI=true]
#   8. Injects "influxdb" block into omr-admin-config.json, restarts omr-admin
#
# Edit the variables below before running, or override the tunables from the
# environment, e.g.:  sudo RESET_DATA=true INSTALL_AI=false sh ./install_omr-ai.sh

INFLUX_ORG="omr"              # kept for omr-admin-config.json compatibility; ignored by v3
INFLUX_BUCKET="omr_metrics"
INFLUX_RETENTION="${INFLUX_RETENTION-60d}"           # retention period (e.g. "60d", "30d", "168h"); "" = infinite
INFLUX_RETENTION_DAYS="${INFLUX_RETENTION_DAYS-60}"  # must match INFLUX_RETENTION (written to omr-admin-config.json)
INFLUX_HOST="http://127.0.0.1:65501"
INFLUX_NODE_ID="omr-node"
INFLUX_DATA_DIR="/var/lib/influxdb3/data"

# Set to "true" ONLY if you want to wipe all InfluxDB 3 data and start fresh.
# Needed when a previous admin token exists but the creds file was lost.
# WARNING: destroys all stored metrics.
RESET_DATA="${RESET_DATA:-false}"
OMR_CONFIG_FILE="/etc/openmptcprouter-vps-admin/omr-admin-config.json"
CREDS_FILE="/etc/influxdb3/omr-influxdb.env"

# Set to "false" to skip PyTorch + decision-model init (~250 MB if pip fallback).
INSTALL_AI="${INSTALL_AI:-true}"

# The pip fallback installs these versions (the Debian packages are used when
# there are some): unpinned, every install got whatever PyPI had that day.
INFLUXDB3_PYTHON_VERSION="${INFLUXDB3_PYTHON_VERSION:-0.21.0}"
TORCH_VERSION="${TORCH_VERSION:-2.8.0}"

# Commit (or branch) omr_metrics.py is downloaded from. The VPS installer sets
# it to its OMR_ADMIN_VERSION so omr_metrics.py matches the installed omradmin.py.
OMR_ADMIN_VERSION="${OMR_ADMIN_VERSION:-develop}"

# ---------------------------------------------------------------------------

ARCH="$(dpkg --print-architecture)"
KEYRING_FILE="/usr/share/keyrings/influxdata-archive.gpg"
SOURCES_FILE="/etc/apt/sources.list.d/influxdata.list"
INFLUX_CONF="/etc/influxdb3/influxdb3-core.conf"
INFLUX_KEY_FINGERPRINT="24C975CBA61A024EE1B631787C3D57159FC2F927"

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }
step() { echo; echo "==> $*"; }

[ "$(id -u)" -eq 0 ] || die "Run as root (sudo $0)"

# Try apt first; fall back to pip if the Debian package is absent.
# Usage: apt_or_pip <apt-pkg> <pip-pkg> [extra-pip-args...]
apt_or_pip() {
    local apt_pkg pip_pkg
    apt_pkg="$1"; pip_pkg="$2"; shift 2
    if apt-cache show "$apt_pkg" > /dev/null 2>&1; then
        log "apt: installing ${apt_pkg}"
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$apt_pkg"
    else
        log "apt: ${apt_pkg} not in archive — pip fallback: ${pip_pkg}"
        pip3 install --quiet --break-system-packages "$pip_pkg" "$@" 2>/dev/null \
            || pip3 install --quiet "$pip_pkg" "$@"
    fi
}

# ---------------------------------------------------------------------------
# 1. Install InfluxDB 3 Core
# ---------------------------------------------------------------------------

# Remove any stale sources/keyring so the initial apt-get update uses only
# Debian repos (avoids "keyring not found" failures on re-runs).
rm -f "$SOURCES_FILE" "$KEYRING_FILE"

step "Installing base dependencies..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq influxdb2 influxdb2-cli 2>/dev/null || true
apt-get install -y -qq curl gnupg apt-transport-https ca-certificates python3-pip

step "Verifying and importing InfluxData GPG key..."
KEY_TMP=$(mktemp)
curl -fsSL https://repos.influxdata.com/influxdata-archive.key -o "$KEY_TMP"
gpg --show-keys --with-fingerprint --with-colons "$KEY_TMP" 2>&1 \
    | grep -q "^fpr:.*${INFLUX_KEY_FINGERPRINT}:$" \
    || die "Key fingerprint mismatch — aborting for security"
gpg --dearmor < "$KEY_TMP" > "$KEYRING_FILE"
rm -f "$KEY_TMP"
chmod 644 "$KEYRING_FILE"
log "Key fingerprint verified: ${INFLUX_KEY_FINGERPRINT}"

step "Adding InfluxData apt repository..."
echo "deb [signed-by=${KEYRING_FILE} arch=${ARCH}] https://repos.influxdata.com/debian stable main" \
    > "$SOURCES_FILE"

step "Installing influxdb3-core..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y influxdb3-core

# ---------------------------------------------------------------------------
# 2. Write config and start service
# ---------------------------------------------------------------------------
step "Writing /etc/influxdb3/influxdb3-core.conf..."
mkdir -p /etc/influxdb3
cat > "$INFLUX_CONF" <<EOF
node-id      = "${INFLUX_NODE_ID}"
object-store = "file"
data-dir     = "${INFLUX_DATA_DIR}"
http-bind    = "127.0.0.1:65501"
# Allow health and ping without a token so monitoring tools and this script
# can reach them regardless of whether auth is enabled.
disable-authz = "health,ping"
EOF
# Ensure data dir is owned by the service user
mkdir -p "$INFLUX_DATA_DIR"
chown -R influxdb3:influxdb3 "$INFLUX_DATA_DIR" 2>/dev/null || true

step "Enabling and (re)starting influxdb3-core to apply config..."
systemctl enable influxdb3-core
systemctl restart influxdb3-core

# Wait (up to 30 s) for the HTTP API.  /health is unauthenticated (disable-authz
# in config); accept 200 (no auth / disabled) or 401 (up, auth required).
_wait_for_influx() {
    HTTP_CODE=""
    _i=1
    while [ "$_i" -le 30 ]; do
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${INFLUX_HOST}/health" 2>/dev/null || true)
        if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "401" ]; then return 0; fi
        sleep 1
        _i=$((_i + 1))
    done
    die "InfluxDB 3 did not respond after 30 seconds (last HTTP code: ${HTTP_CODE:-none})"
}

step "Waiting for InfluxDB 3 HTTP API..."
_wait_for_influx
log "InfluxDB 3 is up (HTTP ${HTTP_CODE})."

# ---------------------------------------------------------------------------
# 3. Bootstrap admin token (idempotent)
# ---------------------------------------------------------------------------
_read_saved_token() {
    [ -f "$CREDS_FILE" ] && grep -q "^INFLUX_ADMIN_TOKEN=." "$CREDS_FILE" 2>/dev/null \
        && grep "^INFLUX_ADMIN_TOKEN=" "$CREDS_FILE" | cut -d= -f2-
}

_extract_token() {
    python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token') or d.get('unhashed_token',''))" 2>/dev/null
}

# Ask the server for a brand-new admin (operator) token.
# influxdb3 3.x parses "create token --admin" as its own sub-command, so
# --host/--format MUST come after --admin ("--host ... --admin" is rejected
# with "unexpected argument '--host' found").  Both output streams are kept:
# on a fresh catalog the CLI prints the token as JSON on stdout; when an
# admin token already exists it prints a non-JSON "token name already exists"
# line and still exits 0; anything else (usage error, connection refused...)
# is shown to the user instead of being mistaken for an existing token.
# Sets ADMIN_TOKEN (empty when none was created) and TOKEN_EXISTS (true/false).
_create_admin_token() {
    ADMIN_TOKEN=""
    TOKEN_EXISTS="false"
    TOKEN_OUT=$(influxdb3 create token --admin --host "$INFLUX_HOST" --format json 2>&1) || true
    ADMIN_TOKEN=$(printf '%s\n' "$TOKEN_OUT" | _extract_token || true)
    [ -n "$ADMIN_TOKEN" ] && return 0
    if printf '%s\n' "$TOKEN_OUT" | grep -qi "already exists"; then
        TOKEN_EXISTS="true"
        return 0
    fi
    echo "ERROR: 'influxdb3 create token --admin --host ${INFLUX_HOST}' failed:" >&2
    printf '%s\n' "$TOKEN_OUT" | sed 's/^/       /' >&2
    exit 1
}

_save_creds() {
    mkdir -p "$(dirname "$CREDS_FILE")"
    : > "$CREDS_FILE"
    chmod 600 "$CREDS_FILE"
    cat > "$CREDS_FILE" <<EOF
INFLUX_HOST=${INFLUX_HOST}
INFLUX_ORG=${INFLUX_ORG}
INFLUX_BUCKET=${INFLUX_BUCKET}
INFLUX_ADMIN_TOKEN=${ADMIN_TOKEN}
EOF
}

ADMIN_TOKEN=""
if ADMIN_TOKEN=$(_read_saved_token) && [ -n "$ADMIN_TOKEN" ]; then
    log "Using existing admin token from ${CREDS_FILE}"
else
    step "Bootstrapping admin token..."
    _create_admin_token

    if [ "$TOKEN_EXISTS" = "true" ]; then
        # Admin token exists in the catalog but we don't have it saved.
        if [ "$RESET_DATA" = "true" ]; then
            log "RESET_DATA=true — wiping catalog to re-bootstrap..."
            systemctl stop influxdb3-core
            rm -rf "${INFLUX_DATA_DIR:?}/${INFLUX_NODE_ID:?}"
            systemctl start influxdb3-core
            _wait_for_influx
            _create_admin_token
            [ "$TOKEN_EXISTS" = "true" ] \
                && die "An admin token still exists after wiping ${INFLUX_DATA_DIR}/${INFLUX_NODE_ID}"
        else
            echo ""
            echo "ERROR: An admin token exists in the InfluxDB 3 catalog but"
            echo "       ${CREDS_FILE} is missing or has no token."
            echo ""
            echo "Options:"
            echo "  1. Restore ${CREDS_FILE} from backup and set INFLUX_ADMIN_TOKEN=<token>"
            echo "  2. Re-run with RESET_DATA=true in the environment to wipe all data and start fresh:"
            echo "       sudo RESET_DATA=true sh $0"
            echo "     WARNING: this destroys all stored metrics in InfluxDB 3."
            exit 1
        fi
    fi

    [ -n "$ADMIN_TOKEN" ] || die "Failed to create or recover admin token"
    log "Admin token ready."
fi

# Persist the token right away: it is never shown again, and a failure in any
# later step (pip, PyTorch, download) must not lose it, otherwise the next run
# would hit the "token exists but creds file missing" dead end above.
_save_creds
log "Credentials saved to ${CREDS_FILE} (mode 600)."

# ---------------------------------------------------------------------------
# 4. Create database
# ---------------------------------------------------------------------------
step "Creating database '${INFLUX_BUCKET}'..."
RETENTION_FLAG=""
[ -n "$INFLUX_RETENTION" ] && RETENTION_FLAG="--retention-period ${INFLUX_RETENTION}"
# shellcheck disable=SC2086
if DB_OUT=$(influxdb3 create database "$INFLUX_BUCKET" \
        --host "$INFLUX_HOST" \
        --token "$ADMIN_TOKEN" \
        $RETENTION_FLAG 2>&1); then
    [ -z "$DB_OUT" ] || printf '%s\n' "$DB_OUT"
elif printf '%s\n' "$DB_OUT" | grep -qi "already exists"; then
    log "Database already exists."
else
    printf '%s\n' "$DB_OUT" >&2
    die "Failed to create database '${INFLUX_BUCKET}'"
fi
log "Database ready."

# ---------------------------------------------------------------------------
# 5. Python influxdb3-python client  (Debian package preferred)
# ---------------------------------------------------------------------------
step "Installing influxdb3-python library..."
apt_or_pip python3-influxdb3 "influxdb3-python==${INFLUXDB3_PYTHON_VERSION}"

# ---------------------------------------------------------------------------
# 6. PyTorch  (Debian package preferred, enabled by default)
# ---------------------------------------------------------------------------
if [ "$INSTALL_AI" = "true" ]; then
    step "Installing PyTorch..."
    apt_or_pip python3-torch "torch==${TORCH_VERSION}" --index-url https://download.pytorch.org/whl/cpu
else
    log "INSTALL_AI=false — skipping PyTorch and decision model."
fi

# ---------------------------------------------------------------------------
# 7. Deploy omr_metrics.py to the installed location
# ---------------------------------------------------------------------------
step "Downloading omr_metrics.py..."
dest=/usr/share/omr-admin/omr_metrics.py
mkdir -p /usr/share/omr-admin
curl -fsSL "https://raw.githubusercontent.com/Ysurac/openmptcprouter-vps-admin/${OMR_ADMIN_VERSION}/omr_metrics.py" \
    -o "$dest"
log "  -> ${dest}"

# The decision model, from omr_metrics.py itself: the one built here kept
# its own copy of the network, which drifted (19 features and other layers),
# so omr-admin refused it at every start and each worker made its own.
if [ "$INSTALL_AI" = "true" ]; then
    step "Initialising the decision model..."
    if python3 -c 'import sys; sys.path.insert(0, "/usr/share/omr-admin"); import omr_metrics; sys.exit(0 if omr_metrics.ensure_decision_model() else 1)'; then
        log "Decision model ready."
    else
        log "WARNING: decision model not initialised; omr-admin makes one at first use."
    fi
fi

# ---------------------------------------------------------------------------
# 8. Inject influxdb block into omr-admin-config.json, then restart omr-admin
#    (restarted before, it came up without the influxdb block until the next
#    restart)
# ---------------------------------------------------------------------------
step "Updating ${OMR_CONFIG_FILE}..."
mkdir -p "$(dirname "$OMR_CONFIG_FILE")"

python3 - "$OMR_CONFIG_FILE" "$INFLUX_HOST" "$INFLUX_ORG" "$INFLUX_BUCKET" "$ADMIN_TOKEN" "$INFLUX_RETENTION_DAYS" <<'PYEOF' || die "${OMR_CONFIG_FILE} left unchanged: fix it, then run this script again"
import sys, json, os, re, fcntl

config_file, url, org, bucket, token, retention_days = sys.argv[1:]
lock_path = os.path.join(os.path.dirname(config_file), ".omr-admin-config.lock")
lock_file = open(lock_path, "a+")
fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
try:
    with open(config_file) as f:
        # a trailing comma, as omr-admin reads it
        cfg = json.loads(re.sub(r",\s*}", "}", f.read()))
except FileNotFoundError:
    cfg = {}
except ValueError as e:
    # Not replaced with {}: that was every user, password and key lost.
    print(f"ERROR: could not parse {config_file} ({e})", file=sys.stderr, flush=True)
    sys.exit(1)

cfg["influxdb"] = {
    "url": url, "token": token, "org": org, "bucket": bucket,
    "retention_days": int(retention_days),
}

# Closed-loop auto-learning of the decision model: enabled by default,
# toggleable at runtime via POST /metrics/decision/auto; never overwrite an
# existing tuned block.
cfg.setdefault("auto_learning", {
    "enabled": True,
    "interval": 300,
    "learning_rate": 0.0001,
    "window": 900,
    "min_points": 5,
    "sharpen": 4.0,
    "exploration": 0.0,
    "exploration_scale": 0.15,
})

tmp = config_file + ".tmp"
if os.path.lexists(tmp):
    os.remove(tmp)
# 0600 from the start: every user's password and VPN keys
with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
    json.dump(cfg, f, indent=4)
    f.write("\n")
os.replace(tmp, config_file)
fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
lock_file.close()
print(f"Written {config_file}")
PYEOF

chmod 600 "$OMR_CONFIG_FILE"
systemctl restart omr-admin 2>/dev/null || true
log "omr-admin restarted."

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo
echo "================================================================"
echo " OpenMPTCProuter — InfluxDB 3 Core + AI setup complete"
echo "================================================================"
echo "  API endpoint   : ${INFLUX_HOST}"
echo "  Database       : ${INFLUX_BUCKET}  (retention: ${INFLUX_RETENTION:-infinite})"
echo "  Measurement    : interface_metrics"
echo "  Node ID        : ${INFLUX_NODE_ID}"
echo "  Data dir       : ${INFLUX_DATA_DIR}"
echo ""
echo "  Admin token    : (see ${CREDS_FILE}  -- mode 600)"
echo "  OMR config     : ${OMR_CONFIG_FILE}"
echo ""
echo "  Note: InfluxDB 3 Core has no built-in web UI."
echo "        Use 'influxdb3 query' or connect Grafana to ${INFLUX_HOST}."
echo ""
echo "  Tags  : username, interface, device, status"
echo "  Fields (numeric):"
echo "          latency, rtt_min, rtt_max, loss, jitter, weight, cost"
echo "          bandwidth_rx_bytes, bandwidth_tx_bytes, bandwidth_rx_bps, bandwidth_tx_bps"
echo "          bbr_bw, bbr_pacing_rate, bbr_delivery_rate, bbr_cwnd, bbr_min_rtt, bbr_retrans"
echo "          congestion_score"
echo "          signal_quality, signal_rssi, signal_rsrp, signal_rsrq, signal_sinr"
echo "          wifi_signal, wifi_noise, wifi_channel, wifi_quality, wifi_quality_max"
echo "          tc_sent_bytes, tc_sent_pkts, tc_dropped, tc_overlimits, tc_requeues"
echo "          tc_ecn_mark, tc_drop_overlimit, tc_backlog_bytes, tc_backlog_pkts"
echo "          tc_flows, tc_throttled, tc_flows_plimit, tc_new_flow_count"
echo "  Fields (string):"
echo "          status_msg, device_ip, device_ip6, gateway, gateway6, asn"
echo "          congestion_level"
echo "          signal_operator, signal_state, signal_type"
echo "          wifi_ssid, wifi_bssid, wifi_mode, wifi_bitrate"
echo "          tc_qdisc"
echo "          json_payload"
if [ "$INSTALL_AI" = "true" ]; then
echo ""
echo "  AI decision engine"
echo "    Backend        : $(python3 -c 'import torch; print("torch", torch.__version__)' 2>/dev/null || echo "torch (installed)")"
echo "    Model file     : /etc/openmptcprouter-vps-admin/omr-decision-model.pt"
echo "    Architecture   : Linear(19->24)->ReLU->Linear(24->8)->ReLU->Linear(8->1)"
echo "    Endpoints      : GET  /metrics/decision[?explain=true]"
echo "                     POST /metrics/decision/train"
echo "                     POST /metrics/decision/reset  (admin)"
echo "    Auto-learning  : enabled (toggle with POST /metrics/decision/auto"
echo "                     or auto_learning.enabled in ${OMR_CONFIG_FILE})"
fi
echo "================================================================"

#!/bin/sh
set -eu

# OpenMPTCProuter — InfluxDB 3 Core + AI decision engine setup for Debian 13 (Trixie).
# No interactive prompts.  Compatible with POSIX sh (dash, busybox sh, bash).
#
# Steps:
#   1. Installs InfluxDB 3 Core (InfluxData apt repo, fingerprint-verified)
#   2. Writes /etc/influxdb3/influxdb3-core.conf and starts the service
#   3. Bootstraps the admin token (first run only — token is never shown again)
#   4. Creates the omr_metrics database with 30-day retention
#   5. python3-influxdb3  (apt when available, pip fallback)
#   6. PyTorch + pre-initialised decision model  [INSTALL_AI=true]
#      python3-torch from Debian when available, CPU-only pip wheel fallback
#   7. Deploys omr_metrics.py and restarts omr-admin
#   8. Injects "influxdb" block into omr-admin-config.json
#
# Edit the variables below before running.

INFLUX_ORG="omr"              # kept for omr-admin-config.json compatibility; ignored by v3
INFLUX_BUCKET="omr_metrics"
INFLUX_RETENTION="30d"        # retention period (e.g. "30d", "168h"); "" = infinite
INFLUX_HOST="http://127.0.0.1:65501"
INFLUX_NODE_ID="omr-node"
INFLUX_DATA_DIR="/var/lib/influxdb3/data"

# Set to "true" ONLY if you want to wipe all InfluxDB 3 data and start fresh.
# Needed when a previous admin token exists but the creds file was lost.
# WARNING: destroys all stored metrics.
RESET_DATA="false"
OMR_CONFIG_FILE="/etc/openmptcprouter-vps-admin/omr-admin-config.json"
CREDS_FILE="/etc/influxdb3/omr-influxdb.env"

# Set to "false" to skip PyTorch + decision-model init (~250 MB if pip fallback).
INSTALL_AI="true"

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

step "Waiting for InfluxDB 3 HTTP API..."
HTTP_CODE=""
_i=1
while [ "$_i" -le 30 ]; do
    # /health is unauthenticated (disable-authz in config).
    # Accept 200 (no auth / disabled) or 401 (up, auth required) as "server ready".
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${INFLUX_HOST}/health" 2>/dev/null || true)
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "401" ]; then break; fi
    [ "$_i" -eq 30 ] && die "InfluxDB 3 did not respond after 30 seconds"
    sleep 1
    _i=$((_i + 1))
done
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

ADMIN_TOKEN=""
if ADMIN_TOKEN=$(_read_saved_token) && [ -n "$ADMIN_TOKEN" ]; then
    log "Using existing admin token from ${CREDS_FILE}"
else
    step "Bootstrapping admin token..."
    ADMIN_TOKEN=$(influxdb3 create token --host "$INFLUX_HOST" --admin --format json 2>/dev/null | _extract_token || true)

    if [ -z "$ADMIN_TOKEN" ]; then
        # Admin token exists in the catalog but we don't have it saved.
        if [ "$RESET_DATA" = "true" ]; then
            log "RESET_DATA=true — wiping catalog to re-bootstrap..."
            systemctl stop influxdb3-core
            rm -rf "${INFLUX_DATA_DIR}/${INFLUX_NODE_ID}"
            systemctl start influxdb3-core
            _i=1
            while [ "$_i" -le 30 ]; do
                HC=$(curl -s -o /dev/null -w "%{http_code}" "${INFLUX_HOST}/health" 2>/dev/null || true)
                if [ "$HC" = "200" ] || [ "$HC" = "401" ]; then break; fi
                sleep 1
                _i=$((_i + 1))
            done
            TOKEN_JSON=$(influxdb3 create token --host "$INFLUX_HOST" --admin --format json 2>/dev/null || true)
            ADMIN_TOKEN=$(echo "$TOKEN_JSON" | _extract_token || true)
        else
            echo ""
            echo "ERROR: An admin token exists in the InfluxDB 3 catalog but"
            echo "       ${CREDS_FILE} is missing or has no token."
            echo ""
            echo "Options:"
            echo "  1. Restore ${CREDS_FILE} from backup and set INFLUX_ADMIN_TOKEN=<token>"
            echo "  2. Re-run with RESET_DATA=\"true\" to wipe all data and start fresh"
            echo "     WARNING: this destroys all stored metrics in InfluxDB 3."
            exit 1
        fi
    fi

    [ -n "$ADMIN_TOKEN" ] || die "Failed to create or recover admin token"
    log "Admin token ready."
fi

# ---------------------------------------------------------------------------
# 4. Create database
# ---------------------------------------------------------------------------
step "Creating database '${INFLUX_BUCKET}'..."
RETENTION_FLAG=""
[ -n "$INFLUX_RETENTION" ] && RETENTION_FLAG="--retention-period ${INFLUX_RETENTION}"
# shellcheck disable=SC2086
influxdb3 create database "$INFLUX_BUCKET" \
    --host "$INFLUX_HOST" \
    --token "$ADMIN_TOKEN" \
    $RETENTION_FLAG 2>&1 | grep -v "already exists" || true
log "Database ready."

# ---------------------------------------------------------------------------
# 5. Python influxdb3-python client  (Debian package preferred)
# ---------------------------------------------------------------------------
step "Installing influxdb3-python library..."
apt_or_pip python3-influxdb3 influxdb3-python

# ---------------------------------------------------------------------------
# 6. PyTorch + decision model  (Debian package preferred, enabled by default)
# ---------------------------------------------------------------------------
if [ "$INSTALL_AI" = "true" ]; then
    step "Installing PyTorch..."
    apt_or_pip python3-torch torch --index-url https://download.pytorch.org/whl/cpu

    DECISION_MODEL_FILE="/etc/openmptcprouter-vps-admin/omr-decision-model.pt"
    if [ -f "$DECISION_MODEL_FILE" ]; then
        log "Decision model already exists — skipping init."
    else
        step "Pre-initialising decision model at ${DECISION_MODEL_FILE}..."
        python3 - "$DECISION_MODEL_FILE" <<'PYEOF'
# Mirrors _make_model() / InterfaceScorer from omr_metrics.py exactly.
import sys, os
import torch
import torch.nn as nn

N_FEATURES = 10
_FEATURE_IMPORTANCES = [2.0, 3.0, 1.5, 1.5, 1.0, 1.0, 0.5, 0.8, 0.5, 0.5]

class InterfaceScorer(nn.Module):
    def __init__(self):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(N_FEATURES, 16), nn.ReLU(),
            nn.Linear(16, 8),          nn.ReLU(),
            nn.Linear(8, 1),
        )
    def forward(self, x):
        return self.net(x).squeeze(-1)

model = InterfaceScorer()
imp = torch.tensor(_FEATURE_IMPORTANCES, dtype=torch.float32)
imp = imp / imp.norm()
with torch.no_grad():
    nn.init.xavier_uniform_(model.net[0].weight)
    model.net[0].weight.data[0] = imp
    model.net[0].bias.data.zero_()
    nn.init.xavier_uniform_(model.net[2].weight)
    model.net[2].bias.data.zero_()
    nn.init.xavier_uniform_(model.net[4].weight)
    model.net[4].bias.data.zero_()
model.eval()

dest = sys.argv[1]
os.makedirs(os.path.dirname(dest), exist_ok=True)
tmp = dest + ".tmp"
torch.save(model.state_dict(), tmp)
os.replace(tmp, dest)
print(f"Decision model saved to {dest}")
PYEOF
    fi
else
    log "INSTALL_AI=false — skipping PyTorch and decision model."
fi

# ---------------------------------------------------------------------------
# 7. Deploy omr_metrics.py to the installed location and restart omr-admin
# ---------------------------------------------------------------------------
step "Downloading omr_metrics.py..."
dest=/usr/share/omr-admin/omr_metrics.py
mkdir -p /usr/share/omr-admin
curl -fsSL "https://raw.githubusercontent.com/Ysurac/openmptcprouter-vps-admin/refs/heads/develop/omr_metrics.py" \
    -o "$dest"
log "  -> ${dest}"
systemctl restart omr-admin 2>/dev/null || true
log "omr-admin restarted."

# ---------------------------------------------------------------------------
# 8. Inject influxdb block into omr-admin-config.json
# ---------------------------------------------------------------------------
step "Updating ${OMR_CONFIG_FILE}..."
mkdir -p "$(dirname "$OMR_CONFIG_FILE")"

python3 - "$OMR_CONFIG_FILE" "$INFLUX_HOST" "$INFLUX_ORG" "$INFLUX_BUCKET" "$ADMIN_TOKEN" <<'PYEOF'
import sys, json, os

config_file, url, org, bucket, token = sys.argv[1:]
try:
    with open(config_file) as f:
        cfg = json.load(f)
except FileNotFoundError:
    cfg = {}
except Exception as e:
    print(f"WARNING: could not parse {config_file} ({e}), backing up and starting fresh", flush=True)
    import shutil, time
    shutil.copy2(config_file, config_file + ".bak." + str(int(time.time())))
    cfg = {}

cfg["influxdb"] = {"url": url, "token": token, "org": org, "bucket": bucket}

tmp = config_file + ".tmp"
with open(tmp, "w") as f:
    json.dump(cfg, f, indent=4)
    f.write("\n")
os.replace(tmp, config_file)
print(f"Written {config_file}")
PYEOF

chmod 600 "$OMR_CONFIG_FILE"

# ---------------------------------------------------------------------------
# 9. Save credentials
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "$CREDS_FILE")"
cat > "$CREDS_FILE" <<EOF
INFLUX_HOST=${INFLUX_HOST}
INFLUX_ORG=${INFLUX_ORG}
INFLUX_BUCKET=${INFLUX_BUCKET}
INFLUX_ADMIN_TOKEN=${ADMIN_TOKEN}
EOF
chmod 600 "$CREDS_FILE"

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
echo "    Architecture   : Linear(10->16)->ReLU->Linear(16->8)->ReLU->Linear(8->1)"
echo "    Endpoints      : GET  /metrics/decision[?explain=true]"
echo "                     POST /metrics/decision/train"
echo "                     POST /metrics/decision/reset  (admin)"
fi
echo "================================================================"

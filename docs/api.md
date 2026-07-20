# OpenMPTCProuter Server API

`omradmin.py` is the REST API used by OpenMPTCProuter routers to configure and query
their VPS. It is built on [FastAPI](https://fastapi.tiangolo.com/) and served over
HTTPS by uvicorn (MPTCP-aware listening socket in single-worker mode).

- Default listen address: `0.0.0.0` (or `::` when IPv6 is available)
- Default port: `65500`
- TLS certificate/key: `/etc/openmptcprouter-vps-admin/cert.pem` / `key.pem`
- Main configuration file: `/etc/openmptcprouter-vps-admin/omr-admin-config.json`

## Running

```
python3 omradmin.py [--host HOST] [--port PORT] [--workers N]
```

Defaults come from `omr-admin-config.json` (`port`, `host`, `workers` keys). With
`--workers 1` the server uses an MPTCP listening socket; with more workers it falls
back to standard TCP sockets (uvicorn multi-process mode).

On startup ("lifespan") the server:

1. Registers MPTCP BPF schedulers from `/usr/share/bpf/scheduler` (if present) and
   re-applies the configured `net.mptcp.scheduler` sysctl.
2. Synchronizes Shadowsocks-Go users from the config.
3. Starts the optional `omr_metrics` auto-learning loop (no-op unless enabled, see
   [omr-decision-engine.md](omr-decision-engine.md)).

## Authentication

All endpoints except `/`, `/token`, `/login_basic`, `/clienthost` and `/mptcpsupport`
require a JWT bearer token.

- `POST /token` — OAuth2 password flow (`username` / `password` form fields).
  Returns `{"access_token": "...", "token_type": "bearer"}`. Users are stored in
  `omr-admin-config.json` under `users`.
- `GET /login_basic` — HTTP Basic login that sets the token as an `Authorization`
  cookie and redirects to `/docs` (used to access the Swagger UI from a browser).
- `GET /logout` — clears the `Authorization` cookie.

The token is accepted either as an `Authorization: Bearer <token>` header or as the
`Authorization` cookie.

### Permissions

Each user has one of three permission levels:

| Level   | Meaning |
|---------|---------|
| `ro`    | Read-only: configuration-changing endpoints return `{'result': 'permission'}` |
| `rw`    | Read/write on the user's own configuration |
| `admin` | Full access, including user management endpoints |

### Response conventions

Configuration endpoints return a JSON object of the form:

```json
{"result": "done|error|warning|permission", "reason": "...", "route": "<endpoint>"}
```

`warning` is typically returned when the target software is not installed on the VPS.

## Endpoints

### General / status

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Welcome banner (no auth) |
| GET | `/status` | Server load average, uptime, release, traffic counters |
| GET | `/config` | Full configuration for the current user (keys, ports, VPN/proxy settings…) |
| GET | `/clienthost` | Client IP as seen by the server (no auth) |
| GET | `/mptcpsupport` | Check whether the current connection uses MPTCP (no auth) |
| GET | `/update` | Trigger the VPS update script (`omr-update` service) |
| GET | `/openapi.json` | OpenAPI schema (auth required) |
| GET | `/docs` | Swagger UI (auth required, see `/login_basic`) |
| GET | `/speedtest?size=N` | Download speed test: streams N MiB (1–100, default 10) of zeroes; `X-MPTCP` header reports MPTCP status |
| POST | `/speedtest` | Upload speed test: measures the received request body, returns bytes/duration/speed |

### Proxy configuration

| Method | Path | Body model | Description |
|--------|------|------------|-------------|
| POST | `/proxy` | `Proxy` | Select the proxy used by the current user (`shadowsocks`, `shadowsocks-go`, `shadowsocks-rust`, `v2ray[-vless/vmess/socks/trojan]`, `xray[-vless/vmess/socks/trojan/shadowsocks]`, `none`) |
| POST | `/shadowsocks` | `ShadowsocksConfigparams` | Shadowsocks-libev settings: port, method, key, fast_open, reuse_port, no_delay, MPTCP, obfs (v2ray/obfs plugin, tls/http) |
| POST | `/shadowsocks-go` | `ShadowsocksGoConfigparams` | Shadowsocks-Go settings: port, method, fast_open, reuse_port, MPTCP |
| POST | `/v2ray` | `V2rayconfig` | Refresh V2Ray key/port in the user config |
| POST | `/xray` | `Xrayconfig` | XRay settings: VLESS Reality toggle (auto-heals an empty/placeholder x25519 key pair), Shadowsocks 2022 method, transport (`tcp`, `grpc`, `xhttp`); also ensures the `omrin-tunnel` inbound carries a VLESS Reverse Proxy client (`reverse_key` in the response) used for VPS→LAN port forwarding |
| POST | `/v2rayredirect` / `/xrayredirect` | `V2rayparams` / `Xrayparams` | Redirect a server port to the router through V2Ray/XRay (name, port, proto, optional destip/destport) |
| POST | `/v2rayunredirect` / `/xrayunredirect` | idem | Remove such a redirection |

### VPN configuration

| Method | Path | Body model | Description |
|--------|------|------------|-------------|
| POST | `/vpn` | `Vpn` | Select the VPN used by the current user (`openvpn`, `openvpn_bonding`, `glorytun_tcp`, `glorytun_udp`, `dsvpn`, `mlvpn`, `mqvpn`, `softether`, `none`) |
| POST | `/glorytun` | `GlorytunConfig` | Glorytun key, port, chacha20 toggle |
| POST | `/dsvpn` | `DSVPN` | DSVPN key and port |
| POST | `/mlvpn` | `MLVPN` | MLVPN password, timeout, reorder buffer, loss tolerance, cleartext |
| POST | `/mqvpn` | `MQVPN` | MQVPN key, scheduler, port (default 443), FEC (xor/reed_solomon/…), reinjection, congestion control (bbr2/bbr/cubic/…), reorder profile and per-port reorder rules |
| POST | `/mqvpn_user` | `MQVPNUser` | Admin only: set or clear a fixed IP for an MQVPN user |
| POST | `/openvpn` | `OpenVPN` | OpenVPN TCP port and cipher |
| POST | `/softethervpn` | `SoftEtherVPN` | SoftEther cipher and password |
| POST | `/wireguard` | `WireGuard` | Replace the WireGuard peer list (`[{ip, key}]`) |
| POST | `/vxlan` | `Vxlan` | VXLAN L2 tunnel over the VPN: enable, VNI, port, local/remote IPv4+IPv6, MTU |
| POST | `/vpnips` | `VPNips` | Set the user's VPN local/remote IPs (RFC1918 IPv4, optional IPv6/ULA) |

Port changes automatically update the Shorewall rules and restart the matching
systemd service when the on-disk configuration actually changed (MD5 comparison).

### Firewall (Shorewall)

| Method | Path | Body model | Description |
|--------|------|------------|-------------|
| POST | `/shorewall` | `ShorewallAllparams` | Enable/disable the "redirect all ports (1–64999) to the router" DNAT rules (`redirect_ports`: `enable`/`disable`, `ipproto`: `ipv4`/`ipv6`) |
| POST | `/shorewalllist` | `ShorewallListparams` | List the OMR-managed rules for the current user |
| POST | `/shorewallopen` | `Shorewallparams` | Open/redirect a port (name, port, proto, fwtype `ACCEPT`/`DNAT`, optional source_dip/source_ip/comment) |
| POST | `/shorewallclose` | `Shorewallparams` | Remove a previously added rule |
| POST | `/sipalg` | `SipALGparams` | Enable/disable SIP ALG |

### Network settings

| Method | Path | Body model | Description |
|--------|------|------------|-------------|
| POST | `/mptcp` | `MPTCPparams` | Server MPTCP settings: checksum, path manager, scheduler, syn retries, congestion control, and protocol-version specific knobs |
| POST | `/bypass` | `ByPass` | IPs to bypass (direct out via `intf` instead of the tunnel) |
| POST | `/wan` | `Wanips` | Router WAN IPs (written to the Shadowsocks ACL white list) |
| POST | `/lan` | `Lanips` | Current user LAN subnets (also updates OpenVPN iroutes when client2client is enabled) |

### Backup

| Method | Path | Description |
|--------|------|-------------|
| POST | `/backuppost` | Upload the router backup (`data`: tar.gz encoded in base64); keeps the 10 most recent timestamped copies |
| GET | `/backupget[?filename=...]` | Download the latest (or a specific) backup for the current user, base64-encoded |
| GET | `/backuplist` | List available backups with modification times |

### User management (admin only)

| Method | Path | Body model | Description |
|--------|------|------------|-------------|
| POST | `/add_user` | `NewUser` | Create a user: username, permission, default VPN/proxy, optional userid, keys, Shadowsocks port, public exit IP |
| POST | `/modify_user` | `ModifyUser` | Change password, enabled/disabled state, VPN or proxy of a user |
| POST | `/remove_user` | `RemoveUser` | Delete a user and all its per-user service configuration |
| POST | `/add_user_note` | `ExistingUser` | Attach a free-form note to a user |
| GET | `/list_users` | — | Dump the full user table |
| GET | `/get-number-of-users` | — | Count of users (excluding the admin) |
| POST | `/client2client` | `ClienttoClient` | Enable/disable client-to-client communication |
| POST | `/serialenforce` | `SerialEnforce` | Enable/disable router serial-number enforcement |

### Metrics and decision engine (`omr_metrics` module)

These routes are provided by the optional [omr_metrics.py](../omr_metrics.py) module
and mounted at startup when the module is importable. See
[omr-decision-engine.md](omr-decision-engine.md) for the full description of the
learning engine.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/metrics` | Stored router metrics for the current user |
| POST | `/metrics` | Store metrics for one WAN interface |
| GET | `/metrics/all` | Metrics of all users (admin only) |
| GET | `/metrics/user` | Current user profile and metrics DB statistics |
| GET | `/metrics/history` | Historical metrics (requires InfluxDB) |
| GET | `/metrics/decision` | Model-assigned weight for each WAN interface |
| GET | `/metrics/quality/forecast` | Link-quality forecast |
| POST | `/metrics/decision/train` | Train the decision model |
| POST | `/metrics/decision/reset` | Reset the decision model |
| GET/POST | `/metrics/decision/auto` | Get/set the auto-learning state |
| GET | `/metrics/prometheus` | Prometheus-format metrics export |
| GET | `/metrics/engine` | Decision engine status |

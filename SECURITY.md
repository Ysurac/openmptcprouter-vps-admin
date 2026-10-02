# Security Policy

## Supported versions

Security fixes are made on the `develop` branch and shipped in the next
`omr-vps-admin` package release. Only the latest release is supported; please
upgrade before reporting an issue.

| Version                     | Supported |
| --------------------------- | --------- |
| Latest release / `develop`  | Yes       |
| Older releases              | No        |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Report vulnerabilities privately through GitHub Security Advisories:
<https://github.com/Ysurac/openmptcprouter-vps-admin/security/advisories/new>

Please include:

- the affected version (`omr-vps-admin` package version or commit hash),
- the affected endpoint(s) or component (`omradmin.py`, `omr_metrics`, install
  scripts, Debian packaging, ...),
- steps to reproduce or a proof of concept,
- the impact you observed (authentication bypass, privilege escalation between
  users, command injection, firewall rule injection, information leak, ...).

You should receive an acknowledgement within a few days. Once the issue is
confirmed, a fix will be prepared and released, and the advisory published
with credit to the reporter unless you prefer to remain anonymous.

## Scope

In scope:

- the REST API (`omradmin.py`): authentication (`/token`, `/login_basic`, JWT
  handling), per-user permission checks, and any endpoint that writes system
  configuration (nftables, VPN, Shadowsocks, sysctl, GRE, ...),
- the metrics / decision engine (`omr_metrics.py`),
- the Debian packaging and systemd units in `debian/`,
- the install scripts shipped in this repository.

Out of scope:

- vulnerabilities in third-party software the API configures (OpenVPN,
  WireGuard, Shadowsocks, Xray, Glorytun, ...); please report those upstream,
- issues requiring an attacker who already has root on the VPS,
- the OpenMPTCProuter router firmware itself, which is tracked in the
  [openmptcprouter](https://github.com/Ysurac/openmptcprouter) repository.



# Public IP pool over BGP (`omr_bgp`)

`omr_bgp.py` is an optional omr-admin module. It shares out public IPv4 and
IPv6 pools, routed to the VPS with BGP, between the routers connected to it:
each router gets its own public IPv4 and/or IPv6, reachable from the internet
and used for its outgoing traffic, announced only while the router is
connected.

Without the module, omr-admin works as before. To disable it, follow
[Uninstall](#uninstall): removing `omr_bgp.py` alone leaves the last routes
announced by BIRD and the `omr_bgp` nft table loaded.

> **Not tested in real conditions.** Only the API, the generated BIRD and nft
> configs and the announce/withdraw sync have been checked, by unit tests and
> on a test VPS with no BGP neighbor. No session with a real upstream, no pool
> actually routed to a VPS, and no traffic through the DNAT/SNAT have been
> tested yet. Try it on a VPS you can reach by other means (provider console)
> before relying on it.

## How it works

```
 Internet ── upstream ══BGP══ VPS (BIRD 3) ──MQVPN── router1  fixed IP 10.255.220.5
                              │                └6in4─         endpoint fd00::a00:6, ULA fda2:b17b:c16e::/48
                              │ announced while router1 is connected:
                              │   203.0.113.1/32, 2001:db8:1::1/128
                              nft:  in   203.0.113.1   -> 10.255.220.5          (DNAT)
                                    out  10.255.220.5  -> 203.0.113.1           (SNAT)
                                    in   2001:db8:1::1 -> fd00::a00:6           (DNAT)
                                    out  fd00::a00:6, fda2:b17b:c16e::/48 -> 2001:db8:1::1  (SNAT)
```

- Each router (omr-admin user) can be given one **public IPv4** and one
  **public IPv6** of the pools (`POST /bgp/router`). They are mapped on the
  router's inner addresses:
  - IPv4: its **MQVPN fixed IP** (`POST /mqvpn_user`);
  - IPv6: its **6in4 tunnel endpoint**, the `REMOTEIP6` the router set with
    `/vpnips` (`ip6in4.remoteip` in its `/config`). Outgoing traffic from its
    ULA prefix (`fc00::/7`) is translated too, so the router's LAN shares the
    public IPv6. A global prefix (the main router's may be one) and `auto` are
    left out.
- Every 10 seconds the module asks the MQVPN daemon which users have a live
  session. For each connected router with a public IP:
  - BIRD announces `<public ip>/32` (IPv4) or `/128` (IPv6) to every
    configured BGP neighbor of the same family;
  - the nft table `inet omr_bgp` maps the public IP 1:1 on the inner
    address: inbound traffic to the public IP goes to the router (DNAT), and
    what the router sends leaves with the public IP (SNAT).
- When the session is lost, the routes are withdrawn and the mappings
  removed within 10 seconds.

The router needs no configuration: the NAT happens on the VPS. The VPS
firewall already forwards DNAT-ed traffic to the VPN and 6in4 interfaces.

### Several VPS

With the same pool on several VPS, each one announces only the routers
connected to it, so the upstream sends a router's traffic to the VPS it is
connected to. Give a router the **same public IPs on every VPS**. If a router
is connected to two VPS at once, both announce its routes and the upstream
chooses between them.

## Requirements

- Debian 13 VPS installed with the OpenMPTCProuter VPS script, running MQVPN,
  with an omr-admin version that loads `omr_bgp`
  (`grep 'import omr_bgp' /usr/bin/omradmin.py`; the install script warns
  when it doesn't).
- BGP sessions offered by the provider or upstream: your AS number (a
  private one, 64512-65534, is often accepted), the neighbor address, its AS,
  and the MD5 password and multihop count if it requires them. IPv4 routes
  are announced over sessions with an IPv4 neighbor and IPv6 routes over
  sessions with an IPv6 neighbor: for both families, configure both
  neighbors (providers usually offer one session per family).
- The public pools routed to the VPS, and the upstream accepting /32 and
  /128 announcements from it. Most transit providers only propagate /24
  (IPv4) and /48 (IPv6) or shorter to the internet: per-router routes are for
  the provider's own network, which then announces the aggregate.
- For IPv6: the router's 6in4 tunnel to the VPS (OpenMPTCProuter's IPv6
  over the VPN), carried by MQVPN.

## Install

On the VPS, as root:

```sh
curl -fsSLO https://raw.githubusercontent.com/Ysurac/openmptcprouter-vps-admin/develop/install_omr-bgp.sh
sh ./install_omr-bgp.sh
```

The script:

1. installs `bird3` from the Debian archive;
2. writes a minimal `/etc/bird/bird.conf` (log to syslog, router id, device
   protocol, include of the generated file) if the current one is the
   package's sample. A customised `bird.conf` is kept: it is backed up to
   `bird.conf.bak-omr-bgp` and the include line is appended;
3. creates `/etc/bird/omr-bgp.conf` as `root:bird 0640` (it holds the BGP
   passwords), and enables and starts BIRD;
4. installs `omr_bgp.py` in `/usr/share/omr-admin` and restarts omr-admin.

Running it again is safe. Environment variables:

| Variable | Default | Use |
|---|---|---|
| `BGP_ROUTER_ID` | the VPS's public IPv4 | BIRD router id |
| `OMR_ADMIN_VERSION` | `develop` | branch or commit `omr_bgp.py` is downloaded from: match the installed omr-admin |
| `OMR_BGP_FILE` | | a local `omr_bgp.py` to install instead of downloading one |

Nothing is announced and no NAT is set up until the module is configured.

## Configure

All the endpoints are admin only. With an admin token:

```sh
API=https://<vps>:65500
TOKEN=$(curl -sk -X POST "$API/token" -d username=admin -d 'password=<admin key>' | jq -r .access_token)
AUTH="Authorization: Bearer $TOKEN"
```

### 1. AS, neighbors and pools

```sh
curl -sk -X POST "$API/bgp" -H "$AUTH" -H 'Content-Type: application/json' -d '{
  "local_as": 65001,
  "neighbors": [
    {"name": "upstream1", "address": "192.0.2.1", "as": 64500, "password": "secret", "multihop": 2},
    {"name": "upstream1v6", "address": "2001:db8::1", "as": 64500, "password": "secret", "multihop": 2}
  ],
  "pools": ["203.0.113.0/28", "2001:db8:1::/64"]
}'
```

| Field | Rules |
|---|---|
| `local_as` | 1-4294967295 |
| `neighbors[].name` | letters, digits, `_`, up to 32. The BIRD protocol is `omr_<name>`; `routers` and `routers6` are refused (`omr_routers` and `omr_routers6` are the static protocols of the routes) |
| `neighbors[].address` | IPv4 or IPv6: the session announces the routes of that family |
| `neighbors[].as` | 1-4294967295 |
| `neighbors[].password` | optional, printable ASCII without space, `"` or `\`, up to 80 |
| `neighbors[].multihop` | optional, 1-255 (often 2 at cloud providers) |
| `pools` | IPv4 and IPv6 networks, not `0.0.0.0/0` nor `::/0`. A pool can't be removed while a router still has an address in it |

Each POST replaces the AS, the neighbors and the pools. The routers' public
IPs are kept.

### 2. The router's inner addresses

For a public IPv4, the router needs an MQVPN fixed IP:

```sh
curl -sk -X POST "$API/mqvpn_user" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"username": "router1", "fixed_ip": "10.255.220.5"}'
```

Or let omr-admin give every MQVPN user one:

```sh
curl -sk -X POST "$API/global_options" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"mqvpn_auto_fixed_ip": true}'
```

A connected router keeps its current address, the others get
subnet + userid + 2 (the same on every VPS with the same users). See
`/mqvpn_user` in [api.md](api.md).

For a public IPv6, it needs its 6in4 tunnel: the router sets it up itself
(`/vpnips`) when IPv6 is enabled on it. `GET /bgp` shows it as
`ipv6_endpoint`.

### 3. Public IPs for the router

```sh
curl -sk -X POST "$API/bgp/router" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"username": "router1"}'
# {"result": "done", "route": "bgp/router", "public_ip": "203.0.113.1"}
curl -sk -X POST "$API/bgp/router" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"username": "router1", "family": 6}'
# {"result": "done", "route": "bgp/router", "public_ip": "2001:db8:1::1"}
```

Without `public_ip`, the first free host address of the pools of that
`family` (4 by default) is used. The IPv4 network and broadcast addresses and
the IPv6 subnet-router anycast address (`::0`) are skipped, and so are the
addresses of the VPS itself (its DNAT would take SSH, the API and MQVPN to the
router). Pass `"public_ip"` to choose one: it must be in a pool, not an
address of the VPS and not used by another router, and gives the family
itself. A router has at most one address per
family: a new one replaces the previous one. Use the same addresses for the
router on every VPS.

To take them back, one family or both (without `family`):

```sh
curl -sk -X POST "$API/bgp/router/remove" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"username": "router1", "family": 6}'
```

`/remove_user` takes both back too.

### 4. Check

```sh
curl -sk "$API/bgp" -H "$AUTH"
```

The reply has the stored config, then for each router its public `ipv4` and
`ipv6`, its inner `fixed_ip` and `ipv6_endpoint`, `connected` (`null` when
MQVPN can't be asked) and the public IPs `announced`, and the output of
`birdc show protocols` under `bird`.

On the VPS:

```sh
birdc show protocols                       # omr_<neighbor>: Established when the session is up
birdc show route protocol omr_routers      # the /32 of the connected routers
birdc show route protocol omr_routers6     # their /128
birdc show route export omr_upstream1      # what is sent to a neighbor
nft list table inet omr_bgp                # the DNAT/SNAT mappings
journalctl -u omr-admin | grep omr_bgp     # apply errors
```

## Files

| Path | Content |
|---|---|
| `/etc/openmptcprouter-vps-admin/omr-bgp.json` | config written by the endpoints (0600: holds the BGP passwords) |
| `/etc/bird/bird.conf` | BIRD main config, includes the generated file |
| `/etc/bird/omr-bgp.conf` | generated by omr-admin, overwritten on every change: don't edit it |
| `/usr/share/omr-admin/omr_bgp.py` | the module |

A generated `/etc/bird/omr-bgp.conf` with one connected router:

```
protocol static omr_routers {
	ipv4;
	route 203.0.113.1/32 blackhole;
}

protocol static omr_routers6 {
	ipv6;
	route 2001:db8:1::1/128 blackhole;
}

protocol bgp omr_upstream1 {
	local as 65001;
	neighbor 192.0.2.1 as 64500;
	multihop 2;
	authentication md5;
	password "secret";
	ipv4 {
		import none;
		export where proto = "omr_routers";
	};
}

protocol bgp omr_upstream1v6 {
	local as 65001;
	neighbor 2001:db8::1 as 64500;
	multihop 2;
	authentication md5;
	password "secret";
	ipv6 {
		import none;
		export where proto = "omr_routers6";
	};
}
```

The static routes are `blackhole`: they only carry the announcement, and nft
forwards the traffic. Nothing is imported from the neighbors, and only the
routers' routes of the session's family are exported to them.

To add your own BIRD settings (filters, more protocols, a static route
announcing the whole pool), put them in `/etc/bird/bird.conf`. Don't use the
names `omr_routers`, `omr_routers6` and `omr_<neighbor>` there.

## Behaviour

- **Apply:** the omr-admin worker holding the `omr-bgp.json.leader` lock
  rewrites `omr-bgp.conf`, runs `birdc configure` and loads the nft table in a
  single transaction, only when something changed. A config BIRD refuses (or
  BIRD stopped) is logged and BIRD keeps running the previous one; the nft
  table is loaded all the same. The next round tries again.
- **MQVPN unreachable:** the announcements are kept for up to 2 failed
  status requests in a row, and withdrawn at the third. A short control socket
  hiccup doesn't make every route flap.
- **Firewall reload:** reloading nftables flushes the `omr_bgp` table and
  restarts omr-admin, which loads it again once it is back up (about 30
  seconds). Announcements are not affected meanwhile.
- **Configuration changes** made through the API are applied within 10
  seconds.

## Limits

- One public address per router and family, translated 1:1 (NAT66 in
  IPv6): no routed IPv6 prefix is delegated to the router's LAN.
- Only traffic routed through MQVPN (and IPv6 through the 6in4 tunnel over
  it) uses the public IPs. Traffic the router
  sends through the Shadowsocks or Xray proxies leaves from the VPS's own IP,
  and so does traffic over other VPNs.
- A router without an MQVPN fixed IP can't be given a public IPv4, nor one
  without a 6in4 tunnel a public IPv6. If they go away later, the public IPs
  stay assigned but are not announced.
- BIRD connects out to the neighbors. A neighbor that only accepts sessions it
  opens itself needs TCP port 179 open in the VPS firewall.

## Uninstall

```sh
rm /usr/share/omr-admin/omr_bgp.py /etc/openmptcprouter-vps-admin/omr-bgp.json*
systemctl restart omr-admin
nft delete table inet omr_bgp
apt-get purge bird3     # or remove the include line from /etc/bird/bird.conf
rm /etc/bird/omr-bgp.conf
```

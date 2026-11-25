# Copyright (C) 2026 Ycarus (Yannick Chabanois) <ycarus@zugaina.org> for OpenMPTCProuter
# SPDX-License-Identifier: AGPL-3.0
#
# Optional module: public IPv4 and IPv6 pools, routed to the VPS by BGP,
# shared out to the routers with BIRD 3. Loaded by omradmin.py when present.
# To disable it, see Uninstall in docs/omr-bgp.md: removed alone, the last
# routes stay announced and the nft table loaded.
#
# Each router (user) can be given one IPv4 and one IPv6 of the pools, mapped
# 1:1 on its inner addresses: its MQVPN fixed IP for IPv4, its 6in4 tunnel
# endpoint (REMOTEIP6 of omr-6in4/user<id>) for IPv6. While the router has a
# live MQVPN session, the VPS:
#   - announces <public ip>/32 or /128 to its BGP neighbors (BIRD static
#     protocols omr_routers and omr_routers6, exported by every
#     omr_<neighbor> BGP protocol of the same family as its address)
#   - DNATs the traffic to the public IP to the inner address, and SNATs
#     what the router sends from it (and, in IPv6, from its ULA prefix) to
#     the public IP (nft table inet omr_bgp, ahead of the VPS's own nat chains)
# so the router enters and exits by its public IP, and only through a VPS
# it is connected to: with several VPS announcing the same pool, the
# upstream follows the router. A lost session is withdrawn within
# BGP_INTERVAL seconds. Setup (install_omr-bgp.sh) and details: docs/omr-bgp.md
#
# Files
# -----
# /etc/openmptcprouter-vps-admin/omr-bgp.json  config, written by the endpoints
# /etc/bird/omr-bgp.conf                       generated, included from
#                                              /etc/bird/bird.conf (the include
#                                              line is appended when missing)
# Nothing on the VPS is touched until omr-bgp.json exists.
#
# Endpoints (admin only)
# ----------------------
# GET  /bgp                config, each router's state, `birdc show protocols`
# POST /bgp                {"local_as": 65001,
#                           "neighbors": [{"name": "up1", "address": "192.0.2.1",
#                                          "as": 64500, "password": "...",
#                                          "multihop": 2}],
#                           "pools": ["203.0.113.0/28", "2001:db8:1::/48"]}
#                          neighbor address IPv4 or IPv6, password and
#                          multihop optional
# POST /bgp/router         {"username": "router1", "public_ip": "203.0.113.5"}
#                          or {"username": "router1", "family": 6}: first free
#                          address of the pools of that family (default 4).
#                          IPv4 needs an MQVPN fixed_ip (POST /mqvpn_user),
#                          IPv6 the router's 6in4 tunnel (POST /vpnips)
# POST /bgp/router/remove  {"username": "router1", "family": 6}
#                          family optional: both addresses

import asyncio
import contextlib
import fcntl
import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

LOG = logging.getLogger('uvicorn.error')

BGP_FILE = '/etc/openmptcprouter-vps-admin/omr-bgp.json'
BIRD_CONF = '/etc/bird/bird.conf'
BIRD_INCLUDE = '/etc/bird/omr-bgp.conf'
MQVPN_FILE = '/etc/mqvpn/server.json'
OMR_CONFIG_FILE = '/etc/openmptcprouter-vps-admin/omr-admin-config.json'
OMR_6IN4_DIR = '/etc/openmptcprouter-vps-admin/omr-6in4'
BGP_INTERVAL = 10
# Consecutive get_status failures before every route is withdrawn: one
# control socket timeout must not flap all the announcements
MQVPN_FAILURES_MAX = 3

# fullmatch: with match, '$' also took a trailing newline into BIRD's config
_NAME_RE = re.compile(r'[A-Za-z0-9_]{1,32}')
# Printable ASCII but space, " and \ : the password is a BIRD string
_PASSWORD_RE = re.compile(r'[!#-\[\]-~]{1,80}')
_ULA_NET = ipaddress.IPv6Network('fc00::/7')

_mqvpn_status = None     # omradmin's _mqvpn_status, set by create_router()
_vps_addresses = None    # every address of the VPS's interfaces, as str
_task = None
_leader_fd = None
_applied = None
_mqvpn_failures = 0


# ---- config ----------------------------------------------------------------

def _read_cfg():
    try:
        with open(BGP_FILE) as f:
            cfg = json.load(f)
    except FileNotFoundError:
        return {}
    except ValueError:
        # Every endpoint answered 500 for good: POST /bgp writes it again
        LOG.warning("omr_bgp: %s is not valid JSON, read as empty", BGP_FILE)
        return {}
    return cfg if isinstance(cfg, dict) else {}


def _write_cfg(cfg):
    # mkstemp creates it 0600: the file holds the BGP passwords
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(BGP_FILE), prefix='.omr-bgp.')
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(cfg, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, BGP_FILE)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise


@contextlib.contextmanager
def _cfg_lock():
    # Every uvicorn worker serves these endpoints
    with open(BGP_FILE + '.lock', 'a') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield


def _family(addr):
    return 'ipv%d' % ipaddress.ip_address(addr).version


def _inner_addresses():
    """{username: {'ipv4': [fixed ip], 'ipv6': [6in4 endpoint, ula]}}: the
    first one is the DNAT target, all are SNAT sources. Checked here: they
    end up in the nft ruleset."""
    inner = {}
    try:
        with open(MQVPN_FILE) as f:
            users = json.load(f).get('users', [])
    except (OSError, ValueError, AttributeError):
        users = []
    for u in users:
        with contextlib.suppress(TypeError, KeyError, ValueError):
            inner.setdefault(u['name'], {})['ipv4'] = [str(ipaddress.IPv4Address(u['fixed_ip']))]
    try:
        with open(OMR_CONFIG_FILE) as f:
            # a trailing comma, as omr-admin reads it
            omr_users = json.loads(re.sub(r',\s*}', '}', f.read()))['users'][0]
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        omr_users = {}
    for name, u in omr_users.items():
        try:
            with open(os.path.join(OMR_6IN4_DIR, 'user%d' % int(u['userid']))) as f:
                kv = dict(line.strip().split('=', 1) for line in f if '=' in line)
            v6 = [str(ipaddress.IPv6Interface(kv['REMOTEIP6']).ip)]
        except (OSError, TypeError, KeyError, ValueError, AttributeError):
            continue
        # On its own: 'auto' (the router picks it) dropped the endpoint too.
        # A ULA only: the main router's may be a global prefix (_valid_ula),
        # which its LAN uses as is, not to be NATed onto one address.
        with contextlib.suppress(ValueError):
            ula = ipaddress.IPv6Network(kv.get('ULA', ''))
            if ula.subnet_of(_ULA_NET):
                v6.append(str(ula))
        inner.setdefault(name, {})['ipv6'] = v6
    return inner


def _connected_users():
    """MQVPN users with a live session, None if the daemon can't tell."""
    status = _mqvpn_status() if _mqvpn_status else None
    if status is None:
        return None
    return {c['user'] for c in status.get('clients') or []
            if isinstance(c, dict) and isinstance(c.get('user'), str)}


def active_routes(cfg, connected, inner):
    """{public ip: inner addresses} of the connected routers' public IPs
    that have inner addresses of their family."""
    return {pub: inner[user][fam] for user, ips in cfg.get('routers', {}).items() if user in connected
            for fam, pub in ips.items() if fam in inner.get(user, {})}


# ---- generated configs -----------------------------------------------------

# family: (BIRD static protocol, announced prefix length)
_STATIC = {'ipv4': ('omr_routers', 32), 'ipv6': ('omr_routers6', 128)}
_NFT = {'ipv4': 'ip', 'ipv6': 'ip6'}


def render_bird(cfg, active):
    lines = ['# Generated by omr-admin (omr_bgp.py): overwritten on every change']
    for fam, (proto, plen) in _STATIC.items():
        # blackhole: the route only carries the announcement, nft table
        # omr_bgp forwards the traffic (even with a kernel protocol exporting it)
        lines += ['', 'protocol static %s {' % proto, '\t%s;' % fam]
        lines += ['\troute %s/%d blackhole;' % (pub, plen) for pub in sorted(active) if _family(pub) == fam]
        lines.append('}')
    for n in cfg.get('neighbors', []):
        fam = _family(n['address'])
        lines += ['', 'protocol bgp omr_%s {' % n['name'],
                  '\tlocal as %d;' % cfg['local_as'],
                  '\tneighbor %s as %d;' % (n['address'], n['as'])]
        if n.get('multihop'):
            lines.append('\tmultihop %d;' % n['multihop'])
        if n.get('password'):
            lines += ['\tauthentication md5;', '\tpassword "%s";' % n['password']]
        # A session carries its own family: IPv6 routes over an IPv4
        # session would need an IPv6 next hop configured by hand
        lines += ['\t%s {' % fam, '\t\timport none;', '\t\texport where proto = "%s";' % _STATIC[fam][0], '\t};', '}']
    return '\n'.join(lines) + '\n'


def render_nft(active):
    # One nft -f transaction: the table is replaced, never seen half-built
    dnat = snat = ''
    for pub, inner in sorted(active.items()):
        nf = _NFT[_family(pub)]
        dnat += '\t\t%s daddr %s dnat %s to %s\n' % (nf, pub, nf, inner[0])
        snat += '\t\t%s saddr { %s } snat %s to %s\n' % (nf, ', '.join(inner), nf, pub)
    return ('table inet omr_bgp\ndelete table inet omr_bgp\ntable inet omr_bgp {\n'
            '\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat - 10; policy accept;\n'
            + dnat + '\t}\n'
            '\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat - 10; policy accept;\n'
            + snat + '\t}\n}\n')


def _apply(bird, nft):
    """True once both are live. The NAT is applied whatever BIRD does (it
    serves a pool routed to the VPS without BGP): a config BIRD refused, or
    BIRD stopped, kept every DNAT as it was."""
    ok = _apply_bird(bird)
    r = subprocess.run(['nft', '-f', '-'], input=nft, capture_output=True, text=True, timeout=30, check=False)
    if r.returncode != 0:
        LOG.warning("omr_bgp: nft failed: %s", (r.stderr or '').strip())
        return False
    return ok


def _apply_bird(bird):
    if shutil.which('birdc'):
        # Rewritten in place: the root:bird 0640 install_omr-bgp.sh gives it
        # is kept (it holds the BGP passwords, and omr-admin can't chown)
        with open(BIRD_INCLUDE, 'w', opener=lambda p, fl: os.open(p, fl, 0o640)) as f:
            f.write(bird)
        include = 'include "%s";' % BIRD_INCLUDE
        with open(BIRD_CONF, 'a+') as f:
            f.seek(0)
            if include not in f.read():
                f.write('\n' + include + '\n')
        r = subprocess.run(['birdc', 'configure'], capture_output=True, text=True, timeout=30, check=False)
        # birdc exits 0 on a refused config too: BIRD keeps the previous one
        if 'Reconfigur' not in (r.stdout or ''):
            LOG.warning("omr_bgp: birdc configure failed: %s", (r.stdout or r.stderr or '').strip())
            return False
    else:
        LOG.warning("omr_bgp: birdc not found, routes not announced")
    return True


def _leader():
    """Only one uvicorn worker applies: the one holding this flock (kept
    until exit, retried by the others every round)."""
    global _leader_fd
    if _leader_fd is None:
        fd = os.open(BGP_FILE + '.leader', os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            return False
        _leader_fd = fd
    return True


def sync_once():
    global _applied, _mqvpn_failures
    if not os.path.isfile(BGP_FILE) or not _leader():
        return
    connected = _connected_users()
    if connected is None:
        _mqvpn_failures += 1
        # At startup too: omr-admin up before mqvpn's control socket withdrew
        # every route BIRD announced from its last config, at each boot
        if _mqvpn_failures < MQVPN_FAILURES_MAX:
            return
        connected = set()
    else:
        _mqvpn_failures = 0
    cfg = _read_cfg()
    active = active_routes(cfg, connected, _inner_addresses())
    wanted = (render_bird(cfg, active), render_nft(active))
    # nftables.service restarts omr-admin on a ruleset reload (its drop-in),
    # so _applied is reset whenever the table was flushed
    if wanted != _applied and _apply(*wanted):
        _applied = wanted
        LOG.info("omr_bgp: %d route(s) announced", len(active))


async def _loop():
    while True:
        try:
            await asyncio.to_thread(sync_once)
        except Exception:  # pylint: disable=broad-except
            LOG.exception("omr_bgp: sync failed")
        await asyncio.sleep(BGP_INTERVAL)


def start():
    global _task
    if _task is None or _task.done():
        _task = asyncio.get_running_loop().create_task(_loop())


def stop():
    global _task, _leader_fd
    if _task is not None:
        _task.cancel()
        _task = None
    if _leader_fd is not None:
        with contextlib.suppress(OSError):
            os.close(_leader_fd)
        _leader_fd = None


def purge_user(username: str, family: Optional[str] = None) -> None:
    """Take back *username*'s public IP of *family* ('ipv4', 'ipv6'), both
    without one."""
    if not os.path.isfile(BGP_FILE):
        return
    with _cfg_lock():
        cfg = _read_cfg()
        routers = cfg.get('routers', {})
        ips = routers.get(username)
        if ips is None or (family and family not in ips):
            return
        if family:
            del ips[family]
        if not family or not ips:
            del routers[username]
        _write_cfg(cfg)


# ---- endpoints -------------------------------------------------------------

class Neighbor(BaseModel):
    name: str
    address: str
    as_: int = Field(alias='as', ge=1, le=4294967295)
    password: Optional[str] = None
    multihop: Optional[int] = Field(None, ge=1, le=255)


class BgpConfig(BaseModel):
    local_as: int = Field(ge=1, le=4294967295)
    neighbors: List[Neighbor] = []
    pools: List[str]


class BgpRouter(BaseModel):
    username: str
    public_ip: Optional[str] = None
    family: Optional[Literal[4, 6]] = None


class BgpRouterRemove(BaseModel):
    username: str
    family: Optional[Literal[4, 6]] = None


def _in_pools(addr, pools):
    # an address is never in a network of the other family
    return any(addr in ipaddress.ip_network(p) for p in pools)


def create_router(get_current_active_user, User, mqvpn_status, vps_addresses) -> APIRouter:
    global _mqvpn_status, _vps_addresses
    _mqvpn_status = mqvpn_status
    _vps_addresses = vps_addresses
    router = APIRouter()

    def _admin(user, route):
        if user.permissions != 'admin':
            return {'result': 'permission', 'reason': 'Admin only', 'route': route}
        return None

    def _error(reason, route):
        return {'result': 'error', 'reason': reason, 'route': route}

    @router.get('/bgp', summary="BGP config, routers' public IPs and state, BIRD protocols")
    def get_bgp(current_user: User = Depends(get_current_active_user)):
        if (refused := _admin(current_user, 'bgp')):
            return refused
        cfg = _read_cfg()
        connected = _connected_users()
        inner = _inner_addresses()
        active = active_routes(cfg, connected or set(), inner)
        routers = [{'username': user, 'ipv4': ips.get('ipv4'), 'ipv6': ips.get('ipv6'),
                    'fixed_ip': inner.get(user, {}).get('ipv4', [None])[0],
                    'ipv6_endpoint': inner.get(user, {}).get('ipv6', [None])[0],
                    'connected': (user in connected) if connected is not None else None,
                    'announced': sorted(pub for pub in ips.values() if pub in active)}
                   for user, ips in sorted(cfg.get('routers', {}).items())]
        bird = None
        if shutil.which('birdc'):
            r = subprocess.run(['birdc', 'show', 'protocols'], capture_output=True, text=True, timeout=10, check=False)
            bird = r.stdout
        return {'result': 'done', 'route': 'bgp', 'config': cfg, 'routers': routers, 'bird': bird}

    @router.post('/bgp', summary="Set the BGP AS, neighbors and public IP pools")
    def set_bgp(params: BgpConfig, current_user: User = Depends(get_current_active_user)):
        if (refused := _admin(current_user, 'bgp')):
            return refused
        neighbors = []
        for n in params.neighbors:
            try:
                address = ipaddress.ip_address(n.address)
            except ValueError:
                return _error('Invalid neighbor address', 'bgp')
            if address.is_link_local:
                # BIRD refuses it without an interface
                return _error('Invalid neighbor address', 'bgp')
            # omr_routers and omr_routers6 are the static protocols: BIRD
            # refused the whole config over a second one of the same name
            if not _NAME_RE.fullmatch(n.name) or n.name in ('routers', 'routers6') \
                    or any(x['name'] == n.name for x in neighbors):
                return _error('Invalid or duplicate neighbor name', 'bgp')
            if n.password is not None and not _PASSWORD_RE.fullmatch(n.password):
                return _error('Invalid neighbor password', 'bgp')
            neighbors.append({'name': n.name, 'address': str(address), 'as': n.as_,
                              'password': n.password, 'multihop': n.multihop})
        try:
            pools = [str(ipaddress.ip_network(p, strict=False)) for p in params.pools]
        except ValueError:
            return _error('Invalid pool', 'bgp')
        if any(ipaddress.ip_network(p).prefixlen == 0 for p in pools):
            return _error('Invalid pool', 'bgp')
        with _cfg_lock():
            cfg = _read_cfg()
            if any(not _in_pools(ipaddress.ip_address(pub), pools)
                   for ips in cfg.get('routers', {}).values() for pub in ips.values()):
                return _error('A router public IP is out of the new pools', 'bgp')
            cfg.update(local_as=params.local_as, neighbors=neighbors, pools=pools)
            _write_cfg(cfg)
        return {'result': 'done', 'route': 'bgp'}

    @router.post('/bgp/router', summary="Give a router a public IP of the pools")
    def set_bgp_router(params: BgpRouter, current_user: User = Depends(get_current_active_user)):
        if (refused := _admin(current_user, 'bgp/router')):
            return refused
        addr = None
        if params.public_ip:
            try:
                addr = ipaddress.ip_address(params.public_ip)
            except ValueError:
                return _error('Invalid public_ip', 'bgp/router')
            if params.family and params.family != addr.version:
                return _error('public_ip is not of that family', 'bgp/router')
        version = addr.version if addr else (params.family or 4)
        fam = 'ipv%d' % version
        if fam not in _inner_addresses().get(params.username, {}):
            return _error('User has no MQVPN fixed_ip' if version == 4 else 'User has no 6in4 tunnel', 'bgp/router')
        with _cfg_lock():
            cfg = _read_cfg()
            pools = cfg.get('pools', [])
            routers = cfg.setdefault('routers', {})
            used = {pub for user, ips in routers.items() if user != params.username for pub in ips.values()}
            # the VPS's own address: its DNAT sent SSH, this API and MQVPN
            # itself to the router, whose session then dropped
            vps = {str(ipaddress.ip_address(a)) for a in _vps_addresses()}
            if addr:
                if not _in_pools(addr, pools):
                    return _error('public_ip is out of the pools', 'bgp/router')
                if str(addr) in used:
                    return _error('public_ip already used by another router', 'bgp/router')
                if str(addr) in vps:
                    return _error('public_ip is an address of the VPS', 'bgp/router')
            else:
                addr = next((a for p in pools if ipaddress.ip_network(p).version == version
                             for a in ipaddress.ip_network(p).hosts() if str(a) not in used | vps), None)
                if addr is None:
                    return _error('No free address in the pools', 'bgp/router')
            routers.setdefault(params.username, {})[fam] = str(addr)
            _write_cfg(cfg)
        return {'result': 'done', 'route': 'bgp/router', 'public_ip': str(addr)}

    @router.post('/bgp/router/remove', summary="Take a router's public IP back")
    def remove_bgp_router(params: BgpRouterRemove, current_user: User = Depends(get_current_active_user)):
        if (refused := _admin(current_user, 'bgp/router/remove')):
            return refused
        purge_user(params.username, params.family and 'ipv%d' % params.family)
        return {'result': 'done', 'route': 'bgp/router/remove'}

    return router

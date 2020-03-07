#!/usr/bin/env python3
#
# Copyright (C) 2018-2019 Ycarus (Yannick Chabanois) <ycarus@zugaina.org>
#
# This is free software, licensed under the GNU General Public License v3.0.
# See /LICENSE for more information.
#

import json
import base64
import secrets
import uuid
import configparser
import subprocess
import os
import sys
import socket
import re
import hashlib
import time
from pprint import pprint
from datetime import datetime, timedelta
from tempfile import mkstemp
from typing import List, Optional
from shutil import move
from enum import Enum
import logging
import uvicorn
import jwt
from jwt import PyJWTError
from netaddr import *
from netjsonconfig import OpenWrt
from fastapi import Depends, FastAPI, HTTPException, Security, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, SecurityScopes, OAuth2
from passlib.context import CryptContext
from fastapi.encoders import jsonable_encoder
from fastapi.security.base import SecurityBase
from fastapi.security.utils import get_authorization_scheme_param
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.openapi.utils import get_openapi
from fastapi.openapi.models import SecurityBase as SecurityBaseModel
from pydantic import BaseModel, ValidationError # pylint: disable=E0611
from starlette.status import HTTP_403_FORBIDDEN
from starlette.responses import RedirectResponse, Response, JSONResponse
from starlette.requests import Request

LOG = logging.getLogger('api')
#LOG.setLevel(logging.ERROR)
LOG.setLevel(logging.DEBUG)

# Generate a random secret key
SECRET_KEY = uuid.uuid4().hex
JWT_SECRET_KEY = uuid.uuid4().hex
PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
ACCESS_TOKEN_EXPIRE_MINUTES = 1440
ALGORITHM = "HS256"

# Get main net interface
FILE = open('/etc/shorewall/params.net', "r")
READ = FILE.read()
IFACE = None
for line in READ.splitlines():
    if 'NET_IFACE=' in line:
        IFACE = line.split('=', 1)[1]

# Get interface rx/tx
def get_bytes(t, iface='eth0'):
    with open('/sys/class/net/' + iface + '/statistics/' + t + '_bytes', 'r') as f:
        data = f.read()
    return int(data)

def get_bytes_ss(port):
    ss_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ss_socket.settimeout(3)
    ss_socket.sendto('ping'.encode(), ("127.0.0.1", 8839))
    ss_recv = ss_socket.recv(1024)
    json_txt = ss_recv.decode("utf-8").replace('stat: ', '')
    result = json.loads(json_txt)
    if str(port) in result:
        return result[str(port)]
    else:
        return 0

def add_ss_user(port, key):
    ss_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data = 'add: {"server_port": ' + port + ', "key": "' + key + '"}'
    ss_socket.sendto(data.encode(), ("127.0.0.1", 8839))
    with open('/etc/shadowsocks-libev/manager.json') as f:
        content = f.read()
    content = re.sub(",\s*}", "}", content) # pylint: disable=W1401
    data = json.loads(content)
    data['port_key'][port] = key
    with open('/etc/shadowsocks-libev/manager.json', 'w') as f:
        json.dump(data, f, indent=4)


def remove_ss_user(port):
    ss_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data = 'remove: {"server_port": ' + port + '}'
    ss_socket.sendto(data.encode(), ("127.0.0.1", 8839))
    with open('/etc/shadowsocks-libev/manager.json') as f:
        content = f.read()
    content = re.sub(",\s*}", "}", content) # pylint: disable=W1401
    data = json.loads(content)
    del data['port_key'][port]
    with open('/etc/shadowsocks-libev/manager.json', 'w') as f:
        json.dump(data, f, indent=4)

def add_glorytun_tcp(userid):
    port = '650{:02d}'.format(userid)
    ip = IPNetwork('10.255.255.0/24')
    subnets = ip.subnet(30)
    network = list(subnets)[userid]
    with open('/etc/glorytun-tcp/tun0', 'r') as f, \
          open('/etc/glorytun-tcp/tun' + str(userid), 'w') as n:
        for line in f:
            if 'PORT' in line:
                n.write('PORT=' + port + "\n")
            elif 'DEV' in line:
                n.write('DEV=tun' + str(userid) + "\n")
            elif (not 'LOCALIP' in line
                  and not 'REMOTEIP' in line
                  and not 'BROADCASTIP' in line
                  and not line == "\n"):
                n.write(line)
        n.write("\n" + 'LOCALIP=' + str(list(network)[1]) + "\n")
        n.write('REMOTEIP=' + str(list(network)[2]) + "\n")
        n.write('BROADCASTIP=' + str(network.broadcast) + "\n")
    glorytun_tcp_key = secrets.token_hex(32)
    with open('/etc/glorytun-tcp/tun' + str(userid) + '.key', 'w') as f:
        f.write(glorytun_tcp_key.upper())
    os.system("systemctl -q enable glorytun-tcp@tun" + str(userid))
    os.system("systemctl -q restart glorytun-tcp@tun" + str(userid))

def remove_glorytun_tcp(userid):
    os.system("systemctl -q disable glorytun-tcp@tun" + str(userid))
    os.system("systemctl -q stop glorytun-tcp@tun" + str(userid))
    os.remove('/etc/glorytun-tcp/tun' + str(userid) + '.key')
    os.remove('/etc/glorytun-tcp/tun' + str(userid))

def add_glorytun_udp(userid):
    port = '650{:02d}'.format(userid)
    ip = IPNetwork('10.255.254.0/24')
    subnets = ip.subnet(30)
    network = list(subnets)[userid]
    with open('/etc/glorytun-udp/tun0', 'r') as f, \
          open('/etc/glorytun-udp/tun' + str(userid), 'w') as n:
        for line in f:
            if 'BIND_PORT' in line:
                n.write('BIND_PORT=' + port + "\n")
            elif 'DEV' in line:
                n.write('DEV=tun' + str(userid) + "\n")
            elif (not 'LOCALIP' in line
                  and not 'REMOTEIP' in line
                  and not 'BROADCASTIP' in line
                  and not line == "\n"):
                n.write(line)
        n.write("\n" + 'LOCALIP=' + str(list(network)[1]) + "\n")
        n.write('REMOTEIP=' + str(list(network)[2]) + "\n")
        n.write('BROADCASTIP=' + str(network.broadcast) + "\n")
    with open('/etc/glorytun-tcp/tun' + str(userid) + '.key', 'r') as f, \
          open('/etc/glorytun-udp/tun' + str(userid) + '.key', 'w') as n:
        for line in f:
            n.write(line)
    os.system("systemctl -q enable glorytun-udp@tun" + str(userid))
    os.system("systemctl -q restart glorytun-udp@tun" + str(userid))

def remove_glorytun_udp(userid):
    os.system("systemctl -q disable glorytun-udp@tun" + str(userid))
    os.system("systemctl -q stop glorytun-udp@tun" + str(userid))
    os.remove('/etc/glorytun-udp/tun' + str(userid) + '.key')
    os.remove('/etc/glorytun-udp/tun' + str(userid))


def add_dsvpn(userid):
    port = '654{:02d}'.format(userid)
    ip = IPNetwork('10.255.251.0/24')
    subnets = ip.subnet(30)
    network = list(subnets)[userid]
    with open('/etc/dsvpn/dsvpn0', 'r') as f, open('/etc/dsvpn/dsvpn' + str(userid), 'w') as n:
        for line in f:
            if 'PORT' in line:
                n.write('PORT=' + port + "\n")
            elif 'DEV' in line:
                n.write('DEV=dsvpn' + str(userid) + "\n")
            elif 'LOCALTUNIP' in line:
                n.write('LOCALTUNIP=' + str(list(network)[1]) + "\n")
            elif 'REMOTETUNIP' in line:
                n.write('REMOTETUNIP=' + str(list(network)[2]) + "\n")
            else:
                n.write(line)
    dsvpn_key = secrets.token_hex(32)
    with open('/etc/dsvpn/dsvpn' + str(userid) + '.key', 'w') as f:
        f.write(dsvpn_key.upper())
    os.system("systemctl -q enable dsvpn@dsvpn" + str(userid))
    os.system("systemctl -q restart dsvpn@dsvpn" + str(userid))

def remove_dsvpn(userid):
    os.system("systemctl -q disable dsvpn@dsvpn" + str(userid))
    os.system("systemctl -q stop dsvpn@dsvpn" + str(userid))
    os.remove('/etc/dsvpn/dsvpn' + str(userid))
    os.remove('/etc/dsvpn/dsvpn' + str(userid) + '.key')


def ordered(obj):
    if isinstance(obj, dict):
        return sorted((k, ordered(v)) for k, v in obj.items())
    if isinstance(obj, list):
        return sorted(ordered(x) for x in obj)
    else:
        return obj

def file_as_bytes(file):
    with file:
        return file.read()

def shorewall_add_port(user, port, proto, name, fwtype='ACCEPT'):
    userid = user.userid
    if userid is None:
        userid = 0
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall/rules', 'rb'))).hexdigest()
    fd, tmpfile = mkstemp()
    with open('/etc/shorewall/rules', 'r') as f, \
          open(tmpfile, 'a+') as n:
        for line in f:
            if (fwtype == 'ACCEPT' and not port + '	# OMR open ' + name + ' port ' + proto in line and not port + '	# OMR ' + user.username + ' open ' + name + ' port ' + proto in line):
                n.write(line)
            elif fwtype == 'DNAT' and not port + '	# OMR redirect ' + name + ' port ' + proto in line and not port + '	# OMR ' + user.username + ' redirect ' + name + ' port ' + proto in line:
                n.write(line)
        if fwtype == 'ACCEPT':
            n.write('ACCEPT		net		$FW		' + proto + '	' + port + '	# OMR ' + user.username + ' open ' + name + ' port ' + proto + "\n")
        elif fwtype == 'DNAT' and userid == 0:
            n.write('DNAT		net		vpn:$OMR_ADDR	' + proto + '	' + port + '	# OMR ' + user.username + ' redirect ' + name + ' port ' + proto + "\n")
        elif fwtype == 'DNAT' and userid != 0:
            n.write('DNAT		net		vpn:$OMR_ADDR_USER' + str(userid) + '	' + proto + '	' + port + '	# OMR ' + user.username + ' redirect ' + name + ' port ' + proto + "\n")
    os.close(fd)
    move(tmpfile, '/etc/shorewall/rules')
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall/rules', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        os.system("systemctl -q reload shorewall")

def shorewall_del_port(username, port, proto, name, fwtype='ACCEPT'):
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall/rules', 'rb'))).hexdigest()
    fd, tmpfile = mkstemp()
    with open('/etc/shorewall/rules', 'r') as f, open(tmpfile, 'a+') as n:
        for line in f:
            if fwtype == 'ACCEPT' and not port + '	# OMR open ' + name + ' port ' + proto in line and not port + '	# OMR ' + username + ' open ' + name + ' port ' + proto in line:
                n.write(line)
            elif fwtype == 'DNAT' and not port + '	# OMR redirect ' + name + ' port ' + proto in line and not port + '	# OMR ' + username + ' redirect ' + name + ' port ' + proto in line:
                n.write(line)
    os.close(fd)
    move(tmpfile, '/etc/shorewall/rules')
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall/rules', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        os.system("systemctl -q reload shorewall")

def shorewall6_add_port(user, port, proto, name, fwtype='ACCEPT'):
    userid = user.userid
    if userid is None:
        userid = 0
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall6/rules', 'rb'))).hexdigest()
    fd, tmpfile = mkstemp()
    with open('/etc/shorewall6/rules', 'r') as f, open(tmpfile, 'a+') as n:
        for line in f:
            if fwtype == 'ACCEPT' and not port + '	# OMR open ' + name + ' port ' + proto in line and not port + '	# OMR ' + user.username + ' open ' + name + ' port ' + proto in line:
                n.write(line)
            elif fwtype == 'DNAT' and not port + '	# OMR redirect ' + name + ' port ' + proto in line and not port + '	# OMR ' + user.username + ' redirect ' + name + ' port ' + proto in line:
                n.write(line)
        if fwtype == 'ACCEPT':
            n.write('ACCEPT		net		$FW		' + proto + '	' + port + '	# OMR ' + user.username + ' open ' + name + ' port ' + proto + "\n")
        elif fwtype == 'DNAT' and userid == 0:
            n.write('DNAT		net		vpn:$OMR_ADDR	' + proto + '	' + port + '	# OMR ' + user.username + ' redirect ' + name + ' port ' + proto + "\n")
        elif fwtype == 'DNAT' and userid != 0:
            n.write('DNAT		net		vpn:$OMR_ADDR_USER' + str(userid) + '	' + proto + '	' + port + '	# OMR ' + user.username + ' redirect ' + name + ' port ' + proto + "\n")
    os.close(fd)
    move(tmpfile, '/etc/shorewall6/rules')
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall6/rules', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        os.system("systemctl -q reload shorewall6")

def shorewall6_del_port(username, port, proto, name, fwtype='ACCEPT'):
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall6/rules', 'rb'))).hexdigest()
    fd, tmpfile = mkstemp()
    with open('/etc/shorewall6/rules', 'r') as f, open(tmpfile, 'a+') as n:
        for line in f:
            if fwtype == 'ACCEPT' and not port + '	# OMR open ' + name + ' port ' + proto in line and not port + '	# OMR ' + username + ' open ' + name + ' port ' + proto in line:
                n.write(line)
            elif fwtype == 'DNAT' and not port + '	# OMR redirect ' + name + ' port ' + proto in line and not port + '	# OMR ' + username + ' redirect ' + name + ' port ' + proto in line:
                n.write(line)
    os.close(fd)
    move(tmpfile, '/etc/shorewall6/rules')
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall6/rules', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        os.system("systemctl -q reload shorewall6")

def set_lastchange(sync=0):
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        content = f.read()
    content = re.sub(",\s*}", "}", content) # pylint: disable=W1401
    try:
        data = json.loads(content)
    except ValueError as e:
        return {'error': 'Config file not readable', 'route': 'lastchange'}
    data["lastchange"] = time.time() + sync
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json', 'w') as outfile:
        json.dump(data, outfile, indent=4)

def set_global_param(key, value):
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        content = f.read()
    content = re.sub(",\s*}", "}", content) # pylint: disable=W1401
    try:
        data = json.loads(content)
    except ValueError as e:
        return {'error': 'Config file not readable', 'route': 'global_param'}
    data[key] = value
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json', 'w') as outfile:
        json.dump(data, outfile, indent=4)

def modif_config_user(user, changes):
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        content = json.load(f)
    content['users'][0][user.username].update(changes)
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json', 'w') as f:
        json.dump(content, f, indent=4)

with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
    omr_config_data = json.load(f)

fake_users_db = omr_config_data['users'][0]

def verify_password(plain_password, user_password):
    if plain_password == user_password:
        LOG.debug("password true")
        return True
    return False

def get_password_hash(password):
    return password

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        LOG.debug("user doesn't exist")
        return False
    if not verify_password(password, user.user_password):
        LOG.debug("wrong password")
        return False
    return user

class Token(BaseModel):
    access_token: str = None
    token_type: str = None


class TokenData(BaseModel):
    username: str = None

class User(BaseModel):
    username: str
    vpn: str = None
    vpn_port: int = None
    vpn_client_ip: str = None
    permissions: str = 'rw'
    shadowsocks_port: int = None
    disabled: bool = 'false'
    userid: int = None


class UserInDB(User):
    user_password: str

# Add support for auth before seeing doc
class OAuth2PasswordBearerCookie(OAuth2):
    def __init__(
            self,
            tokenUrl: str,
            scheme_name: str = None,
            scopes: dict = None,
            auto_error: bool = True,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(password={"tokenUrl": tokenUrl, "scopes": scopes})
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(self, request: Request) -> Optional[str]:
        header_authorization: str = request.headers.get("Authorization")
        cookie_authorization: str = request.cookies.get("Authorization")

        header_scheme, header_param = get_authorization_scheme_param(
            header_authorization
        )
        cookie_scheme, cookie_param = get_authorization_scheme_param(
            cookie_authorization
        )

        if header_scheme.lower() == "bearer":
            authorization = True
            scheme = header_scheme
            param = header_param

        elif cookie_scheme.lower() == "bearer":
            authorization = True
            scheme = cookie_scheme
            param = cookie_param

        else:
            authorization = False

        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN, detail="Not authenticated"
                )
            else:
                return None
        return param

class BasicAuth(SecurityBase):
    def __init__(self, scheme_name: str = None, auto_error: bool = True):
        self.scheme_name = scheme_name or self.__class__.__name__
        self.model = SecurityBaseModel(type="http")
        self.auto_error = auto_error

    async def __call__(self, request: Request) -> Optional[str]:
        authorization: str = request.headers.get("Authorization")
        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "basic":
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN, detail="Not authenticated"
                )
            else:
                return None
        return param

basic_auth = BasicAuth(auto_error=False)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearerCookie(tokenUrl="/token")

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def create_access_token(*, data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=60)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=HTTP_403_FORBIDDEN,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            LOG.debug("get_current_user: Username not found")
            raise credentials_exception
        token_data = TokenData(username=username)
    except PyJWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# Show something at homepage
@app.get("/")
async def homepage():
    return "Welcome to OpenMPTCProuter Server part"

# Provide a method to create access tokens. The create_jwt()
# function is used to actually generate the token
@app.post('/token', response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        LOG.debug("Incorrect username or password")
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    # Identity can be any data that is json serializable
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/logout")
async def route_logout_and_remove_cookie():
    response = RedirectResponse(url="/")
    response.delete_cookie("Authorization")
    return response


# Login for doc
@app.get("/login_basic")
async def login_basic(auth: BasicAuth = Depends(basic_auth)):
    if not auth:
        response = Response(headers={"WWW-Authenticate": "Basic"}, status_code=401)
        return response

    try:
        decoded = base64.b64decode(auth).decode("ascii")
        username, _, password = decoded.partition(":")
        user = authenticate_user(fake_users_db, username, password)
        if not user:
            raise HTTPException(status_code=400, detail="Incorrect email or password")

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": username}, expires_delta=access_token_expires
        )

        token = jsonable_encoder(access_token)

        response = RedirectResponse(url="/docs")
        response.set_cookie(
            "Authorization",
            value=f"Bearer {token}",
            httponly=True,
            max_age=1800,
            expires=1800,
        )
        return response

    except:
        response = Response(headers={"WWW-Authenticate": "Basic"}, status_code=401)
        return response


@app.get("/openapi.json")
async def get_open_api_endpoint(current_user: User = Depends(get_current_active_user)):
    return JSONResponse(get_openapi(title="FastAPI", version=1, routes=app.routes))


@app.get("/docs")
async def get_documentation(current_user: User = Depends(get_current_active_user)):
    return get_swagger_ui_html(openapi_url="/openapi.json", title="docs")


# Get VPS status
@app.get('/status')
async def status(current_user: User = Depends(get_current_user)):
    LOG.debug('Get status...')
    vps_loadavg = os.popen("cat /proc/loadavg | awk '{print $1\" \"$2\" \"$3}'").read().rstrip()
    vps_uptime = os.popen("cat /proc/uptime | awk '{print $1}'").read().rstrip()
    vps_hostname = socket.gethostname()
    vps_current_time = time.time()
    vps_kernel = os.popen('uname -r').read().rstrip()
    vps_omr_version = os.popen("grep -s 'OpenMPTCProuter VPS' /etc/* | awk '{print $4}'").read().rstrip()
    mptcp_enabled = os.popen('sysctl -n net.mptcp.mptcp_enabled').read().rstrip()
    #shadowsocks_port = current_user.shadowsocks_port
    #if not shadowsocks_port == None:
    #    ss_traffic = get_bytes_ss(current_user.shadowsocks_port)
    #else:
    ss_traffic = 0

    LOG.debug('Get status: done')
    if IFACE:
        return {'vps': {'time': vps_current_time, 'loadavg': vps_loadavg, 'uptime': vps_uptime, 'mptcp': mptcp_enabled, 'hostname': vps_hostname, 'kernel': vps_kernel, 'omr_version': vps_omr_version}, 'network': {'tx': get_bytes('tx', IFACE), 'rx': get_bytes('rx', IFACE)}, 'shadowsocks': {'traffic': ss_traffic}}
    else:
        return {'error': 'No iface defined', 'route': 'status'}

# Get VPS config
@app.get('/config')
async def config(current_user: User = Depends(get_current_user)):
    LOG.debug('Get config...')
    userid = current_user.userid
    if userid is None:
        userid = 0
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        try:
            omr_config_data = json.load(f)
        except ValueError as e:
            omr_config_data = {}
    LOG.debug('Get config... shadowsocks')
    with open('/etc/shadowsocks-libev/manager.json') as f:
        content = f.read()
    content = re.sub(",\s*}", "}", content) # pylint: disable=W1401
    try:
        data = json.loads(content)
    except ValueError as e:
        data = {'key': '', 'server_port': 65101, 'method': 'chacha20'}
    #shadowsocks_port = data["server_port"]
    shadowsocks_port = current_user.shadowsocks_port
    if not shadowsocks_port == None:
        shadowsocks_key = data["port_key"][str(shadowsocks_port)]
    else:
        shadowsocks_key = ''
    shadowsocks_method = data["method"]
    if 'fast_open' in data:
        shadowsocks_fast_open = data["fast_open"]
    else:
        shadowsocks_fast_open = False
    if 'reuse_port' in data:
        shadowsocks_reuse_port = data["reuse_port"]
    else:
        shadowsocks_reuse_port = False
    if 'no_delay' in data:
        shadowsocks_no_delay = data["no_delay"]
    else:
        shadowsocks_no_delay = False
    if 'mptcp' in data:
        shadowsocks_mptcp = data["mptcp"]
    else:
        shadowsocks_mptcp = False
    if 'ebpf' in data:
        shadowsocks_ebpf = data["ebpf"]
    else:
        shadowsocks_ebpf = False
    if "plugin" in data:
        shadowsocks_obfs = True
        if 'v2ray' in data["plugin"]:
            shadowsocks_obfs_plugin = 'v2ray'
        else:
            shadowsocks_obfs_plugin = 'obfs'
        if 'tls' in data["plugin_opts"]:
            shadowsocks_obfs_type = 'tls'
        else:
            shadowsocks_obfs_type = 'http'
    else:
        shadowsocks_obfs = False
        shadowsocks_obfs_plugin = ''
        shadowsocks_obfs_type = ''
    shadowsocks_port = current_user.shadowsocks_port
    #if not shadowsocks_port == None:
    #    ss_traffic = get_bytes_ss(current_user.shadowsocks_port)
    #else:
    ss_traffic = 0

    LOG.debug('Get config... glorytun')
    if os.path.isfile('/etc/glorytun-tcp/tun' + str(userid) +'.key'):
        glorytun_key = open('/etc/glorytun-tcp/tun' + str(userid) + '.key').readline().rstrip()
    else:
        glorytun_key = ''
    glorytun_port = '65001'
    glorytun_chacha = False
    glorytun_tcp_host_ip = ''
    glorytun_tcp_client_ip = ''
    glorytun_udp_host_ip = ''
    glorytun_udp_client_ip = ''
    if os.path.isfile('/etc/glorytun-tcp/tun' + str(userid)):
        with open('/etc/glorytun-tcp/tun' + str(userid), "r") as glorytun_file:
            for line in glorytun_file:
                if 'PORT=' in line:
                    glorytun_port = line.replace(line[:5], '').rstrip()
                if 'LOCALIP=' in line:
                    glorytun_tcp_host_ip = line.replace(line[:8], '').rstrip()
                if 'REMOTEIP=' in line:
                    glorytun_tcp_client_ip = line.replace(line[:9], '').rstrip()
                if 'chacha' in line:
                    glorytun_chacha = True
    if userid == 0 and glorytun_tcp_host_ip == '':
        if 'glorytun_tcp_type' in omr_config_data:
            if omr_config_data['glorytun_tcp_type'] == 'static':
                glorytun_tcp_host_ip = '10.255.255.1'
                glorytun_tcp_client_ip = '10.255.255.2'
            else:
                glorytun_tcp_host_ip = 'dhcp'
                glorytun_tcp_client_ip = 'dhcp'
        else:
            glorytun_tcp_host_ip = '10.255.255.1'
            glorytun_tcp_client_ip = '10.255.255.2'
    if os.path.isfile('/etc/glorytun-udp/tun' + str(userid)):
        with open('/etc/glorytun-udp/tun' + str(userid), "r") as glorytun_file:
            for line in glorytun_file:
                if 'LOCALIP=' in line:
                    glorytun_udp_host_ip = line.replace(line[:8], '').rstrip()
                if 'REMOTEIP=' in line:
                    glorytun_udp_client_ip = line.replace(line[:9], '').rstrip()

    if userid == 0 and glorytun_udp_host_ip == '':
        if 'glorytun_udp_type' in omr_config_data:
            if omr_config_data['glorytun_udp_type'] == 'static':
                glorytun_udp_host_ip = '10.255.254.1'
                glorytun_udp_client_ip = '10.255.254.2'
            else:
                glorytun_udp_host_ip = 'dhcp'
                glorytun_udp_client_ip = 'dhcp'
        else:
            glorytun_udp_host_ip = '10.255.254.1'
            glorytun_udp_client_ip = '10.255.254.2'
    available_vpn = ["glorytun-tcp", "glorytun-udp"]
    LOG.debug('Get config... dsvpn')
    if os.path.isfile('/etc/dsvpn/dsvpn' + str(userid) + '.key'):
        dsvpn_key = open('/etc/dsvpn/dsvpn' + str(userid) + '.key').readline().rstrip()
        available_vpn.append("dsvpn")
    else:
        dsvpn_key = ''
    dsvpn_port = '65401'
    dsvpn_host_ip = ''
    dsvpn_client_ip = ''
    if os.path.isfile('/etc/dsvpn/dsvpn' + str(userid)):
        with open('/etc/dsvpn/dsvpn' + str(userid), "r") as dsvpn_file:
            for line in dsvpn_file:
                if 'PORT=' in line:
                    dsvpn_port = line.replace(line[:5], '').rstrip()
                if 'LOCALTUNIP=' in line:
                    dsvpn_host_ip = line.replace(line[:11], '').rstrip()
                if 'REMOTETUNIP=' in line:
                    dsvpn_client_ip = line.replace(line[:12], '').rstrip()

    if userid == 0 and dsvpn_host_ip == '':
        dsvpn_host_ip = '10.255.251.1'
        dsvpn_client_ip = '10.255.251.2'

    LOG.debug('Get config... iperf3')
    if os.path.isfile('/etc/iperf3/public.pem'):
        with open('/etc/iperf3/public.pem', "rb") as iperfkey_file:
            iperf_keyb = base64.b64encode(iperfkey_file.read())
            iperf3_key = iperf_keyb.decode('utf-8')
    else:
        iperf3_key = ''

    if os.path.isfile('/etc/pihole/setupVars.conf'):
        pihole = True
    else:
        pihole = False

    LOG.debug('Get config... openvpn')
    #if os.path.isfile('/etc/openvpn/server/static.key'):
    #    with open('/etc/openvpn/server/static.key',"rb") as ovpnkey_file:
    #        openvpn_keyb = base64.b64encode(ovpnkey_file.read())
    #        openvpn_key = openvpn_keyb.decode('utf-8')
    #    available_vpn.append("openvpn")
    #else:
    #    openvpn_key = ''
    openvpn_key = ''
    if os.path.isfile('/etc/openvpn/ca/pki/private/' + current_user.username + '.key'):
        with open('/etc/openvpn/ca/pki/private/' + current_user.username + '.key', "rb") as ovpnkey_file:
            openvpn_keyb = base64.b64encode(ovpnkey_file.read())
            openvpn_client_key = openvpn_keyb.decode('utf-8')
    else:
        openvpn_client_key = ''
    if os.path.isfile('/etc/openvpn/ca/pki/issued/' + current_user.username + '.crt'):
        with open('/etc/openvpn/ca/pki/issued/' + current_user.username + '.crt', "rb") as ovpnkey_file:
            openvpn_keyb = base64.b64encode(ovpnkey_file.read())
            openvpn_client_crt = openvpn_keyb.decode('utf-8')
        available_vpn.append("openvpn")
    else:
        openvpn_client_crt = ''
    if os.path.isfile('/etc/openvpn/ca/pki/ca.crt'):
        with open('/etc/openvpn/ca/pki/ca.crt', "rb") as ovpnkey_file:
            openvpn_keyb = base64.b64encode(ovpnkey_file.read())
            openvpn_client_ca = openvpn_keyb.decode('utf-8')
    else:
        openvpn_client_ca = ''
    openvpn_port = '65301'
    if os.path.isfile('/etc/openvpn/openvpn-tun0.conf'):
        with open('/etc/openvpn/openvpn-tun0.conf', "r") as openvpn_file:
            for line in openvpn_file:
                if 'port ' in line:
                    openvpn_port = line.replace(line[:5], '').rstrip()
    openvpn_host_ip = '10.255.252.1'
    #openvpn_client_ip = '10.255.252.2'
    openvpn_client_ip = 'dhcp'

    LOG.debug('Get config... mlvpn')
    if os.path.isfile('/etc/mlvpn/mlvpn0.conf'):
        mlvpn_config = configparser.ConfigParser()
        mlvpn_config.read_file(open(r'/etc/mlvpn/mlvpn0.conf'))
        mlvpn_key = mlvpn_config.get('general', 'password').strip('"')
        available_vpn.append("mlvpn")
    else:
        mlvpn_key = ''
    mlvpn_host_ip = '10.255.253.1'
    mlvpn_client_ip = '10.255.253.2'

    if 'vpnremoteip' in omr_config_data['users'][0][current_user.username]:
        vpn_remote_ip = omr_config_data['users'][0][current_user.username]['vpnremoteip']
    else:
        vpn_remote_ip = ''
    if 'vpnlocalip' in omr_config_data['users'][0][current_user.username]:
        vpn_local_ip = content['users'][0][current_user.username]['vpnlocalip']
    else:
        vpn_local_ip = ''

    LOG.debug('Get config... mptcp')
    mptcp_enabled = os.popen('sysctl -n net.mptcp.mptcp_enabled').read().rstrip()
    mptcp_checksum = os.popen('sysctl -n net.mptcp.mptcp_checksum').read().rstrip()
    mptcp_path_manager = os.popen('sysctl -n  net.mptcp.mptcp_path_manager').read().rstrip()
    mptcp_scheduler = os.popen('sysctl -n net.mptcp.mptcp_scheduler').read().rstrip()
    mptcp_syn_retries = os.popen('sysctl -n net.mptcp.mptcp_syn_retries').read().rstrip()

    congestion_control = os.popen('sysctl -n net.ipv4.tcp_congestion_control').read().rstrip()

    LOG.debug('Get config... ipv6')
    ipv6_network = os.popen('ip -6 addr show ' + IFACE +' | grep -oP "(?<=inet6 ).*(?= scope global)"').read().rstrip()
    #ipv6_addr = os.popen('wget -6 -qO- -T 2 ipv6.openmptcprouter.com').read().rstrip()
    ipv6_addr = os.popen('ip -6 addr show ' + IFACE +' | grep -oP "(?<=inet6 ).*(?= scope global)" | cut -d/ -f1').read().rstrip()
    #ipv4_addr = os.popen('wget -4 -qO- -T 1 https://ip.openmptcprouter.com').read().rstrip()
    LOG.debug('get server IPv4')
    ipv4_addr = os.popen("dig -4 TXT +timeout=2 +tries=1 +short o-o.myaddr.l.google.com @ns1.google.com | awk -F'\"' '{ print $2}'").read().rstrip()
    if ipv4_addr == '':
        ipv4_addr = os.popen('wget -4 -qO- -T 1 http://ifconfig.co').read().rstrip()
    #ipv4_addr = ""

    test_aes = os.popen('cat /proc/cpuinfo | grep aes').read().rstrip()
    if test_aes == '':
        vps_aes = False
    else:
        vps_aes = True
    vps_kernel = os.popen('uname -r').read().rstrip()
    vps_machine = os.popen('uname -m').read().rstrip()
    vps_omr_version = os.popen("grep -s 'OpenMPTCProuter VPS' /etc/* | awk '{print $4}'").read().rstrip()
    vps_loadavg = os.popen("cat /proc/loadavg | awk '{print $1" "$2" "$3}'").read().rstrip()
    vps_uptime = os.popen("cat /proc/uptime | awk '{print $1}'").read().rstrip()
    LOG.debug('get hostname')
    vps_domain = os.popen('wget -4 -qO- -T 1 http://hostname.openmptcprouter.com').read().rstrip()
    #vps_domain = os.popen('dig -4 +short +times=3 +tries=1 -x ' + ipv4_addr + " | sed 's/\.$//'").read().rstrip()
    user_permissions = current_user.permissions

    localip6 = ''
    remoteip6 = ''
    if userid == 0:
        if os.path.isfile('/etc/openmptcprouter-vps-admin/omr-6in4/user' + str(userid)):
            with open('/etc/openmptcprouter-vps-admin/omr-6in4/user' + str(userid), "r") as omr6in4_file:
                for line in omr6in4_file:
                    if 'LOCALIP6=' in line:
                        localip6 = line.replace(line[:9], '').rstrip()
                    if 'REMOTEIP6=' in line:
                        remoteip6 = line.replace(line[:10], '').rstrip()
    else:
        locaip6 = 'fe80::a00:1'
        remoteip6 = 'fe80::a00:2'

    vpn = 'glorytun_tcp'
    if 'vpn' in omr_config_data['users'][0][current_user.username]:
        vpn = omr_config_data['users'][0][current_user.username]['vpn']
    #vpn = current_user.vpn
    if user_permissions == 'ro':
        del available_vpn
        available_vpn = [vpn]

    alllanips = []
    client2client = False
    if 'client2client' in omr_config_data and omr_config_data['client2client']:
        client2client = True
        for users in omr_config_data['users'][0]:
            if 'lanips' in omr_config_data['users'][0][users] and users != current_user.username and omr_config_data['users'][0][users]['lanips'][0] not in alllanips:
                alllanips.append(omr_config_data['users'][0][users]['lanips'][0])

    shorewall_redirect = "enable"
    with open('/etc/shorewall/rules', 'r') as f:
        for line in f:
            if '#DNAT		net		vpn:$OMR_ADDR	tcp	1-64999' in line:
                shorewall_redirect = "disable"
    LOG.debug('Get config: done')
    return {'vps': {'kernel': vps_kernel, 'machine': vps_machine, 'omr_version': vps_omr_version, 'loadavg': vps_loadavg, 'uptime': vps_uptime, 'aes': vps_aes}, 'shadowsocks': {'traffic': ss_traffic, 'key': shadowsocks_key, 'port': shadowsocks_port, 'method': shadowsocks_method, 'fast_open': shadowsocks_fast_open, 'reuse_port': shadowsocks_reuse_port, 'no_delay': shadowsocks_no_delay, 'mptcp': shadowsocks_mptcp, 'ebpf': shadowsocks_ebpf, 'obfs': shadowsocks_obfs, 'obfs_plugin': shadowsocks_obfs_plugin, 'obfs_type': shadowsocks_obfs_type}, 'glorytun': {'key': glorytun_key, 'udp': {'host_ip': glorytun_udp_host_ip, 'client_ip': glorytun_udp_client_ip}, 'tcp': {'host_ip': glorytun_tcp_host_ip, 'client_ip': glorytun_tcp_client_ip}, 'port': glorytun_port, 'chacha': glorytun_chacha}, 'dsvpn': {'key': dsvpn_key, 'host_ip': dsvpn_host_ip, 'client_ip': dsvpn_client_ip, 'port': dsvpn_port}, 'openvpn': {'key': openvpn_key, 'client_key': openvpn_client_key, 'client_crt': openvpn_client_crt, 'client_ca': openvpn_client_ca, 'host_ip': openvpn_host_ip, 'client_ip': openvpn_client_ip, 'port': openvpn_port}, 'mlvpn': {'key': mlvpn_key, 'host_ip': mlvpn_host_ip, 'client_ip': mlvpn_client_ip}, 'shorewall': {'redirect_ports': shorewall_redirect}, 'mptcp': {'enabled': mptcp_enabled, 'checksum': mptcp_checksum, 'path_manager': mptcp_path_manager, 'scheduler': mptcp_scheduler, 'syn_retries': mptcp_syn_retries}, 'network': {'congestion_control': congestion_control, 'ipv6_network': ipv6_network, 'ipv6': ipv6_addr, 'ipv4': ipv4_addr, 'domain': vps_domain}, 'vpn': {'available': available_vpn, 'current': vpn, 'remoteip': vpn_remote_ip, 'localip': vpn_local_ip}, 'iperf': {'user': 'openmptcprouter', 'password': 'openmptcprouter', 'key': iperf3_key}, 'pihole': {'state': pihole}, 'user': {'name': current_user.username, 'permission': user_permissions}, '6in4': {'localip': localip6, 'remoteip': remoteip6}, 'client2client': {'enabled': client2client, 'lanips': alllanips}}

# Set shadowsocks config
class ShadowsocksConfigparams(BaseModel):
    port: int
    method: str
    fast_open: bool
    reuse_port: bool
    no_delay: bool
    mptcp: bool
    obfs: bool
    obfs_plugin: str
    obfs_type: str
    key: str

@app.post('/shadowsocks')
def shadowsocks(*, params: ShadowsocksConfigparams, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        set_lastchange(10)
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'shadowsocks'}
    ipv6_network = os.popen('ip -6 addr show ' + IFACE +' | grep -oP "(?<=inet6 ).*(?= scope global)"').read().rstrip()
    with open('/etc/shadowsocks-libev/manager.json') as f:
        content = f.read()
    content = re.sub(",\s*}", "}", content) # pylint: disable=W1401
    try:
        data = json.loads(content)
    except ValueError as e:
        data = {'timeout': 600, 'verbose': 0, 'prefer_ipv6': False}
    #key = data["key"]
    if 'timeout' in data:
        timeout = data["timeout"]
    if 'verbose' in data:
        verbose = data["verbose"]
    else:
        verbose = 0
    prefer_ipv6 = data["prefer_ipv6"]
    port = params.port
    method = params.method
    fast_open = params.fast_open
    reuse_port = params.reuse_port
    no_delay = params.no_delay
    mptcp = params.mptcp
    obfs = params.obfs
    obfs_plugin = params.obfs_plugin
    obfs_type = params.obfs_type
    ebpf = 0
    key = params.key
    portkey = data["port_key"]
    modif_config_user(current_user, {'shadowsocks_port': port})
    portkey[str(port)] = key
    #ipv4_addr = os.popen('wget -4 -qO- -T 2 http://ip.openmptcprouter.com').read().rstrip()
    vps_domain = os.popen('wget -4 -qO- -T 2 http://hostname.openmptcprouter.com').read().rstrip()

    if port is None or method is None or fast_open is None or reuse_port is None or no_delay is None or key is None:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'shadowsocks'}
    if ipv6_network == '':
        if obfs:
            if obfs_plugin == "v2ray":
                if obfs_type == "tls":
                    if vps_domain == '':
                        shadowsocks_config = {'server': '0.0.0.0', 'port_key': portkey, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl', 'plugin': '/usr/local/bin/v2ray-plugin', 'plugin_opts': 'server;tls'}
                    else:
                        shadowsocks_config = {'server': '0.0.0.0', 'port_key': portkey, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl', 'plugin': '/usr/local/bin/v2ray-plugin', 'plugin_opts': 'server;tls;host=' + vps_domain}
                else:
                    shadowsocks_config = {'server': '0.0.0.0', 'port_key': portkey, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl', 'plugin': '/usr/local/bin/v2ray-plugin', 'plugin_opts': 'server'}
            else:
                if obfs_type == 'tls':
                    if vps_domain == '':
                        shadowsocks_config = {'server': '0.0.0.0', 'port_key': portkey, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl', 'plugin': '/usr/local/bin/obfs-server', 'plugin_opts': 'obfs=tls;mptcp;fast-open;t=400'}
                    else:
                        shadowsocks_config = {'server': '0.0.0.0', 'port_key': portkey, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl', 'plugin': '/usr/local/bin/obfs-server', 'plugin_opts': 'obfs=tls;mptcp;fast-open;t=400;host=' + vps_domain}
                else:
                    shadowsocks_config = {'server': '0.0.0.0', 'port_key': portkey, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl', 'plugin': '/usr/local/bin/obfs-server', 'plugin_opts': 'obfs=http;mptcp;fast-open;t=400'}
        else:
            shadowsocks_config = {'server': '0.0.0.0', 'port_key': portkey, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl'}
    else:
        if obfs:
            if obfs_plugin == "v2ray":
                if obfs_type == "tls":
                    if vps_domain == '':
                        shadowsocks_config = {'server': '::0', 'port_key': portkey, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl', 'plugin': '/usr/local/bin/v2ray-plugin', 'plugin_opts': 'server;tls'}
                    else:
                        shadowsocks_config = {'server': '::0', 'port_key': portkey, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl', 'plugin': '/usr/local/bin/v2ray-plugin', 'plugin_opts': 'server;tls;host=' + vps_domain}
                else:
                    shadowsocks_config = {'server': '::0', 'port_key': portkey, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl', 'plugin': '/usr/local/bin/v2ray-plugin', 'plugin_opts': 'server'}
            else:
                if obfs_type == 'tls':
                    if vps_domain == '':
                        shadowsocks_config = {'server': ('[::0]', '0.0.0.0'), 'port_key': portkey, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl', 'plugin': '/usr/local/bin/obfs-server', 'plugin_opts': 'obfs=tls;mptcp;fast-open;t=400'}
                    else:
                        shadowsocks_config = {'server': ('[::0]', '0.0.0.0'), 'port_key': portkey, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl', 'plugin': '/usr/local/bin/obfs-server', 'plugin_opts': 'obfs=tls;mptcp;fast-open;t=400;host=' + vps_domain}
                else:
                    shadowsocks_config = {'server': ('[::0]', '0.0.0.0'), 'port_key': portkey, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl', 'plugin': '/usr/local/bin/obfs-server', 'plugin_opts': 'obfs=http;mptcp;fast-open;t=400'}
        else:
            shadowsocks_config = {'server': ('[::0]', '0.0.0.0'), 'port_key': portkey, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl'}

    if ordered(data) != ordered(json.loads(json.dumps(shadowsocks_config))):
        with open('/etc/shadowsocks-libev/manager.json', 'w') as outfile:
            json.dump(shadowsocks_config, outfile, indent=4)
        os.system("systemctl restart shadowsocks-libev-manager@manager.service")
        for x in range(1, os.cpu_count()):
            os.system("systemctl restart shadowsocks-libev-manager@manager" + str(x) + ".service")
        shorewall_add_port(current_user, str(port), 'tcp', 'shadowsocks')
        shorewall_add_port(current_user, str(port), 'udp', 'shadowsocks')
        set_lastchange()
        return {'result': 'done', 'reason': 'changes applied', 'route': 'shadowsocks'}
    else:
        return {'result': 'done', 'reason': 'no changes', 'route': 'shadowsocks'}

# Set shorewall config
class ShorewallAllparams(BaseModel):
    redirect_ports: str
    ipproto: str = "ipv4"

@app.post('/shorewall')
def shorewall(*, params: ShorewallAllparams, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'shorewall'}
    state = params.redirect_ports
    if state is None:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'shorewall'}
    if params.ipproto == 'ipv4':
        initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall/rules', 'rb'))).hexdigest()
        fd, tmpfile = mkstemp()
        with open('/etc/shorewall/rules', 'r') as f, open(tmpfile, 'a+') as n:
            for line in f:
                if state == 'enable' and line == '#DNAT		net		vpn:$OMR_ADDR	tcp	1-64999\n':
                    n.write(line.replace(line[:1], ''))
                elif state == 'enable' and line == '#DNAT		net		vpn:$OMR_ADDR	udp	1-64999\n':
                    n.write(line.replace(line[:1], ''))
                elif state == 'disable' and line == 'DNAT		net		vpn:$OMR_ADDR	tcp	1-64999\n':
                    n.write('#' + line)
                elif state == 'disable' and line == 'DNAT		net		vpn:$OMR_ADDR	udp	1-64999\n':
                    n.write('#' + line)
                else:
                    n.write(line)
        os.close(fd)
        move(tmpfile, '/etc/shorewall/rules')
        final_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall/rules', 'rb'))).hexdigest()
        if not initial_md5 == final_md5:
            os.system("systemctl -q reload shorewall")
    else:
        initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall6/rules', 'rb'))).hexdigest()
        fd, tmpfile = mkstemp()
        with open('/etc/shorewall6/rules', 'r') as f, open(tmpfile, 'a+') as n:
            for line in f:
                if state == 'enable' and line == '#DNAT		net		vpn:$OMR_ADDR	tcp	1-64999\n':
                    n.write(line.replace(line[:1], ''))
                elif state == 'enable' and line == '#DNAT		net		vpn:$OMR_ADDR	udp	1-64999\n':
                    n.write(line.replace(line[:1], ''))
                elif state == 'disable' and line == 'DNAT		net		vpn:$OMR_ADDR	tcp	1-64999\n':
                    n.write('#' + line)
                elif state == 'disable' and line == 'DNAT		net		vpn:$OMR_ADDR	udp	1-64999\n':
                    n.write('#' + line)
                else:
                    n.write(line)
        os.close(fd)
        move(tmpfile, '/etc/shorewall6/rules')
        final_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall6/rules', 'rb'))).hexdigest()
        if not initial_md5 == final_md5:
            os.system("systemctl -q reload shorewall6")
    # Need to do the same for IPv6...
    return {'result': 'done', 'reason': 'changes applied'}

class ShorewallListparams(BaseModel):
    name: str
    ipproto: str = "ipv4"

@app.post('/shorewalllist')
def shorewall_list(*, params: ShorewallListparams, current_user: User = Depends(get_current_user)):
    name = params.name
    if name is None:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'shorewalllist'}
    fwlist = []
    if params.ipproto == 'ipv4':
        with open('/etc/shorewall/rules', 'r') as f:
            for line in f:
                if '# OMR ' + name in line:
                    fwlist.append(line)
    else:
        with open('/etc/shorewall6/rules', 'r') as f:
            for line in f:
                if '# OMR ' + name in line:
                    fwlist.append(line)
    return {'list': fwlist}

class Shorewallparams(BaseModel):
    name: str
    port: str
    proto: str
    fwtype: str
    ipproto: str = "ipv4"

@app.post('/shorewallopen')
def shorewall_open(*, params: Shorewallparams, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'shorewallopen'}
    name = params.name
    port = params.port
    proto = params.proto
    fwtype = params.fwtype
    if name is None:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'shorewallopen'}
    if params.ipproto == 'ipv4':
        shorewall_add_port(current_user, str(port), proto, name, fwtype)
    else:
        shorewall6_add_port(current_user, str(port), proto, name, fwtype)
    return {'result': 'done', 'reason': 'changes applied'}

@app.post('/shorewallclose')
def shorewall_close(*, params: Shorewallparams, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'shorewallclose'}
    name = params.name
    port = params.port
    proto = params.proto
    fwtype = params.fwtype
    if name is None:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'shorewallclose'}
    if params.ipproto == 'ipv4':
        shorewall_del_port(current_user.username, str(port), proto, name, fwtype)
    else:
        shorewall6_del_port(current_user.username, str(port), proto, name, fwtype)
    return {'result': 'done', 'reason': 'changes applied', 'route': 'shorewallclose'}

# Set MPTCP config
class MPTCPparams(BaseModel):
    checksum: str
    path_manager: str
    scheduler: str
    syn_retries: int
    congestion_control: str

@app.post('/mptcp')
def mptcp(*, params: MPTCPparams, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        set_lastchange(10)
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'mptcp'}
    checksum = params.checksum
    path_manager = params.path_manager
    scheduler = params.scheduler
    syn_retries = params.syn_retries
    congestion_control = params.congestion_control
    if not checksum or not path_manager or not scheduler or not syn_retries or not congestion_control:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'mptcp'}
    os.system('sysctl -qw net.mptcp.mptcp_checksum=' + checksum)
    os.system('sysctl -qw net.mptcp.mptcp_path_manager=' + path_manager)
    os.system('sysctl -qw net.mptcp.mptcp_scheduler=' + scheduler)
    os.system('sysctl -qw net.mptcp.mptcp_syn_retries=' + str(syn_retries))
    os.system('sysctl -qw net.ipv4.tcp_congestion_control=' + congestion_control)
    set_lastchange()
    return {'result': 'done', 'reason': 'changes applied'}

class Vpn(BaseModel):
    vpn: str

# Set global VPN config
@app.post('/vpn')
def vpn(*, vpnconfig: Vpn, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        set_lastchange(10)
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'vpn'}
    vpn = vpnconfig.vpn
    if not vpn:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'vpn'}
    os.system('echo ' + vpn + ' > /etc/openmptcprouter-vps-admin/current-vpn')
    modif_config_user(current_user, {'vpn': vpn})
    current_user.vpn = vpn
    set_lastchange()
    return {'result': 'done', 'reason': 'changes applied'}


class GlorytunConfig(BaseModel):
    key: str
    port: int
    chacha: bool

# Set Glorytun config
@app.post('/glorytun')
def glorytun(*, glorytunconfig: GlorytunConfig, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        set_lastchange(10)
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'glorytun'}
    userid = current_user.userid
    if userid == None:
        userid = 0
    key = glorytunconfig.key
    port = glorytunconfig.port
    chacha = glorytunconfig.chacha
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/glorytun-tcp/tun' + str(userid), 'rb'))).hexdigest()
    with open('/etc/glorytun-tcp/tun' + str(userid) + '.key', 'w') as outfile:
        outfile.write(key)
    with open('/etc/glorytun-udp/tun' + str(userid) + '.key', 'w') as outfile:
        outfile.write(key)
    fd, tmpfile = mkstemp()
    with open('/etc/glorytun-tcp/tun' + str(userid), 'r') as f, open(tmpfile, 'a+') as n:
        for line in f:
            if 'PORT=' in line:
                n.write('PORT=' + str(port) + '\n')
            elif 'OPTIONS=' in line:
                if chacha:
                    n.write('OPTIONS="chacha20 retry count -1 const 5000000 timeout 90000 keepalive count 5 idle 10 interval 2 buffer-size 65536 multiqueue"\n')
                else:
                    n.write('OPTIONS="retry count -1 const 5000000 timeout 90000 keepalive count 5 idle 10 interval 2 buffer-size 65536 multiqueue"\n')
            else:
                n.write(line)
    os.close(fd)
    move(tmpfile, '/etc/glorytun-tcp/tun' + str(userid))
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/glorytun-tcp/tun' + str(userid), 'rb'))).hexdigest()
    if not initial_md5 == final_md5:
        os.system("systemctl -q restart glorytun-tcp@tun" + str(userid))
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/glorytun-udp/tun' + str(userid), 'rb'))).hexdigest()
    fd, tmpfile = mkstemp()
    with open('/etc/glorytun-udp/tun' + str(userid), 'r') as f, open(tmpfile, 'a+') as n:
        for line in f:
            if 'BIND_PORT=' in line:
                n.write('BIND_PORT=' + str(port) + '\n')
            elif 'OPTIONS=' in line:
                if chacha:
                    n.write('OPTIONS="chacha persist"\n')
                else:
                    n.write('OPTIONS="persist"\n')
            else:
                n.write(line)
    os.close(fd)
    move(tmpfile, '/etc/glorytun-udp/tun' + str(userid))
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/glorytun-udp/tun' + str(userid), 'rb'))).hexdigest()
    if not initial_md5 == final_md5:
        os.system("systemctl -q restart glorytun-udp@tun" + str(userid))
    shorewall_add_port(current_user, str(port), 'tcp', 'glorytun')
    set_lastchange()
    return {'result': 'done'}

# Set A Dead Simple VPN config
class DSVPN(BaseModel):
    key: str
    port: int

@app.post('/dsvpn')
def dsvpn(*, params: DSVPN, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        set_lastchange(10)
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'dsvpn'}
    userid = current_user.userid
    if userid == None:
        userid = 0
    key = params.key
    port = params.port
    if not key or port is None:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'dsvpn'}

    fd, tmpfile = mkstemp()
    with open('/etc/dsvpn/dsvpn' + str(userid), 'r') as f, open(tmpfile, 'a+') as n:
        for line in f:
            if 'PORT=' in line:
                n.write('PORT=' + str(port) + '\n')
            else:
                n.write(line)
    os.close(fd)
    move(tmpfile, '/etc/dsvpn/dsvpn' + str(userid))

    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/dsvpn/dsvpn' + str(userid) + '.key', 'rb'))).hexdigest()
    with open('/etc/dsvpn/dsvpn.key', 'w') as outfile:
        outfile.write(key)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/dsvpn/dsvpn' + str(userid) + '.key', 'rb'))).hexdigest()
    if not initial_md5 == final_md5:
        os.system("systemctl -q restart dsvpn-server@dsvpn" + str(userid))
    shorewall_add_port(current_user, str(port), 'tcp', 'dsvpn')
    set_lastchange()
    return {'result': 'done'}

# Set OpenVPN config
class OpenVPN(BaseModel):
    key: str

@app.post('/openvpn')
def openvpn(*, ovpn: OpenVPN, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        set_lastchange(10)
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'openvpn'}
    key = ovpn.key
    if not key:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'openvpn'}
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/openvpn/server/static.key', 'rb'))).hexdigest()
    with open('/etc/openvpn/server/static.key', 'w') as outfile:
        outfile.write(base64.b64decode(key))
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/openvpn/server/static.key', 'rb'))).hexdigest()
    if not initial_md5 == final_md5:
        os.system("systemctl -q restart openvpn@tun0")
    set_lastchange()
    return {'result': 'done'}

class Wanips(BaseModel):
    ips: str

# Set WANIP
@app.post('/wan')
def wan(*, wanips: Wanips, current_user: User = Depends(get_current_user)):
    ips = wanips.ips
    if not ips:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'wan'}
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shadowsocks-libev/local.acl', 'rb'))).hexdigest()
    with open('/etc/shadowsocks-libev/local.acl', 'w') as outfile:
        outfile.write('[white_list]\n')
        outfile.write(ips)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/shadowsocks-libev/local.acl', 'rb'))).hexdigest()
    #modif_config_user(current_user,{'wanips': wanip})
    return {'result': 'done'}

class Lanips(BaseModel):
    lanips: List[str] = []

# Set user lan config
@app.post('/lan')
def lan(*, lanconfig: Lanips, current_user: User = Depends(get_current_user)):
    lanips = lanconfig.lanips
    if not lanips:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'lan'}
    modif_config_user(current_user, {'lanips': lanips})
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        omr_config_data = json.load(f)
    client2client = False
    if 'client2client' in omr_config_data:
        client2client = omr_config_data["client2client"]
    if client2client == True:
        with open('/etc/openvpn/ccd/' + current_user.username, 'w') as outfile:
            for lan in lanips:
                ip = IPNetwork(lan)
                outfile.write('iroute ' + str(ip.network) + ' ' + str(ip.netmask) + "\n")
                #outfile.write('route ' + str(ip.network) + ' ' + str(ip.netmask) + "\n")
        initial_md5 = hashlib.md5(file_as_bytes(open('/etc/openvpn/tun0.conf', 'rb'))).hexdigest()
        fd, tmpfile = mkstemp()
        with open('/etc/openvpn/tun0.conf', 'r') as f, open(tmpfile, 'a+') as n:
            for line in f:
                if not 'push "route ' + str(ip.network) + ' ' + str(ip.netmask) + '"' in line:
                    n.write(line)
            n.write('push "route ' + str(ip.network) + ' ' + str(ip.netmask) + '"' + "\n")
        os.close(fd)
        move(tmpfile, '/etc/openvpn/tun0.conf')
        final_md5 = hashlib.md5(file_as_bytes(open('/etc/openvpn/tun0.conf', 'rb'))).hexdigest()
        if not initial_md5 == final_md5:
            os.system("systemctl -q restart openvpn@tun0")
            set_lastchange()
    return {'result': 'done', 'reason': 'changes applied'}

class VPNips(BaseModel):
    remoteip: str
    localip: str

# Set user vpn IPs
@app.post('/vpnips')
def vpnips(*, vpnconfig: VPNips, current_user: User = Depends(get_current_user)):
    remoteip = vpnconfig.remoteip
    localip = vpnconfig.localip
    if not remoteip or not localip:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'vpnips'}
    modif_config_user(current_user, {'vpnremoteip': remoteip})
    modif_config_user(current_user, {'vpnlocalip': localip})
    userid = current_user.userid
    if userid == None:
        userid = 0
    if os.path.isfile('/etc/openmptcprouter-vps-admin/omr-6in4/user' + str(userid)):
        initial_md5 = hashlib.md5(file_as_bytes(open('/etc/openmptcprouter-vps-admin/omr-6in4/user' + str(userid), 'rb'))).hexdigest()
    else:
        initial_md5 = ''
    with open('/etc/openmptcprouter-vps-admin/omr-6in4/user' + str(userid), 'w+') as n:
        n.write('LOCALIP=' + localip + "\n")
        n.write('REMOTEIP=' + remoteip + "\n")
        n.write('LOCALIP6=fe80::a0' + hex(userid)[2:] + ':1/126' + "\n")
        n.write('REMOTEIP6=fe80::a0' + hex(userid)[2:] + ':2/126' + "\n")
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/openmptcprouter-vps-admin/omr-6in4/user' + str(userid), 'rb'))).hexdigest()
    if not initial_md5 == final_md5:
        os.system("systemctl -q restart omr6in4@user" + str(userid))
        set_lastchange()

    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall/params.vpn', 'rb'))).hexdigest()
    fd, tmpfile = mkstemp()
    with open('/etc/shorewall/params.vpn', 'r') as f, open(tmpfile, 'a+') as n:
        for line in f:
            if not ('OMR_ADDR_USER' + str(userid) +'=' in line and not userid == 0) and not ('OMR_ADDR=' in line and userid == 0):
                n.write(line)
        if not userid == 0:
            n.write('OMR_ADDR_USER' + str(userid) + '=' + remoteip + '\n')
        elif userid == 0:
            n.write('OMR_ADDR=' + remoteip + '\n')
    os.close(fd)
    move(tmpfile, '/etc/shorewall/params.vpn')
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall/params.vpn', 'rb'))).hexdigest()
    if not initial_md5 == final_md5:
        os.system("systemctl -q reload shorewall")
        set_lastchange()

    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall6/params.vpn', 'rb'))).hexdigest()
    fd, tmpfile = mkstemp()
    with open('/etc/shorewall6/params.vpn', 'r') as f, open(tmpfile, 'a+') as n:
        for line in f:
            if not ('OMR_ADDR_USER' + str(userid) +'=' in line and not userid == 0) and not ('OMR_ADDR=' in line and userid == 0):
                n.write(line)
        if  not userid == 0:
            n.write('OMR_ADDR_USER' + str(userid) + '=fe80::a0' + hex(userid)[2:] + ':2/126' + '\n')
        elif userid == 0:
            n.write('OMR_ADDR=fe80::a0' + hex(userid)[2:] + ':2/126' + '\n')

    os.close(fd)
    move(tmpfile, '/etc/shorewall6/params.vpn')
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall6/params.vpn', 'rb'))).hexdigest()
    if not initial_md5 == final_md5:
        os.system("systemctl -q reload shorewall6")
        set_lastchange()

    return {'result': 'done', 'reason': 'changes applied'}


# Update VPS
@app.get('/update')
def update(current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'update'}
    os.system("wget -O - http://www.openmptcprouter.com/server/debian9-x86_64.sh | sh")
    # Need to reboot if kernel change
    return {'result': 'done'}

# Backup
class Backupfile(BaseModel):
    data: str

@app.post('/backuppost')
def backuppost(*, backupfile: Backupfile, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'backuppost'}
    backup_file = backupfile.data
    if not backup_file:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'backuppost'}
    with open('/var/opt/openmptcprouter/' + current_user.username + '-backup.tar.gz', 'wb') as f:
        f.write(base64.b64decode(backup_file))
    return {'result': 'done'}

@app.get('/backupget')
def send_backup(current_user: User = Depends(get_current_user)):
    with open('/var/opt/openmptcprouter/' + current_user.username + '-backup.tar.gz', "rb") as backup_file:
        file_base64 = base64.b64encode(backup_file.read())
        file_base64utf = file_base64.decode('utf-8')
    return {'data': file_base64utf}

@app.get('/backuplist')
def list_backup(current_user: User = Depends(get_current_user)):
    if os.path.isfile('/var/opt/openmptcprouter/' + current_user.username + '-backup.tar.gz'):
        modiftime = os.path.getmtime('/var/opt/openmptcprouter/' + current_user.username + '-backup.tar.gz')
        return {'backup': True, 'modif': modiftime}
    else:
        return {'backup': False}

@app.get('/backupshow')
def show_backup(current_user: User = Depends(get_current_user)):
    if os.path.isfile('/var/opt/openmptcprouter/' + current_user.username + '-backup.tar.gz'):
        router = OpenWrt(native=open('/var/opt/openmptcprouter/' + current_user.username + '-backup.tar.gz'))
        return {'backup': True, 'data': router}
    else:
        return {'backup': False}

@app.post('/backupedit')
def edit_backup(params, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'backupedit'}
    o = OpenWrt(params)
    o.write(current_user.username + '-backup', path='/var/opt/openmptcprouter/')
    return {'result': 'done'}

class VPN(str, Enum):
    openvpn = "openvpn"
    glorytuntcp = "glorytun_tcp"
    glorytunudp = "glorytun_udp"

class permissions(str, Enum):
    ro = "ro"
    rw = "rw"
    admin = "admin"

class NewUser(BaseModel):
    username: str = Query(None, title="Username")
    permission: permissions = Query("ro", title="permission of the user")
#    shadowsocks_port: int = Query(None, title="Shadowsocks port")
    vpn: VPN = Query("openvpn", title="default VPN for the user")
#    vpn_port: int = None
#    userid: int = Query(0, title="User ID",description="User ID is used to create port of each VPN and shadowsocks",gt=0,le=99)

@app.post('/add_user')
def add_user(*, params: NewUser, current_user: User = Depends(get_current_user)):
    if not current_user.permissions == "admin":
        return {'result': 'permission', 'reason': 'Need admin user', 'route': 'add_user'}
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        content = json.load(f)
    userid = 2
    for users in content['users'][0]:
        if 'userid' in content['users'][0][users]:
            if int(content['users'][0][users]['userid']) > userid:
                userid = int(content['users'][0][users]['userid'])
    userid = userid + 1
    user_key = secrets.token_hex(32)
    user_json = json.loads('{"'+ params.username + '": {"username":"'+ params.username +'","permissions":"'+params.permission+'","user_password": "'+user_key.upper()+'","disabled":"false","userid":"' + str(userid) + '"}}')
#    shadowsocks_port = params.shadowsocks_port
#    if params.shadowsocks_port is None:
    shadowsocks_port = '651{:02d}'.format(userid)

    shadowsocks_key = base64.urlsafe_b64encode(secrets.token_hex(16).encode())
    add_ss_user(str(shadowsocks_port), shadowsocks_key.decode('utf-8'))
    user_json[params.username].update({"shadowsocks_port": shadowsocks_port})
    if params.vpn is not None:
        user_json[params.username].update({"vpn": params.vpn})
    content['users'][0].update(user_json)
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json', 'w') as f:
        json.dump(content, f, indent=4)
    # Create VPNs configuration
    os.system('cd /etc/openvpn/ca && EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "' + params.username + '" nopass')
    add_glorytun_tcp(userid)
    add_glorytun_udp(userid)
    add_dsvpn(userid)

    set_lastchange(30)
    os.execv(__file__, sys.argv)

class RemoveUser(BaseModel):
    username: str

@app.post('/remove_user')
def remove_user(*, params: RemoveUser, current_user: User = Depends(get_current_user)):
    if not current_user.permissions == "admin":
        return {'result': 'permission', 'reason': 'Need admin user', 'route': 'remove_user'}
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        content = json.load(f)
    shadowsocks_port = content['users'][0][params.username]['shadowsocks_port']
    userid = int(content['users'][0][params.username]['userid'])
    del content['users'][0][params.username]
    remove_ss_user(str(shadowsocks_port))
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json', 'w') as f:
        json.dump(content, f, indent=4)
    os.system('cd /etc/openvpn/ca && ./easyrsa --batch revoke ' + params.username)
    os.system('cd /etc/openvpn/ca && ./easyrsa gen-crl')
    os.system("systemctl -q restart openvpn@tun0")
    remove_glorytun_tcp(userid)
    remove_glorytun_udp(userid)
    remove_dsvpn(userid)

    set_lastchange(30)
    os.execv(__file__, sys.argv)

class ClienttoClient(BaseModel):
    enable: bool = False

@app.post('/client2client')
def client2client(*, params: ClienttoClient, current_user: User = Depends(get_current_user)):
    if not current_user.permissions == "admin":
        return {'result': 'permission', 'reason': 'Need admin user', 'route': 'client2client'}
    set_global_param('client2client', params.enable)
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/openvpn/tun0.conf', 'rb'))).hexdigest()
    fd, tmpfile = mkstemp()
    with open('/etc/openvpn/tun0.conf', 'r') as f, open(tmpfile, 'a+') as n:
        for line in f:
            if not 'client-to-client' in line:
                n.write(line)
        if params.enable == True:
            n.write('client-to-client' + "\n")
    os.close(fd)
    move(tmpfile, '/etc/openvpn/tun0.conf')
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/openvpn/tun0.conf', 'rb'))).hexdigest()
    if not initial_md5 == final_md5:
        os.system("systemctl -q restart openvpn@tun0")
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall/policy', 'rb'))).hexdigest()
    fd, tmpfile = mkstemp()
    with open('/etc/shorewall/policy', 'r') as f, open(tmpfile, 'a+') as n:
        for line in f:
            if not line == 'vpn		vpn		DROP\n' and not line == '# THE FOLLOWING POLICY MUST BE LAST\n' and not line == 'all		all		REJECT		info\n':
                n.write(line)
        if params.enable == False:
            n.write('vpn		vpn		DROP\n')
        n.write('# THE FOLLOWING POLICY MUST BE LAST\n')
        n.write('all		all		REJECT		info\n')
    os.close(fd)
    move(tmpfile, '/etc/shorewall/policy')
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall/policy', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        os.system("systemctl -q reload shorewall")
    return {'result': 'done'}

@app.get('/list_users')
async def list_users(current_user: User = Depends(get_current_user)):
    if not current_user.permissions == "admin":
        return {'result': 'permission', 'reason': 'Need admin user', 'route': 'list_users'}
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        content = json.load(f)
    return content['users'][0]

if __name__ == '__main__':
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        omr_config_data = json.load(f)
    omrport = 65500
    if 'port' in omr_config_data:
        omrport = omr_config_data["port"]
    omrhost = '0.0.0.0'
    if 'host' in omr_config_data:
        omrhost = omr_config_data["host"]
#    uvicorn.run(app,host='0.0.0.0',port=omrport,log_level='debug',ssl_certfile='/etc/openmptcprouter-vps-admin/cert.pem',ssl_keyfile='/etc/openmptcprouter-vps-admin/key.pem')
    uvicorn.run(app, host=omrhost, port=omrport, log_level='error', ssl_certfile='/etc/openmptcprouter-vps-admin/cert.pem', ssl_keyfile='/etc/openmptcprouter-vps-admin/key.pem')
#    uvicorn.run(app,host='0.0.0.0',port=omrport,ssl_context=('/etc/openmptcprouter-vps-admin/cert.pem', '/etc/openmptcprouter-vps-admin/key.pem'),threaded=True)

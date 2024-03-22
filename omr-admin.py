#!/usr/bin/env python3
#
# Copyright (C) 2018-2023 Ycarus (Yannick Chabanois) <ycarus@zugaina.org> for OpenMPTCProuter
#
# This is free software, licensed under the GNU General Public License v3.0.
# See /LICENSE for more information.
#

import json
import base64
import secrets
import uuid
import configparser
import argparse
import subprocess
import os
import sys
import glob
import socket
from operator import itemgetter, attrgetter
import re
import hashlib
import pathlib
import shutil
import psutil
import time
import uuid
from pprint import pprint
from datetime import datetime, timedelta
from tempfile import mkstemp
from typing import List, Optional
from shutil import move
from enum import Enum
from os import path
import logging
import uvicorn
import jwt
import requests
from jwt import PyJWTError
from netaddr import *
from ipaddress import ip_address, IPv4Address, IPv6Address
from netjsonconfig import OpenWrt
from fastapi import Depends, FastAPI, HTTPException, Security, Query, Request, UploadFile
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, SecurityScopes, OAuth2
from passlib.context import CryptContext
from fastapi.encoders import jsonable_encoder
from fastapi.security.base import SecurityBase
from fastapi.security.utils import get_authorization_scheme_param
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.openapi.utils import get_openapi
from fastapi.openapi.models import SecurityBase as SecurityBaseModel
from fastapi.responses import StreamingResponse, FileResponse
from pydantic import BaseModel, ValidationError # pylint: disable=E0611
from starlette.status import HTTP_403_FORBIDDEN
from starlette.responses import RedirectResponse, Response, JSONResponse
#from starlette.requests import Request
import netifaces

#logging.basicConfig(filename='/tmp/omr-admin.log', encoding='utf-8', level=logging.DEBUG)
LOG = logging.getLogger('api')
LOG.setLevel(logging.ERROR)
#LOG.setLevel(logging.DEBUG)

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
FILE.close()

# Get ipv6 net interface
FILE = open('/etc/shorewall6/params.net', "r")
READ = FILE.read()
IFACE6 = None
for line in READ.splitlines():
    if 'NET_IFACE=' in line:
        IFACE6 = line.split('=', 1)[1]
FILE.close()

def delete_oldest_files(path, keep = 10):
    files = glob.glob(path)
    fileData = {}
    for fname in files:
        fileData[fname] = os.stat(fname).st_mtime
    sorted_files = sorted(fileData.items(), key = itemgetter(1))
    if len(sorted_files) > keep:
        delete = len(sorted_files) - keep
        for x in range(0, delete):
            os.remove(sorted_files[x][0])

def backup_config():
    shutil.copy2('/etc/openmptcprouter-vps-admin/omr-admin-config.json','/etc/openmptcprouter-vps-admin/omr-admin-config.json.' + str(int(time.time())))
    delete_oldest_files('/etc/openmptcprouter-vps-admin/omr-admin-config.json.*')

# Get interface rx/tx
def get_bytes(t, iface='eth0'):
    if path.exists('/sys/class/net/' + iface + '/statistics/' + t + '_bytes'):
        with open('/sys/class/net/' + iface + '/statistics/' + t + '_bytes', 'r') as f:
            data = f.read()
        return int(data)
    return 0

def get_bytes_openvpn(user):
    try:
        ovpn_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ovpn_socket.settimeout(2)
        ovpn_socket.connect(("127.0.0.1", 65302))
        fd = ovpn_socket.makefile('rb')
        line = fd.readline()
        if not line.startswith('>INFO:OpenVPN'.encode()):
            ovpn_socket.close()
            LOG.debug("OpenVPN error")
            return { 'downlinkBytes': 0, 'uplinkBytes': 0 }
        ovpn_socket.send('status\r\n'.encode())
        ovpn_stats = []
        while True:
            line = fd.readline()
            ovpn_stats.append(line.decode())
            if line.strip() == 'END'.encode():
                break
        ovpn_socket.close()
    except socket.timeout as err:
        LOG.debug("OpenVPN stats timeout (" + str(err) + ")")
        return { 'downlinkBytes': 0, 'uplinkBytes': 0 }
    except socket.error as err:
        LOG.debug("OpenVPN stats error (" + str(err) + ")")
        return { 'downlinkBytes': 0, 'uplinkBytes': 0 }
    for data in ovpn_stats:
        if user in data:
            stats = data.split(',')
            return { 'downlinkBytes': int(stats[2]), 'uplinkBytes': int(stats[3]) }
    return { 'downlinkBytes': 0, 'uplinkBytes': 0 }


def get_bytes_ss(port):
    try:
        ss_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ss_socket.settimeout(1)
        ss_socket.sendto('ping'.encode(), ("127.0.0.1", 8839))
        ss_recv = ss_socket.recv(1024)
    except socket.timeout as err:
        LOG.debug("Shadowsocks stats timeout (" + str(err) + ")")
        return 0
    except socket.error as err:
        LOG.debug("Shadowsocks stats error (" + str(err) + ")")
        return 0
    json_txt = ss_recv.decode("utf-8").replace('stat: ', '')
    result = json.loads(json_txt)
    if str(port) in result:
        return result[str(port)]
    return 0

def get_bytes_ss_go(user):
    try:
        r = requests.get(url="http://127.0.0.1:65279/v1/servers/ss-2022/stats")
    except requests.exceptions.Timeout:
        LOG.debug("Shadowsocks go stats timeout")
        return { 'downlinkBytes': 0, 'uplinkBytes': 0 }
    except requests.exceptions.RequestException as err:
        LOG.debug("Shadowsocks go stats error (" + str(err) + ")")
        return { 'downlinkBytes': 0, 'uplinkBytes': 0 }
    if 'error' in r.json():
        return { 'downlinkBytes': 0, 'uplinkBytes': 0 }
    for userdata in r.json()['users']:
        if userdata['username'] == user:
            return { 'downlinkBytes': userdata['downlinkBytes'], 'uplinkBytes': userdata['uplinkBytes'] }
    return { 'downlinkBytes': 0, 'uplinkBytes': 0 }

def get_bytes_v2ray(t,user):
    if t == "tx":
        side="downlink"
    else:
        side="uplink"
    try:
        data = subprocess.check_output('/usr/bin/v2ray api stats --server=127.0.0.1:10085 -json ' + "'" + 'user>>>' + user + '>>>traffic>>>' + side + "'" + ' 2>/dev/null | jq -r .stat[0].value | tr -d " " | tr -d "\n"', shell = True)
        #data = subprocess.check_output('/usr/bin/v2ctl api --server=127.0.0.1:10085 StatsService.GetStats ' + "'" + 'name: "user>>>' + user + '>>>traffic>>>' + side + '"' + "'" + ' 2>/dev/null | grep value | cut -d: -f2 | tr -d " "', shell = True)
    except:
        return 0
    if data.decode("utf-8") != '' and data.decode("utf-8") != 'null':
        try:
            return int(data.decode("utf-8"))
        except ValueError:
            return 0
    else:
        return 0

def get_bytes_xray(t,user):
    if t == "tx":
        side="downlink"
    else:
        side="uplink"
    try:
        data = subprocess.check_output('/usr/bin/xray api stats --server=127.0.0.1:10086 -name ' + "'" + 'user>>>' + user + '>>>traffic>>>' + side + "'" + ' 2>/dev/null | jq -r .stat.value | tr -d " " | tr -d "\n"', shell = True)
    except:
        return 0
    if data.decode("utf-8") != '' and data.decode("utf-8") != 'null':
        try:
            return int(data.decode("utf-8"))
        except ValueError:
            return 0
    else:
        return 0

def checkIfProcessRunning(processName):
    for proc in psutil.process_iter():
        try:
            if processName.lower() in proc.name().lower():
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False;

def file_as_bytes(file):
    with file:
        return file.read()

def get_username_from_userid(userid):
    if userid == 0:
        return 'openmptcprouter'
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        content = f.read()
    content = re.sub(",\s*}", "}", content) # pylint: disable=W1401
    try:
        data = json.loads(content)
    except ValueError as e:
        return {'error': 'Config file not readable', 'route': 'get_username'}
    for user in data['users'][0]:
        if 'userid' in data['users'][0][user] and int(data['users'][0][user]['userid']) == userid:
            return user
    return ''

def get_userid_from_username(username):
    if username == 'openmptcprouter':
        return 0
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        content = f.read()
    content = re.sub(",\s*}", "}", content) # pylint: disable=W1401
    try:
        data = json.loads(content)
    except ValueError as e:
        return {'error': 'Config file not readable', 'route': 'get_username'}
    return int(data['users'][0][username]['userid'])

def check_username_serial(username, serial):
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        content = f.read()
    content = re.sub(",\s*}", "}", content) # pylint: disable=W1401
    try:
        configdata = json.loads(content)
        data = configdata
    except ValueError as e:
        return {'error': 'Config file not readable', 'route': 'check_serial'}
    if 'serial_enforce' not in data or data['serial_enforce'] == False:
        return True
    if 'serial' not in data['users'][0][username]:
        data['users'][0][username]['serial'] = serial
        if data:
            with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json', 'w') as outfile:
                json.dump(data, outfile, indent=4)
        return True
    if data['users'][0][username]['serial'] == serial:
        return True
    if 'serial_error' not in data['users'][0][username]:
        data['users'][0][username]['serial_error'] = 1
    else:
        data['users'][0][username]['serial_error'] = int(data['users'][0][username]['serial_error']) + 1
    backup_config()
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json', 'w') as outfile:
        json.dump(data, outfile, indent=4)
    return False

def set_global_param(key, value):
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        content = f.read()
    content = re.sub(",\s*}", "}", content) # pylint: disable=W1401
    try:
        configdata = json.loads(content)
        data = configdata
    except ValueError as e:
        LOG.debug("Can't read file for set_global_param")
        return {'error': 'Config file not readable', 'route': 'global_param'}
    if not key in data or data[key] != value:
        data[key] = value
        backup_config()
        with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json', 'w') as outfile:
            json.dump(data, outfile, indent=4)
    else:
        LOG.debug("Already exist data for set_global_param key:" + key)

def modif_config_user(user, changes):
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        content = json.load(f)
    content['users'][0][user].update(changes)
    backup_config()
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json', 'w') as f:
        json.dump(content, f, indent=4)

def add_ss_user(port, key, userid=0, ip=''):
    with open('/etc/shadowsocks-libev/manager.json') as f:
        content = f.read()
    content = re.sub(",\s*}", "}", content) # pylint: disable=W1401
    data = json.loads(content)
    if ip == '' and 'port_key' in data:
        if port is None or port == '' or port == 0 or port == 'None':
            port = int(max(data['port_key'], key=int)) + 1
        data['port_key'][str(port)] = key
    else:
        if 'port_conf' not in data:
            data['port_conf'] = {}
        if 'port_key' in data:
            for old_port in data['port_key']:
                data['port_conf'][old_port] = {'key': data['port_key'][old_port]}
            del data['port_key']
        if port == '' or port == "None" or port is None or port == 0:
            port = int(max(data['port_conf'], key=int)) + 1
        if ip != '':
            data['port_conf'][str(port)] = {'key': key, 'local_address': ip, 'userid': userid}
        else:
            data['port_conf'][str(port)] = {'key': key, 'userid': userid}
    with open('/etc/shadowsocks-libev/manager.json', 'w') as f:
        json.dump(data, f, indent=4)
    try:
        ss_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if ip != '':
            data = 'add: {"server_port": ' + str(port) + ', "key": "' + key + '", "local_addr": "' + ip + '"}'
        else:
            data = 'add: {"server_port": ' + str(port) + ', "key": "' + key + '"}'
        ss_socket.settimeout(1)
        ss_socket.sendto(data.encode(), ("127.0.0.1", 8839))
    except socket.timeout as err:
        LOG.debug("Shadowsocks add timeout (" + str(err) + ")")
    except socket.error as err:
        LOG.debug("Shadowsocks add error (" + str(err) + ")")
    return port

def remove_ss_user(port):
    with open('/etc/shadowsocks-libev/manager.json') as f:
        content = f.read()
    content = re.sub(",\s*}", "}", content) # pylint: disable=W1401
    data = json.loads(content)
    if 'port_key' in data:
        if str(port) in data['port_key']:
            del data['port_key'][str(port)]
    else:
        if str(port) in data['port_conf']:
            del data['port_conf'][str(port)]
    with open('/etc/shadowsocks-libev/manager.json', 'w') as f:
        json.dump(data, f, indent=4)
    try:
        ss_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        data = 'remove: {"server_port": ' + str(port) + '}'
        ss_socket.settimeout(1)
        ss_socket.sendto(data.encode(), ("127.0.0.1", 8839))
    except socket.timeout as err:
        LOG.debug("Shadowsocks remove timeout (" + str(err) + ")")
    except socket.error as err:
        LOG.debug("Shadowsocks remove error (" + str(err) + ")")

def add_ss_go_user(user, key=''):
    try:
        r = requests.post(url="http://127.0.0.1:65279/v1/servers/ss-2022/users", json= {'username': user,'uPSK': key})
    except requests.exceptions.Timeout:
        LOG.debug("Shadowsocks go add timeout")
    except requests.exceptions.RequestException as err:
        LOG.debug("Shadowsocks go add error (" + str(err) + ")")
    return key

def remove_ss_go_user(user):
    try:
        r = requests.delete(url="http://127.0.0.1:65279/v1/servers/ss-2022/users/" + user)
    except requests.exceptions.Timeout:
        LOG.debug("Shadowsocks go remove timeout")
    except requests.exceptions.RequestException as err:
        LOG.debug("Shadowsocks go remove error (" + str(err) + ")")

def v2ray_add_user(user, v2rayuuid='', restart=1):
    if v2rayuuid == '': 
        v2rayuuid = str(uuid.uuid1())
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    with open('/etc/v2ray/v2ray-server.json') as f:
        data = json.load(f)
        exist = 0
        for inbounds in data['inbounds']:
            if inbounds['tag'] == 'omrin-tunnel':
                inbounds['settings']['clients'].append({'id': v2rayuuid, 'level': 0, 'alterId': 0, 'email': user})
            if inbounds['tag'] == 'omrin-vmess-tunnel':
                inbounds['settings']['clients'].append({'id': v2rayuuid, 'level': 0, 'alterId': 0, 'email': user})
            if inbounds['tag'] == 'omrin-trojan-tunnel':
                inbounds['settings']['clients'].append({'password': v2rayuuid, 'email': user})
            if inbounds['tag'] == 'omrin-socks-tunnel':
                inbounds['settings']['accounts'].append({'pass': v2rayuuid, 'user': user})
    with open('/etc/v2ray/v2ray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        try:
            data = subprocess.check_output('/usr/bin/v2ray api adu --server=127.0.0.1:10085 -users ' + "'" + '{"tag":"omrin-vmess-tunnel","users":[{"user": "' + user + '","key": "' + v2rayuuid + '"}]}', shell = True)
        except:
            LOG.debug("V2Ray VMESS: Can't add user")
        if restart == 1:
            os.system("systemctl -q restart v2ray")
    return v2rayuuid

def xray_add_user(user,xrayuuid='',ukeyss2022='',restart=1):
    if xrayuuid == '': 
        xrayuuid = str(uuid.uuid1())
    if ukeyss2022 == '': 
        ukeyss2022 = str(base64.b64encode(os.urandom(15).encode('ascii')))
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    with open('/etc/xray/xray-server.json') as f:
        data = json.load(f)
        exist = 0
        for inbounds in data['inbounds']:
            if inbounds['tag'] == 'omrin-tunnel':
                inbounds['settings']['clients'].append({'id': xrayuuid, 'level': 0, 'alterId': 0, 'email': user})
            if inbounds['tag'] == 'omrin-vmess-tunnel':
                inbounds['settings']['clients'].append({'id': xrayuuid, 'level': 0, 'alterId': 0, 'email': user})
            if inbounds['tag'] == 'omrin-trojan-tunnel':
                inbounds['settings']['clients'].append({'password': xrayuuid, 'email': user})
            if inbounds['tag'] == 'omrin-socks-tunnel':
                inbounds['settings']['accounts'].append({'pass': xrayuuid, 'user': user})
            if inbounds['tag'] == 'omrin-shadowsocks-tunnel':
                inbounds['settings']['clients'].append({'password': ukeyss2022, 'email': user})
    with open('/etc/xray/xray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5 and restart == 1:
        os.system("systemctl -q restart xray")
    return xrayuuid

def v2ray_del_user(user, restart=1, protocol="vless"):
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    with open('/etc/v2ray/v2ray-server.json') as f:
        data = json.load(f)
        for inbounds in data['inbounds']:
            if inbounds['tag'] == 'omrin-tunnel':
                for v2rayuser in inbounds['settings']['clients']:
                    if v2rayuser['email'] == user:
                        inbounds['settings']['clients'].remove(v2rayuser)
            if inbounds['tag'] == 'omrin-vmess-tunnel':
                for v2rayuser in inbounds['settings']['clients']:
                    if v2rayuser['email'] == user:
                        inbounds['settings']['clients'].remove(v2rayuser)
            if inbounds['tag'] == 'omrin-trojan-tunnel':
                for v2rayuser in inbounds['settings']['clients']:
                    if v2rayuser['email'] == user:
                        inbounds['settings']['clients'].remove(v2rayuser)
            if inbounds['tag'] == 'omrin-socks-tunnel':
                for v2rayuser in inbounds['settings']['accounts']:
                    if v2rayuser['user'] == user:
                        inbounds['settings']['accounts'].remove(v2rayuser)
    with open('/etc/v2ray/v2ray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5 and restart == 1:
        os.system("systemctl -q restart v2ray")

def xray_del_user(user, restart=1, protocol="vless"):
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    with open('/etc/xray/xray-server.json') as f:
        data = json.load(f)
        for inbounds in data['inbounds']:
            if inbounds['tag'] == 'omrin-tunnel':
                for xrayuser in inbounds['settings']['clients']:
                    if xrayuser['email'] == user:
                        inbounds['settings']['clients'].remove(xrayuser)
            if inbounds['tag'] == 'omrin-vmess-tunnel':
                for xrayuser in inbounds['settings']['clients']:
                    if xrayuser['email'] == user:
                        inbounds['settings']['clients'].remove(xrayuser)
            if inbounds['tag'] == 'omrin-trojan-tunnel':
                for xrayuser in inbounds['settings']['clients']:
                    if xrayuser['email'] == user:
                        inbounds['settings']['clients'].remove(xrayuser)
            if inbounds['tag'] == 'omrin-socks-tunnel':
                for xrayuser in inbounds['settings']['accounts']:
                    if xrayuser['user'] == user:
                        inbounds['settings']['accounts'].remove(xrayuser)
            if inbounds['tag'] == 'omrin-shadowsocks-tunnel':
                for xrayuser in inbounds['settings']['clients']:
                    if xrayuser['email'] == user:
                        inbounds['settings']['clients'].remove(xrayuser)
    with open('/etc/xray/xray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5 and restart == 1:
        os.system("systemctl -q restart xray")

def v2ray_add_outbound(tag,ip, restart=1):
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    with open('/etc/v2ray/v2ray-server.json') as f:
        data = json.load(f)
        data['outbounds'].append({'protocol': 'freedom', 'settings': { 'userLevel': 0 }, 'tag': tag, 'sendThrough': ip})
    with open('/etc/v2ray/v2ray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5 and restart == 1:
        os.system("systemctl -q restart v2ray")

def xray_add_outbound(tag,ip, restart=1):
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    with open('/etc/xray/xray-server.json') as f:
        data = json.load(f)
        data['outbounds'].append({'protocol': 'freedom', 'settings': { 'userLevel': 0 }, 'tag': tag, 'sendThrough': ip})
    with open('/etc/xray/xray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5 and restart == 1:
        os.system("systemctl -q restart xray")

def v2ray_del_outbound(tag, restart=1):
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    with open('/etc/v2ray/v2ray-server.json') as f:
        data = json.load(f)
        for outbounds in data['outbounds']:
            if outbounds['tag'] == tag:
                data['outbounds'].remove(outbounds)
    with open('/etc/v2ray/v2ray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5 and restart == 1:
        os.system("systemctl -q restart v2ray")

def xray_del_outbound(tag, restart=1):
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    with open('/etc/xray/xray-server.json') as f:
        data = json.load(f)
        for outbounds in data['outbounds']:
            if outbounds['tag'] == tag:
                data['outbounds'].remove(outbounds)
    with open('/etc/xray/xray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5 and restart == 1:
        os.system("systemctl -q restart xray")

def v2ray_add_routing(tag, restart=1):
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    with open('/etc/v2ray/v2ray-server.json') as f:
        data = json.load(f)
        data['routing']['rules'].append({'type': 'field', 'inboundTag': ( 'omrintunnel' ), 'outboundTag': tag})
    with open('/etc/v2ray/v2ray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5 and restart == 1:
        os.system("systemctl -q restart v2ray")

def xray_add_routing(tag, restart=1):
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    with open('/etc/xray/xray-server.json') as f:
        data = json.load(f)
        data['routing']['rules'].append({'type': 'field', 'inboundTag': ( 'omrintunnel' ), 'outboundTag': tag})
    with open('/etc/xray/xray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5 and restart == 1:
        os.system("systemctl -q restart xray")

def v2ray_del_routing(tag, restart=1):
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    with open('/etc/v2ray/v2ray-server.json') as f:
        data = json.load(f)
        for rules in data['routing']['rules']:
            if rules['outboundTag'] == tag:
                data['routing']['rules'].remove(rules)
    with open('/etc/v2ray/v2ray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5 and restart == 1:
        os.system("systemctl -q restart v2ray")

def xray_del_routing(tag, restart=1):
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    with open('/etc/xray/xray-server.json') as f:
        data = json.load(f)
        for rules in data['routing']['rules']:
            if rules['outboundTag'] == tag:
                data['routing']['rules'].remove(rules)
    with open('/etc/xray/xray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5 and restart == 1:
        os.system("systemctl -q restart xray")


def add_gre_tunnels():
    nbip = 0
    allips = []
    for intf in netifaces.interfaces():
        addrs = netifaces.ifaddresses(intf)
        try:
            ipv4_addr_list = addrs[netifaces.AF_INET]
            for ip_info in ipv4_addr_list:
                addr = ip_info['addr']
                if not IPAddress(addr).is_private() and not IPAddress(addr).is_reserved():
                    allips.append(addr)
                    nbip = nbip + 1
        except Exception as exception:
            pass

    if nbip > 1:
        nbgre = 0
        nbip = 0
        initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall/snat', 'rb'))).hexdigest()
        for intf in netifaces.interfaces():
            addrs = netifaces.ifaddresses(intf)
            try:
                ipv4_addr_list = addrs[netifaces.AF_INET]
                for ip_info in ipv4_addr_list:
                    addr = ip_info['addr']
                    if not IPAddress(addr).is_private() and not IPAddress(addr).is_reserved():
                        netmask = ip_info['netmask']
                        ip = IPNetwork('10.255.249.0/24')
                        with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
                            content = json.load(f)
                        for user in content['users'][0]:
                            if user != "admin":
                                subnets = ip.subnet(30)
                                network = list(subnets)[nbgre]
                                nbgre = nbgre + 1
                                userid = 0
                                username = user
                                iface = intf.split(':')[0]
                                if 'userid' in content['users'][0][user]:
                                    userid = content['users'][0][user]['userid']
                                if 'username' in content['users'][0][user]:
                                    username = content['users'][0][user]['username']
                                gre_intf = 'gre-user' + str(userid) + '-ip' + str(nbip)
                                with open('/etc/openmptcprouter-vps-admin/intf/' + gre_intf, 'w') as n:
                                    n.write('INTF=' + str(intf.split(':')[0]) + "\n")
                                    n.write('INTFADDR=' + str(addr) + "\n")
                                    n.write('INTFNETMASK=' + str(netmask) + "\n")
                                    n.write('NETWORK=' + str(network) + "\n")
                                    n.write('LOCALIP=' + str(list(network)[1]) + "\n")
                                    n.write('REMOTEIP=' + str(list(network)[2]) + "\n")
                                    n.write('NETMASK=255.255.255.252' + "\n")
                                    n.write('BROADCASTIP=' + str(network.broadcast) + "\n")
                                    n.write('USERNAME=' + str(username) + "\n")
                                    n.write('USERID=' + str(userid) + "\n")
                                fd, tmpfile = mkstemp()
                                with open('/etc/shorewall/snat', 'r') as h, open(tmpfile, 'a+') as n:
                                    for line in h:
                                        if not '# OMR GRE for public IP ' + str(addr) + ' for user ' + str(user) in line:
                                            n.write(line)
                                    n.write('SNAT(' + str(addr) + ')	' + str(network) + '	' + str(iface) + ' # OMR GRE for public IP ' + str(addr) + ' for user ' + str(user) + "\n")
                                    n.write('SNAT(' + str(list(network)[1]) + ')	-	' + gre_intf + ' # OMR GRE for public IP ' + str(addr) + ' for user ' + str(user) + "\n")
                                os.close(fd)
                                move(tmpfile, '/etc/shorewall/snat')
                                #fd, tmpfile = mkstemp()
                                #with open('/etc/shorewall/interfaces', 'r') as h, open(tmpfile, 'a+') as n:
                                #    for line in h:
                                #        if not 'gre-user' + str(userid) + '-ip' + str(nbip) in line:
                                #            n.write(line)
                                #    n.write('vpn	gre-user' + str(userid) + '-ip' + str(nbip) + '	nosmurfs,tcpflags' + "\n")
                                #os.close(fd)
                                #move(tmpfile, '/etc/shorewall/interfaces')
                                if str(iface) != IFACE:
                                    fd, tmpfile = mkstemp()
                                    with open('/etc/shorewall/interfaces', 'r') as h, open(tmpfile, 'a+') as n:
                                        for line in h:
                                            if not str(iface) in line:
                                                n.write(line)
                                        n.write('net	' + str(iface) + '	dhcp,nosmurfs,tcpflags,routefilter,sourceroute=0' + "\n")
                                    os.close(fd)
                                    move(tmpfile, '/etc/shorewall/interfaces')
                                user_gre_tunnels = {}
                                if 'gre_tunnels' in content['users'][0][user]:
                                    user_gre_tunnels = content['users'][0][user]['gre_tunnels']
                                if not gre_intf in user_gre_tunnels or user_gre_tunnels[gre_intf]['public_ip'] != str(addr):
                                    with open('/etc/shadowsocks-libev/manager.json') as g:
                                        contentss = g.read()
                                    contentss = re.sub(",\s*}", "}", contentss) # pylint: disable=W1401
                                    datass = json.loads(contentss)
                                    makechange = True
                                    if 'port_conf' in datass:
                                        for sscport in datass['port_conf']:
                                            if 'local_address' in datass['port_conf'][sscport] and datass['port_conf'][sscport]['local_address'] == str(addr):
                                                shadowsocks_port = sscport
                                                makechange = False
                                    if makechange:
                                        ss_port = content['users'][0][user]['shadowsocks_port']
                                        if 'port_key' in datass:
                                            ss_key = datass['port_key'][str(ss_port)]
                                        if 'port_conf' in datass:
                                            ss_key = datass['port_conf'][str(ss_port)]['key']
                                        if gre_intf not in user_gre_tunnels:
                                            user_gre_tunnels[gre_intf] = {}
                                        shadowsocks_port = str(add_ss_user('', ss_key, userid, str(addr)))
                                    user_gre_tunnels[gre_intf] = {'shadowsocks_port': shadowsocks_port, 'local_ip': str(list(network)[1]), 'remote_ip': str(list(network)[2]), 'public_ip': str(addr)}
                                    #user_gre_tunnels[gre_intf] = {'local_ip': str(list(network)[1]), 'remote_ip': str(list(network)[2]), 'public_ip': str(addr)}
                                    modif_config_user(user, {'gre_tunnels': user_gre_tunnels})
                        nbip = nbip + 1
            except Exception as exception:
                pass
        final_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall/snat', 'rb'))).hexdigest()
        if initial_md5 != final_md5:
            os.system("systemctl -q reload shorewall")
            os.system("systemctl -q restart shadowsocks-libev-manager@manager")
    set_global_param('allips', allips)

add_gre_tunnels()


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

def v2ray_add_port(user, port, proto, name, destip, destport):
    userid = user.userid
    if userid is None:
        userid = 0
    tag = user.username + '_redir_' + proto + '_' + str(port) + '_to_' + destip + ':' + str(destport)
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    with open('/etc/v2ray/v2ray-server.json') as f:
        data = json.load(f)
        exist = 0
        for inbounds in data['inbounds']:
            LOG.debug(inbounds)
            if inbounds['tag'] == tag:
                exist = 1
        if exist == 0:
            inbounds = {'tag': tag, 'port': int(port), 'protocol': 'dokodemo-door', 'settings': {'network': proto, 'port': int(destport), 'address': destip}}
            #inbounds = {'tag': user.username + '_redir_' + proto + '_' + str(port), 'port': str(port), 'protocol': 'dokodemo-door', 'settings': {'network': proto, 'port': str(destport), 'address': destip}}
            data['inbounds'].append(inbounds)
            routing = {'type': 'field','inboundTag': [tag], 'outboundTag': 'OMRLan'}
            data['routing']['rules'].append(routing)
    with open('/etc/v2ray/v2ray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        os.system("systemctl -q restart v2ray")

def xray_add_port(user, port, proto, name, destip, destport):
    userid = user.userid
    if userid is None:
        userid = 0
    tag = user.username + '_redir_' + proto + '_' + str(port) + '_to_' + destip + ':' + str(destport)
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    with open('/etc/xray/xray-server.json') as f:
        data = json.load(f)
        exist = 0
        for inbounds in data['inbounds']:
            LOG.debug(inbounds)
            if inbounds['tag'] == tag:
                exist = 1
        if exist == 0:
            inbounds = {'tag': tag, 'port': int(port), 'protocol': 'dokodemo-door', 'settings': {'network': proto, 'port': int(destport), 'address': destip}}
            #inbounds = {'tag': user.username + '_redir_' + proto + '_' + str(port), 'port': str(port), 'protocol': 'dokodemo-door', 'settings': {'network': proto, 'port': str(destport), 'address': destip}}
            data['inbounds'].append(inbounds)
            routing = {'type': 'field','inboundTag': [tag], 'outboundTag': 'OMRLan'}
            data['routing']['rules'].append(routing)
    with open('/etc/xray/xray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        os.system("systemctl -q restart xray")


def v2ray_del_port(user, port, proto, name, destip, destport):
    userid = user.userid
    if userid is None:
        userid = 0
    tag = user.username + '_redir_' + proto + '_' + str(port)
    if destip != '':
        tag = tag + '_to_' + destip + ':' + str(destport)
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    with open('/etc/v2ray/v2ray-server.json') as f:
        data = json.load(f)
        for inbounds in data['inbounds']:
            if inbounds['tag'] == tag:
                data['inbounds'].remove(inbounds)
        for routing in data['routing']['rules']:
            if routing['inboundTag'][0] == tag:
                data['routing']['rules'].remove(routing)
    with open('/etc/v2ray/v2ray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        os.system("systemctl -q restart v2ray")

def xray_del_port(user, port, proto, name, destip, destport):
    userid = user.userid
    if userid is None:
        userid = 0
    tag = user.username + '_redir_' + proto + '_' + str(port)
    if destip != '':
        tag = tag + '_to_' + destip + ':' + str(destport)
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    with open('/etc/xray/xray-server.json') as f:
        data = json.load(f)
        for inbounds in data['inbounds']:
            if inbounds['tag'] == tag:
                data['inbounds'].remove(inbounds)
        for routing in data['routing']['rules']:
            if routing['inboundTag'][0] == tag:
                data['routing']['rules'].remove(routing)
    with open('/etc/xray/xray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        os.system("systemctl -q restart xray")

def shorewall_add_port(user, port, proto, name, fwtype='ACCEPT', source_dip='', dest_ip='', vpn='default', gencomment=''):
    userid = user.userid
    if userid is None:
        userid = 0
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall/rules', 'rb'))).hexdigest()
    fd, tmpfile = mkstemp()
    with open('/etc/shorewall/rules', 'r') as f, \
          open(tmpfile, 'a+') as n:
        for line in f:
            if source_dip == '' and dest_ip == '':
                if (fwtype == 'ACCEPT' and not port + '	# OMR open ' + name + ' port ' + proto + gencomment in line and not port + '	# OMR ' + user.username + ' open ' + name + ' port ' + proto + gencomment in line):
                    n.write(line)
                elif fwtype == 'DNAT' and not port + '	# OMR redirect ' + name + ' port ' + proto + gencomment in line and not port + '	# OMR ' + user.username + ' redirect ' + name + ' port ' + proto + gencomment in line:
                    n.write(line)
            else:
                comment = ''
                if source_dip != '':
                    comment = ' to ' + source_dip
                if dest_ip != '':
                    comment = comment + ' from ' + dest_ip
                if (fwtype == 'ACCEPT' and not '# OMR ' + user.username + ' open ' + name + ' port ' + proto + comment + gencomment in line):
                    n.write(line)
                elif fwtype == 'DNAT' and not '# OMR ' + user.username + ' redirect ' + name + ' port ' + proto + comment + gencomment in line:
                    n.write(line)
        if source_dip == '' and dest_ip == '':
            if fwtype == 'ACCEPT':
                n.write('ACCEPT		net		$FW		' + proto + '	' + port + '	# OMR ' + user.username + ' open ' + name + ' port ' + proto + gencomment + "\n")
            elif fwtype == 'DNAT' and userid == 0:
                n.write('DNAT		net		vpn:$OMR_ADDR	' + proto + '	' + port + '	# OMR ' + user.username + ' redirect ' + name + ' port ' + proto + gencomment + "\n")
            elif fwtype == 'DNAT' and userid != 0:
                n.write('DNAT		net		vpn:$OMR_ADDR_USER' + str(userid) + '	' + proto + '	' + port + '	# OMR ' + user.username + ' redirect ' + name + ' port ' + proto + gencomment + "\n")
        else:
            net = 'net'
            comment = ''
            if source_dip != '':
                comment = ' to ' + source_dip
            if dest_ip != '':
                comment = comment + ' from ' + dest_ip
                net = 'net:' + dest_ip
            if fwtype == 'ACCEPT':
                n.write('ACCEPT		' + net + '		$FW		' + proto + '	' + port + '	-	' + source_dip + '	# OMR ' + user.username + ' open ' + name + ' port ' + proto + comment + gencomment + "\n")
            elif fwtype == 'DNAT' and vpn != 'default':
                n.write('DNAT		' + net + '		vpn:' + vpn + '	' + proto + '	' + port + '	-	' + source_dip +  '	# OMR ' + user.username + ' redirect ' + name + ' port ' + proto + comment +  gencomment + "\n")
                #n.write('DNAT		' + net + '		vpn:$OMR_ADDR' + '	' + proto + '	' + port + '	-	' + source_dip +  '	# OMR ' + user.username + ' redirect ' + name + ' port ' + proto + comment +  "\n")
            elif fwtype == 'DNAT' and userid == 0:
                n.write('DNAT		' + net + '		vpn:$OMR_ADDR	' + proto + '	' + port + '	-	' + source_dip + '	# OMR ' + user.username + ' redirect ' + name + ' port ' + proto + comment + gencomment + "\n")
            elif fwtype == 'DNAT' and userid != 0:
                n.write('DNAT		' + net + '		vpn:$OMR_ADDR_USER' + str(userid) + '	' + proto + '	' + port + '	-	' + source_dip + '	# OMR ' + user.username + ' redirect ' + name + ' port ' + proto + comment + gencomment + "\n")
    os.close(fd)
    move(tmpfile, '/etc/shorewall/rules')
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall/rules', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        os.system("systemctl -q reload shorewall")

def shorewall_del_port(username, port, proto, name, fwtype='ACCEPT', source_dip='', dest_ip='', gencomment=''):
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall/rules', 'rb'))).hexdigest()
    fd, tmpfile = mkstemp()
    with open('/etc/shorewall/rules', 'r') as f, open(tmpfile, 'a+') as n:
        for line in f:
            if source_dip == '' and dest_ip == '':
                if fwtype == 'ACCEPT' and not port + '	# OMR open ' + name + ' port ' + proto + gencomment in line and not port + '	# OMR ' + username + ' open ' + name + ' port ' + proto + gencomment in line:
                    n.write(line)
                elif fwtype == 'DNAT' and not port + '	# OMR redirect ' + name + ' port ' + proto + gencomment in line and not port + '	# OMR ' + username + ' redirect ' + name + ' port ' + proto + gencomment  in line:
                    n.write(line)
            else:
                comment = ''
                if source_dip != '':
                    comment = ' to ' + source_dip
                if dest_ip != '':
                    comment = comment + ' from ' + dest_ip
                if fwtype == 'ACCEPT' and not '# OMR ' + username + ' open ' + name + ' port ' + proto + comment + gencomment in line:
                    n.write(line)
                elif fwtype == 'DNAT' and not '# OMR ' + username + ' redirect ' + name + ' port ' + proto + comment + gencomment in line:
                    n.write(line)
    os.close(fd)
    move(tmpfile, '/etc/shorewall/rules')
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall/rules', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        os.system("systemctl -q reload shorewall")

def shorewall6_add_port(user, port, proto, name, fwtype='ACCEPT', source_dip='', dest_ip='', gencomment=''):
    userid = user.userid
    if userid is None:
        userid = 0
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall6/rules', 'rb'))).hexdigest()
    fd, tmpfile = mkstemp()
    with open('/etc/shorewall6/rules', 'r') as f, open(tmpfile, 'a+') as n:
        for line in f:
            if source_dip == '' and dest_ip == '':
                if fwtype == 'ACCEPT' and not port + '	# OMR open ' + name + ' port ' + proto + gencomment in line and not port + '	# OMR ' + user.username + ' open ' + name + ' port ' + proto + gencomment in line:
                    n.write(line)
                elif fwtype == 'DNAT' and not port + '	# OMR redirect ' + name + ' port ' + proto + gencomment in line and not port + '	# OMR ' + user.username + ' redirect ' + name + ' port ' + proto + gencomment in line:
                    n.write(line)
            else:
                comment = ''
                if source_dip != '':
                    comment = ' to ' + source_dip
                if dest_ip != '':
                    comment = comment + ' from ' + dest_ip
                if fwtype == 'ACCEPT' and not '# OMR ' + user.username + ' open ' + name + ' port ' + proto + comment + gencomment in line:
                    n.write(line)
                elif fwtype == 'DNAT' and not '# OMR ' + user.username + ' redirect ' + name + ' port ' + proto + comment + gencomment in line:
                    n.write(line)
        if source_dip == '' and dest_ip == '':
            if fwtype == 'ACCEPT':
                n.write('ACCEPT		net		$FW		' + proto + '	' + port + '	# OMR ' + user.username + ' open ' + name + ' port ' + proto + gencomment + "\n")
            elif fwtype == 'DNAT' and userid == 0:
                n.write('DNAT		net		vpn:$OMR_ADDR	' + proto + '	' + port + '	# OMR ' + user.username + ' redirect ' + name + ' port ' + proto + gencomment + "\n")
            elif fwtype == 'DNAT' and userid != 0:
                n.write('DNAT		net		vpn:$OMR_ADDR_USER' + str(userid) + '	' + proto + '	' + port + '	# OMR ' + user.username + ' redirect ' + name + ' port ' + proto + gencomment + "\n")
        else:
            net = 'net'
            comment = ''
            if source_dip != '':
                comment = ' to ' + source_dip
            if dest_ip != '':
                comment = comment + ' from ' + dest_ip
                net = 'net:' + dest_ip
            if fwtype == 'ACCEPT':
                n.write('ACCEPT		' + net + '		$FW		' + proto + '	' + port +  '	-	' + source_dip + '	# OMR ' + user.username + ' open ' + name + ' port ' + proto + comment + gencomment + "\n")
            elif fwtype == 'DNAT' and vpn != 'default':
                n.write('DNAT		' + net + '		vpn:' + vpn + '	' + proto + '	' + port + '	-	' + source_dip +  '	# OMR ' + user.username + ' redirect ' + name + ' port ' + proto + comment +  gencomment + "\n")
            elif fwtype == 'DNAT' and userid == 0:
                n.write('DNAT		' + net + '		vpn:$OMR_ADDR	' + proto + '	' + port +  '	-	' + source_dip + '	# OMR ' + user.username + ' redirect ' + name + ' port ' + proto + comment + gencomment + "\n")
            elif fwtype == 'DNAT' and userid != 0:
                n.write('DNAT		' + net + '		vpn:$OMR_ADDR_USER' + str(userid) + '	' + proto + '	' + port +  '	-	' + source_dip + '	# OMR ' + user.username + ' redirect ' + name + ' port ' + proto + comment + gencomment + "\n")
    os.close(fd)
    move(tmpfile, '/etc/shorewall6/rules')
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall6/rules', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        os.system("systemctl -q reload shorewall6")

def shorewall6_del_port(username, port, proto, name, fwtype='ACCEPT', source_dip='', dest_ip=''):
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall6/rules', 'rb'))).hexdigest()
    fd, tmpfile = mkstemp()
    with open('/etc/shorewall6/rules', 'r') as f, open(tmpfile, 'a+') as n:
        for line in f:
            if source_dip == '':
                if fwtype == 'ACCEPT' and not port + '	# OMR open ' + name + ' port ' + proto in line and not port + '	# OMR ' + username + ' open ' + name + ' port ' + proto + gencomment in line:
                    n.write(line)
                elif fwtype == 'DNAT' and not port + '	# OMR redirect ' + name + ' port ' + proto in line and not port + '	# OMR ' + username + ' redirect ' + name + ' port ' + proto + gencomment in line:
                    n.write(line)
            else:
                if fwtype == 'ACCEPT' and not '# OMR ' + username + ' open ' + name + ' port ' + proto + ' to ' + source_dip + gencomment in line:
                    n.write(line)
                elif fwtype == 'DNAT' and not '# OMR ' + username + ' redirect ' + name + ' port ' + proto + ' to ' + source_dip + gencomment in line:
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
        configdata = json.loads(content)
        data = configdata
    except ValueError as e:
        return {'error': 'Config file not readable', 'route': 'lastchange'}
    data["lastchange"] = time.time() + sync
    if data and data != configdata:
        backup_config()
        with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json', 'w') as outfile:
            json.dump(data, outfile, indent=4)
    else:
        LOG.debug("Empty data for set_last_change")


with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
    omr_config_data = json.load(f)
    if 'debug' in omr_config_data and omr_config_data['debug']:
        LOG.setLevel(logging.DEBUG)

fake_users_db = omr_config_data['users'][0]

def verify_password(plain_password, user_password):
    if secrets.compare_digest(plain_password,user_password):
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

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, title="OpenMPTCProuter Server API")


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
    return JSONResponse(get_openapi(title="OpenMPTCProuter Server API", version="2.0.0", routes=app.routes))


@app.get("/docs")
async def get_documentation(current_user: User = Depends(get_current_active_user)):
    return get_swagger_ui_html(openapi_url="/openapi.json", title="docs")

# Get Client IP
@app.get('/clienthost')
async def status(request: Request):
    client_host = request.client.host
    return {"client_host": client_host}

# Check if MPTCP is enabled on this connection
@app.get('/mptcpsupport')
async def mptcpsupport(request: Request):
    ip = request.client.host
    if type(ip_address(ip)) is IPv4Address:
        ipr = list(reversed(ip.split('.')))
        iptohex = '{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ipr))
        if path.exists('/proc/net/mptcp_net/mptcp'):
            with open('/proc/net/mptcp_net/mptcp') as f:
                if iptohex in f.read():
                    return {"mptcp": "working"}
        elif not os.popen("ss -M | grep " + ip) == '':
            return {"mptcp": "working"}
        return {"mptcp": "not working"}

# Get VPS status
@app.get('/status', summary="Get current server load average, uptime and release")
async def status(userid: Optional[int] = Query(None), username: Optional[str] = Query(None), serial: Optional[str] = Query(None), current_user: User = Depends(get_current_user)):
    LOG.debug('Get status...')
    if not current_user.permissions == "admin":
        userid = current_user.userid
    elif username is not None:
        userid = get_userid_from_username(username)
    if userid is None:
        userid = 0
    username = get_username_from_userid(userid)
    if not current_user.permissions == "admin" and serial is not None:
        if not check_username_serial(username, serial):
            return {'error': 'False serial number'}
    vps_loadavg = os.popen("cat /proc/loadavg | awk '{print $1\" \"$2\" \"$3}'").read().rstrip()
    vps_uptime = os.popen("cat /proc/uptime | awk '{print $1}'").read().rstrip()
    vps_hostname = socket.gethostname()
    vps_current_time = time.time()
    vps_kernel = os.popen('uname -r').read().rstrip()
    vps_omr_version = os.popen("grep -s 'OpenMPTCProuter VPS' /etc/* | awk '{print $4}'").read().rstrip()
    mptcp_enabled = "0"
    if path.exists("/proc/sys/net/mptcp/mptcp_enabled"):
        mptcp_enabled = os.popen('sysctl -qn net.mptcp.mptcp_enabled').read().rstrip()
    elif path.exists("/proc/sys/net/mptcp/enabled"):
        mptcp_enabled = os.popen('sysctl -qn net.mptcp.enabled').read().rstrip()
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        try:
            omr_config_data = json.load(f)
        except ValueError as e:
            omr_config_data = {}
    proxy = 'shadowsocks'
    if 'proxy' in omr_config_data['users'][0][username]:
        proxy = omr_config_data['users'][0][username]['proxy']
    shadowsocks_port = current_user.shadowsocks_port
    if not shadowsocks_port == None and proxy == 'shadowsocks':
        ss_traffic = get_bytes_ss(current_user.shadowsocks_port)
    else:
        ss_traffic = 0
    ss_go_tx = 0
    ss_go_rx = 0
    if os.path.isfile('/etc/shadowsocks-go/server.json') and ('shadowsocks-go' in proxy or 'shadowsocks-rust' in proxy) and checkIfProcessRunning('shadowsocks-go'):
        ss_go_txrx = get_bytes_ss_go(username)
        ss_go_tx = ss_go_txrx['downlinkBytes']
        ss_go_rx = ss_go_txrx['uplinkBytes']
    v2ray_tx = 0
    v2ray_rx = 0
    if os.path.isfile('/etc/v2ray/v2ray-server.json') and 'v2ray' in proxy and checkIfProcessRunning('v2ray'):
        v2ray_tx = get_bytes_v2ray('tx',username)
        v2ray_rx = get_bytes_v2ray('rx',username)
    xray_tx = 0
    xray_rx = 0
    if os.path.isfile('/etc/xray/xray-server.json') and 'xray' in proxy and checkIfProcessRunning('xray'):
        xray_tx = get_bytes_xray('tx',username)
        xray_rx = get_bytes_xray('rx',username)
    vpn = 'glorytun_tcp'
    if 'vpn' in omr_config_data['users'][0][username]:
        vpn = omr_config_data['users'][0][username]['vpn']
    vpn_traffic_rx = 0
    vpn_traffic_tx = 0
    if vpn == 'glorytun_tcp':
        vpn_traffic_rx = get_bytes('rx', 'gt-tun' + str(userid))
        vpn_traffic_tx = get_bytes('tx', 'gt-tun' + str(userid))
    elif vpn == 'glorytun_udp':
        vpn_traffic_rx = get_bytes('rx', 'gt-udp-tun' + str(userid))
        vpn_traffic_tx = get_bytes('tx', 'gt-udp-tun' + str(userid))
    elif vpn == 'mlvpn':
        vpn_traffic_rx = get_bytes('rx', 'mlvpn' + str(userid))
        vpn_traffic_tx = get_bytes('tx', 'mlvpn' + str(userid))
    elif vpn == 'dsvpn':
        vpn_traffic_rx = get_bytes('rx', 'dsvpn' + str(userid))
        vpn_traffic_tx = get_bytes('tx', 'dsvpn' + str(userid))
    elif vpn == 'openvpn':
        # vpn_traffic_rx = get_bytes('rx', 'tun0')
        # vpn_traffic_tx = get_bytes('tx', 'tun0')
        vpn_txrx = get_bytes_openvpn(username)
        vpn_traffic_rx = vpn_txrx['uplinkBytes']
        vpn_traffic_tx = vpn_txrx['downlinkBytes']
    elif vpn == 'openvpn_bonding':
        vpn_traffic_rx = get_bytes('rx', 'omr-bonding')
        vpn_traffic_tx = get_bytes('tx', 'omr-bonding')
    LOG.debug('Get status: done')
    if IFACE:
        return {'vps': {'time': vps_current_time, 'loadavg': vps_loadavg, 'uptime': vps_uptime, 'mptcp': mptcp_enabled, 'hostname': vps_hostname, 'kernel': vps_kernel, 'omr_version': vps_omr_version}, 'network': {'tx': get_bytes('tx', IFACE), 'rx': get_bytes('rx', IFACE)}, 'shadowsocks': {'traffic': ss_traffic}, 'vpn': {'tx': vpn_traffic_tx, 'rx': vpn_traffic_rx}, 'v2ray': {'tx': v2ray_tx, 'rx': v2ray_rx},'xray': {'tx': xray_tx, 'rx': xray_rx},'shadowsocks_go': {'tx': ss_go_tx, 'rx': ss_go_rx}}
    else:
        return {'error': 'No iface defined', 'route': 'status'}

# Get VPS config
@app.get('/config', summary="Get full server configuration for current user")
async def config(userid: Optional[int] = Query(None), serial: Optional[str] = Query(None), current_user: User = Depends(get_current_user)):
    LOG.debug('Get config...')
    if not current_user.permissions == "admin":
        userid = current_user.userid
    if userid is None:
        userid = 0
    username = get_username_from_userid(userid)
    if not current_user.permissions == "admin" and serial is not None:
        if not check_username_serial(username, serial):
            return {'error': 'False serial number'}
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        try:
            omr_config_data = json.load(f)
        except ValueError as e:
            omr_config_data = {}
    LOG.debug('Get config... shadowsocks')
    proxy = 'shadowsocks'
    if 'proxy' in omr_config_data['users'][0][username]:
        proxy = omr_config_data['users'][0][username]['proxy']

    with open('/etc/shadowsocks-libev/manager.json') as f:
        content = f.read()
    content = re.sub(",\s*}", "}", content) # pylint: disable=W1401
    try:
        data = json.loads(content)
    except ValueError as e:
        data = {'port_key': '', 'server_port': 65101, 'method': 'chacha20'}
    #shadowsocks_port = data["server_port"]
    shadowsocks_port = current_user.shadowsocks_port
    if shadowsocks_port is not None:
        if 'port_key' in data:
            shadowsocks_key = data["port_key"][str(shadowsocks_port)]
        else:
            shadowsocks_key = data["port_conf"][str(shadowsocks_port)]["key"]
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
    if not shadowsocks_port == None and proxy == 'shadowsocks':
        ss_traffic = get_bytes_ss(current_user.shadowsocks_port)
    else:
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
    available_vpn = ["glorytun_tcp", "glorytun_udp"]
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
    if os.path.isfile('/etc/openvpn/ca/pki/private/' + username + '.key'):
        with open('/etc/openvpn/ca/pki/private/' + username + '.key', "rb") as ovpnkey_file:
            openvpn_keyb = base64.b64encode(ovpnkey_file.read())
            openvpn_client_key = openvpn_keyb.decode('utf-8')
    else:
        openvpn_client_key = ''
    if os.path.isfile('/etc/openvpn/ca/pki/issued/' + username + '.crt'):
        with open('/etc/openvpn/ca/pki/issued/' + username + '.crt', "rb") as ovpnkey_file:
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
    openvpn_cipher = 'AES-256-GCM'
    if os.path.isfile('/etc/openvpn/tun0.conf'):
        with open('/etc/openvpn/tun0.conf', "r") as openvpn_file:
            for line in openvpn_file:
                if 'port ' in line:
                    openvpn_port = line.replace(line[:5], '').rstrip()
                if 'cipher ' in line:
                    openvpn_cipher = line.replace(line[:7], '').rstrip()
    openvpn_host_ip = '10.255.252.1'
    #openvpn_client_ip = '10.255.252.2'
    openvpn_client_ip = 'dhcp'

    if os.path.isfile('/etc/openvpn/bonding1.conf'):
        available_vpn.append("openvpn_bonding")

    LOG.debug('Get config... mlvpn')
    if os.path.isfile('/etc/mlvpn/mlvpn0.conf'):
        mlvpn_config = configparser.ConfigParser()
        mlvpn_config.read_file(open(r'/etc/mlvpn/mlvpn0.conf'))
        mlvpn_key = mlvpn_config.get('general', 'password').strip('"')
        mlvpn_timeout = mlvpn_config.get('general', 'timeout')
        mlvpn_reorder_buffer_size = mlvpn_config.get('general', 'reorder_buffer_size')
        mlvpn_loss_tolerence = mlvpn_config.get('general', 'loss_tolerence')
        if mlvpn_config.has_option('general', 'cleartext_data'):
            mlvpn_cleartext_data = mlvpn_config.get('general', 'cleartext_data')
        else:
            mlvpn_cleartext_data = ''
        available_vpn.append("mlvpn")
    else:
        mlvpn_key = ''
        mlvpn_timeout = ''
        mlvpn_reorder_buffer_size = ''
        mlvpn_loss_tolerence = ''
        mlvpn_cleartext_data = ''
    mlvpn_host_ip = '10.255.253.1'
    mlvpn_client_ip = '10.255.253.2'

    LOG.debug('Get config... wireguard')
    if os.path.isfile('/etc/wireguard/vpn-server-public.key'):
        with open('/etc/wireguard/vpn-server-public.key', "rb") as wgkey_file:
            wireguard_key = wgkey_file.read()
    else:
        wireguard_key = ''
    wireguard_host_ip = '10.255.247.1'
    wireguard_port = '65311'

    LOG.debug('Get config... wireguard for external clients')
    if os.path.isfile('/etc/wireguard/vpn-client-private.key'):
        with open('/etc/wireguard/vpn-client-private.key', "rb") as wgkey_file:
            wireguard_client_key = wgkey_file.read()
    else:
        wireguard_client_key = ''
    wireguard_client_ip = '10.255.246.2'
    wireguard_client_port = '65312'

    gre_tunnel = False
    gre_tunnel_conf = []
#    for tunnel in pathlib.Path('/etc/openmptcprouter-vps-admin/intf').glob('gre-user' + str(userid) + '-ip*'):
#        gre_tunnel = True
#        with open(tunnel, "r") as tunnel_conf:
#            for line in tunnel_conf:
#                if 'LOCALIP=' in line:
#                    gre_tunnel_localip = line.replace(line[:8], '').rstrip()
#                if 'REMOTEIP=' in line:
#                    gre_tunnel_remoteip = line.replace(line[:9], '').rstrip()
#                if 'NETMASK=' in line:
#                    gre_tunnel_netmask = line.replace(line[:8], '').rstrip()
#                if 'INTFADDR=' in line:
#                    gre_tunnel_intfaddr = line.replace(line[:9], '').rstrip()
#        gre_tunnel_conf.append("{'local_ip': '" + gre_tunnel_localip + "', 'remote_ip': '" + gre_tunnel_remoteip + "', 'netmask': '" + gre_tunnel_netmask + "', 'public_ip': '" + gre_tunnel_intfaddr + "'}")

    if 'gre_tunnels' in omr_config_data['users'][0][username]:
        gre_tunnel = True
        gre_tunnel_conf = omr_config_data['users'][0][username]['gre_tunnels']

    if 'vpnremoteip' in omr_config_data['users'][0][username]:
        vpn_remote_ip = omr_config_data['users'][0][username]['vpnremoteip']
    else:
        vpn_remote_ip = ''
    if 'vpnlocalip' in omr_config_data['users'][0][username]:
        vpn_local_ip = omr_config_data['users'][0][username]['vpnlocalip']
    else:
        vpn_local_ip = ''

    v2ray = False
    v2ray_conf = []
    v2ray_tx = 0
    v2ray_rx = 0
    if os.path.isfile('/etc/v2ray/v2ray-server.json'):
        v2ray = True
        if not 'v2ray' in omr_config_data['users'][0][username]:
            v2ray_key = os.popen("jq -r '.inbounds[0].settings.clients[] | select(.email=" + '"' + username + '"' + ") | .id' /etc/v2ray/v2ray-server.json").read().rstrip()
            v2ray_port = os.popen('jq -r .inbounds[0].port /etc/v2ray/v2ray-server.json').read().rstrip()
            v2ray_conf = { 'key': v2ray_key, 'port': v2ray_port}
            modif_config_user(username, {'v2ray': v2ray_conf})
        else:
            v2ray_conf = omr_config_data['users'][0][username]['v2ray']
        if checkIfProcessRunning('v2ray') and proxy == 'v2ray':
            v2ray_tx = get_bytes_v2ray('tx',username)
            v2ray_rx = get_bytes_v2ray('rx',username)

    xray = False
    xray_conf = []
    xray_tx = 0
    xray_rx = 0
    if os.path.isfile('/etc/xray/xray-server.json'):
        xray = True
        if not 'xray' in omr_config_data['users'][0][username]:
            xray_key = os.popen("jq -r '.inbounds[0].settings.clients[] | select(.email=" + '"' + username + '"' + ") | .id' /etc/xray/xray-server.json").read().rstrip()
            xray_ss_skey = os.popen("jq -r '.inbounds[] | select(.tag==" + '"' + 'omrin-shadowsocks-tunnel' + '"' + ") | .settings.password' /etc/xray/xray-server.json").read().rstrip()
            xray_ss_ukey = os.popen("jq -r '.inbounds[] | select(.tag==" + '"' + 'omrin-shadowsocks-tunnel' + '"' + ") | .settings.clients[] | select(.email=" + '"' + username + '"' + ") | .password' /etc/xray/xray-server.json").read().rstrip()
            xray_ss_key = xray_ss_skey + ':' + xray_ss_ukey
            xray_port = os.popen('jq -r .inbounds[0].port /etc/xray/xray-server.json').read().rstrip()
            xray_ss_method = os.popen("jq -r '.inbounds[] | select(.tag==" + '"' + 'omrin-shadowsocks-tunnel' + '"' + ") | .settings.method' /etc/xray/xray-server.json").read().rstrip()
            xray_vless_reality_public_key = ''
            if os.path.isfile('/etc/xray/xray-vless-reality.json'):
                xray_vless_reality_public_key = os.popen("jq -r '.inbounds[] | select(.tag==" + '"' + 'omrin-vless-reality' + '"' + ") | .streamSettings.realitySettings.publicKey' /etc/xray/xray-vless-reality.json").read().rstrip()
            test_vless_reality = os.popen("jq -r '.inbounds[] | select(.tag==" + '"' + 'omrin-vless-reality' + '"' + ")' /etc/xray/xray-server.json").read().rstrip()
            if test_vless_reality != '':
                vless_reality = True
            else:
                vless_reality = False
            xray_conf = { 'key': xray_key, 'port': xray_port, 'sskey': xray_ss_key, 'vless_reality': vless_reality, 'vless_reality_key': xray_vless_reality_public_key, 'ss_method': xray_ss_method }
            modif_config_user(username, {'xray': xray_conf})
        else:
            xray_conf = omr_config_data['users'][0][username]['xray']
        if checkIfProcessRunning('xray') and proxy == 'xray':
            xray_tx = get_bytes_xray('tx',username)
            xray_rx = get_bytes_xray('rx',username)

    shadowsocks_go = False
    shadowsocks_go_conf = []
    ss_go_tx = 0
    ss_go_rx = 0
    if os.path.isfile('/etc/shadowsocks-go/server.json'):
        shadowsocks_go = True
        if not 'shadowsocks-go' in omr_config_data['users'][0][username]:
            shadowsocks_go_psk = os.popen("jq -r '.servers[] | select(.name=" + '"ss-2022"' + ") | .psk' /etc/shadowsocks-go/server.json").read().rstrip()
            shadowsocks_go_port = os.popen("jq -r '.servers[] | select(.name=" + '"ss-2022"' + ") | .tcpListeners[0].address' /etc/shadowsocks-go/server.json | cut -d ':' -f1").read().rstrip()
            shadowsocks_go_protocol = os.popen("jq -r '.servers[] | select(.name=" + '"ss-2022"' + ") | .protocol' /etc/shadowsocks-go/server.json").read().rstrip()
            shadowsocks_go_upsk = os.popen("jq -r --arg user " + '"' + username + '"' + " '.[$user]' /etc/shadowsocks-go/upsks.json").read().rstrip()
            shadowsocks_go_conf= { 'password': shadowsocks_go_psk + ':' + shadowsocks_go_upsk, 'port': shadowsocks_go_port, 'protocol': shadowsocks_go_protocol }
            modif_config_user(username, {'shadowsocks-go': shadowsocks_go_conf})
        else:
            shadowsocks_go_conf = omr_config_data['users'][0][username]['shadowsocks-go']
        ss_go_txrx = get_bytes_ss_go(username)
        ss_go_tx = int(ss_go_txrx['downlinkBytes'])
        ss_go_rx = int(ss_go_txrx['uplinkBytes'])

    LOG.debug('Get config... mptcp')
    mptcp_version = mptcp_enabled = mptcp_checksum = '0'
    mptcp_path_manager = mptcp_scheduler = mptcp_syn_retries = ''
    if path.exists('/proc/sys/net/mptcp/mptcp_enabled'):
        mptcp_enabled = os.popen('sysctl -n net.mptcp.mptcp_enabled').read().rstrip()
        mptcp_checksum = os.popen('sysctl -n net.mptcp.mptcp_checksum').read().rstrip()
        mptcp_path_manager = os.popen('sysctl -n  net.mptcp.mptcp_path_manager').read().rstrip()
        mptcp_scheduler = os.popen('sysctl -n net.mptcp.mptcp_scheduler').read().rstrip()
        mptcp_syn_retries = os.popen('sysctl -n net.mptcp.mptcp_syn_retries').read().rstrip()
        mptcp_version = os.popen('sysctl -n net.mptcp.mptcp_version').read().rstrip()
    elif path.exists('/proc/sys/net/mptcp/enabled'):
        mptcp_enabled = os.popen('sysctl -n net.mptcp.enabled').read().rstrip()
        mptcp_checksum = os.popen('sysctl -n net.mptcp.checksum_enabled').read().rstrip()
        mptcp_version = '1'

    congestion_control = os.popen('sysctl -n net.ipv4.tcp_congestion_control').read().rstrip()

    LOG.debug('Get config... ipv6')
    if 'ipv6_network' in omr_config_data:
        ipv6_network = omr_config_data['ipv6_network']
    else:
        ipv6_network = os.popen('ip -6 addr show ' + IFACE6 +' | grep -oP "(?<=inet6 ).*(?= scope global)"').read().rstrip()
    #ipv6_addr = os.popen('wget -6 -qO- -T 2 ipv6.openmptcprouter.com').read().rstrip()
    if 'ipv6_addr' in omr_config_data:
        ipv6_addr = omr_config_data['ipv6_addr']
    else:
        ipv6_addr = os.popen('ip -6 addr show ' + IFACE6 +' | grep -oP "(?<=inet6 ).*(?= scope global)" | cut -d/ -f1').read().rstrip()
    #ipv4_addr = os.popen('wget -4 -qO- -T 1 https://ip.openmptcprouter.com').read().rstrip()
    LOG.debug('get server IPv4')
    ipv4_addr = ''
    if 'ipv4' in omr_config_data:
        ipv4_addr = omr_config_data['ipv4']
    elif 'internet' in omr_config_data and not omr_config_data['internet']:
        ipv4_addr = os.popen('ip -4 addr show ' + IFACE +' | grep -oP "(?<=inet ).*(?= scope global)" | cut -d/ -f1').read().rstrip()
    else:
        #ipv4_addr = os.popen("dig -4 TXT +timeout=2 +tries=1 +short o-o.myaddr.l.google.com @ns1.google.com | awk -F'\"' '{ print $2}'").read().rstrip()
        if ipv4_addr == '':
            ipv4_addr = os.popen('wget -4 -qO- -t 1 -T 1 http://ip.openmptcprouter.com').read().rstrip()
        if ipv4_addr == '':
            ipv4_addr = os.popen('wget -4 -qO- -t 1 -T 1 http://ifconfig.me').read().rstrip()
        if ipv4_addr != '':
            set_global_param('ipv4', ipv4_addr)

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
    if 'hostname' in omr_config_data:
        vps_domain = omr_config_data['hostname']
    elif 'internet' in omr_config_data and not omr_config_data['internet']:
        vps_domain = ''
    else:
        vps_domain = os.popen('wget -4 -qO- -t 1 -T 1 http://hostname.openmptcprouter.com').read().rstrip()
        if vps_domain != '':
            set_global_param('hostname', vps_domain)
    #vps_domain = os.popen('dig -4 +short +times=3 +tries=1 -x ' + ipv4_addr + " | sed 's/\.$//'").read().rstrip()
    user_permissions = current_user.permissions

    internet = True
    if 'internet' in omr_config_data and not omr_config_data['internet']:
        internet = False

    localip6 = ''
    remoteip6 = ''
    ula = ''
    if userid == 0:
        if os.path.isfile('/etc/openmptcprouter-vps-admin/omr-6in4/user' + str(userid)):
            with open('/etc/openmptcprouter-vps-admin/omr-6in4/user' + str(userid), "r") as omr6in4_file:
                for line in omr6in4_file:
                    if 'LOCALIP6=' in line:
                        localip6 = line.replace(line[:9], '').rstrip()
                    if 'REMOTEIP6=' in line:
                        remoteip6 = line.replace(line[:10], '').rstrip()
                    if 'ULA=' in line:
                        ula = line.replace(line[:4], '').rstrip()
    else:
        locaip6 = 'fd00::a00:1'
        remoteip6 = 'fd00::a00:2'

    vpn = 'glorytun_tcp'
    if 'vpn' in omr_config_data['users'][0][username]:
        vpn = omr_config_data['users'][0][username]['vpn']

    vpn_traffic_rx = 0
    vpn_traffic_tx = 0
    if vpn == 'glorytun_tcp':
        vpn_traffic_rx = get_bytes('rx', 'gt-tun' + str(userid))
        vpn_traffic_tx = get_bytes('tx', 'gt-tun' + str(userid))
    elif vpn == 'glorytun_udp':
        vpn_traffic_rx = get_bytes('rx', 'gt-udp-tun' + str(userid))
        vpn_traffic_tx = get_bytes('tx', 'gt-udp-tun' + str(userid))
    elif vpn == 'mlvpn':
        vpn_traffic_rx = get_bytes('rx', 'mlvpn' + str(userid))
        vpn_traffic_tx = get_bytes('tx', 'mlvpn' + str(userid))
    elif vpn == 'dsvpn':
        vpn_traffic_rx = get_bytes('rx', 'dsvpn' + str(userid))
        vpn_traffic_tx = get_bytes('tx', 'dsvpn' + str(userid))
    elif vpn == 'openvpn':
        #vpn_traffic_rx = get_bytes('rx', 'tun0')
        #vpn_traffic_tx = get_bytes('tx', 'tun0')
        vpn_txrx = get_bytes_openvpn(username)
        vpn_traffic_rx = vpn_txrx['uplinkBytes']
        vpn_traffic_tx = vpn_txrx['downlinkBytes']
    elif vpn == 'openvpn_bonding':
        vpn_traffic_rx = get_bytes('rx', 'omr-bonding')
        vpn_traffic_tx = get_bytes('tx', 'omr-bonding')

    #vpn = current_user.vpn
    available_proxy = ["shadowsocks", "shadowsocks-go","v2ray","v2ray-vmess","v2ray-socks","v2ray-trojan","xray","xray-vless-reality","xray-vmess","xray-socks","xray-trojan","xray-shadowsocks"]
    if user_permissions == 'ro':
        del available_vpn
        available_vpn = [vpn]
        del available_proxy
        available_proxy = [proxy]

    localvpn = ""
    if os.popen('ip l | grep " vpn"').read().rstrip() != '':
        localvpn = "vpn1"

    alllanips = []
    client2client = False
    if 'client2client' in omr_config_data and omr_config_data['client2client']:
        client2client = True
        for users in omr_config_data['users'][0]:
            if 'lanips' in omr_config_data['users'][0][users] and users != username and omr_config_data['users'][0][users]['lanips'][0] not in alllanips:
                alllanips.append(omr_config_data['users'][0][users]['lanips'][0])

    shorewall_redirect = "enable"
    with open('/etc/shorewall/rules', 'r') as f:
        for line in f:
            if '#DNAT		net		vpn:$OMR_ADDR	tcp	1-64999' in line:
                shorewall_redirect = "disable"
    LOG.debug('Get config: done')
    return {'vps': {'kernel': vps_kernel, 'machine': vps_machine, 'omr_version': vps_omr_version, 'loadavg': vps_loadavg, 'uptime': vps_uptime, 'aes': vps_aes}, 'shadowsocks': {'traffic': ss_traffic, 'key': shadowsocks_key, 'port': shadowsocks_port, 'method': shadowsocks_method, 'fast_open': shadowsocks_fast_open, 'reuse_port': shadowsocks_reuse_port, 'no_delay': shadowsocks_no_delay, 'mptcp': shadowsocks_mptcp, 'ebpf': shadowsocks_ebpf, 'obfs': shadowsocks_obfs, 'obfs_plugin': shadowsocks_obfs_plugin, 'obfs_type': shadowsocks_obfs_type}, 'glorytun': {'key': glorytun_key, 'udp': {'host_ip': glorytun_udp_host_ip, 'client_ip': glorytun_udp_client_ip}, 'tcp': {'host_ip': glorytun_tcp_host_ip, 'client_ip': glorytun_tcp_client_ip}, 'port': glorytun_port, 'chacha': glorytun_chacha}, 'dsvpn': {'key': dsvpn_key, 'host_ip': dsvpn_host_ip, 'client_ip': dsvpn_client_ip, 'port': dsvpn_port}, 'openvpn': {'key': openvpn_key, 'client_key': openvpn_client_key, 'client_crt': openvpn_client_crt, 'client_ca': openvpn_client_ca, 'host_ip': openvpn_host_ip, 'client_ip': openvpn_client_ip, 'port': openvpn_port, 'cipher': openvpn_cipher},'wireguard': {'key': wireguard_key, 'host_ip': wireguard_host_ip, 'port': wireguard_port, 'client_key': wireguard_client_key, 'client_ip': wireguard_client_ip, 'client_port': wireguard_client_port}, 'mlvpn': {'key': mlvpn_key, 'host_ip': mlvpn_host_ip, 'client_ip': mlvpn_client_ip,'timeout': mlvpn_timeout,'reorder_buffer_size': mlvpn_reorder_buffer_size,'loss_tolerence': mlvpn_loss_tolerence,'cleartext_data': mlvpn_cleartext_data}, 'shorewall': {'redirect_ports': shorewall_redirect}, 'mptcp': {'enabled': mptcp_enabled, 'checksum': mptcp_checksum, 'path_manager': mptcp_path_manager, 'scheduler': mptcp_scheduler, 'syn_retries': mptcp_syn_retries, 'version': mptcp_version}, 'network': {'congestion_control': congestion_control, 'ipv6_network': ipv6_network, 'ipv6': ipv6_addr, 'ipv4': ipv4_addr, 'domain': vps_domain, 'internet': internet}, 'vpn': {'available': available_vpn, 'current': vpn, 'remoteip': vpn_remote_ip, 'localip': vpn_local_ip, 'rx': vpn_traffic_rx, 'tx': vpn_traffic_tx}, 'iperf': {'user': 'openmptcprouter', 'password': 'openmptcprouter', 'key': iperf3_key}, 'pihole': {'state': pihole}, 'user': {'name': username, 'permission': user_permissions}, 'ip6in4': {'localip': localip6, 'remoteip': remoteip6, 'ula': ula}, 'client2client': {'enabled': client2client, 'lanips': alllanips}, 'gre_tunnel': {'enabled': gre_tunnel, 'config': gre_tunnel_conf}, 'v2ray': {'enabled': v2ray, 'config': v2ray_conf, 'tx': v2ray_tx, 'rx': v2ray_rx},'xray': {'enabled': xray, 'config': xray_conf, 'tx': xray_tx, 'rx': xray_rx},'shadowsocks_go': {'enabled': shadowsocks_go, 'config': shadowsocks_go_conf,'tx': ss_go_tx, 'rx': ss_go_rx}, 'proxy': {'available': available_proxy, 'current': proxy}, 'localvpn': localvpn}

# Set shadowsocks config
class OBFSPLUGIN(str, Enum):
    v2ray = "v2ray"
    obfs = "obfs"

class OBFSTYPE(str, Enum):
    tls = "tls"
    http = "http"


class ShadowsocksConfigparams(BaseModel):
    port: int = Query(..., gt=0, lt=65535)
    method: str
    fast_open: bool
    reuse_port: bool
    no_delay: bool
    mptcp: bool = Query(True, title="Enable/Disable MPTCP support")
    obfs: bool = Query(False, title="Enable/Disable obfuscation support")
    obfs_plugin: OBFSPLUGIN = Query("v2ray", title="Choose obfuscation plugin")
    obfs_type: OBFSTYPE = Query("tls", title="Choose obfuscation method")
    key: str

@app.post('/shadowsocks', summary="Modify Shadowsocks-libev configuration")
def shadowsocks(*, params: ShadowsocksConfigparams, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        set_lastchange(10)
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'shadowsocks'}
    ipv6_network = os.popen('ip -6 addr show ' + IFACE6 +' | grep -oP "(?<=inet6 ).*(?= scope global)"').read().rstrip()
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shadowsocks-libev/manager.json', 'rb'))).hexdigest()
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
    if 'port_key' in data:
        portkey = data["port_key"]
        portkey[str(port)] = key
    if 'port_conf' in data:
        portconf = data["port_conf"]
        portconf[str(port)]['key'] = key
    modif_config_user(current_user.username, {'shadowsocks_port': port})
    userid = current_user.userid
    if userid is None:
        userid = 0
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        try:
            omr_config_data = json.load(f)
        except ValueError as e:
            omr_config_data = {}

    #ipv4_addr = os.popen('wget -4 -qO- -T 2 http://ip.openmptcprouter.com').read().rstrip()
    if 'hostname' in omr_config_data:
        vps_domain = omr_config_data['hostname']
    else:
        vps_domain = os.popen('wget -4 -qO- -t 1 -T 1 http://hostname.openmptcprouter.com').read().rstrip()
        if vps_domain != '':
            set_global_param('hostname', vps_domain)

    if port is None or method is None or fast_open is None or reuse_port is None or no_delay is None or key is None:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'shadowsocks'}
    if 'port_key' in data:
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
    else:
        if ipv6_network == '':
            if obfs:
                if obfs_plugin == "v2ray":
                    if obfs_type == "tls":
                        if vps_domain == '':
                            shadowsocks_config = {'server': '0.0.0.0', 'port_conf': portconf, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl', 'plugin': '/usr/local/bin/v2ray-plugin', 'plugin_opts': 'server;tls'}
                        else:
                            shadowsocks_config = {'server': '0.0.0.0', 'port_conf': portconf, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl', 'plugin': '/usr/local/bin/v2ray-plugin', 'plugin_opts': 'server;tls;host=' + vps_domain}
                    else:
                        shadowsocks_config = {'server': '0.0.0.0', 'port_conf': portconf, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl', 'plugin': '/usr/local/bin/v2ray-plugin', 'plugin_opts': 'server'}
                else:
                    if obfs_type == 'tls':
                        if vps_domain == '':
                            shadowsocks_config = {'server': '0.0.0.0', 'port_conf': portconf, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl', 'plugin': '/usr/local/bin/obfs-server', 'plugin_opts': 'obfs=tls;mptcp;fast-open;t=400'}
                        else:
                            shadowsocks_config = {'server': '0.0.0.0', 'port_conf': portconf, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl', 'plugin': '/usr/local/bin/obfs-server', 'plugin_opts': 'obfs=tls;mptcp;fast-open;t=400;host=' + vps_domain}
                    else:
                        shadowsocks_config = {'server': '0.0.0.0', 'port_conf': portconf, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl', 'plugin': '/usr/local/bin/obfs-server', 'plugin_opts': 'obfs=http;mptcp;fast-open;t=400'}
            else:
                shadowsocks_config = {'server': '0.0.0.0', 'port_conf': portconf, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl'}
        else:
            if obfs:
                if obfs_plugin == "v2ray":
                    if obfs_type == "tls":
                        if vps_domain == '':
                            shadowsocks_config = {'server': '::0', 'port_conf': portconf, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl', 'plugin': '/usr/local/bin/v2ray-plugin', 'plugin_opts': 'server;tls'}
                        else:
                            shadowsocks_config = {'server': '::0', 'port_conf': portconf, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl', 'plugin': '/usr/local/bin/v2ray-plugin', 'plugin_opts': 'server;tls;host=' + vps_domain}
                    else:
                        shadowsocks_config = {'server': '::0', 'port_conf': portconf, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl', 'plugin': '/usr/local/bin/v2ray-plugin', 'plugin_opts': 'server'}
                else:
                    if obfs_type == 'tls':
                        if vps_domain == '':
                            shadowsocks_config = {'server': ('[::0]', '0.0.0.0'), 'port_conf': portconf, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl', 'plugin': '/usr/local/bin/obfs-server', 'plugin_opts': 'obfs=tls;mptcp;fast-open;t=400'}
                        else:
                            shadowsocks_config = {'server': ('[::0]', '0.0.0.0'), 'port_conf': portconf, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl', 'plugin': '/usr/local/bin/obfs-server', 'plugin_opts': 'obfs=tls;mptcp;fast-open;t=400;host=' + vps_domain}
                    else:
                        shadowsocks_config = {'server': ('[::0]', '0.0.0.0'), 'port_conf': portconf, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl', 'plugin': '/usr/local/bin/obfs-server', 'plugin_opts': 'obfs=http;mptcp;fast-open;t=400'}
            else:
                shadowsocks_config = {'server': ('[::0]', '0.0.0.0'), 'port_conf': portconf, 'local_port': 1081, 'mode': 'tcp_and_udp', 'timeout': timeout, 'method': method, 'verbose': verbose, 'ipv6_first': True, 'prefer_ipv6': prefer_ipv6, 'fast_open': fast_open, 'no_delay': no_delay, 'reuse_port': reuse_port, 'mptcp': mptcp, 'ebpf': ebpf, 'acl': '/etc/shadowsocks-libev/local.acl'}

    with open('/etc/shadowsocks-libev/manager.json', 'w') as outfile:
        json.dump(shadowsocks_config, outfile, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/shadowsocks-libev/manager.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        os.system("systemctl restart shadowsocks-libev-manager@manager.service")
        #for x in range(1, os.cpu_count()):
        #    os.system("systemctl restart shadowsocks-libev-manager@manager" + str(x) + ".service")
        shorewall_add_port(current_user, str(port), 'tcp', 'shadowsocks')
        shorewall_add_port(current_user, str(port), 'udp', 'shadowsocks')
        set_lastchange()
        return {'result': 'done', 'reason': 'changes applied', 'route': 'shadowsocks'}
    else:
        return {'result': 'done', 'reason': 'no changes', 'route': 'shadowsocks'}

class ShadowsocksGoConfigparams(BaseModel):
    port: int = Query(..., gt=0, lt=65535)
    method: str
    fast_open: bool
    reuse_port: bool
    mptcp: bool = Query(True, title="Enable/Disable MPTCP support")
    #key: str

@app.post('/shadowsocks-go', summary="Modify Shadowsocks-Go configuration")
def shadowsocks_go(*, params: ShadowsocksGoConfigparams, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        set_lastchange(10)
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'shadowsocks-go'}
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shadowsocks-go/server.json', 'rb'))).hexdigest()
    with open('/etc/shadowsocks-go/server.json') as f:
        content = f.read()
    content = re.sub(",\s*}", "}", content) # pylint: disable=W1401
    try:
        data = json.loads(content)
    except ValueError as e:
        return {'result': 'error', 'reason': 'Read only user', 'route': 'shadowsocks-go'}
    port = params.port
    # If method is aes 128 then key need to be length 16 instead of 32, so force aes-256-gcm for now
    #method = params.method
    method = "2022-blake3-aes-256-gcm"
    fast_open = params.fast_open
    reuse_port = params.reuse_port
    mptcp = params.mptcp
    #key = params.key
    modif_config_user(current_user.username, {'shadowsocks-go_port': port})
    userid = current_user.userid
    if userid is None:
        userid = 0
    data["servers"][0]["tcpListeners"][0]["address"] = ":" + str(port)
    data["servers"][0]["tcpListeners"][0]["fastOpen"] = fast_open
    data["servers"][0]["listenerTFO"] = fast_open
    data["servers"][0]["tcpListeners"][0]["reusePort"] = reuse_port
    data["servers"][0]["tcpListeners"][0]["multipath"] = mptcp
    data["servers"][0]["protocol"] = method
    #data.servers[0].psk = key
    with open('/etc/shadowsocks-go/server.json', 'w') as outfile:
        json.dump(data, outfile, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/shadowsocks-go/server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        os.system("systemctl restart shadowsocks-go.service")
        shorewall_add_port(current_user, str(port), 'tcp', 'shadowsocks-go')
        shorewall_add_port(current_user, str(port), 'udp', 'shadowsocks-go')
        set_lastchange()
        return {'result': 'done', 'reason': 'changes applied', 'route': 'shadowsocks-go'}
    else:
        return {'result': 'done', 'reason': 'no changes', 'route': 'shadowsocks-go'}

# Set shorewall config
class IPPROTO(str, Enum):
    ipv4 = "ipv4"
    ipv6 = "ipv6"

class ShorewallAllparams(BaseModel):
    redirect_ports: str = Query(..., title="Port or ports range")
    ipproto: IPPROTO = Query("ipv4", title="Protocol IP to apply changes")

@app.post('/shorewall', summary="Redirect all ports from Server to router")
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
        if initial_md5 != final_md5:
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
        if initial_md5 != final_md5:
            os.system("systemctl -q reload shorewall6")
    # Need to do the same for IPv6...
    return {'result': 'done', 'reason': 'changes applied'}

class ShorewallListparams(BaseModel):
    name: str
    ipproto: IPPROTO = Query("ipv4", title="Protocol IP to list")

@app.post('/shorewalllist', summary="Display all OpenMPTCProuter rules in Shorewall config")
def shorewall_list(*, params: ShorewallListparams, current_user: User = Depends(get_current_user)):
    name = params.name
    if name is None:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'shorewalllist'}
    fwlist = []
    if params.ipproto == 'ipv4':
        with open('/etc/shorewall/rules', 'r') as f:
            for line in f:
                if '# OMR ' + current_user.username + ' ' + name in line:
                    fwlist.append(line)
    else:
        with open('/etc/shorewall6/rules', 'r') as f:
            for line in f:
                if '# OMR ' + current_user.username + ' ' + name in line:
                    fwlist.append(line)
    return {'list': fwlist}

class Shorewallparams(BaseModel):
    name: str
    port: str
    proto: str
    fwtype: str
    ipproto: IPPROTO = Query("ipv4", title="Protocol IP for changes")
    source_dip: str = ""
    source_ip: str = ""
    comment: str = ""

@app.post('/shorewallopen', summary="Redirect a port from Server to Router")
def shorewall_open(*, params: Shorewallparams, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'shorewallopen'}
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        try:
            omr_config_data = json.load(f)
        except ValueError as e:
            omr_config_data = {}
    name = params.name
    port = params.port
    proto = params.proto
    fwtype = params.fwtype
    source_dip = params.source_dip
    source_ip = params.source_ip
    comment = params.comment
    if comment != '':
        comment = ' --- ' + comment
    vpn = "default"
    username = current_user.username
    if name is None:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'shorewallopen'}
    #proxy = 'shadowsocks'
    #if 'proxy' in omr_config_data['users'][0][username]:
    #    proxy = omr_config_data['users'][0][username]['proxy']
    #if proxy == 'v2ray':
    #    v2ray_add_port(current_user, str(port), proto, name)
    #    fwtype = 'ACCEPT'
    if params.ipproto == 'ipv4':
        if 'gre_tunnels' in omr_config_data['users'][0][current_user.username]:
            for tunnel in omr_config_data['users'][0][current_user.username]['gre_tunnels']:
                if omr_config_data['users'][0][current_user.username]['gre_tunnels'][tunnel]['public_ip'] == source_dip:
                    vpn = omr_config_data['users'][0][current_user.username]['gre_tunnels'][tunnel]['remote_ip']
        shorewall_add_port(current_user, str(port), proto, name, fwtype, source_dip, source_ip, vpn, comment)
    else:
        shorewall6_add_port(current_user, str(port), proto, name, fwtype, source_dip, source_ip, comment)
    return {'result': 'done', 'reason': 'changes applied'}

@app.post('/shorewallclose', summary="Remove a redirected port")
def shorewall_close(*, params: Shorewallparams, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'shorewallclose'}
    name = params.name
    port = params.port
    proto = params.proto
    fwtype = params.fwtype
    source_dip = params.source_dip
    source_ip = params.source_ip
    comment = params.comment
    if comment != '':
        comment = ' --- ' + comment
    if name is None:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'shorewallclose'}
    #v2ray_del_port(current_user.username, str(port), proto, name)
    if params.ipproto == 'ipv4':
        shorewall_del_port(current_user.username, str(port), proto, name, 'DNAT', source_dip, source_ip, comment)
        shorewall_del_port(current_user.username, str(port), proto, name, 'ACCEPT', source_dip, source_ip, comment)
    else:
        shorewall6_del_port(current_user.username, str(port), proto, name, 'DNAT', source_dip, source_ip, comment)
        shorewall6_del_port(current_user.username, str(port), proto, name, 'ACCEPT', source_dip, source_ip, comment)
    return {'result': 'done', 'reason': 'changes applied', 'route': 'shorewallclose'}

class SipALGparams(BaseModel):
    enable: bool = Query(True, title="Enable or disable SIP ALG")

@app.post('/sipalg', summary="Enable/Disable SIP ALG")
def sipalg(*, params: SipALGparams, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'sipalg'}
    enable = params.enable

    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall/shorewall.conf', 'rb'))).hexdigest()
    fd, tmpfile = mkstemp()
    with open('/etc/shorewall/shorewall.conf', 'r') as f, open(tmpfile, 'a+') as n:
        for line in f:
            if not enable and line == 'DONT_LOAD=\n':
                n.write('DONT_LOAD=nf_conntrack_sip\n')
            elif not enable and line == 'AUTOHELPERS=Yes\n':
                n.write('AUTOHELPERS=No\n')
            elif enable and 'DONT_LOAD' in line and line != 'DONT_LOAD=\n':
                n.write('DONT_LOAD=\n')
            elif enable and line == 'AUTOHELPERS=No\n':
                n.write('AUTOHELPERS=Yes\n')
            else:
                n.write(line)
    os.close(fd)
    move(tmpfile, '/etc/shorewall/shorewall.conf')
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall/shorewall.conf', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        os.system("systemctl -q reload shorewall")
    return {'result': 'done', 'reason': 'changes applied', 'route': 'sipalg'}

class V2rayconfig(BaseModel):
    userid: str

@app.post('/v2ray', summary="Set v2ray settings")
def v2ray(*, params: V2rayconfig, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'v2rayredirect'}
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    #with open('/etc/v2ray/v2ray-server.json') as f:
    #    v2ray_config = json.load(f)
    #v2ruserid = params.userid
    #for inbounds in v2ray_config['inbounds']:
    #    if inbounds['tag'] == 'omrin-tunnel':
    #        inbounds['settings']['clients'][0]['id'] = v2ruserid
    #with open('/etc/v2ray/v2ray-server.json', 'w') as outfile:
    #    json.dump(v2ray_config, outfile, indent=4)
    username = current_user.username
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    v2ray_key = os.popen("jq -r '.inbounds[0].settings.clients[] | select(.email=" + '"' + username + '"' + ") | .id' /etc/v2ray/v2ray-server.json").read().rstrip()
    v2ray_port = os.popen('jq -r .inbounds[0].port /etc/v2ray/v2ray-server.json').read().rstrip()
    v2ray_conf = { 'key': v2ray_key, 'port': v2ray_port}
    modif_config_user(username, {'v2ray': v2ray_conf})
    if initial_md5 != final_md5:
        os.system("systemctl restart v2ray")
        set_lastchange()
        return {'result': 'done', 'reason': 'changes applied', 'route': 'v2ray'}
    else:
        return {'result': 'done', 'reason': 'no changes', 'route': 'v2ray'}

class Xrayconfig(BaseModel):
    userid: str
    vless_reality: bool = Query(False, title="Enable or disable VLESS Reality")
    ss_method: str = "2022-blake3-aes-256-gcm"

@app.post('/xray', summary="Set xray settings")
def xray(*, params: Xrayconfig, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'xrayredirect'}
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    test_vless_reality = os.popen("jq -r '.inbounds[] | select(.tag==" + '"' + 'omrin-vless-reality' + '"' + ")' /etc/xray/xray-server.json").read().rstrip()
    if test_vless_reality != '':
        chk_vless_reality = True
    else:
        chk_vless_reality = False
    with open('/etc/xray/xray-server.json') as f:
        xray_config = json.load(f)
        if params.vless_reality and not chk_vless_reality:
            with open('/etc/xray/xray-vless-reality.json') as f:
                vless_reality_config = json.load(f)
            xray_config['inbounds'].append(vless_reality_config['inbounds'][0])
        elif not params.vless_reality and chk_vless_reality:
            for inbounds in xray_config['inbounds']:
                if inbounds['tag'] == 'omrin-vless-reality':
                    xray_config['inbounds'].remove(inbounds)
        for inbounds in xray_config['inbounds']:
            if inbounds['tag'] == 'omrin-shadowsocks-tunnel':
                inbounds['settings']['method'] = params.ss_method

    with open('/etc/xray/xray-server.json', 'w') as outfile:
        json.dump(xray_config, outfile, indent=4)
    #with open('/etc/xray/xray-server.json') as f:
    #    xray_config = json.load(f)
    #xruserid = params.userid
    #for inbounds in xray_config['inbounds']:
    #    if inbounds['tag'] == 'omrin-tunnel':
    #        inbounds['settings']['clients'][0]['id'] = xruserid
    #with open('/etc/xray/xray-server.json', 'w') as outfile:
    #    json.dump(xray_config, outfile, indent=4)
    username = current_user.username
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    xray_key = os.popen("jq -r '.inbounds[0].settings.clients[] | select(.email=" + '"' + username + '"' + ") | .id' /etc/xray/xray-server.json").read().rstrip()
    xray_ss_skey = os.popen("jq -r '.inbounds[] | select(.tag==" + '"' + 'omrin-shadowsocks-tunnel' + '"' + ") | .settings.password' /etc/xray/xray-server.json").read().rstrip()
    xray_ss_ukey = os.popen("jq -r '.inbounds[] | select(.tag==" + '"' + 'omrin-shadowsocks-tunnel' + '"' + ") | .settings.clients[] | select(.email=" + '"' + username + '"' + ") | .password' /etc/xray/xray-server.json").read().rstrip()
    xray_ss_key = xray_ss_skey + ':' + xray_ss_ukey
    xray_port = os.popen('jq -r .inbounds[0].port /etc/xray/xray-server.json').read().rstrip()
    test_vless_reality = os.popen("jq -r '.inbounds[] | select(.tag==" + '"' + 'omrin-vless-reality' + '"' + ")' /etc/xray/xray-server.json").read().rstrip()
    if test_vless_reality != '':
        vless_reality = True
    else:
        vless_reality = False
    if os.path.isfile('/etc/xray/xray-vless-reality.json'):
        xray_vless_reality_public_key = os.popen("jq -r '.inbounds[] | select(.tag==" + '"' + 'omrin-vless-reality' + '"' + ") | .streamSettings.realitySettings.publicKey' /etc/xray/xray-vless-reality.json").read().rstrip()
    xray_conf = { 'key': xray_key, 'port': xray_port, 'sskey': xray_ss_key, 'vless_reality_key': xray_vless_reality_public_key, 'vless_reality': vless_reality, 'ss_method': params.ss_method }
    modif_config_user(username, {'xray': xray_conf})
    if initial_md5 != final_md5:
        if params.vless_reality and not chk_vless_reality:
            shorewall_add_port(current_user, '443', 'tcp', 'xray vless-reality')
        elif not params.vless_reality and chk_vless_reality:
            shorewall_del_port(current_user.username, '443', 'tcp', 'xray vless-reality')
        os.system("systemctl restart xray")
        set_lastchange()
        return {'result': 'done', 'reason': 'changes applied', 'route': 'xray'}
    else:
        return {'result': 'done', 'reason': 'no changes', 'route': 'xray'}


class V2rayparams(BaseModel):
    name: str
    port: str
    proto: str
    destip: str = ""
    destport: str = ""

@app.post('/v2rayredirect', summary="Redirect a port from Server to Router with V2Ray")
def v2ray_redirect(*, params: V2rayparams, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'v2rayredirect'}
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        try:
            omr_config_data = json.load(f)
        except ValueError as e:
            omr_config_data = {}
    name = params.name
    port = params.port
    proto = params.proto
    destip = params.destip
    destport = params.destport
    username = current_user.username
    if name is None:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'v2rayredirect'}
    v2ray_add_port(current_user, port, proto, name, destip, destport)
    return {'result': 'done', 'reason': 'changes applied'}

class Xrayparams(BaseModel):
    name: str
    port: str
    proto: str
    destip: str = ""
    destport: str = ""

@app.post('/xrayredirect', summary="Redirect a port from Server to Router with XRay")
def xray_redirect(*, params: Xrayparams, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'xrayredirect'}
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        try:
            omr_config_data = json.load(f)
        except ValueError as e:
            omr_config_data = {}
    name = params.name
    port = params.port
    proto = params.proto
    destip = params.destip
    destport = params.destport
    username = current_user.username
    if name is None:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'xrayredirect'}
    xray_add_port(current_user, port, proto, name, destip, destport)
    return {'result': 'done', 'reason': 'changes applied'}

@app.post('/v2rayunredirect', summary="Remove a redirected port from Server to Router with V2Ray")
def v2ray_unredirect(*, params: V2rayparams, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'v2rayredirect'}
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        try:
            omr_config_data = json.load(f)
        except ValueError as e:
            omr_config_data = {}
    name = params.name
    port = params.port
    proto = params.proto
    destip = params.destip
    destport = params.destport
    username = current_user.username
    if name is None:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'v2rayunredirect'}
    v2ray_del_port(current_user, port, proto, name, destip, destport)
    return {'result': 'done', 'reason': 'changes applied'}

@app.post('/xrayunredirect', summary="Remove a redirected port from Server to Router with XRay")
def xray_unredirect(*, params: Xrayparams, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'xrayredirect'}
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        try:
            omr_config_data = json.load(f)
        except ValueError as e:
            omr_config_data = {}
    name = params.name
    port = params.port
    proto = params.proto
    destip = params.destip
    destport = params.destport
    username = current_user.username
    if name is None:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'xrayunredirect'}
    xray_del_port(current_user, port, proto, name, destip, destport)
    return {'result': 'done', 'reason': 'changes applied'}

# Set MPTCP config
class MPTCPparams(BaseModel):
    checksum: str
    path_manager: str
    scheduler: str
    syn_retries: int
    congestion_control: str
    version: int = 0

@app.post('/mptcp', summary="Modify MPTCP configuration of the server")
def mptcp(*, params: MPTCPparams, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        set_lastchange(10)
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'mptcp'}
    checksum = params.checksum
    path_manager = params.path_manager
    scheduler = params.scheduler
    syn_retries = params.syn_retries
    congestion_control = params.congestion_control
    version = params.version
    if not checksum or not path_manager or not scheduler or not syn_retries or not congestion_control:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'mptcp'}
    if path.exists('/proc/sys/net/mptcp/mptcp_enabled'):
        os.system('sysctl -qw net.mptcp.mptcp_checksum=' + checksum)
        os.system('sysctl -qw net.mptcp.mptcp_path_manager=' + path_manager)
        os.system('sysctl -qw net.mptcp.mptcp_scheduler=' + scheduler)
        os.system('sysctl -qw net.mptcp.mptcp_syn_retries=' + str(syn_retries))
        os.system('sysctl -qw net.mptcp.mptcp_version=' + str(version))
    else:
        os.system('sysctl -qw net.mptcp.checksum_enabled=' + checksum)
    os.system('sysctl -qw net.ipv4.tcp_congestion_control=' + congestion_control)
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/sysctl.d/90-shadowsocks.conf', 'rb'))).hexdigest()
    fd, tmpfile = mkstemp()
    with open('/etc/sysctl.d/90-shadowsocks.conf', 'r') as f, open(tmpfile, 'a+') as n:
        for line in f:
            if not 'net.mptcp' in line and not 'net.ipv4.tcp_congestion_control' in line:
                n.write(line)
        n.write('net.mptcp.mptcp_checksum=' + checksum + "\n")
        n.write('net.mptcp.mptcp_path_manager=' + path_manager + "\n")
        n.write('net.mptcp.mptcp_scheduler=' + scheduler + "\n")
        n.write('net.mptcp.mptcp_syn_retries=' + str(syn_retries) + "\n")
        n.write('net.mptcp.mptcp_version=' + str(version) + "\n")
        n.write('net.mptcp.checksum_enabled=' + checksum + "\n")
        n.write('net.ipv4.tcp_congestion_control=' + congestion_control + "\n")
    os.close(fd)
    move(tmpfile, '/etc/sysctl.d/90-shadowsocks.conf')
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/sysctl.d/90-shadowsocks.conf', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        os.system("systemctl -q restart shadowsocks-libev-manager@manager")
        os.system("systemctl -q restart v2ray")
        os.system("systemctl -q restart xray")
        os.system("systemctl -q restart glorytun-tcp@tun0")
        os.system("systemctl -q restart openvpn@tun0")
    set_lastchange()
    return {'result': 'done', 'reason': 'changes applied'}

class VPN(str, Enum):
    openvpn = "openvpn"
    openvpnbonding = "openvpn_bonding"
    glorytuntcp = "glorytun_tcp"
    glorytunudp = "glorytun_udp"
    dsvpn = "dsvpn"
    mlvpn = "mlvpn"
    none = "none"

class Vpn(BaseModel):
    vpn: VPN

# Set global VPN config
@app.post('/vpn', summary="Set VPN used by the current user")
def vpn(*, vpnconfig: Vpn, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        set_lastchange(10)
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'vpn'}
    vpn = vpnconfig.vpn
    if not vpn:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'vpn'}
    os.system('echo ' + vpn + ' > /etc/openmptcprouter-vps-admin/current-vpn')
    modif_config_user(current_user.username, {'vpn': vpn})
    current_user.vpn = vpn
    set_lastchange()
    return {'result': 'done', 'reason': 'changes applied'}

class PROXY(str, Enum):
    v2ray = "v2ray"
    v2rayvless = "v2ray-vless"
    v2rayvmess = "v2ray-vmess"
    v2raysocks = "v2ray-socks"
    v2raytrojan = "v2ray-trojan"
    xray = "xray"
    xrayvless = "xray-vless"
    xrayvmess = "xray-vmess"
    xraysocks = "xray-socks"
    xraytrojan = "xray-trojan"
    xrayshadowsocks = "xray-shadowsocks"
    shadowsockslibev = "shadowsocks"
    shadowsocksgo = "shadowsocks-go"
    shadowsocksrust = "shadowsocks-rust"
    none = "none"

class Proxy(BaseModel):
    proxy: PROXY

# Set global Proxy config
@app.post('/proxy', summary="Set Proxy used by the current user")
def proxy(*, proxyconfig: Proxy, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        set_lastchange(10)
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'proxy'}
    proxy = proxyconfig.proxy
    if not proxy:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'proxy'}
    os.system('echo ' + proxy + ' > /etc/openmptcprouter-vps-admin/current-proxy')
    modif_config_user(current_user.username, {'proxy': proxy})
    #current_user.proxy = proxy
    set_lastchange()
    return {'result': 'done', 'reason': 'changes applied'}


class GlorytunConfig(BaseModel):
    key: str
    port: int = Query(..., gt=0, lt=65535, title="Glorytun TCP and UDP port")
    chacha: bool = Query(True, title="Enable of disable chacha20, if disable AES is used")

# Set Glorytun config
@app.post('/glorytun', summary="Modify Glorytun configuration")
def glorytun(*, glorytunconfig: GlorytunConfig, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        set_lastchange(10)
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'glorytun'}
    userid = current_user.userid
    if userid is None:
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
    if initial_md5 != final_md5:
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
    if initial_md5 != final_md5:
        os.system("systemctl -q restart glorytun-udp@tun" + str(userid))
    shorewall_add_port(current_user, str(port), 'tcp', 'glorytun')
    shorewall_add_port(current_user, str(port), 'udp', 'glorytun')
    set_lastchange()
    return {'result': 'done'}

# Set A Dead Simple VPN config
class DSVPN(BaseModel):
    key: str
    port: int = Query(..., gt=0, lt=65535)

@app.post('/dsvpn', summary="Modify DSVPN configuration")
def dsvpn(*, params: DSVPN, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        set_lastchange(10)
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'dsvpn'}
    userid = current_user.userid
    if userid is None:
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
    if initial_md5 != final_md5:
        os.system("systemctl -q restart dsvpn-server@dsvpn" + str(userid))
    shorewall_add_port(current_user, str(port), 'tcp', 'dsvpn')
    set_lastchange()
    return {'result': 'done'}

# Set MLVPN config
class MLVPN(BaseModel):
    timeout: int
    reorder_buffer_size: int
    loss_tolerence: int
    cleartext_data: int
    password: str

@app.post('/mlvpn', summary="Modify MLVPN configuration")
def mlvpn(*, params: MLVPN, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        set_lastchange(10)
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'mlvpn'}
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/mlvpn/mlvpn0.conf', 'rb'))).hexdigest()
    mlvpn_config = configparser.ConfigParser()
    mlvpn_config.read_file(open(r'/etc/mlvpn/mlvpn0.conf'))
    mlvpn_config.set('general', 'password', '"' + params.password + '"')
    mlvpn_config.set('general', 'timeout',str(params.timeout))
    mlvpn_config.set('general', 'reorder_buffer_size',str(params.reorder_buffer_size))
    mlvpn_config.set('general', 'loss_tolerence',str(params.loss_tolerence))
    mlvpn_config.set('general', 'cleartext_data',str(params.cleartext_data))
    with open('/etc/mlvpn/mlvpn0.conf','w') as mlvpn_file:
        mlvpn_config.write(mlvpn_file)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/mlvpn/mlvpn0.conf', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        os.system("systemctl -q restart mlvpn@mlvpn0")
        set_lastchange()
    return {'result': 'done', 'reason': 'changes applied', 'route': 'mlvpn'}


# Set OpenVPN config
class OpenVPN(BaseModel):
    port: int = Query(..., gt=0, lt=65535)
    cipher: str = "AES-256-CBC"

@app.post('/openvpn', summary="Modify OpenVPN TCP configuration")
def openvpn(*, params: OpenVPN, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        set_lastchange(10)
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'openvpn'}
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/openvpn/tun0.conf', 'rb'))).hexdigest()
    fd, tmpfile = mkstemp()
    with open('/etc/openvpn/tun0.conf', 'r') as f, open(tmpfile, 'a+') as n:
        for line in f:
            if 'cipher ' in line:
                n.write('cipher ' + params.cipher + '\n')
            elif 'port ' in line:
                n.write('port ' + str(params.port) + '\n')
            else:
                n.write(line)
    os.close(fd)
    move(tmpfile, '/etc/openvpn/tun0.conf')
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/openvpn/tun0.conf', 'rb'))).hexdigest()

    if initial_md5 != final_md5:
        os.system("systemctl -q restart openvpn@tun0")
        shorewall_add_port(current_user, str(params.port), 'tcp', 'openvpn')
        set_lastchange()
    return {'result': 'done'}

# Set WireGuard config
class WireGuardPeer(BaseModel):
    ip: str
    key: str

class WireGuard(BaseModel):
    peers: List[WireGuardPeer] = []

@app.post('/wireguard', summary="Modify Wireguard configuration")
def wireguard(*, params: WireGuard, current_user: User = Depends(get_current_user)):
    if not os.path.isfile('/etc/wireguard/wg0.conf'):
        return {'result': 'error', 'reason': 'Wireguard config not found', 'route': 'wireguard'}
    wg_config = configparser.ConfigParser(strict=False)
    wg_config.read_file(open(r'/etc/wireguard/wg0.conf'))
    wg_port = wg_config.get('Interface', 'ListenPort')
    wg_key = wg_config.get('Interface', 'PrivateKey')

    fd, tmpfile = mkstemp()
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/wireguard/wg0.conf', 'rb'))).hexdigest()
    with open(tmpfile, 'a+') as n:
        n.write('[Interface]\n')
        n.write('ListenPort = ' + wg_port + '\n')
        n.write('PrivateKey = ' + wg_key + '\n')
        for peer in params.peers:
            n.write('\n')
            n.write('[Peer]\n')
            n.write('PublicKey  = ' + peer.key + '\n')
            n.write('AllowedIPs = ' + peer.ip + '\n')
    move(tmpfile, '/etc/wireguard/wg0.conf')
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/wireguard/wg0.conf', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        os.system("wg setconf wg0 /etc/wireguard/wg0.conf")
        shorewall_add_port(current_user, str(wg_port), 'udp', 'wireguard')
        set_lastchange()
    return {'result': 'done', 'reason': 'changes applied', 'route': 'wireguard'}

class ByPass(BaseModel):
    ipv4s: List[str] = []
    ipv6s: List[str] = []
    intf: str

@app.post('/bypass', summary="Set IPs to Bypass")
def bypass(*, bypassconfig: ByPass, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'bypass'}
    bypassipv4s = bypassconfig.ipv4s
    bypassipv6s = bypassconfig.ipv6s
    if not bypassconfig.intf:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'bypass'}
    if os.path.isfile('/etc/openmptcprouter-vps-admin/omr-bypass.json'):
        with open('/etc/openmptcprouter-vps-admin/omr-bypass.json') as f:
            content = f.read()
        content = re.sub(",\s*}", "}", content) # pylint: disable=W1401
        try:
            configdata = json.loads(content)
            data = configdata
        except ValueError as e:
            return {'error': 'Config file not readable', 'route': 'lastchange'}
    else:
        data = {}
        configdata = {}
    data[bypassconfig.intf] = {}
    data[bypassconfig.intf]["ipv4"] = bypassipv4s
    data[bypassconfig.intf]["ipv6"] = bypassipv6s
    #if data and data != configdata:
    with open('/etc/openmptcprouter-vps-admin/omr-bypass.json', 'w') as outfile:
        json.dump(data, outfile, indent=4)
    return {'result': 'done', 'reason': 'changes applied', 'route': 'bypass'}



class Wanips(BaseModel):
    ips: str

# Set WANIP
@app.post('/wan', summary="Set WAN IPs")
def wan(*, wanips: Wanips, current_user: User = Depends(get_current_user)):
    ips = wanips.ips
    if not ips:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'wan'}
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shadowsocks-libev/local.acl', 'rb'))).hexdigest()
    with open('/etc/shadowsocks-libev/local.acl', 'w') as outfile:
        outfile.write('[white_list]\n')
        outfile.write(ips)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/shadowsocks-libev/local.acl', 'rb'))).hexdigest()
    #modif_config_user(current_user.username,{'wanips': wanip})
    return {'result': 'done', 'reason': 'changes applied', 'route': 'wan'}

class Lanips(BaseModel):
    lanips: List[str] = []

# Set user lan config
@app.post('/lan', summary="Set current user LAN IPs")
def lan(*, lanconfig: Lanips, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'lan'}
    lanips = lanconfig.lanips
    if not lanips:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'lan'}
    modif_config_user(current_user.username, {'lanips': lanips})
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
        if initial_md5 != final_md5:
            os.system("systemctl -q restart openvpn@tun0")
            set_lastchange()
    return {'result': 'done', 'reason': 'changes applied', 'route': 'lan'}

class VPNips(BaseModel):
    remoteip: str = Query(..., pattern='^(10(\.(25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})){3}|((172\.(1[6-9]|2[0-9]|3[01]))|192\.168)(\.(25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})){2})$')
    localip: str = Query(..., pattern='^(10(\.(25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})){3}|((172\.(1[6-9]|2[0-9]|3[01]))|192\.168)(\.(25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})){2})$')
    remoteip6: Optional[str] = None
    localip6: Optional[str] = None
    ula: Optional[str] = None

# Set user vpn IPs
@app.post('/vpnips', summary="Set current user VPN IPs")
def vpnips(*, vpnconfig: VPNips, current_user: User = Depends(get_current_user)):
    #if current_user.permissions == "ro":
    #    return {'result': 'permission', 'reason': 'Read only user', 'route': 'vpnips'}
    remoteip = vpnconfig.remoteip
    localip = vpnconfig.localip
    remoteip6 = vpnconfig.remoteip6
    localip6 = vpnconfig.localip6
    ula = vpnconfig.ula
    if not remoteip or not localip:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'vpnips'}
    modif_config_user(current_user.username, {'vpnremoteip': remoteip})
    modif_config_user(current_user.username, {'vpnlocalip': localip})
    if ula:
        modif_config_user(current_user.username, {'ula': ula})
    userid = current_user.userid
    if userid is None:
        userid = 0
    if os.path.isfile('/etc/openmptcprouter-vps-admin/omr-6in4/user' + str(userid)):
        initial_md5 = hashlib.md5(file_as_bytes(open('/etc/openmptcprouter-vps-admin/omr-6in4/user' + str(userid), 'rb'))).hexdigest()
    else:
        initial_md5 = ''
    with open('/etc/openmptcprouter-vps-admin/omr-6in4/user' + str(userid), 'w+') as n:
        n.write('LOCALIP=' + localip + "\n")
        n.write('REMOTEIP=' + remoteip + "\n")
        if localip6:
            n.write('LOCALIP6=' + localip6 + "\n")
        else:
            n.write('LOCALIP6=fd00::a0' + hex(userid)[2:] + ':1/126' + "\n")
        if remoteip6:
            n.write('REMOTEIP6=' + remoteip6 + "\n")
        else:
            n.write('REMOTEIP6=fd00::a0' + hex(userid)[2:] + ':2/126' + "\n")
        if ula:
            n.write('ULA=' + ula + "\n")
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/openmptcprouter-vps-admin/omr-6in4/user' + str(userid), 'rb'))).hexdigest()
    if initial_md5 != final_md5:
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
    if initial_md5 != final_md5:
        os.system("systemctl -q reload shorewall")
        set_lastchange()

    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall6/params.vpn', 'rb'))).hexdigest()
    fd, tmpfile = mkstemp()
    with open('/etc/shorewall6/params.vpn', 'r') as f, open(tmpfile, 'a+') as n:
        for line in f:
            if not ('OMR_ADDR_USER' + str(userid) +'=' in line and not userid == 0) and not ('OMR_ADDR=' in line and userid == 0):
                n.write(line)
        if  not userid == 0:
            n.write('OMR_ADDR_USER' + str(userid) + '=fd00::a0' + hex(userid)[2:] + ':2/126' + '\n')
        elif userid == 0:
            n.write('OMR_ADDR=fd00::a0' + hex(userid)[2:] + ':2/126' + '\n')

    os.close(fd)
    move(tmpfile, '/etc/shorewall6/params.vpn')
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall6/params.vpn', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        os.system("systemctl -q reload shorewall6")
        set_lastchange()

    return {'result': 'done', 'reason': 'changes applied', 'route': 'vpnips'}

# Update VPS
@app.get('/update', summary="Update VPS script")
def update(current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'update'}
    LOG.debug("Update VPS...")
    with open("/etc/openmptcprouter-vps-admin/update", mode='a'): pass
    os.system("systemctl stop omr")
    os.system("systemctl -q restart omr-update")
    LOG.debug("Update VPS... done")
    return {'result': 'done', 'route': 'update'}

# Backup
class Backupfile(BaseModel):
    data: str = Query(..., title="OpenMPTCProuter backup file in tar.gz encoded in base64")

@app.post('/backuppost', summary="Send current user router backup file")
def backuppost(*, backupfile: Backupfile, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'backuppost'}
    backup_file = backupfile.data
    if not backup_file:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'backuppost'}
    with open('/var/opt/openmptcprouter/' + current_user.username + '-backup.tar.gz', 'wb') as f, open('/var/opt/openmptcprouter/' + current_user.username + '-' + str(int(time.time())) + '-backup.tar.gz', 'wb') as g:
        g.write(base64.b64decode(backup_file))
        f.write(base64.b64decode(backup_file))
    delete_oldest_files('/var/opt/openmptcprouter/' + current_user.username + '-*-backup.tar.gz')
    return {'result': 'done', 'route': 'backuppost'}

@app.get('/backupget', summary="Get current user router backup file")
def send_backup(filename: Optional[str] = Query(None), current_user: User = Depends(get_current_user)):
    if filename is not None and current_user.username in filename:
        with open('/var/opt/openmptcprouter/' + filename, "rb") as backup_file:
            file_base64 = base64.b64encode(backup_file.read())
            file_base64utf = file_base64.decode('utf-8')
    else:
        with open('/var/opt/openmptcprouter/' + current_user.username + '-backup.tar.gz', "rb") as backup_file:
            file_base64 = base64.b64encode(backup_file.read())
            file_base64utf = file_base64.decode('utf-8')
    return {'data': file_base64utf}

@app.get('/backuplist', summary="List available current user backup")
def list_backup(current_user: User = Depends(get_current_user)):
    files = glob.glob('/var/opt/openmptcprouter/' + current_user.username + '*' + '-backup.tar.gz')
    fileData = {}
    for fname in files:
        fileData[os.path.relpath(fname,'/var/opt/openmptcprouter/')] = os.stat(fname).st_mtime
    sorted_files = sorted(fileData.items(), key = itemgetter(1))
    if os.path.isfile('/var/opt/openmptcprouter/' + current_user.username + '-backup.tar.gz'):
        modiftime = os.path.getmtime('/var/opt/openmptcprouter/' + current_user.username + '-backup.tar.gz')
    if len(sorted_files) > 0:
        return {'backup': True, 'modif': modiftime,'sorted': sorted_files}
    else:
        return {'backup': False}

@app.get('/backupshow', summary="Show current user backup")
def show_backup(current_user: User = Depends(get_current_user)):
    if os.path.isfile('/var/opt/openmptcprouter/' + current_user.username + '-backup.tar.gz'):
        router = OpenWrt(native=open('/var/opt/openmptcprouter/' + current_user.username + '-backup.tar.gz'))
        return {'backup': True, 'data': router}
    else:
        return {'backup': False}

@app.post('/backupedit', summary="Modify current user backup")
def edit_backup(params, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'backupedit'}
    o = OpenWrt(params)
    o.write(current_user.username + '-backup', path='/var/opt/openmptcprouter/')
    return {'result': 'done'}

#class VPN(str, Enum):
#    openvpn = "openvpn"
#    glorytuntcp = "glorytun_tcp"
#    glorytunudp = "glorytun_udp"
#    dsvpn = "dsvpn"

class permissions(str, Enum):
    ro = "ro"
    rw = "rw"
    admin = "admin"

class NewUser(BaseModel):
    username: str = Query(..., title="Username")
    permission: permissions = Query("ro", title="permission of the user")
    vpn: VPN = Query("openvpn", title="default VPN for the user")
    proxy: PROXY = Query("shadowsocks-rust", title="default Proxy for the user")
    shadowsocks_port: Optional[int] = Query(None, gt=0, lt=65535, title="Shadowsocks port")
    userid: Optional[int] = Query(None, title="User ID")
    ips: Optional[List[str]] = Query(None, title="Public exit IP")
#    userid: int = Query(0, title="User ID",description="User ID is used to create port of each VPN and shadowsocks",gt=0,le=99)

@app.post('/add_user', summary="Add a new user")
def add_user(*, params: NewUser, current_user: User = Depends(get_current_user)):
    if not current_user.permissions == "admin":
        return {'result': 'permission', 'reason': 'Need admin user', 'route': 'add_user'}
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        content = json.load(f)
    userid = params.userid
    if userid is None or userid == 0:
        userid = 2
        for users in content['users'][0]:
            if 'userid' in content['users'][0][users]:
                if int(content['users'][0][users]['userid']) > userid:
                    userid = int(content['users'][0][users]['userid'])
        userid = userid + 1
    if params.ips is None:
        publicips = []
    else:
        publicips = params.ips
    user_key = secrets.token_hex(32)
    user_json = json.loads('{"'+ params.username + '": {"username":"'+ params.username +'","permissions":"'+params.permission+'","user_password": "'+user_key.upper()+'","disabled":"false","userid":"' + str(userid) + '","public_ips":'+ json.dumps(publicips) +'}}')
#    shadowsocks_port = params.shadowsocks_port
#    if params.shadowsocks_port is None:
#    shadowsocks_port = '651{:02d}'.format(userid)
    shadowsocks_port = params.shadowsocks_port
    shadowsocks_key = base64.urlsafe_b64encode(secrets.token_hex(16).encode())
    shadowsocks2022_key = base64.urlsafe_b64encode(secrets.token_hex(32).encode())
    if not publicips:
        if os.path.isfile('/etc/shadowsocks-libev/manager.json'):
            shadowsocks_port = add_ss_user(str(shadowsocks_port), shadowsocks_key.decode('utf-8'), userid)
        if os.path.isfile('/etc/shadowsocks-go/server.json'):
            upsk = add_ss_go_user(params.username, shadowsocks2022_key.decode('utf-8'))
        else:
            upsk = ''
        if os.path.isfile('/etc/v2ray/v2ray-server.json'):
            if params.proxy is not None and params.proxy == 'v2ray-vmess':
                uuid = v2ray_add_user(params.username,'',0)
            else:
                uuid = v2ray_add_user(params.username)
        else:
            uuid = ''
        if os.path.isfile('/etc/xray/xray-server.json'):
            xray_add_user(params.username,uuid,upsk)
    else:
        for publicip in publicips:
            if os.path.isfile('/etc/shadowsocks-libev/manager.json'):
                shadowsocks_port = add_ss_user(str(shadowsocks_port), shadowsocks_key.decode('utf-8'), userid, publicip)
                shadowsocks_port = shadowsocks_port + 1
    user_json[params.username].update({"shadowsocks_port": shadowsocks_port})
    if params.vpn is not None:
        user_json[params.username].update({"vpn": params.vpn})
    if params.proxy is not None:
        user_json[params.username].update({"proxy": params.proxy})
    content['users'][0].update(user_json)
    if content:
        backup_config()
        with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json', 'w') as f:
            json.dump(content, f, indent=4)
    else:
        LOG.debug("Empty data for add_user")
    # Create VPNs configuration
    if os.path.isfile('/etc/openvpn/tun0.conf'):
        os.system('cd /etc/openvpn/ca && EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-client-full "' + params.username + '" nopass')
    if os.path.isfile('/etc/glorytun-tcp/tun0'):
        add_glorytun_tcp(userid)
    if os.path.isfile('/etc/glorytun-udp/tun0'):
        add_glorytun_udp(userid)
    if os.path.isfile('/etc/dsvpn/dsvpn0'):
        add_dsvpn(userid)

    set_lastchange(30)
    #os.execv(__file__, sys.argv)
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        global fake_users_db
        omr_config_data = json.load(f)
        fake_users_db = omr_config_data['users'][0]

class ExistingUser(BaseModel):
    username: str = Query(..., title="Username")
    note: list = []

@app.post('/add_user_note', summary="Add a note to an user")
def add_user_note(*, params: ExistingUser, current_user: User = Depends(get_current_user)):
    if not current_user.permissions == "admin":
        return {'result': 'permission', 'reason': 'Need admin user', 'route': 'add_user'}
    modif_config_user(params.username,{"note": params.note})
    set_lastchange(30)


class RemoveUser(BaseModel):
    username: str

@app.post('/remove_user', summary="Remove an user")
def remove_user(*, params: RemoveUser, current_user: User = Depends(get_current_user)):
    if not current_user.permissions == "admin":
        return {'result': 'permission', 'reason': 'Need admin user', 'route': 'remove_user'}
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        content = json.load(f)
    shadowsocks_port = content['users'][0][params.username]['shadowsocks_port']
    userid = int(content['users'][0][params.username]['userid'])
    del content['users'][0][params.username]
    if os.path.isfile('/etc/shadowsocks-libev/manager.json'):
        remove_ss_user(str(shadowsocks_port))
    if os.path.isfile('/etc/shadowsocks-go/server.json'):
        remove_ss_go_user(params.username)
    if os.path.isfile('/etc/v2ray/v2ray-server.json'):
        v2ray_del_user(params.username)
    if os.path.isfile('/etc/xray/xray-server.json'):
        xray_del_user(params.username)
    if content:
        backup_config()
        with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json', 'w') as f:
            json.dump(content, f, indent=4)
    else:
        LOG.debug("Empty data for remover_user")
    if os.path.isfile('/etc/openvpn/tun0.conf'):
        os.system('cd /etc/openvpn/ca && ./easyrsa --batch revoke ' + params.username)
        os.system('cd /etc/openvpn/ca && ./easyrsa gen-crl')
        os.system("systemctl -q restart openvpn@tun0")
    if os.path.isfile('/etc/glorytun-tcp/tun0'):
        remove_glorytun_tcp(userid)
    if os.path.isfile('/etc/glorytun-udp/tun0'):
        remove_glorytun_udp(userid)
    if os.path.isfile('/etc/dsvpn/dsvpn0'):
        remove_dsvpn(userid)
    set_lastchange(30)
    #os.execv(__file__, sys.argv)
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        global fake_users_db
        omr_config_data = json.load(f)
        fake_users_db = omr_config_data['users'][0]

class ClienttoClient(BaseModel):
    enable: bool = False

@app.post('/client2client', summary="Enable client 2 client communications")
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
    if initial_md5 != final_md5:
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

class SerialEnforce(BaseModel):
    enable: bool = False

@app.post('/serialenforce', summary="Enable client serial number control")
def serialenforce(*, params: SerialEnforce, current_user: User = Depends(get_current_user)):
    if not current_user.permissions == "admin":
        return {'result': 'permission', 'reason': 'Need admin user', 'route': 'serialenforce'}
    set_global_param('serial_enforce', params.enable)
    return {'result': 'done'}

@app.get('/list_users', summary="List all users")
async def list_users(current_user: User = Depends(get_current_user)):
    if not current_user.permissions == "admin":
        return {'result': 'permission', 'reason': 'Need admin user', 'route': 'list_users'}
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        content = json.load(f)
    return content['users'][0]

@app.get('/speedtest', summary="Test speed from the server")
async def speedtest(current_user: User = Depends(get_current_user)):
    return FileResponse('/usr/share/omr-server/speedtest/test.img')

@app.post('/speedtest', summary="Test upload speed from the server")
async def speedtestul(file: UploadFile, current_user: User = Depends(get_current_user)):
    if not file:
        return {'result': 'No upload file sent'}
    else:
        return {'filename': file.filename}

def main(omrport: int, omrhost: str):
    LOG.debug("Main OMR-Admin launch")
    uvicorn.run(app, host=omrhost, port=omrport, log_level='error', ssl_certfile='/etc/openmptcprouter-vps-admin/cert.pem', ssl_keyfile='/etc/openmptcprouter-vps-admin/key.pem', ssl_version=5)

if __name__ == '__main__':
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        omr_config_data = json.load(f)
    omrport = 65500
    if 'port' in omr_config_data:
        omrport = omr_config_data["port"]
    omrhost = '0.0.0.0'
    if 'host' in omr_config_data:
        omrhost = omr_config_data["host"]
    parser = argparse.ArgumentParser(description="OpenMPTCProuter Server API")
    parser.add_argument("--port", type=int, help="Listening port", default=omrport)
    parser.add_argument("--host", type=str, help="Listening host", default=omrhost)
    args = parser.parse_args()
    main(args.port, args.host)
    #uvicorn.run("__main__:app", host=omrhost, port=omrport, log_level='error', ssl_certfile='/etc/openmptcprouter-vps-admin/cert.pem', ssl_keyfile='/etc/openmptcprouter-vps-admin/key.pem', ssl_version=5, workers=6)

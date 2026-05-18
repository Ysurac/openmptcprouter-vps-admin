#!/usr/bin/env python3
#
# Copyright (C) 2018-2026 Ycarus (Yannick Chabanois) <ycarus@zugaina.org> for OpenMPTCProuter
#
# This is free software, licensed under the GNU General Public License v3.0.
# See /LICENSE for more information.
#

import json
import base64
import secrets
import uuid
import configparser
import ipaddress
import argparse
import subprocess
import os
import platform
#import sys
import glob
import socket
import socket as _socket
from operator import itemgetter
import re
import hashlib
#import pathlib
import shutil
import time
import copy
#from pprint import pprint
from datetime import datetime, timedelta
from tempfile import mkstemp
from typing import List, Optional
from shutil import move
from enum import Enum
from os import path
from ipaddress import ip_address, IPv4Address, IPv6Address
import logging
import asyncio
import contextlib
import uvicorn
import jwt
import requests
from jwt import PyJWTError
from netaddr import *
import psutil
#from netjsonconfig import OpenWrt
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.security import OAuth2PasswordRequestForm, OAuth2
from fastapi.encoders import jsonable_encoder
from fastapi.security.base import SecurityBase
from fastapi.security.utils import get_authorization_scheme_param
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.openapi.utils import get_openapi
from fastapi.openapi.models import SecurityBase as SecurityBaseModel
from fastapi.responses import FileResponse
from pydantic import BaseModel # pylint: disable=E0611
from starlette.status import HTTP_403_FORBIDDEN
from starlette.responses import RedirectResponse, Response, JSONResponse, StreamingResponse
#from starlette.requests import Request
import netifaces

#logging.basicConfig(filename='/tmp/omr-admin.log', encoding='utf-8', level=logging.DEBUG)
LOG = logging.getLogger('api')


logging.basicConfig(level=logging.INFO,
                    format="%(levelname)s: "
                           "%(module)s:%(funcName)s:%(lineno)d - %(message)s")
#LOG = logging.getLogger('OMR-Admin')
LOG = logging.getLogger('uvicorn.error')

PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
ACCESS_TOKEN_EXPIRE_MINUTES = 1440
ALGORITHM = "HS256"

# Get main net interface
IFACE = None
try:
    with open('/etc/shorewall/params.net', "r") as FILE:
        READ = FILE.read()
        for line in READ.splitlines():
            if 'NET_IFACE=' in line:
                IFACE = line.split('=', 1)[1]
except OSError as err:
    LOG.warning("Could not read /etc/shorewall/params.net: %s", err)

# Get ipv6 net interface
IFACE6 = None
try:
    with open('/etc/shorewall6/params.net', "r") as FILE:
        READ = FILE.read()
        for line in READ.splitlines():
            if 'NET_IFACE=' in line:
                IFACE6 = line.split('=', 1)[1]
except OSError as err:
    LOG.warning("Could not read /etc/shorewall6/params.net: %s", err)

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
        #r = requests.get(url="http://127.0.0.1:65279/v1/servers/ss-2022/stats")
        r = requests.get(url="http://127.0.0.1:65279/api/ssm/v1/servers/ss-2022/stats", timeout=5)
    except requests.exceptions.Timeout:
        LOG.debug("Shadowsocks go stats timeout")
        return { 'downlinkBytes': 0, 'uplinkBytes': 0 }
    except requests.exceptions.RequestException as err:
        LOG.debug("Shadowsocks go stats error (" + str(err) + ")")
        return { 'downlinkBytes': 0, 'uplinkBytes': 0 }
    try:
        if 'error' in r.json():
            return { 'downlinkBytes': 0, 'uplinkBytes': 0 }
    except requests.exceptions.JSONDecodeError:
        try:
            r = requests.get(url="http://127.0.0.1:65279/v1/servers/ss-2022/stats", timeout=5)
            #r = requests.get(url="http://127.0.0.1:65279/api/ssm/v1/servers/ss-2022/stats")
        except requests.exceptions.Timeout:
            LOG.debug("Shadowsocks go stats timeout")
            return { 'downlinkBytes': 0, 'uplinkBytes': 0 }
        except requests.exceptions.RequestException as err:
            LOG.debug("Shadowsocks go stats error (" + str(err) + ")")
            return { 'downlinkBytes': 0, 'uplinkBytes': 0 }
    try:
        if 'error' in r.json():
            return { 'downlinkBytes': 0, 'uplinkBytes': 0 }
    except requests.exceptions.JSONDecodeError as err:
        LOG.debug("Shadowsocks go stats error (" + str(err) + ")")
        return { 'downlinkBytes': 0, 'uplinkBytes': 0 }
    if 'users' in r.json():
        for userdata in r.json()['users']:
            if userdata['username'] == user:
                return { 'downlinkBytes': userdata['downlinkBytes'], 'uplinkBytes': userdata['uplinkBytes'] }
    return { 'downlinkBytes': 0, 'uplinkBytes': 0 }

def get_bytes_v2ray(t,user):
    if t == "tx":
        side="downlink"
    else:
        side="uplink"
    stat_name = f"user>>>{user}>>>traffic>>>{side}"
    try:
        data = subprocess.run(
            ["/usr/bin/v2ray", "api", "stats", "--server=127.0.0.1:10085", "-json", stat_name],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return 0
    if data.returncode != 0 or data.stdout.strip() == '':
        return 0
    try:
        payload = json.loads(data.stdout)
    except ValueError:
        return 0
    stats = payload.get('stat', [])
    if not stats:
        return 0
    value = stats[0].get('value')
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def get_bytes_xray(t,user):
    if t == "tx":
        side="downlink"
    else:
        side="uplink"
    stat_name = f"user>>>{user}>>>traffic>>>{side}"
    try:
        data = subprocess.run(
            ["/usr/bin/xray", "api", "stats", "--server=127.0.0.1:10086", "-name", stat_name],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return 0
    if data.returncode != 0 or data.stdout.strip() == '':
        return 0
    try:
        payload = json.loads(data.stdout)
    except ValueError:
        return 0
    stat = payload.get('stat', {})
    value = stat.get('value')
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def get_bytes_softether(user):
    createBytesPayload = {
        "jsonrpc": "2.0",
        "id": "rpc_call_id",
        "method": "GetUser",
        "params": {
            "HubName_str": "OMRVPN",
            "Name_str": user,
        },
    }
    try:
        r = requests.post(url="http://127.0.0.1:65390/api", json=createBytesPayload, headers=softethervpnPassword, verify=False)
    except requests.exceptions.Timeout:
        LOG.debug("SoftEther VPN get bytes timeout")
        return { 'downlinkBytes': 0, 'uplinkBytes': 0 }
    except requests.exceptions.RequestException as err:
        LOG.debug("SoftEther VPN get bytes error (" + str(err) + ")")
        return { 'downlinkBytes': 0, 'uplinkBytes': 0 }
    try:
        if 'error' in r.json():
            return { 'downlinkBytes': 0, 'uplinkBytes': 0 }
    except requests.exceptions.JSONDecodeError as err:
        LOG.debug("Shadowsocks go stats error (" + str(err) + ")")
        return { 'downlinkBytes': 0, 'uplinkBytes': 0 }
    return { 'downlinkBytes': r.json()['result']['Recv.UnicastBytes_u64'], 'uplinkBytes': r.json()['result']['Send.UnicastBytes_u64'] }

def checkIfProcessRunning(processName):
    for proc in psutil.process_iter():
        try:
            if processName.lower() in proc.name().lower():
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False

def file_as_bytes(file):
    with file:
        return file.read()

def read_proc(path):
    """Read a /proc or /sys/fs file and return stripped string, '' on error."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except OSError:
        return ''

def read_omr_config():
    """Read and parse omr-admin-config.json, tolerating trailing commas."""
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        content = f.read()
    content = re.sub(r",\s*}", "}", content)  # pylint: disable=W1401
    try:
        return json.loads(content)
    except ValueError:
        return {}

_OMR_VERSION_CACHE: Optional[str] = None

def get_omr_version():
    """Python equivalent of: grep -s 'OpenMPTCProuter VPS' /etc/* | awk '{print $4}'"""
    global _OMR_VERSION_CACHE
    if _OMR_VERSION_CACHE is not None:
        return _OMR_VERSION_CACHE
    for filepath in glob.glob('/etc/*'):
        if not os.path.isfile(filepath):
            continue
        try:
            with open(filepath, 'r', errors='ignore') as f:
                for line in f:
                    if 'OpenMPTCProuter VPS' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            _OMR_VERSION_CACHE = parts[3]
                            return _OMR_VERSION_CACHE
        except OSError:
            pass
    _OMR_VERSION_CACHE = ''
    return _OMR_VERSION_CACHE

def get_username_from_userid(userid):
    if userid == 0:
        return 'openmptcprouter'
    data = read_omr_config()
    if not data:
        return {'error': 'Config file not readable', 'route': 'get_username'}
    for user in data['users'][0]:
        if 'userid' in data['users'][0][user] and int(data['users'][0][user]['userid']) == userid:
            return user
    return ''

def get_userid_from_username(username):
    if username == 'openmptcprouter':
        return 0
    data = read_omr_config()
    if not data:
        return {'error': 'Config file not readable', 'route': 'get_username'}
    if username not in data['users'][0]:
        return {'error': 'Unknown user', 'route': 'get_username'}
    return int(data['users'][0][username]['userid'])

def check_username_serial(username, serial):
    data = read_omr_config()
    if not data:
        return False
    if 'serial_enforce' not in data or data['serial_enforce'] is False:
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
    data = read_omr_config()
    if not data:
        LOG.debug("Can't read file for set_global_param")
        return {'error': 'Config file not readable', 'route': 'global_param'}
    if not key in data or data[key] != value:
        data[key] = value
        #LOG.debug("backup_config() in set_global_param")
        backup_config()
        with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json', 'w') as outfile:
            json.dump(data, outfile, indent=4)
#    else:
#        LOG.debug("Already exist data for set_global_param key:" + key)

def modif_config_user(user, changes):
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        content = json.load(f)
    content_initial = copy.deepcopy(content)
    content['users'][0][user].update(changes)
    if content_initial != content:
        LOG.debug("backup_config() in modif_config_user")
        backup_config()
        with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json', 'w') as f:
            json.dump(content, f, indent=4)
    else:
        LOG.debug("No real changes in modif_config_user")

def add_ss_user(port, key, userid=0, ip=''):
    try:
        f_ss = open('/etc/shadowsocks-libev/manager.json')
    except FileNotFoundError:
        return port
    with f_ss as f:
        content = f.read()
    content = re.sub(r",\s*}", "}", content) # pylint: disable=W1401
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
    try:
        f_ss = open('/etc/shadowsocks-libev/manager.json')
    except FileNotFoundError:
        return
    with f_ss as f:
        content = f.read()
    content = re.sub(r",\s*}", "}", content) # pylint: disable=W1401
    data = json.loads(content)
    if 'port_key' in data:
        data['port_key'].pop(str(port), None)
    else:
        data['port_conf'].pop(str(port), None)
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
    if not os.path.exists('/etc/shadowsocks-go/server.json'):
        return key
    try:
        r = requests.post(url="http://127.0.0.1:65279/api/ssm/v1/servers/ss-2022/users", json= {'username': user,'uPSK': key})
    except requests.exceptions.Timeout:
        LOG.debug("Shadowsocks go add timeout")
    except requests.exceptions.RequestException as err:
        try:
            r = requests.post(url="http://127.0.0.1:65279/v1/servers/ss-2022/users", json= {'username': user,'uPSK': key})
        except requests.exceptions.Timeout:
            LOG.debug("Shadowsocks go add timeout")
        except requests.exceptions.RequestException as err:
            LOG.debug("Shadowsocks go add error (" + str(err) + ")")
    return key

def remove_ss_go_user(user):
    if not os.path.exists('/etc/shadowsocks-go/server.json'):
        return
    try:
        r = requests.delete(url="http://127.0.0.1:65279/api/ssm/v1/servers/ss-2022/users/" + user)
    except requests.exceptions.Timeout:
        LOG.debug("Shadowsocks go remove timeout")
    except requests.exceptions.RequestException as err:
        try:
            r = requests.delete(url="http://127.0.0.1:65279/v1/servers/ss-2022/users/" + user)
        except requests.exceptions.Timeout:
            LOG.debug("Shadowsocks go remove timeout")
        except requests.exceptions.RequestException as err:
            LOG.debug("Shadowsocks go remove error (" + str(err) + ")")

def add_softether_user(user, password):
    createUserPayload = {
        "jsonrpc": "2.0",
        "id": "rpc_call_id",
        "method": "CreateUser",
        "params": {
            "HubName_str": "OMRVPN",
            "Name_str": user,
            "AuthType_u32": 1,
            "Auth_Password_str": password,
        },
    }
    try:
        r = requests.post(url="http://127.0.0.1:65390/api", json=createUserPayload, headers=softethervpnPassword, verify=False)
    except requests.exceptions.Timeout:
        LOG.debug("SoftEther VPN add timeout")
    except requests.exceptions.RequestException as err:
        LOG.debug("SoftEther VPN remove error (" + str(err) + ")")
    return password

def remove_softether_user(user):
    removeUserPayload = {
        "jsonrpc": "2.0",
        "id": "rpc_call_id",
        "method": "DeleteUser",
        "params": {
            "HubName_str": "OMRVPN",
            "Name_str": user,
        },
    }
    try:
        r = requests.post(url="http://127.0.0.1:65390/api", json=removeUserPayload, headers=softethervpnPassword, verify=False)
    except requests.exceptions.Timeout:
        LOG.debug("SoftEther VPN add timeout")
    except requests.exceptions.RequestException as err:
        LOG.debug("SoftEther VPN remove error (" + str(err) + ")")

def v2ray_add_user(user, v2rayuuid='', restart=1):
    if v2rayuuid == '':
        v2rayuuid = str(uuid.uuid1())
    if not shutil.which('v2ray') and not os.path.isfile('/usr/bin/v2ray'):
        return v2rayuuid
    if not os.path.isfile('/etc/v2ray/v2ray-server.json'):
        return v2rayuuid
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    with open('/etc/v2ray/v2ray-server.json') as f:
        data = json.load(f)
        exist = 0
        for inbounds in data['inbounds']:
            custominbounds = {"inbounds": []}
            if inbounds['tag'] == 'omrin-tunnel':
                inbounds['settings']['clients'].append({'id': v2rayuuid, 'level': 0, 'alterId': 0, 'email': user})
                #os.system("xray api rmi --server=127.0.0.1:65080 omrin-tunnel")
                custominbounds['inbounds'].append(inbounds)
                with open('/etc/v2ray/newconfig.json', 'w') as f:
                    json.dump(custominbounds, f, indent=4)
                #os.system("v2ray api adi --server=127.0.0.1:65080 " + json.dumps(custominbounds))
                subprocess.run(["v2ray", "api", "adi", "--server=127.0.0.1:10085", "/etc/v2ray/newconfig.json"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if inbounds['tag'] == 'omrin-vmess-tunnel':
                inbounds['settings']['clients'].append({'id': v2rayuuid, 'level': 0, 'alterId': 0, 'email': user})
                #os.system("v2ray api rmi --server=127.0.0.1:65080 omrin-vmess-tunnel")
                custominbounds['inbounds'].append(inbounds)
                with open('/etc/v2ray/newconfig.json', 'w') as f:
                    json.dump(custominbounds, f, indent=4)
                #os.system("v2ray api adi --server=127.0.0.1:65080 " + json.dumps(custominbounds))
                subprocess.run(["v2ray", "api", "adi", "--server=127.0.0.1:10085", "/etc/v2ray/newconfig.json"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if inbounds['tag'] == 'omrin-trojan-tunnel':
                inbounds['settings']['clients'].append({'password': v2rayuuid, 'email': user})
                #os.system("v2ray api rmi --server=127.0.0.1:65080 omrin-trojan-tunnel")
                custominbounds['inbounds'].append(inbounds)
                with open('/etc/v2ray/newconfig.json', 'w') as f:
                    json.dump(custominbounds, f, indent=4)
                #os.system("v2ray api adi --server=127.0.0.1:65080 " + json.dumps(custominbounds))
                subprocess.run(["v2ray", "api", "adi", "--server=127.0.0.1:10085", "/etc/v2ray/newconfig.json"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if inbounds['tag'] == 'omrin-socks-tunnel':
                inbounds['settings']['accounts'].append({'pass': v2rayuuid, 'user': user})
                #os.system("v2ray api rmi --server=127.0.0.1:65080 omrin-socks-tunnel")
                custominbounds['inbounds'].append(inbounds)
                with open('/etc/v2ray/newconfig.json', 'w') as f:
                    json.dump(custominbounds, f, indent=4)
                #os.system("v2ray api adi --server=127.0.0.1:65080 " + json.dumps(custominbounds))
                subprocess.run(["v2ray", "api", "adi", "--server=127.0.0.1:10085", "/etc/v2ray/newconfig.json"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    with open('/etc/v2ray/v2ray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        #try:
        #    data = subprocess.check_output('/usr/bin/v2ray api adi --server=127.0.0.1:10085 -users ' + "'" + '{"tag":"omrin-vmess-tunnel","users":[{"user": "' + user + '","key": "' + v2rayuuid + '"}]}' + "'", shell = True)
        #except:
        #    LOG.debug("V2Ray VMESS: Can't add user")
        if restart == 1:
            subprocess.run(["systemctl", "-q", "restart", "v2ray"], check=False)
    return v2rayuuid

def xray_add_user(user,xrayuuid='',ukeyss2022='',restart=1, ip=''):
    if xrayuuid == '':
        xrayuuid = str(uuid.uuid1())
    if ukeyss2022 == '':
        ukeyss2022 = base64.urlsafe_b64encode(secrets.token_hex(16).encode()).decode('utf-8')
    if not shutil.which('xray') and not os.path.isfile('/usr/bin/xray'):
        return xrayuuid
    if not os.path.isfile('/etc/xray/xray-server.json'):
        return xrayuuid
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    with open('/etc/xray/xray-server.json') as f:
        data = json.load(f)
        exist = 0
        for inbounds in data['inbounds']:
            custominbounds = {"inbounds": []}
            if inbounds['tag'] == 'omrin-tunnel':
                inbounds['settings']['clients'].append({'id': xrayuuid, 'level': 0, 'alterId': 0, 'email': user})
                #os.system("xray api rmi --server=127.0.0.1:65080 omrin-tunnel")
                custominbounds['inbounds'].append(inbounds)
                with open('/etc/xray/newconfig.json', 'w') as f:
                    json.dump(custominbounds, f, indent=4)
                #os.system("xray api adi --server=127.0.0.1:65080 " + json.dumps(custominbounds))
                tt = subprocess.run(["/usr/bin/xray", "api", "adi", "--server=127.0.0.1:10086", "/etc/xray/newconfig.json"], check=False).returncode
                LOG.debug(tt)
            if inbounds['tag'] == 'omrin-vmess-tunnel':
                inbounds['settings']['clients'].append({'id': xrayuuid, 'level': 0, 'alterId': 0, 'email': user})
                #os.system("xray api rmi --server=127.0.0.1:65080 omrin-vmess-tunnel")
                custominbounds['inbounds'].append(inbounds)
                with open('/etc/xray/newconfig.json', 'w') as f:
                    json.dump(custominbounds, f, indent=4)
                #os.system("xray api adi --server=127.0.0.1:65080 " + json.dumps(custominbounds))
                tt = subprocess.run(["/usr/bin/xray", "api", "adi", "--server=127.0.0.1:10086", "/etc/xray/newconfig.json"], check=False).returncode
                LOG.debug(tt)
            if inbounds['tag'] == 'omrin-trojan-tunnel':
                inbounds['settings']['clients'].append({'password': xrayuuid, 'email': user})
                #os.system("xray api rmi --server=127.0.0.1:65080 omrin-trojan-tunnel")
                custominbounds['inbounds'].append(inbounds)
                with open('/etc/xray/newconfig.json', 'w') as f:
                    json.dump(custominbounds, f, indent=4)
                #os.system("xray api adi --server=127.0.0.1:65080 " + json.dumps(custominbounds))
                tt = subprocess.run(["/usr/bin/xray", "api", "adi", "--server=127.0.0.1:10086", "/etc/xray/newconfig.json"], check=False).returncode
                LOG.debug(tt)
            if inbounds['tag'] == 'omrin-socks-tunnel':
                inbounds['settings']['accounts'].append({'pass': xrayuuid, 'user': user})
                #os.system("xray api rmi --server=127.0.0.1:65080 omrin-socks-tunnel")
                custominbounds['inbounds'].append(inbounds)
                with open('/etc/xray/newconfig.json', 'w') as f:
                    json.dump(custominbounds, f, indent=4)
                #os.system("xray api adi --server=127.0.0.1:65080 " + json.dumps(custominbounds))
                tt = subprocess.run(["/usr/bin/xray", "api", "adi", "--server=127.0.0.1:10086", "/etc/xray/newconfig.json"], check=False).returncode
                LOG.debug(tt)
            if inbounds['tag'] == 'omrin-shadowsocks-tunnel':
                inbounds['settings']['clients'].append({'password': ukeyss2022, 'email': user})
                #os.system("xray api rmi --server=127.0.0.1:65080 omrin-shadowsocks-tunnel")
                custominbounds['inbounds'].append(inbounds)
                with open('/etc/xray/newconfig.json', 'w') as f:
                    json.dump(custominbounds, f, indent=4)
                #os.system("xray api adi --server=127.0.0.1:65080 " + json.dumps(custominbounds))
                tt = subprocess.run(["/usr/bin/xray", "api", "adi", "--server=127.0.0.1:10086", "/etc/xray/newconfig.json"], check=False).returncode
                LOG.debug(tt)
    with open('/etc/xray/xray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    if ip != '':
        try:
            xray_tag = 'output-' + str(ip)
            xray_add_routing(xray_tag,user,0)
            xray_add_outbound(xray_tag,str(ip),0)
        except Exception as exception:
            pass
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    #if initial_md5 != final_md5 and restart == 1:
    #    subprocess.run(["systemctl", "-q", "restart", "xray"], check=False)
    return xrayuuid

def v2ray_del_user(user, restart=1):
    if not shutil.which('v2ray') and not os.path.isfile('/usr/bin/v2ray'):
        return
    if not os.path.isfile('/etc/v2ray/v2ray-server.json'):
        return
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    with open('/etc/v2ray/v2ray-server.json') as f:
        data = json.load(f)
        for inbounds in data['inbounds']:
            if inbounds['tag'] == 'omrin-tunnel':
                for v2rayuser in list(inbounds['settings']['clients']):
                    if v2rayuser['email'] == user:
                        inbounds['settings']['clients'].remove(v2rayuser)
            if inbounds['tag'] == 'omrin-vmess-tunnel':
                for v2rayuser in list(inbounds['settings']['clients']):
                    if v2rayuser['email'] == user:
                        inbounds['settings']['clients'].remove(v2rayuser)
            if inbounds['tag'] == 'omrin-trojan-tunnel':
                for v2rayuser in list(inbounds['settings']['clients']):
                    if v2rayuser['email'] == user:
                        inbounds['settings']['clients'].remove(v2rayuser)
            if inbounds['tag'] == 'omrin-socks-tunnel':
                for v2rayuser in list(inbounds['settings']['accounts']):
                    if v2rayuser['user'] == user:
                        inbounds['settings']['accounts'].remove(v2rayuser)
    with open('/etc/v2ray/v2ray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5 and restart == 1:
        subprocess.run(["systemctl", "-q", "restart", "v2ray"], check=False)

def xray_del_user(user, restart=1):
    if not shutil.which('xray') and not os.path.isfile('/usr/bin/xray'):
        return
    if not os.path.isfile('/etc/xray/xray-server.json'):
        return
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    with open('/etc/xray/xray-server.json') as f:
        data = json.load(f)
        for inbounds in data['inbounds']:
            custominbounds = {"inbounds": []}
            if inbounds['tag'] == 'omrin-tunnel':
                for xrayuser in list(inbounds['settings']['clients']):
                    if xrayuser['email'] == user:
                        inbounds['settings']['clients'].remove(xrayuser)
                subprocess.run(["/usr/bin/xray", "api", "rmi", "--server=127.0.0.1:10086", "omrin-tunnel"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                custominbounds['inbounds'].append(inbounds)
                with open('/etc/xray/newconfig.json', 'w') as f:
                    json.dump(custominbounds, f, indent=4)
                #os.system("xray api adi --server=127.0.0.1:65080 " + json.dumps(custominbounds))
                subprocess.run(["/usr/bin/xray", "api", "adi", "--server=127.0.0.1:10086", "/etc/xray/newconfig.json"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if inbounds['tag'] == 'omrin-vmess-tunnel':
                for xrayuser in list(inbounds['settings']['clients']):
                    if xrayuser['email'] == user:
                        inbounds['settings']['clients'].remove(xrayuser)
                subprocess.run(["/usr/bin/xray", "api", "rmi", "--server=127.0.0.1:10086", "omrin-vmess-tunnel"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                custominbounds['inbounds'].append(inbounds)
                with open('/etc/xray/newconfig.json', 'w') as f:
                    json.dump(custominbounds, f, indent=4)
                #os.system("xray api adi --server=127.0.0.1:65080 " + json.dumps(custominbounds))
                subprocess.run(["/usr/bin/xray", "api", "adi", "--server=127.0.0.1:10086", "/etc/xray/newconfig.json"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if inbounds['tag'] == 'omrin-trojan-tunnel':
                for xrayuser in list(inbounds['settings']['clients']):
                    if xrayuser['email'] == user:
                        inbounds['settings']['clients'].remove(xrayuser)
                subprocess.run(["/usr/bin/xray", "api", "rmi", "--server=127.0.0.1:10086", "omrin-trojan-tunnel"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                custominbounds['inbounds'].append(inbounds)
                with open('/etc/xray/newconfig.json', 'w') as f:
                    json.dump(custominbounds, f, indent=4)
                #os.system("xray api adi --server=127.0.0.1:65080 " + json.dumps(custominbounds))
                subprocess.run(["/usr/bin/xray", "api", "adi", "--server=127.0.0.1:10086", "/etc/xray/newconfig.json"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if inbounds['tag'] == 'omrin-socks-tunnel':
                for xrayuser in list(inbounds['settings']['accounts']):
                    if xrayuser['user'] == user:
                        inbounds['settings']['accounts'].remove(xrayuser)
                subprocess.run(["/usr/bin/xray", "api", "rmi", "--server=127.0.0.1:10086", "omrin-socks-tunnel"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                custominbounds['inbounds'].append(inbounds)
                with open('/etc/xray/newconfig.json', 'w') as f:
                    json.dump(custominbounds, f, indent=4)
                #os.system("xray api adi --server=127.0.0.1:65080 " + json.dumps(custominbounds))
                subprocess.run(["/usr/bin/xray", "api", "adi", "--server=127.0.0.1:10086", "/etc/xray/newconfig.json"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if inbounds['tag'] == 'omrin-shadowsocks-tunnel':
                for xrayuser in list(inbounds['settings']['clients']):
                    if xrayuser['email'] == user:
                        inbounds['settings']['clients'].remove(xrayuser)
                subprocess.run(["/usr/bin/xray", "api", "rmi", "--server=127.0.0.1:10086", "omrin-shadowsocks-tunnel"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                custominbounds['inbounds'].append(inbounds)
                with open('/etc/xray/newconfig.json', 'w') as f:
                    json.dump(custominbounds, f, indent=4)
                #os.system("xray api adi --server=127.0.0.1:65080 " + json.dumps(custominbounds))
                subprocess.run(["/usr/bin/xray", "api", "adi", "--server=127.0.0.1:10086", "/etc/xray/newconfig.json"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    with open('/etc/xray/xray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    #if initial_md5 != final_md5 and restart == 1:
    #    subprocess.run(["systemctl", "-q", "restart", "xray"], check=False)

def v2ray_add_outbound(tag,ip, restart=1):
    if not os.path.isfile('/etc/v2ray/v2ray-server.json'):
        return
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    with open('/etc/v2ray/v2ray-server.json') as f:
        data = json.load(f)
        data['outbounds'].append({'protocol': 'freedom', 'settings': { 'userLevel': 0 }, 'tag': tag, 'sendThrough': ip})
    with open('/etc/v2ray/v2ray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5 and restart == 1:
        subprocess.run(["systemctl", "-q", "restart", "v2ray"], check=False)

def xray_add_outbound(tag,ip, restart=1):
    if not os.path.isfile('/etc/xray/xray-server.json'):
        return
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    with open('/etc/xray/xray-server.json') as f:
        data = json.load(f)
        data['outbounds'].append({'protocol': 'freedom', 'settings': { 'userLevel': 0 }, 'tag': tag, 'sendThrough': ip})
    with open('/etc/xray/xray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5 and restart == 1:
        subprocess.run(["systemctl", "-q", "restart", "xray"], check=False)

def v2ray_del_outbound(tag, restart=1):
    if not os.path.isfile('/etc/v2ray/v2ray-server.json'):
        return
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    with open('/etc/v2ray/v2ray-server.json') as f:
        data = json.load(f)
        for outbounds in list(data['outbounds']):
            if outbounds['tag'] == tag:
                data['outbounds'].remove(outbounds)
    with open('/etc/v2ray/v2ray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5 and restart == 1:
        subprocess.run(["systemctl", "-q", "restart", "v2ray"], check=False)

def xray_del_outbound(tag, restart=1):
    if not os.path.isfile('/etc/xray/xray-server.json'):
        return
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    with open('/etc/xray/xray-server.json') as f:
        data = json.load(f)
        for outbounds in list(data['outbounds']):
            if outbounds['tag'] == tag:
                data['outbounds'].remove(outbounds)
    with open('/etc/xray/xray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5 and restart == 1:
        subprocess.run(["systemctl", "-q", "restart", "xray"], check=False)

def v2ray_add_routing(tag, user, restart=1):
    if not os.path.isfile('/etc/v2ray/v2ray-server.json'):
        return
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    with open('/etc/v2ray/v2ray-server.json') as f:
        data = json.load(f)
        if user == "":
                data['routing']['rules'].append({'type': 'field', 'inboundTag': ( 'omrin-tunnel' ), 'outboundTag': tag})
        else:
                data['routing']['rules'].append({'type': 'field', 'inboundTag': ( 'omrin-tunnel' ), 'user': ( user ), 'outboundTag': tag})

    with open('/etc/v2ray/v2ray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5 and restart == 1:
        subprocess.run(["systemctl", "-q", "restart", "v2ray"], check=False)

def xray_add_routing(tag, user, restart=1):
    if not os.path.isfile('/etc/xray/xray-server.json'):
        return
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    with open('/etc/xray/xray-server.json') as f:
        data = json.load(f)
        if user == "":
                data['routing']['rules'].insert(0,{'type': 'field', 'inboundTag': ( 'omrin-tunnel' ), 'outboundTag': tag})
        else:
                data['routing']['rules'].insert(0,{'type': 'field', 'inboundTag': ( 'omrin-tunnel' ), 'user': ( user ), 'outboundTag': tag})
    with open('/etc/xray/xray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5 and restart == 1:
        subprocess.run(["systemctl", "-q", "restart", "xray"], check=False)

def v2ray_del_routing(tag, restart=1):
    if not os.path.isfile('/etc/v2ray/v2ray-server.json'):
        return
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    with open('/etc/v2ray/v2ray-server.json') as f:
        data = json.load(f)
        for rules in list(data['routing']['rules']):
            if rules['outboundTag'] == tag:
                data['routing']['rules'].remove(rules)
    with open('/etc/v2ray/v2ray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5 and restart == 1:
        subprocess.run(["systemctl", "-q", "restart", "v2ray"], check=False)

def xray_del_routing(tag, restart=1):
    if not os.path.isfile('/etc/xray/xray-server.json'):
        return
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    with open('/etc/xray/xray-server.json') as f:
        data = json.load(f)
        for rules in list(data['routing']['rules']):
            if rules['outboundTag'] == tag:
                data['routing']['rules'].remove(rules)
    with open('/etc/xray/xray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5 and restart == 1:
        subprocess.run(["systemctl", "-q", "restart", "xray"], check=False)


def add_gre_tunnels(addtouser = 'openmptcprouter', addwithip = ''):
    LOG.debug("Add gre-tunnels now...")
    nbip = 0
    allips = []
    for intf in netifaces.interfaces():
        addrs = netifaces.ifaddresses(intf)
        try:
            ipv4_addr_list = addrs[netifaces.AF_INET]
            for ip_info in ipv4_addr_list:
                addr = ip_info['addr']
                #LOG.debug("Check if " + str(addr) + " is not IPv4 or reserved")
                if not IPAddress(addr).is_link_local() and not IPAddress(addr).is_reserved() and not IPAddress(addr).is_private():
                    allips.append(addr)
                    nbip = nbip + 1
        except Exception as exception:
            #LOG.debug("There is an exception in add_gre_tunnels")
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
                    if not IPAddress(addr).is_private() and not IPAddress(addr).is_reserved() and not IPAddress(addr).is_link_local():
                        netmask = ip_info['netmask']
                        ip = IPNetwork('10.255.249.0/24')
                        with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
                            content = json.load(f)
                        for user in content['users'][0]:
                            if user != "admin" and ((user == addtouser and str(ip) == addwithip) or user == 'openmptcprouter'):
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
                                if not os.path.isfile('/etc/openmptcprouter-vps-admin/intf/' + gre_intf):
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
                                user_gre_tunnels[gre_intf] = {'local_ip': str(list(network)[1]), 'remote_ip': str(list(network)[2]), 'public_ip': str(addr)}
                                if os.path.isfile('/etc/shadowsocks-libev/manager.json') and not 'shadowsocks_port' in user_gre_tunnels[gre_intf]:
                                    with open('/etc/shadowsocks-libev/manager.json') as g:
                                        contentss = g.read()
                                    contentss = re.sub(r",\s*}", "}", contentss) # pylint: disable=W1401
                                    datass = json.loads(contentss)
                                    makechange = True
                                    shadowsocks_port = 65101
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
                                        shadowsocks_port = str(add_ss_user('', ss_key, userid, str(addr))) # pylint: disable=E0606
                                        user_gre_tunnels[gre_intf].update({'shadowsocks_port': shadowsocks_port})
                                        #user_gre_tunnels[gre_intf] = {'local_ip': str(list(network)[1]), 'remote_ip': str(list(network)[2]), 'public_ip': str(addr)}
                                        #modif_config_user(user, {'gre_tunnels': user_gre_tunnels})
                                if os.path.isfile('/etc/xray/xray-server.json') and not 'xray' in user_gre_tunnels[gre_intf]:
                                    try:
                                        xray_user = str(username) + gre_intf
                                        xrayuuid = str(uuid.uuid1())
                                        ukeyss2022 = base64.urlsafe_b64encode(secrets.token_hex(16).encode()).decode('utf-8')
                                        LOG.debug("Delete XRay user...")
                                        xray_del_user(xray_user)
                                        LOG.debug("Create XRay user...")
                                        xray_add_user(xray_user,xrayuuid,ukeyss2022)
                                        xray_tag = 'output-' + str(addr)
                                        LOG.debug("Delete XRay routing...")
                                        xray_del_routing(xray_tag)
                                        LOG.debug("Add XRay routing...")
                                        xray_add_routing(xray_tag,xray_user,0)
                                        LOG.debug("Delete XRay outbound...")
                                        xray_del_outbound(xray_tag)
                                        LOG.debug("Add XRay outbound...")
                                        xray_add_outbound(xray_tag,str(addr),0)
                                        if gre_intf not in user_gre_tunnels:
                                            user_gre_tunnels[gre_intf] = {}
                                        LOG.debug("Prepare json XRay outbound...")
                                        user_gre_tunnels[gre_intf].update({'xray': {'uuid': xrayuuid,'ss2022': ukeyss2022}})
                                    except Exception as exception:
                                        pass
                                modif_config_user(user, {'gre_tunnels': user_gre_tunnels})
                        nbip = nbip + 1
            except Exception as exception:
                pass
        final_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall/snat', 'rb'))).hexdigest()
        if initial_md5 != final_md5:
            subprocess.run(["systemctl", "-q", "reload", "shorewall"], check=False)
            if os.path.isfile('/etc/shadowsocks-libev/manager.json'):
                subprocess.run(["systemctl", "-q", "restart", "shadowsocks-libev-manager@manager"], check=False)
    set_global_param('allips', allips)

def add_glorytun_tcp(userid):
    if not os.path.isfile('/etc/glorytun-tcp/tun0'):
        return
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
    subprocess.run(["systemctl", "-q", "enable", f"glorytun-tcp@tun{userid}"], check=False)
    subprocess.run(["systemctl", "-q", "restart", f"glorytun-tcp@tun{userid}"], check=False)

def remove_glorytun_tcp(userid):
    if not os.path.isfile('/etc/glorytun-tcp/tun' + str(userid) + '.key'):
        return
    subprocess.run(["systemctl", "-q", "disable", f"glorytun-tcp@tun{userid}"], check=False)
    subprocess.run(["systemctl", "-q", "stop", f"glorytun-tcp@tun{userid}"], check=False)
    os.remove('/etc/glorytun-tcp/tun' + str(userid) + '.key')

def add_glorytun_udp(userid):
    if not os.path.isfile('/etc/glorytun-udp/tun0'):
        return
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
    subprocess.run(["systemctl", "-q", "enable", f"glorytun-udp@tun{userid}"], check=False)
    subprocess.run(["systemctl", "-q", "restart", f"glorytun-udp@tun{userid}"], check=False)

def remove_glorytun_udp(userid):
    if not os.path.isfile('/etc/glorytun-udp/tun' + str(userid) + '.key'):
        return
    subprocess.run(["systemctl", "-q", "disable", f"glorytun-udp@tun{userid}"], check=False)
    subprocess.run(["systemctl", "-q", "stop", f"glorytun-udp@tun{userid}"], check=False)
    os.remove('/etc/glorytun-udp/tun' + str(userid) + '.key')
    os.remove('/etc/glorytun-udp/tun' + str(userid))


def add_dsvpn(userid):
    if not os.path.isfile('/etc/dsvpn/dsvpn0'):
        return
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
    subprocess.run(["systemctl", "-q", "restart", f"dsvpn-server@dsvpn{userid}"], check=False)
    subprocess.run(["systemctl", "-q", "enable", f"dsvpn-server@dsvpn{userid}"], check=False)
def remove_dsvpn(userid):
    if not os.path.isfile('/etc/dsvpn/dsvpn' + str(userid)):
        return
    subprocess.run(["systemctl", "-q", "disable", f"dsvpn-server@dsvpn{userid}"], check=False)
    subprocess.run(["systemctl", "-q", "stop", f"dsvpn-server@dsvpn{userid}"], check=False)
    os.remove('/etc/dsvpn/dsvpn' + str(userid))
    os.remove('/etc/dsvpn/dsvpn' + str(userid) + '.key')

def add_mqvpn(username, fixed_ip=None):
    mqvpn_user_key = secrets.token_urlsafe(32)
    mqvpn_api({'cmd': 'add_user', 'name': username, 'key': mqvpn_user_key})
    try:
        with open('/etc/mqvpn/server.json') as f:
            mqvpn_config = json.load(f)
        users = mqvpn_config.get('users', [])
        if not any(u.get('name') == username for u in users):
            entry = {'name': username, 'key': mqvpn_user_key}
            if fixed_ip:
                entry['fixed_ip'] = fixed_ip
            users.append(entry)
            mqvpn_config['users'] = users
        with open('/etc/mqvpn/server.json', 'w') as f:
            json.dump(mqvpn_config, f, indent=2)
    except Exception as e:
        LOG.debug("MQVPN add user json error (" + str(e) + ")")

def remove_mqvpn(username):
    mqvpn_api({'cmd': 'remove_user', 'name': username})
    try:
        with open('/etc/mqvpn/server.json') as f:
            mqvpn_config = json.load(f)
        mqvpn_config['users'] = [u for u in mqvpn_config.get('users', []) if u.get('name') != username]
        with open('/etc/mqvpn/server.json', 'w') as f:
            json.dump(mqvpn_config, f, indent=2)
    except Exception as e:
        LOG.debug("MQVPN remove user json error (" + str(e) + ")")


def ordered(obj):
    if isinstance(obj, dict):
        return sorted((k, ordered(v)) for k, v in obj.items())
    if isinstance(obj, list):
        return sorted(ordered(x) for x in obj)
    else:
        return obj

def v2ray_add_port(user, port, proto, name, destip, destport):
    if not os.path.isfile('/etc/v2ray/v2ray-server.json'):
        return
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
        subprocess.run(["systemctl", "-q", "restart", "v2ray"], check=False)

def xray_add_port(user, port, proto, name, destip, destport):
    if not os.path.isfile('/etc/xray/xray-server.json'):
        return
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
        subprocess.run(["systemctl", "-q", "restart", "xray"], check=False)


def v2ray_del_port(user, port, proto, name, destip, destport):
    if not os.path.isfile('/etc/v2ray/v2ray-server.json'):
        return
    userid = user.userid
    if userid is None:
        userid = 0
    tag = user.username + '_redir_' + proto + '_' + str(port)
    if destip != '':
        tag = tag + '_to_' + destip + ':' + str(destport)
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    with open('/etc/v2ray/v2ray-server.json') as f:
        data = json.load(f)
        for inbounds in list(data['inbounds']):
            if inbounds['tag'] == tag:
                data['inbounds'].remove(inbounds)
        for routing in list(data['routing']['rules']):
            if routing['inboundTag'][0] == tag:
                data['routing']['rules'].remove(routing)
    with open('/etc/v2ray/v2ray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/v2ray/v2ray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        subprocess.run(["systemctl", "-q", "restart", "v2ray"], check=False)

def xray_del_port(user, port, proto, name, destip, destport):
    if not os.path.isfile('/etc/xray/xray-server.json'):
        return
    userid = user.userid
    if userid is None:
        userid = 0
    tag = user.username + '_redir_' + proto + '_' + str(port)
    if destip != '':
        tag = tag + '_to_' + destip + ':' + str(destport)
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    with open('/etc/xray/xray-server.json') as f:
        data = json.load(f)
        for inbounds in list(data['inbounds']):
            if inbounds['tag'] == tag:
                data['inbounds'].remove(inbounds)
        for routing in list(data['routing']['rules']):
            if routing['inboundTag'][0] == tag:
                data['routing']['rules'].remove(routing)
    with open('/etc/xray/xray-server.json', 'w') as f:
        json.dump(data, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/xray/xray-server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        subprocess.run(["systemctl", "-q", "restart", "xray"], check=False)

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
        subprocess.run(["systemctl", "-q", "reload", "shorewall"], check=False)

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
        subprocess.run(["systemctl", "-q", "reload", "shorewall"], check=False)

def shorewall6_add_port(user, port, proto, name, fwtype='ACCEPT', source_dip='', dest_ip='', vpn='default', gencomment=''):
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
        subprocess.run(["systemctl", "-q", "reload", "shorewall6"], check=False)

def shorewall6_del_port(username, port, proto, name, fwtype='ACCEPT', source_dip='', dest_ip='', gencomment=''):
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall6/rules', 'rb'))).hexdigest()
    fd, tmpfile = mkstemp()
    with open('/etc/shorewall6/rules', 'r') as f, open(tmpfile, 'a+') as n:
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
    move(tmpfile, '/etc/shorewall6/rules')
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall6/rules', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        subprocess.run(["systemctl", "-q", "reload", "shorewall6"], check=False)

def set_lastchange(sync=0):
    configdata = read_omr_config()
    if not configdata:
        return {'error': 'Config file not readable', 'route': 'lastchange'}
    data = copy.deepcopy(configdata)
    data["lastchange"] = time.time() + sync
    if data and data != configdata:
        LOG.debug("backup_config() in set_last_change")
        backup_config()
        with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json', 'w') as outfile:
            json.dump(data, outfile, indent=4)
    else:
        LOG.debug("Empty data for set_last_change")


with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
    omr_config_data = json.load(f)
if 'debug' in omr_config_data and omr_config_data['debug']:
    LOG.setLevel(logging.DEBUG)
if 'gre_tunnels' in omr_config_data and omr_config_data['gre_tunnels']:
    LOG.debug("Add GRE tunnels")
    add_gre_tunnels()

fake_users_db = omr_config_data['users'][0]

# Generate a random secret key
if 'secret_key' in omr_config_data:
    SECRET_KEY = omr_config_data['secret_key']
else:
    SECRET_KEY = uuid.uuid4().hex
    set_global_param('secret_key',SECRET_KEY)

softethervpnPassword = {}
if 'softethervpn_admin_password' in omr_config_data:
    softethervpnPassword = { "X-VPNADMIN-PASSWORD": omr_config_data['softethervpn_admin_password'] }


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
    disabled: bool = False
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

        if not authorization or scheme.lower() != "bearer": # pylint: disable=E0606
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN, detail="Not authenticated"
                )
            else:
                return None
        return param # pylint: disable=E0606

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
                raise HTTPException(
                    status_code=401,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Basic"},
                )
        return param

basic_auth = BasicAuth(auto_error=False)


oauth2_scheme = OAuth2PasswordBearerCookie(tokenUrl="/token")

@contextlib.asynccontextmanager
async def _lifespan(app):
    sync_ss_go_users()
    yield


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, title="OpenMPTCProuter Server API", lifespan=_lifespan)


def sync_ss_go_users():
    if not os.path.isfile('/etc/shadowsocks-go/upsks.json'):
        return
    try:
        with open('/etc/shadowsocks-go/upsks.json') as f:
            upsks = json.load(f)
    except Exception as e:
        LOG.debug("sync_ss_go_users: failed to read upsks.json: " + str(e))
        return

    xray_users = set()
    if os.path.isfile('/etc/xray/xray-server.json'):
        try:
            with open('/etc/xray/xray-server.json') as f:
                xray_data = json.load(f)
            for inbound in xray_data.get('inbounds', []):
                settings = inbound.get('settings', {})
                for client in settings.get('clients', []):
                    if 'email' in client:
                        xray_users.add(client['email'])
                for account in settings.get('accounts', []):
                    if 'user' in account:
                        xray_users.add(account['user'])
        except Exception as e:
            LOG.debug("sync_ss_go_users: failed to read xray config: " + str(e))

    mqvpn_users = set()
    if os.path.isfile('/etc/mqvpn/server.json'):
        try:
            with open('/etc/mqvpn/server.json') as f:
                mqvpn_data = json.load(f)
            for u in mqvpn_data.get('users', []):
                if 'name' in u:
                    mqvpn_users.add(u['name'])
        except Exception as e:
            LOG.debug("sync_ss_go_users: failed to read mqvpn config: " + str(e))

    for username, upsk in upsks.items():
        if os.path.isfile('/etc/xray/xray-server.json') and username not in xray_users:
            LOG.info("sync_ss_go_users: adding %s to xray", username)
            xray_add_user(username, '', upsk)
        if os.path.isfile('/etc/mqvpn/server.json') and username not in mqvpn_users:
            LOG.info("sync_ss_go_users: adding %s to mqvpn", username)
            add_mqvpn(username)


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
        LOG.debug("PyJWTError")
        raise credentials_exception
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        omr_config_data = json.load(f)
    fake_users_db = omr_config_data['users'][0]
    LOG.debug('token user: ' + token_data.username)
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        LOG.debug("user is none")
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
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        omr_config_data = json.load(f)
    fake_users_db = omr_config_data['users'][0]

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
async def login_basic(request: Request, auth: BasicAuth = Depends(basic_auth)):
    if not auth:
        response = Response(headers={"WWW-Authenticate": "Basic"}, status_code=401)
        return response

    try:
        decoded = base64.b64decode(auth).decode("ascii")
        username, _, password = decoded.partition(":")
        with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
            omr_config_data = json.load(f)
            fake_users_db = omr_config_data['users'][0]

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
            secure=(request.url.scheme == "https"),
            samesite="lax",
        )
        return response

    except Exception:
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
async def clienthost(request: Request):
    client_host = request.client.host
    return {"client_host": client_host}

# Check if MPTCP is enabled on this connection
@app.get('/mptcpsupport')
async def mptcpsupport(request: Request):
    ip = request.client.host
    try:
        ip_address(ip)
    except ValueError:
        return {"mptcp": "check only support IPv4"}
    if type(ip_address(ip)) is IPv6Address:
        mapped = ip_address(ip).ipv4_mapped
        if mapped is None:
            return {"mptcp": "check only support IPv4"}
        ip = str(mapped)
    if type(ip_address(ip)) is IPv4Address:
        ipr = list(reversed(ip.split('.')))
        iptohex = '{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ipr))
        if path.exists('/proc/net/mptcp_net/mptcp'):
            with open('/proc/net/mptcp_net/mptcp') as f:
                if iptohex in f.read():
                    return {"mptcp": "working"}
        else:
            try:
                mptcpcheck = subprocess.Popen(["ss", "-M"], stdout=subprocess.PIPE)
                ss_output, _ = mptcpcheck.communicate(timeout=2)
                if ip.encode() in ss_output:
                    return {"mptcp": "working"}
            except subprocess.TimeoutExpired:
                mptcpcheck.kill()
        return {"mptcp": "not working"}
    return {"mptcp": "check only support IPv4"}

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
    vps_loadavg = ' '.join(read_proc('/proc/loadavg').split()[:3])
    vps_cpu_count = os.cpu_count()
    vps_memory = psutil.virtual_memory()
    vps_memory_total = vps_memory.total
    vps_memory_available = vps_memory.available
    vps_memory_percent = vps_memory.percent
    vps_memory_used = vps_memory.used
    vps_memory_free = vps_memory.free
    vps_disk = psutil.disk_usage('/')
    vps_disk_total = vps_disk.total
    vps_disk_used = vps_disk.used
    vps_disk_free = vps_disk.free
    vps_disk_percent = vps_disk.percent
    try:
        vps_cpu_freq = psutil.cpu_freq().current
    except Exception:
        vps_cpu_freq = None
    vps_cpu_model = ''
    with open('/proc/cpuinfo', 'r') as _f:
        for _line in _f:
            if _line.startswith('model name'):
                vps_cpu_model = _line.split(':', 1)[1].strip()
                break
    vps_uptime = read_proc('/proc/uptime').split()[0]
    vps_hostname = socket.gethostname()
    vps_current_time = time.time()
    vps_kernel = platform.uname().release
    vps_omr_version = get_omr_version()
    mptcp_enabled = "0"
    if path.exists("/proc/sys/net/mptcp/mptcp_enabled"):
        mptcp_enabled = read_proc('/proc/sys/net/mptcp/mptcp_enabled')
    elif path.exists("/proc/sys/net/mptcp/enabled"):
        mptcp_enabled = read_proc('/proc/sys/net/mptcp/enabled')
    omr_config_data = read_omr_config()
    user_config = omr_config_data['users'][0][username]
    proxy = 'shadowsocks'
    if 'proxy' in user_config:
        proxy = user_config['proxy']
    shadowsocks_port = user_config.get('shadowsocks_port')
    if not shadowsocks_port == None and proxy == 'shadowsocks':
        ss_traffic = get_bytes_ss(shadowsocks_port)
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
    elif vpn == 'mqvpn':
        vpn_traffic_rx = get_bytes('rx', 'mqvpn' + str(userid))
        vpn_traffic_tx = get_bytes('tx', 'mqvpn' + str(userid))
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
    elif vpn == 'softether':
        vpn_txrx = get_bytes_softether(username)
        vpn_traffic_rx = vpn_txrx['uplinkBytes']
        vpn_traffic_tx = vpn_txrx['downlinkBytes']

    LOG.debug('Get status: done')
    if IFACE:
        return {'vps': {'time': vps_current_time, 'loadavg': vps_loadavg,'cpu_model': vps_cpu_model, 'cpu_count': vps_cpu_count, 'memory_total': vps_memory_total, 'memory_available': vps_memory_available, 'memory_percent': vps_memory_percent, 'memory_used': vps_memory_used, 'memory_free': vps_memory_free,'disk_total': vps_disk_total, 'disk_used': vps_disk_used, 'disk_free': vps_disk_free, 'disk_percent': vps_disk_percent, 'cpu_freq': vps_cpu_freq, 'uptime': vps_uptime, 'mptcp': mptcp_enabled, 'hostname': vps_hostname, 'kernel': vps_kernel, 'omr_version': vps_omr_version}, 'network': {'tx': get_bytes('tx', IFACE), 'rx': get_bytes('rx', IFACE)}, 'shadowsocks': {'traffic': ss_traffic}, 'vpn': {'tx': vpn_traffic_tx, 'rx': vpn_traffic_rx}, 'v2ray': {'tx': v2ray_tx, 'rx': v2ray_rx},'xray': {'tx': xray_tx, 'rx': xray_rx},'shadowsocks_go': {'tx': ss_go_tx, 'rx': ss_go_rx}}
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
    omr_config_data = read_omr_config()
    user_config = omr_config_data['users'][0][username]
    LOG.debug('Get config... shadowsocks')
    proxy = 'shadowsocks'
    if 'proxy' in user_config:
        proxy = user_config['proxy']

    if os.path.isfile('/etc/shadowsocks-libev/manager.json'):
        with open('/etc/shadowsocks-libev/manager.json') as f:
            content = f.read()
        content = re.sub(r",\s*}", "}", content) # pylint: disable=W1401
        try:
            data = json.loads(content)
        except ValueError as e:
            data = {'server_port': 65101, 'method': 'chacha20'}
    else:
        data = {'server_port': 65101, 'method': 'chacha20'}
    #shadowsocks_port = data["server_port"]
    shadowsocks_port = user_config.get('shadowsocks_port')
    shadowsocks_key = ''
    if shadowsocks_port is not None:
        if 'port_key' in data:
            shadowsocks_key = data["port_key"][str(shadowsocks_port)]
        elif 'port_conf' in data:
            shadowsocks_key = data["port_conf"][str(shadowsocks_port)]["key"]
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
    shadowsocks_port = user_config.get('shadowsocks_port')
    if not shadowsocks_port == None and proxy == 'shadowsocks':
        ss_traffic = get_bytes_ss(shadowsocks_port)
    else:
        ss_traffic = 0

    LOG.debug('Get config... glorytun')
    if os.path.isfile('/etc/glorytun-tcp/tun' + str(userid) +'.key'):
        glorytun_key = open('/etc/glorytun-tcp/tun' + str(userid) + '.key').readline().rstrip()
    elif os.path.isfile('/etc/glorytun-udp/tun' + str(userid) +'.key'):
        glorytun_key = open('/etc/glorytun-udp/tun' + str(userid) + '.key').readline().rstrip()
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
    if not os.path.isfile('/etc/openvpn/ca/pki/private/' + username + '.key') or not os.path.isfile('/etc/openvpn/ca/pki/issued/' + username + '.crt'):
        if os.path.isfile('/etc/openvpn/tun0.conf'):
            LOG.debug("OpenVPN cert missing for %s, creating it", username)
            index_file = '/etc/openvpn/ca/pki/index.txt'
            if os.path.isfile(index_file):
                with open(index_file, 'r') as f:
                    lines = f.readlines()
                filtered = [l for l in lines if '/CN=' + username not in l]
                if len(filtered) != len(lines):
                    LOG.debug("Removing stale PKI index entry for %s", username)
                    with open(index_file, 'w') as f:
                        f.writelines(filtered)
            for stale in [
                f"/etc/openvpn/ca/pki/reqs/{username}.req",
                f"/etc/openvpn/ca/pki/private/{username}.key",
                f"/etc/openvpn/ca/pki/issued/{username}.crt",
            ]:
                if os.path.isfile(stale):
                    os.remove(stale)
            env = os.environ.copy()
            env['EASYRSA_CERT_EXPIRE'] = '3650'
            result = subprocess.run(["./easyrsa", "--batch", "build-client-full", username, "nopass"], cwd="/etc/openvpn/ca", env=env, capture_output=True, check=False)
            if result.returncode != 0:
                LOG.error("easyrsa failed for %s: %s", username, result.stderr.decode())
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

    softether = False
    if os.path.isfile('/var/lib/softether/vpn_server.config'):
        available_vpn.append("softether")
        softether = True
    softether_password = ''
    if 'softethervpn' in omr_config_data['users'][0][username]:
        softethervpn_config = omr_config_data['users'][0][username]['softethervpn']
        if isinstance(softethervpn_config, dict):
            softether_password = softethervpn_config.get('password', '')
        else:
            softether_password = softethervpn_config
    softether_port = '65390'
    softether_cipher = 'AES-256-GCM'
    softether_host_ip = '10.255.210.1'
    softether_client_ip = 'dhcp'

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

    LOG.debug('Get config... mqvpn')
    if os.path.isfile('/etc/mqvpn/server.json'):
        with open('/etc/mqvpn/server.json') as _f:
            try:
                mqvpn_cfg = json.load(_f)
            except json.JSONDecodeError:
                mqvpn_cfg = {}
        mqvpn_users = mqvpn_cfg.get('users', [])
        mqvpn_user_entry = next((u for u in mqvpn_users if u.get('name') == username), None)
        mqvpn_key = mqvpn_user_entry['key'] if mqvpn_user_entry else ''
        mqvpn_fixed_ip = mqvpn_user_entry.get('fixed_ip', '') if mqvpn_user_entry else ''
        mqvpn_scheduler = mqvpn_cfg.get('scheduler', 'wlb')
        mqvpn_listen = mqvpn_cfg.get('listen', '0.0.0.0:443')
        mqvpn_port = mqvpn_listen.split(':')[-1] if ':' in mqvpn_listen else '443'
        mqvpn_fec_enable = mqvpn_cfg.get('fec_enable', False)
        mqvpn_fec_scheme = mqvpn_cfg.get('fec_scheme', 'xor')
        mqvpn_reinjection_control = mqvpn_cfg.get('reinjection_control', False)
        mqvpn_reinjection_mode = mqvpn_cfg.get('reinjection_mode', 'default')
        mqvpn_cc = mqvpn_cfg.get('cc', 'bbr2')
        mqvpn_subnet = mqvpn_cfg.get('subnet', '10.255.220.0/24')
        mqvpn_net = ipaddress.ip_network(mqvpn_subnet, strict=False)
        mqvpn_hosts = list(mqvpn_net.hosts())
        mqvpn_host_ip = str(mqvpn_hosts[0]) if mqvpn_hosts else '10.255.220.1'
        mqvpn_client_ip = mqvpn_fixed_ip if mqvpn_fixed_ip else (str(mqvpn_hosts[1]) if len(mqvpn_hosts) > 1 else '10.255.220.2')
        available_vpn.append("mqvpn")
    else:
        mqvpn_key = ''
        mqvpn_fixed_ip = ''
        mqvpn_scheduler = ''
        mqvpn_port = ''
        mqvpn_fec_enable = False
        mqvpn_fec_scheme = ''
        mqvpn_reinjection_control = False
        mqvpn_reinjection_mode = ''
        mqvpn_cc = ''
        mqvpn_host_ip = '10.255.220.1'
        mqvpn_client_ip = '10.255.220.2'

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

    LOG.debug("Gre tunnels... ?")
    LOG.debug(omr_config_data['users'][0][username])
    if 'gre_tunnels' in omr_config_data['users'][0][username]:
    #if 'gre_tunnels' in current_user:
        LOG.debug("Gre tunnels...")
        gre_tunnel = True
        gre_tunnel_conf = omr_config_data['users'][0][username]['gre_tunnels']
        #gre_tunnel_conf = current_user.gre_tunnels

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
            with open('/etc/v2ray/v2ray-server.json') as _f:
                _v2 = json.load(_f)
            v2ray_key = next((c.get('id', '') for c in _v2['inbounds'][0].get('settings', {}).get('clients', []) if c.get('email') == username), '')
            v2ray_port = str(_v2['inbounds'][0].get('port', ''))
            v2ray_conf = { 'key': v2ray_key, 'port': v2ray_port}
            LOG.debug("modif_config_user for v2ray")
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
            with open('/etc/xray/xray-server.json') as _f:
                _xr = json.load(_f)
            xray_key = next((c.get('id', '') for c in _xr['inbounds'][0].get('settings', {}).get('clients', []) if c.get('email') == username), '')
            xray_port = str(_xr['inbounds'][0].get('port', ''))
            xray_ss_skey = xray_ss_ukey = xray_ss_method = ''
            xray_transport = _xr['inbounds'][0].get('streamSettings', {}).get('network', 'tcp')
            for _ib in _xr['inbounds']:
                if _ib.get('tag') == 'omrin-shadowsocks-tunnel':
                    xray_ss_skey = _ib.get('settings', {}).get('password', '')
                    xray_ss_method = _ib.get('settings', {}).get('method', '')
                    xray_ss_ukey = next((c.get('password', '') for c in _ib.get('settings', {}).get('clients', []) if c.get('email') == username), '')
            xray_ss_key = xray_ss_skey + ':' + xray_ss_ukey
            xray_vless_reality_public_key = ''
            if os.path.isfile('/etc/xray/xray-vless-reality.json'):
                with open('/etc/xray/xray-vless-reality.json') as _f:
                    _vr = json.load(_f)
                xray_vless_reality_public_key = next((ib.get('streamSettings', {}).get('realitySettings', {}).get('publicKey', '') for ib in _vr['inbounds'] if ib.get('tag') == 'omrin-vless-reality'), '')
            vless_reality = any(ib.get('tag') == 'omrin-vless-reality' for ib in _xr['inbounds'])
            xray_conf = { 'key': xray_key, 'port': xray_port, 'sskey': xray_ss_key, 'vless_reality': vless_reality, 'vless_reality_key': xray_vless_reality_public_key, 'ss_method': xray_ss_method, 'transport': xray_transport }
            LOG.debug("modif_config_user for xray")
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
            with open('/etc/shadowsocks-go/server.json') as _f:
                _sg = json.load(_f)
            _srv = next((s for s in _sg.get('servers', []) if s.get('name') == 'ss-2022'), {})
            shadowsocks_go_psk = _srv.get('psk', '')
            _listeners = _srv.get('tcpListeners', [{}])
            shadowsocks_go_port = _listeners[0].get('address', ':').rsplit(':', 1)[-1] if _listeners else ''
            shadowsocks_go_protocol = _srv.get('protocol', '')
            shadowsocks_go_upsk = ''
            if os.path.isfile('/etc/shadowsocks-go/upsks.json'):
                with open('/etc/shadowsocks-go/upsks.json') as _f:
                    shadowsocks_go_upsk = json.load(_f).get(username, '')
            shadowsocks_go_conf= { 'password': shadowsocks_go_psk + ':' + shadowsocks_go_upsk, 'port': shadowsocks_go_port, 'protocol': shadowsocks_go_protocol }
            LOG.debug("modif_config_user for shadowsocks-go")
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
        mptcp_enabled = read_proc('/proc/sys/net/mptcp/mptcp_enabled')
        mptcp_checksum = read_proc('/proc/sys/net/mptcp/mptcp_checksum')
        mptcp_path_manager = read_proc('/proc/sys/net/mptcp/mptcp_path_manager')
        mptcp_scheduler = read_proc('/proc/sys/net/mptcp/mptcp_scheduler')
        mptcp_syn_retries = read_proc('/proc/sys/net/mptcp/mptcp_syn_retries')
        mptcp_version = read_proc('/proc/sys/net/mptcp/mptcp_version')
    elif path.exists('/proc/sys/net/mptcp/enabled'):
        mptcp_enabled = read_proc('/proc/sys/net/mptcp/enabled')
        mptcp_checksum = read_proc('/proc/sys/net/mptcp/checksum_enabled')
        mptcp_version = '1'

    congestion_control = read_proc('/proc/sys/net/ipv4/tcp_congestion_control')

    LOG.debug('Get config... ipv6')
    if 'ipv6_network' in omr_config_data:
        ipv6_network = omr_config_data['ipv6_network']
    else:
        try:
            _ip6out = subprocess.check_output(['ip', '-6', 'addr', 'show', IFACE6], timeout=2, stderr=subprocess.DEVNULL).decode()
            _m = re.search(r'inet6 (\S+) scope global', _ip6out)
            ipv6_network = _m.group(1) if _m else ''
        except (subprocess.SubprocessError, OSError):
            ipv6_network = ''
    if ipv6_network != '':
        set_global_param('ipv6_network', ipv6_network)
    if 'ipv6_addr' in omr_config_data:
        ipv6_addr = omr_config_data['ipv6_addr']
    else:
        ipv6_addr = ipv6_network.split('/')[0] if ipv6_network else ''
    if ipv6_addr != '':
        set_global_param('ipv6_addr', ipv6_addr)
    LOG.debug('get server IPv4')
    ipv4_addr = ''
    if 'ipv4' in omr_config_data:
        ipv4_addr = omr_config_data['ipv4']
    elif 'internet' in omr_config_data and not omr_config_data['internet']:
        try:
            _ip4out = subprocess.check_output(['ip', '-4', 'addr', 'show', IFACE], timeout=2, stderr=subprocess.DEVNULL).decode()
            _m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/', _ip4out)
            ipv4_addr = _m.group(1) if _m else ''
        except (subprocess.SubprocessError, OSError):
            ipv4_addr = ''
    else:
        try:
            ipv4_addr = requests.get('http://ip.openmptcprouter.com', timeout=2).text.strip()
        except Exception:
            pass
        if not ipv4_addr:
            try:
                ipv4_addr = requests.get('http://ifconfig.me', timeout=2).text.strip()
            except Exception:
                pass
        if ipv4_addr:
            set_global_param('ipv4', ipv4_addr)

    with open('/proc/cpuinfo', 'r') as _f:
        vps_aes = 'aes' in _f.read()
    _uname = platform.uname()
    vps_kernel = _uname.release
    vps_machine = _uname.machine
    vps_omr_version = get_omr_version()
    vps_loadavg = ' '.join(read_proc('/proc/loadavg').split()[:3])
    vps_uptime = read_proc('/proc/uptime').split()[0]
    LOG.debug('get hostname')
    if 'hostname' in omr_config_data:
        vps_domain = omr_config_data['hostname']
    elif 'internet' in omr_config_data and not omr_config_data['internet']:
        vps_domain = ''
    else:
        try:
            vps_domain = requests.get('http://hostname.openmptcprouter.com', timeout=2).text.strip()
        except Exception:
            vps_domain = ''
        if vps_domain:
            set_global_param('hostname', vps_domain)
    #vps_domain = os.popen('dig -4 +short +times=3 +tries=1 -x ' + ipv4_addr + " | sed 's/\.$//'").read().rstrip()
    user_permissions = user_config.get('permissions', current_user.permissions)

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
        localip6 = 'fd00::a00:1'
        remoteip6 = 'fd00::a00:2'

    vpn = 'openvpn'
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
    elif vpn == 'mqvpn':
        vpn_traffic_rx = get_bytes('rx', 'mqvpn' + str(userid))
        vpn_traffic_tx = get_bytes('tx', 'mqvpn' + str(userid))
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
    elif vpn == 'softether':
        vpn_txrx = get_bytes_softether(username)
        vpn_traffic_rx = vpn_txrx['uplinkBytes']
        vpn_traffic_tx = vpn_txrx['downlinkBytes']

    #vpn = current_user.vpn
    available_proxy = ["shadowsocks", "shadowsocks-go","v2ray","v2ray-vmess","v2ray-socks","v2ray-trojan","xray","xray-vless-reality","xray-vmess","xray-socks","xray-trojan","xray-shadowsocks"]
    if user_permissions == 'ro':
        del available_vpn
        available_vpn = [vpn]
        del available_proxy
        available_proxy = [proxy]

    localvpn = ""
    if any(iface.startswith('vpn') for iface in netifaces.interfaces()):
        localvpn = "vpn1"

    lanips = ""
    if 'lanips' in omr_config_data['users'][0][username]:
        lanips = omr_config_data['users'][0][username]['lanips']

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
    return {'vps': {'kernel': vps_kernel, 'machine': vps_machine, 'omr_version': vps_omr_version, 'loadavg': vps_loadavg, 'uptime': vps_uptime, 'aes': vps_aes}, 'lan': {'ips': lanips}, 'shadowsocks': {'traffic': ss_traffic, 'key': shadowsocks_key, 'port': shadowsocks_port, 'method': shadowsocks_method, 'fast_open': shadowsocks_fast_open, 'reuse_port': shadowsocks_reuse_port, 'no_delay': shadowsocks_no_delay, 'mptcp': shadowsocks_mptcp, 'ebpf': shadowsocks_ebpf, 'obfs': shadowsocks_obfs, 'obfs_plugin': shadowsocks_obfs_plugin, 'obfs_type': shadowsocks_obfs_type}, 'glorytun': {'key': glorytun_key, 'udp': {'host_ip': glorytun_udp_host_ip, 'client_ip': glorytun_udp_client_ip}, 'tcp': {'host_ip': glorytun_tcp_host_ip, 'client_ip': glorytun_tcp_client_ip}, 'port': glorytun_port, 'chacha': glorytun_chacha}, 'dsvpn': {'key': dsvpn_key, 'host_ip': dsvpn_host_ip, 'client_ip': dsvpn_client_ip, 'port': dsvpn_port}, 'openvpn': {'key': openvpn_key, 'client_key': openvpn_client_key, 'client_crt': openvpn_client_crt, 'client_ca': openvpn_client_ca, 'host_ip': openvpn_host_ip, 'client_ip': openvpn_client_ip, 'port': openvpn_port, 'cipher': openvpn_cipher},'wireguard': {'key': wireguard_key, 'host_ip': wireguard_host_ip, 'port': wireguard_port, 'client_key': wireguard_client_key, 'client_ip': wireguard_client_ip, 'client_port': wireguard_client_port}, 'mlvpn': {'key': mlvpn_key, 'host_ip': mlvpn_host_ip, 'client_ip': mlvpn_client_ip,'timeout': mlvpn_timeout,'reorder_buffer_size': mlvpn_reorder_buffer_size,'loss_tolerence': mlvpn_loss_tolerence,'cleartext_data': mlvpn_cleartext_data}, 'mqvpn': {'key': mqvpn_key, 'host_ip': mqvpn_host_ip, 'client_ip': mqvpn_client_ip, 'fixed_ip': mqvpn_fixed_ip, 'port': mqvpn_port, 'scheduler': mqvpn_scheduler, 'fec_enable': mqvpn_fec_enable, 'fec_scheme': mqvpn_fec_scheme, 'reinjection_control': mqvpn_reinjection_control, 'reinjection_mode': mqvpn_reinjection_mode, 'cc': mqvpn_cc}, 'shorewall': {'redirect_ports': shorewall_redirect}, 'mptcp': {'enabled': mptcp_enabled, 'checksum': mptcp_checksum, 'path_manager': mptcp_path_manager, 'scheduler': mptcp_scheduler, 'syn_retries': mptcp_syn_retries, 'version': mptcp_version}, 'network': {'congestion_control': congestion_control, 'ipv6_network': ipv6_network, 'ipv6': ipv6_addr, 'ipv4': ipv4_addr, 'domain': vps_domain, 'internet': internet}, 'vpn': {'available': available_vpn, 'current': vpn, 'remoteip': vpn_remote_ip, 'localip': vpn_local_ip, 'rx': vpn_traffic_rx, 'tx': vpn_traffic_tx}, 'iperf': {'user': 'openmptcprouter', 'password': 'openmptcprouter', 'key': iperf3_key}, 'pihole': {'state': pihole}, 'user': {'name': username, 'permission': user_permissions}, 'ip6in4': {'localip': localip6, 'remoteip': remoteip6, 'ula': ula}, 'client2client': {'enabled': client2client, 'lanips': alllanips}, 'gre_tunnel': {'enabled': gre_tunnel, 'config': gre_tunnel_conf}, 'v2ray': {'enabled': v2ray, 'config': v2ray_conf, 'tx': v2ray_tx, 'rx': v2ray_rx},'xray': {'enabled': xray, 'config': xray_conf, 'tx': xray_tx, 'rx': xray_rx},'shadowsocks_go': {'enabled': shadowsocks_go, 'config': shadowsocks_go_conf,'tx': ss_go_tx, 'rx': ss_go_rx}, 'proxy': {'available': available_proxy, 'current': proxy}, 'softethervpn': {'enabled': softether, 'port': softether_port, 'password': softether_password, 'cipher': softether_cipher, 'host_ip': softether_host_ip, 'client_ip': softether_client_ip},'localvpn': localvpn}

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
        #set_lastchange(10)
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'shadowsocks'}
    if not os.path.isfile('/etc/shadowsocks-libev/manager.json'):
        return {'result': 'warning', 'reason': 'Shadowsocks-lib not installed', 'route': 'shadowsocks'}

    try:
        _ip6out = subprocess.check_output(['ip', '-6', 'addr', 'show', IFACE6], timeout=2, stderr=subprocess.DEVNULL).decode()
        _m = re.search(r'inet6 (\S+) scope global', _ip6out)
        ipv6_network = _m.group(1) if _m else ''
    except (subprocess.SubprocessError, OSError):
        ipv6_network = ''
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shadowsocks-libev/manager.json', 'rb'))).hexdigest()
    with open('/etc/shadowsocks-libev/manager.json') as f:
        content = f.read()
    content = re.sub(r",\s*}", "}", content) # pylint: disable=W1401
    try:
        data = json.loads(content)
    except ValueError as e:
        data = {'timeout': 600, 'verbose': 0, 'prefer_ipv6': False}
    #key = data["key"]
    if 'timeout' in data:
        timeout = data["timeout"]
    else:
        timeout = 600
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
    LOG.debug("modif_config_user for shadowsocks_port")
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
        try:
            vps_domain = requests.get('http://hostname.openmptcprouter.com', timeout=2).text.strip()
        except Exception:
            vps_domain = ''
        if vps_domain:
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
        subprocess.run(["systemctl", "-q", "restart", "shadowsocks-libev-manager@manager.service"], check=False)
        #for x in range(1, os.cpu_count()):
        #    os.system("systemctl restart shadowsocks-libev-manager@manager" + str(x) + ".service")
        shorewall_add_port(current_user, str(port), 'tcp', 'shadowsocks')
        shorewall_add_port(current_user, str(port), 'udp', 'shadowsocks')
        #set_lastchange()
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
        #set_lastchange(10)
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'shadowsocks-go'}
    if not os.path.isfile('/etc/shadowsocks-go/server.json'):
        return {'result': 'warning', 'reason': 'Shadowsocks-go not installed', 'route': 'shadowsocks-go'}

    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shadowsocks-go/server.json', 'rb'))).hexdigest()
    with open('/etc/shadowsocks-go/server.json') as f:
        content = f.read()
    content = re.sub(r",\s*}", "}", content) # pylint: disable=W1401
    try:
        data = json.loads(content)
    except ValueError as e:
        return {'result': 'error', 'reason': 'Read only user', 'route': 'shadowsocks-go'}
    port = params.port
    # If method is aes 128 then key need to be length 16 instead of 32, so force aes-256-gcm for now
    method = params.method
    if method == "2022-blake3-aes-128-gcm":
        method = "2022-blake3-aes-256-gcm"
    fast_open = params.fast_open
    reuse_port = params.reuse_port
    mptcp = params.mptcp
    #key = params.key
    LOG.debug("modif_config_user for shadowsocks-go port")
    _srv = next((s for s in data.get('servers', []) if s.get('name') == 'ss-2022'), {})
    shadowsocks_go_psk = _srv.get('psk', '')
    shadowsocks_go_upsk = ''
    if os.path.isfile('/etc/shadowsocks-go/upsks.json'):
        with open('/etc/shadowsocks-go/upsks.json') as _f:
            shadowsocks_go_upsk = json.load(_f).get(current_user.username, '')
    shadowsocks_go_conf= { 'password': shadowsocks_go_psk + ':' + shadowsocks_go_upsk, 'port': port, 'protocol': method }
    modif_config_user(current_user.username, {'shadowsocks-go': shadowsocks_go_conf})
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
        subprocess.run(["systemctl", "-q", "restart", "shadowsocks-go.service"], check=False)
        shorewall_add_port(current_user, str(port), 'tcp', 'shadowsocks-go')
        shorewall_add_port(current_user, str(port), 'udp', 'shadowsocks-go')
        #set_lastchange()
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
            subprocess.run(["systemctl", "-q", "reload", "shorewall"], check=False)
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
            subprocess.run(["systemctl", "-q", "reload", "shorewall6"], check=False)
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
        subprocess.run(["systemctl", "-q", "reload", "shorewall"], check=False)
    return {'result': 'done', 'reason': 'changes applied', 'route': 'sipalg'}

class V2rayconfig(BaseModel):
    userid: str

@app.post('/v2ray', summary="Set v2ray settings")
def v2ray(*, params: V2rayconfig, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'v2ray'}
    if not os.path.isfile('/etc/v2ray/v2ray-server.json'):
        return {'result': 'warning', 'reason': 'V2Ray not installed', 'route': 'v2ray'}

    username = current_user.username
    with open('/etc/v2ray/v2ray-server.json') as f:
        v2ray_config = json.load(f)
    v2ray_key = next((c.get('id', '') for c in v2ray_config['inbounds'][0].get('settings', {}).get('clients', []) if c.get('email') == username), '')
    v2ray_port = str(v2ray_config['inbounds'][0].get('port', ''))
    v2ray_conf = { 'key': v2ray_key, 'port': v2ray_port}
    LOG.debug("modif_config_user for v2ray conf")
    modif_config_user(username, {'v2ray': v2ray_conf})
    return {'result': 'done', 'reason': 'no changes', 'route': 'v2ray'}

class XRAYTRANSPORT(str, Enum):
    tcp = "tcp"
    grpc = "grpc"
    xhttp = "xhttp"

class Xrayconfig(BaseModel):
    userid: str
    vless_reality: bool = Query(False, title="Enable or disable VLESS Reality")
    ss_method: str = "2022-blake3-aes-256-gcm"
    transport: XRAYTRANSPORT = Query("tcp", title="Choose transport")

@app.post('/xray', summary="Set xray settings")
def xray(*, params: Xrayconfig, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'xray'}
    if not os.path.isfile('/etc/xray/xray-server.json'):
        return {'result': 'warning', 'reason': 'Xay not installed', 'route': 'xray'}

    # Read file once — compute initial MD5, parse JSON, avoid re-reads later
    with open('/etc/xray/xray-server.json', 'rb') as f:
        _initial_bytes = f.read()
    initial_md5 = hashlib.md5(_initial_bytes).hexdigest()
    xray_config = json.loads(_initial_bytes)

    chk_vless_reality = any(ib.get('tag') == 'omrin-vless-reality' for ib in xray_config['inbounds'])
    if params.vless_reality and not chk_vless_reality:
        with open('/etc/xray/xray-vless-reality.json') as f:
            vless_reality_config = json.load(f)
        xray_config['inbounds'].append(vless_reality_config['inbounds'][0])
    elif not params.vless_reality and chk_vless_reality:
        xray_config['inbounds'] = [ib for ib in xray_config['inbounds'] if ib.get('tag') != 'omrin-vless-reality']
    for inbounds in xray_config['inbounds']:
        if inbounds.get('tag') == 'omrin-shadowsocks-tunnel':
            inbounds['settings']['method'] = params.ss_method
        if 'streamSettings' in inbounds:
            inbounds['streamSettings']['network'] = params.transport

    with open('/etc/xray/xray-server.json', 'w') as outfile:
        json.dump(xray_config, outfile, indent=4)
    # Compute final MD5 from in-memory dump — no extra disk read
    final_md5 = hashlib.md5(json.dumps(xray_config, indent=4).encode()).hexdigest()

    username = current_user.username
    # Extract all values from in-memory xray_config — no jq subprocesses
    xray_key = next((c.get('id', '') for c in xray_config['inbounds'][0].get('settings', {}).get('clients', []) if c.get('email') == username), '')
    xray_port = str(xray_config['inbounds'][0].get('port', ''))
    xray_ss_skey = xray_ss_ukey = ''
    for _ib in xray_config['inbounds']:
        if _ib.get('tag') == 'omrin-shadowsocks-tunnel':
            xray_ss_skey = _ib.get('settings', {}).get('password', '')
            xray_ss_ukey = next((c.get('password', '') for c in _ib.get('settings', {}).get('clients', []) if c.get('email') == username), '')
    xray_ss_key = xray_ss_skey + ':' + xray_ss_ukey
    vless_reality = any(ib.get('tag') == 'omrin-vless-reality' for ib in xray_config['inbounds'])
    xray_vless_reality_public_key = ''
    if os.path.isfile('/etc/xray/xray-vless-reality.json'):
        with open('/etc/xray/xray-vless-reality.json') as f:
            _vr = json.load(f)
        xray_vless_reality_public_key = next((ib.get('streamSettings', {}).get('realitySettings', {}).get('publicKey', '') for ib in _vr['inbounds'] if ib.get('tag') == 'omrin-vless-reality'), '')
    xray_conf = { 'key': xray_key, 'port': xray_port, 'sskey': xray_ss_key, 'vless_reality_key': xray_vless_reality_public_key, 'vless_reality': vless_reality, 'ss_method': params.ss_method }
    LOG.debug("modif_config_user for xray conf")
    modif_config_user(username, {'xray': xray_conf})
    if initial_md5 != final_md5:
        if params.vless_reality and not chk_vless_reality:
            shorewall_add_port(current_user, '443', 'tcp', 'xray vless-reality')
        elif not params.vless_reality and chk_vless_reality:
            shorewall_del_port(current_user.username, '443', 'tcp', 'xray vless-reality')
        subprocess.run(["systemctl", "-q", "restart", "xray"], check=False)
        #set_lastchange()
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
    if not os.path.isfile('/etc/v2ray/v2ray-server.json'):
        return {'result': 'warning', 'reason': 'V2Ray not installed', 'route': 'v2rayredirect'}
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
    if not os.path.isfile('/etc/xray/xray-server.json'):
        return {'result': 'warning', 'reason': 'Xay not installed', 'route': 'xrayredirect'}

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
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'v2rayunredirect'}
    if not os.path.isfile('/etc/v2ray/v2ray-server.json'):
        return {'result': 'warning', 'reason': 'V2Ray not installed', 'route': 'v2rayunredirect'}
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
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'xrayunredirect'}
    if not os.path.isfile('/etc/xray/xray-server.json'):
        return {'result': 'warning', 'reason': 'Xay not installed', 'route': 'xrayunredirect'}
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
        #set_lastchange(10)
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
        subprocess.run(["sysctl", "-qw", f"net.mptcp.mptcp_checksum={checksum}"], check=False)
        subprocess.run(["sysctl", "-qw", f"net.mptcp.mptcp_path_manager={path_manager}"], check=False)
        subprocess.run(["sysctl", "-qw", f"net.mptcp.mptcp_scheduler={scheduler}"], check=False)
        subprocess.run(["sysctl", "-qw", f"net.mptcp.mptcp_syn_retries={syn_retries}"], check=False)
        subprocess.run(["sysctl", "-qw", f"net.mptcp.mptcp_version={version}"], check=False)
    else:
        subprocess.run(["sysctl", "-qw", f"net.mptcp.checksum_enabled={checksum}"], check=False)
    subprocess.run(["sysctl", "-qw", f"net.ipv4.tcp_congestion_control={congestion_control}"], check=False)
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
        if os.path.isfile('/etc/shadowsocks-libev/manager.json'):
            subprocess.run(["systemctl", "-q", "restart", "shadowsocks-libev-manager@manager"], check=False)
        if os.path.isfile('/etc/v2ray/v2ray-server.json'):
            subprocess.run(["systemctl", "-q", "restart", "v2ray"], check=False)
        if os.path.isfile('/etc/xray/xray-server.json'):
            subprocess.run(["systemctl", "-q", "restart", "xray"], check=False)
        if os.path.isfile('/etc/glorytun-tcp/tun0'):
            subprocess.run(["systemctl", "-q", "restart", "glorytun-tcp@tun0"], check=False)
        if os.path.isfile('/etc/openvpn/tun0.conf'):
            subprocess.run(["systemctl", "-q", "restart", "openvpn@tun0"], check=False)
    #set_lastchange()
    return {'result': 'done', 'reason': 'changes applied'}

class VPN(str, Enum):
    openvpn = "openvpn"
    openvpnbonding = "openvpn_bonding"
    glorytuntcp = "glorytun_tcp"
    glorytunudp = "glorytun_udp"
    dsvpn = "dsvpn"
    mlvpn = "mlvpn"
    mqvpn = "mqvpn"
    softether = "softether"
    none = "none"

class Vpn(BaseModel):
    vpn: VPN

# Set global VPN config
@app.post('/vpn', summary="Set VPN used by the current user")
def vpn(*, vpnconfig: Vpn, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        #set_lastchange(10)
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'vpn'}
    vpn = vpnconfig.vpn
    if not vpn:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'vpn'}
    with open('/etc/openmptcprouter-vps-admin/current-vpn', 'w') as f:
        f.write(vpn + '\n')
    LOG.debug("modif_config_user for vpn setting")
    modif_config_user(current_user.username, {'vpn': vpn})
    current_user.vpn = vpn
    #set_lastchange()
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
        #set_lastchange(10)
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'proxy'}
    proxy = proxyconfig.proxy
    if not proxy:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'proxy'}
    with open('/etc/openmptcprouter-vps-admin/current-proxy', 'w') as f:
        f.write(proxy + '\n')
    LOG.debug("modif_config_user for proxy")
    modif_config_user(current_user.username, {'proxy': proxy})
    #current_user.proxy = proxy
    #set_lastchange()
    return {'result': 'done', 'reason': 'changes applied'}


class GlorytunConfig(BaseModel):
    key: str
    port: int = Query(..., gt=0, lt=65535, title="Glorytun TCP and UDP port")
    chacha: bool = Query(True, title="Enable of disable chacha20, if disable AES is used")

# Set Glorytun config
@app.post('/glorytun', summary="Modify Glorytun configuration")
def glorytun(*, glorytunconfig: GlorytunConfig, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        #set_lastchange(10)
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'glorytun'}
    if not os.path.isfile('/etc/glorytun-tcp/tun0') and not os.path.isfile('/etc/glorytun-udp/tun0'):
        return {'result': 'warning', 'reason': 'Glorytun is not installed', 'route': 'glorytun'}

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
        subprocess.run(["systemctl", "-q", "restart", f"glorytun-tcp@tun{userid}"], check=False)
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
        subprocess.run(["systemctl", "-q", "restart", f"glorytun-udp@tun{userid}"], check=False)
    shorewall_add_port(current_user, str(port), 'tcp', 'glorytun')
    shorewall_add_port(current_user, str(port), 'udp', 'glorytun')
    #set_lastchange()
    return {'result': 'done'}

# Set A Dead Simple VPN config
class DSVPN(BaseModel):
    key: str
    port: int = Query(..., gt=0, lt=65535)

@app.post('/dsvpn', summary="Modify DSVPN configuration")
def dsvpn(*, params: DSVPN, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        #set_lastchange(10)
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'dsvpn'}
    if not os.path.isfile('/etc/dsvpn/dsvpn'):
        return {'result': 'warning', 'reason': 'DSVPN is not installed', 'route': 'dsvpn'}
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
        subprocess.run(["systemctl", "-q", "restart", f"dsvpn-server@dsvpn{userid}"], check=False)
    shorewall_add_port(current_user, str(port), 'tcp', 'dsvpn')
    #set_lastchange()
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
        #set_lastchange(10)
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'mlvpn'}
    if not os.path.isfile('/etc/mlvpn/mlvpn0.conf'):
        return {'result': 'warning', 'reason': 'MLVPN is not installed', 'route': 'mlvpn'}
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
        subprocess.run(["systemctl", "-q", "restart", "mlvpn@mlvpn0"], check=False)
        #set_lastchange()
    return {'result': 'done', 'reason': 'changes applied', 'route': 'mlvpn'}


# MQVPN helpers

def mqvpn_api(cmd: dict) -> dict:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(('127.0.0.1', 9090))
            s.sendall((json.dumps(cmd) + '\n').encode())
            data = b''
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b'\n' in chunk:
                    break
        return json.loads(data.decode().strip())
    except Exception as e:
        return {'ok': False, 'error': str(e)}

# Set MQVPN config
class MQVPNcc(str, Enum):
    bbr2 = "bbr2"
    bbr = "bbr"
    cubic = "cubic"
    new_reno = "new_reno"
    copa = "copa"
    unlimited = "unlimited"

class MQVPNReinjectionMode(str, Enum):
    default = "default"
    deadline = "deadline"
    dgram = "dgram"

class MQVPNFecScheme(str, Enum):
    galois_calculation = "galois_calculation"
    packet_mask = "packet_mask"
    reed_solomon = "reed_solomon"
    xor = "xor"

class MQVPN(BaseModel):
    key: str
    scheduler: str = 'wlb'
    port: int = Query(443, gt=0, lt=65535)
    fec_enable: bool = False
    fec_scheme: MQVPNFecScheme = MQVPNFecScheme.xor
    reinjection_control: bool = False
    reinjection_mode: MQVPNReinjectionMode = MQVPNReinjectionMode.default
    cc: MQVPNcc = MQVPNcc.bbr2

@app.post('/mqvpn', summary="Modify MQVPN configuration")
def mqvpn_set_config(*, params: MQVPN, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'mqvpn'}
    if not os.path.isfile('/etc/mqvpn/server.json'):
        return {'result': 'warning', 'reason': 'MQVPN is not installed', 'route': 'mqvpn'}
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/mqvpn/server.json', 'rb'))).hexdigest()
    with open('/etc/mqvpn/server.json') as f:
        mqvpn_cfg = json.load(f)
    host_part = mqvpn_cfg.get('listen', '0.0.0.0:443').rsplit(':', 1)[0]
    mqvpn_cfg['auth_key'] = params.key
    mqvpn_cfg['scheduler'] = params.scheduler
    mqvpn_cfg['listen'] = host_part + ':' + str(params.port)
    mqvpn_cfg['fec_enable'] = params.fec_enable
    mqvpn_cfg['fec_scheme'] = params.fec_scheme
    mqvpn_cfg['reinjection_control'] = params.reinjection_control
    mqvpn_cfg['reinjection_mode'] = params.reinjection_mode
    mqvpn_cfg['cc'] = params.cc
    with open('/etc/mqvpn/server.json', 'w') as f:
        json.dump(mqvpn_cfg, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/mqvpn/server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        subprocess.run(["systemctl", "-q", "restart", "mqvpn"], check=False)
        #set_lastchange()
    return {'result': 'done', 'reason': 'changes applied', 'route': 'mqvpn'}

# Set MQVPN per-user config (fixed IP)
class MQVPNUser(BaseModel):
    username: str
    fixed_ip: Optional[str] = None

@app.post('/mqvpn_user', summary="Set or clear a fixed IP for an MQVPN user")
def mqvpn_user_set_config(*, params: MQVPNUser, current_user: User = Depends(get_current_user)):
    if current_user.permissions not in ("admin",):
        return {'result': 'permission', 'reason': 'Admin only', 'route': 'mqvpn_user'}
    if not os.path.isfile('/etc/mqvpn/server.json'):
        return {'result': 'warning', 'reason': 'MQVPN is not installed', 'route': 'mqvpn_user'}
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/mqvpn/server.json', 'rb'))).hexdigest()
    with open('/etc/mqvpn/server.json') as f:
        mqvpn_cfg = json.load(f)
    users = mqvpn_cfg.get('users', [])
    user_entry = next((u for u in users if u.get('name') == params.username), None)
    if user_entry is None:
        return {'result': 'error', 'reason': 'User not found', 'route': 'mqvpn_user'}
    if params.fixed_ip:
        user_entry['fixed_ip'] = params.fixed_ip
    else:
        user_entry.pop('fixed_ip', None)
    with open('/etc/mqvpn/server.json', 'w') as f:
        json.dump(mqvpn_cfg, f, indent=4)
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/mqvpn/server.json', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        subprocess.run(["systemctl", "-q", "restart", "mqvpn"], check=False)
    return {'result': 'done', 'reason': 'changes applied', 'route': 'mqvpn_user'}


# Set OpenVPN config
class OpenVPN(BaseModel):
    port: int = Query(..., gt=0, lt=65535)
    cipher: str = "AES-256-CBC"

@app.post('/openvpn', summary="Modify OpenVPN TCP configuration")
def openvpn(*, params: OpenVPN, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        #set_lastchange(10)
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'openvpn'}
    if not os.path.isfile('/etc/openvpn/tun0.conf'):
        return {'result': 'warning', 'reason': 'OpenVPN is not installed', 'route': 'openvpn'}
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
        subprocess.run(["systemctl", "-q", "restart", "openvpn@tun0"], check=False)
        shorewall_add_port(current_user, str(params.port), 'tcp', 'openvpn')
        #set_lastchange()
    return {'result': 'done'}

# Set SoftEther VPN config
class SoftEtherVPN(BaseModel):
#    port: int = Query(..., gt=0, lt=65535)
    cipher: str = "AES-256-GCM"
    password: str = ""

@app.post('/softethervpn', summary="Modify SoftEther VPN configuration")
def softethervpn(*, params: SoftEtherVPN, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'softethervpn'}
    if not os.path.isfile('/var/lib/softether/vpn_server.config'):
        return {'result': 'warning', 'reason': 'SoftEther VPN is not installed', 'route': 'softethervpn'}
    cipherPayload = {
        "jsonrpc": "2.0",
        "id": "rpc_call_id",
        "method": "SetServerCipher",
        "params": {
            "String_str": params.cipher
        }
    }
    try:
        r = requests.post(url="http://127.0.0.1:65390/api", json=cipherPayload, headers=softethervpnPassword, verify=False)
    except requests.exceptions.Timeout:
        LOG.debug("SoftEther VPN change cipher timeout")
        return {'result': 'error'}
    except requests.exceptions.RequestException as err:
        LOG.debug("SoftEther VPN change cipher error (" + str(err) + ")")
        return {'result': 'error'}
    if params.password != "":
        passwordPayload = {
            "jsonrpc": "2.0",
            "id": "rpc_call_id",
            "method": "SetUser",
            "params": {
                "HubName_str": "OMRVPN",
                "Name_str": current_user.username,
                "Auth_Password_str": params.password 
            }
        }
        try:
            r = requests.post(url="http://127.0.0.1:65390/api", json=passwordPayload, headers=softethervpnPassword, verify=False)
        except requests.exceptions.Timeout:
            LOG.debug("SoftEther VPN change password timeout")
            return {'result': 'error'}
        except requests.exceptions.RequestException as err:
            LOG.debug("SoftEther VPN change password error (" + str(err) + ")")
            return {'result': 'error'}
        modif_config_user(current_user.username, {'softethervpn': {'password': params.password}})
    #shorewall_add_port(current_user, str(params.port), 'tcp', 'softethervpn')
    return {'result': 'done'}

# Set WireGuard config
class WireGuardPeer(BaseModel):
    ip: str
    key: str

class WireGuard(BaseModel):
    peers: List[WireGuardPeer] = []

@app.post('/wireguard', summary="Modify Wireguard configuration")
def wireguard(*, params: WireGuard, current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'wireguard'}
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
        subprocess.run(["wg", "setconf", "wg0", "/etc/wireguard/wg0.conf"], check=False)
        shorewall_add_port(current_user, str(wg_port), 'udp', 'wireguard')
        #set_lastchange()
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
        content = re.sub(r",\s*}", "}", content) # pylint: disable=W1401
        try:
            configdata = json.loads(content)
            data = configdata
        except ValueError as e:
            return {'error': 'Config file not readable', 'route': 'bypass'}
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
    #if current_user.permissions == "ro":
    #    return {'result': 'permission', 'reason': 'Read only user', 'route': 'wan'}
    ips = wanips.ips
    if not ips:
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'wan'}
    if not os.path.isfile('/etc/shadowsocks-libev/manager.json'):
        return {'result': 'warning', 'reason': 'Shadowsocks-libev is not installed', 'route': 'wan'}

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
    LOG.debug("modif_config_user for lanip")
    modif_config_user(current_user.username, {'lanips': lanips})
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        omr_config_data = json.load(f)
    client2client = False
    if 'client2client' in omr_config_data:
        client2client = omr_config_data["client2client"]
    if client2client == True and os.path.isfile('/etc/openvpn/tun0.conf'):
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
            subprocess.run(["systemctl", "-q", "restart", "openvpn@tun0"], check=False)
            #set_lastchange()
    return {'result': 'done', 'reason': 'changes applied', 'route': 'lan'}

class VPNips(BaseModel):
    remoteip: str = Query(..., pattern=r'^(10(\.(25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})){3}|((172\.(1[6-9]|2[0-9]|3[01]))|192\.168)(\.(25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})){2})$')
    localip: str = Query(..., pattern=r'^(10(\.(25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})){3}|((172\.(1[6-9]|2[0-9]|3[01]))|192\.168)(\.(25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})){2})$')
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
        return {'result': 'done', 'reason': 'No changes', 'route': 'vpnips'}
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        omr_config_data = json.load(f)
    if 'vpnremoteip' in omr_config_data['users'][0][current_user.username] and omr_config_data['users'][0][current_user.username]['vpnremoteip'] == remoteip and 'vpnlocalip' in omr_config_data['users'][0][current_user.username] and omr_config_data['users'][0][current_user.username]['vpnlocalip'] == localip and ula and ('ula' in omr_config_data['users'][0][current_user.username] and omr_config_data['users'][0][current_user.username]['ula'] == ula):
        return {'result': 'error', 'reason': 'Invalid parameters', 'route': 'vpnips'}
    if 'vpnremoteip' not in omr_config_data['users'][0][current_user.username] or omr_config_data['users'][0][current_user.username]['vpnremoteip'] != remoteip:
        LOG.debug("modif_config_user for vpnips")
        modif_config_user(current_user.username, {'vpnremoteip': remoteip})
    if 'vpnlocalip' not in omr_config_data['users'][0][current_user.username] or omr_config_data['users'][0][current_user.username]['vpnlocalip'] != localip:
        LOG.debug("modif_config_user for vpn local ip")
        modif_config_user(current_user.username, {'vpnlocalip': localip})
    if ula and ('ula' not in omr_config_data['users'][0][current_user.username] or omr_config_data['users'][0][current_user.username]['ula'] != ula):
        LOG.debug("modif_config_user for ula")
        modif_config_user(current_user.username, {'ula': ula})
    userid = current_user.userid
    if userid is None:
        userid = 0

    if not '6in4' in omr_config_data or omr_config_data['6in4']:
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
            subprocess.run(["systemctl", "-q", "restart", f"omr6in4@user{userid}"], check=False)
            #set_lastchange()

    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall/params.vpn', 'rb'))).hexdigest()
    fd, tmpfile = mkstemp()
    dataexist = False
    with open('/etc/shorewall/params.vpn', 'r') as f, open(tmpfile, 'a+') as n:
        for line in f:
            if not ('OMR_ADDR_USER' + str(userid) +'=' in line and not userid == 0) and not ('OMR_ADDR=' in line and userid == 0):
                n.write(line)
            elif not userid == 0:
                n.write('OMR_ADDR_USER' + str(userid) + '=' + remoteip + '\n')
                dataexist = True
            elif userid == 0:
                n.write('OMR_ADDR=' + remoteip + '\n')
                dataexist = True
        if not dataexist:
            if not userid == 0:
                n.write('OMR_ADDR_USER' + str(userid) + '=' + remoteip + '\n')
            elif userid == 0:
                n.write('OMR_ADDR=' + remoteip + '\n')
    os.close(fd)
    move(tmpfile, '/etc/shorewall/params.vpn')
    final_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall/params.vpn', 'rb'))).hexdigest()
    if initial_md5 != final_md5:
        subprocess.run(["systemctl", "-q", "reload", "shorewall"], check=False)
        #set_lastchange()

    if not '6in4' in omr_config_data or omr_config_data['6in4']:
        initial_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall6/params.vpn', 'rb'))).hexdigest()
        fd, tmpfile = mkstemp()
        dataexist = False
        with open('/etc/shorewall6/params.vpn', 'r') as f, open(tmpfile, 'a+') as n:
            for line in f:
                if not ('OMR_ADDR_USER' + str(userid) +'=' in line and not userid == 0) and not ('OMR_ADDR=' in line and userid == 0):
                    n.write(line)
                elif  not userid == 0:
                    n.write('OMR_ADDR_USER' + str(userid) + '=fd00::a0' + hex(userid)[2:] + ':2' + '\n')
                    dataexist = True
                elif userid == 0:
                    n.write('OMR_ADDR=fd00::a0' + hex(userid)[2:] + ':2' + '\n')
                    dataexist = True
            if not dataexist:
                if  not userid == 0:
                    n.write('OMR_ADDR_USER' + str(userid) + '=fd00::a0' + hex(userid)[2:] + ':2' + '\n')
                elif userid == 0:
                    n.write('OMR_ADDR=fd00::a0' + hex(userid)[2:] + ':2' + '\n')
        os.close(fd)
        move(tmpfile, '/etc/shorewall6/params.vpn')
        final_md5 = hashlib.md5(file_as_bytes(open('/etc/shorewall6/params.vpn', 'rb'))).hexdigest()
        if initial_md5 != final_md5:
            subprocess.run(["systemctl", "-q", "reload", "shorewall6"], check=False)
            #set_lastchange()

    return {'result': 'done', 'reason': 'changes applied', 'route': 'vpnips'}

# Update VPS
@app.get('/update', summary="Update VPS script")
def update(current_user: User = Depends(get_current_user)):
    if current_user.permissions == "ro":
        return {'result': 'permission', 'reason': 'Read only user', 'route': 'update'}
    LOG.debug("Update VPS...")
    with open("/etc/openmptcprouter-vps-admin/update", mode='a'): pass
    subprocess.run(["systemctl", "-q", "stop", "omr"], check=False)
    subprocess.run(["systemctl", "-q", "restart", "omr-update"], check=False)
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
    backup_dir = '/var/opt/openmptcprouter'
    backup_name = current_user.username + '-backup.tar.gz'
    if filename is not None:
        # Accept only direct filenames for the current user to avoid traversal.
        candidate = os.path.basename(filename)
        if candidate != filename:
            return {'result': 'error', 'reason': 'Invalid filename', 'route': 'backupget'}
        if not candidate.startswith(current_user.username + '-') or not candidate.endswith('-backup.tar.gz'):
            return {'result': 'error', 'reason': 'Invalid filename', 'route': 'backupget'}
        backup_name = candidate
    backup_path = os.path.join(backup_dir, backup_name)
    if not os.path.isfile(backup_path):
        return {'result': 'error', 'reason': 'Backup not found', 'route': 'backupget'}
    with open(backup_path, "rb") as backup_file:
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
    modiftime = "0"
    if os.path.isfile('/var/opt/openmptcprouter/' + current_user.username + '-backup.tar.gz'):
        modiftime = os.path.getmtime('/var/opt/openmptcprouter/' + current_user.username + '-backup.tar.gz')
    if len(sorted_files) > 0:
        return {'backup': True, 'modif': modiftime,'sorted': sorted_files}
    else:
        return {'backup': False}

#@app.get('/backupshow', summary="Show current user backup")
#def show_backup(current_user: User = Depends(get_current_user)):
#    if os.path.isfile('/var/opt/openmptcprouter/' + current_user.username + '-backup.tar.gz'):
#        router = OpenWrt(native=open('/var/opt/openmptcprouter/' + current_user.username + '-backup.tar.gz'))
#        return {'backup': True, 'data': router}
#    else:
#        return {'backup': False}

#@app.post('/backupedit', summary="Modify current user backup")
#def edit_backup(params, current_user: User = Depends(get_current_user)):
#    if current_user.permissions == "ro":
#        return {'result': 'permission', 'reason': 'Read only user', 'route': 'backupedit'}
#    o = OpenWrt(params)
#    o.write(current_user.username + '-backup', path='/var/opt/openmptcprouter/')
#    return {'result': 'done'}

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
    vpn: VPN = Query("mqvpn", title="default VPN for the user")
    proxy: PROXY = Query("shadowsocks-rust", title="default Proxy for the user")
    shadowsocks_port: Optional[int] = Query(None, gt=0, lt=65535, title="Shadowsocks-libev port")
    userid: Optional[int] = Query(None, title="User ID")
    ips: Optional[List[str]] = Query(None, title="Public exit IP (only one supported for now)")
    user_key: Optional[str] = Query(None, title="User key")
    shadowsocks_key: Optional[str] = Query(None, title="Shadowsocks key")
    shadowsocks2022_key: Optional[str] = Query(None, title="Shadowsocks 2022 key")
    softethervpn_pass: Optional[str] = Query(None, title="SoftEther VPN password")

@app.post('/add_user', summary="Add a new user")
def add_user(*, params: NewUser, current_user: User = Depends(get_current_user), request: Request):
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
    user_json = {params.username: {"username": params.username, "permissions": params.permission, "user_password": user_key.upper(), "disabled": "false", "userid": str(userid), "public_ips": publicips}}
#    shadowsocks_port = params.shadowsocks_port
#    if params.shadowsocks_port is None:
#    shadowsocks_port = '651{:02d}'.format(userid)
    shadowsocks_port = params.shadowsocks_port
    shadowsocks_key = params.shadowsocks_key
    if shadowsocks_key is None:
        shadowsocks_key = base64.urlsafe_b64encode(secrets.token_hex(16).encode()).decode('utf-8')
    shadowsocks2022_key = params.shadowsocks2022_key
    if shadowsocks2022_key is None:
        shadowsocks2022_key = base64.urlsafe_b64encode(secrets.token_hex(16).encode()).decode('utf-8')
    softethervpn_pass = params.softethervpn_pass
    upsk = ''
    uuid = ''
    if not publicips:
        if os.path.isfile('/etc/shadowsocks-libev/manager.json'):
            shadowsocks_port = add_ss_user(str(shadowsocks_port), shadowsocks_key, userid)
        if os.path.isfile('/etc/shadowsocks-go/server.json'):
            upsk = add_ss_go_user(params.username, shadowsocks2022_key)
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
                shadowsocks_port = add_ss_user(str(shadowsocks_port), shadowsocks_key, userid, publicip)
                shadowsocks_port = shadowsocks_port + 1
            if os.path.isfile('/etc/xray/xray-server.json'):
                xray_add_user(params.username,uuid,upsk)
            add_gre_tunnels(params.username, publicip)
    if shadowsocks_port is not None:
        user_json[params.username].update({"shadowsocks_port": shadowsocks_port})
    if params.vpn is not None:
        user_json[params.username].update({"vpn": params.vpn})
    if params.proxy is not None:
        user_json[params.username].update({"proxy": params.proxy})
    # Create OpenVPN cert first — fail early before saving the user
    if os.path.isfile('/etc/openvpn/tun0.conf'):
        LOG.debug("Create user " + params.username + " in OpenVPN")
        # Clean up any leftover revoked PKI entry for this CN so easyrsa can reissue
        index_file = '/etc/openvpn/ca/pki/index.txt'
        if os.path.isfile(index_file):
            with open(index_file, 'r') as f:
                lines = f.readlines()
            filtered = [l for l in lines if '/CN=' + params.username not in l]
            if len(filtered) != len(lines):
                LOG.debug("Removing stale PKI index entry for %s", params.username)
                with open(index_file, 'w') as f:
                    f.writelines(filtered)
        for stale in [
            f"/etc/openvpn/ca/pki/reqs/{params.username}.req",
            f"/etc/openvpn/ca/pki/private/{params.username}.key",
            f"/etc/openvpn/ca/pki/issued/{params.username}.crt",
        ]:
            if os.path.isfile(stale):
                os.remove(stale)
        env = os.environ.copy()
        env['EASYRSA_CERT_EXPIRE'] = '3650'
        result = subprocess.run(["./easyrsa", "--batch", "build-client-full", params.username, "nopass"], cwd="/etc/openvpn/ca", env=env, capture_output=True, check=False)
        if result.returncode != 0 or not os.path.isfile('/etc/openvpn/ca/pki/issued/' + params.username + '.crt'):
            LOG.error("easyrsa failed for %s: %s", params.username, result.stderr.decode())
            return {'result': 'error', 'reason': 'OpenVPN certificate creation failed', 'route': 'add_user'}

    content['users'][0].update(user_json)
    if content:
        LOG.debug("backup_config() in add user")
        backup_config()
        with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json', 'w') as f:
            json.dump(content, f, indent=4)
    else:
        LOG.debug("Empty data for add_user")
    if os.path.isfile('/etc/glorytun-tcp/tun0'):
        LOG.debug("Create user " + params.username + " in Glorytun-TCP")
        add_glorytun_tcp(userid)
    if os.path.isfile('/etc/glorytun-udp/tun0'):
        LOG.debug("Create user " + params.username + " in Glorytun-UDP")
        add_glorytun_udp(userid)
    if os.path.isfile('/etc/dsvpn/dsvpn0'):
        LOG.debug("Create user " + params.username + " in DSVPN")
        add_dsvpn(userid)
    if os.path.isfile('/etc/mqvpn/server.json'):
        LOG.debug("Create user " + params.username + " in MQVPN")
        add_mqvpn(params.username)
    if os.path.isfile('/var/lib/softether/vpn_server.config'):
        LOG.debug("Create user " + params.username + " in SoftEther VPN")
        if softethervpn_pass is None:
            softethervpn_pass = base64.urlsafe_b64encode(secrets.token_hex(16).encode()).decode('utf-8')
        add_softether_user(params.username, softethervpn_pass)
        modif_config_user(params.username, {'softethervpn': {'password': softethervpn_pass}})

    LOG.info("User admin (IP: " + request.client.host + ") added user " + params.username)

    #set_lastchange(30)
    #os.execv(__file__, sys.argv)
    #with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
    #    global fake_users_db
    #    omr_config_data = json.load(f)
    #    fake_users_db = omr_config_data['users'][0]

class ExistingUser(BaseModel):
    username: str = Query(..., title="Username")
    note: list = []

@app.post('/add_user_note', summary="Add a note to an user")
def add_user_note(*, params: ExistingUser, current_user: User = Depends(get_current_user)):
    if not current_user.permissions == "admin":
        return {'result': 'permission', 'reason': 'Need admin user', 'route': 'add_user'}
    modif_config_user(params.username,{"note": params.note})
    #set_lastchange(30)


class RemoveUser(BaseModel):
    username: str

@app.post('/remove_user', summary="Remove an user")
def remove_user(*, params: RemoveUser, current_user: User = Depends(get_current_user), request: Request):
    if not current_user.permissions == "admin":
        return {'result': 'permission', 'reason': 'Need admin user', 'route': 'remove_user'}
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        content = json.load(f)
    if not params.username in content['users'][0]:
        return {'result': 'error', 'reason': 'User doesnt exist', 'route': 'remove_user'}
    LOG.debug("Remove user " + params.username)
    userid = int(content['users'][0][params.username]['userid'])
    if userid == 0:
        return {'result': 'not allowed', 'reason': 'Userid 0 is protected', 'route': 'remove_user'}
    if os.path.isfile('/etc/shadowsocks-libev/manager.json'):
        shadowsocks_port = content['users'][0][params.username].get('shadowsocks_port')
        if shadowsocks_port is not None:
            remove_ss_user(str(shadowsocks_port))
    if os.path.isfile('/etc/shadowsocks-go/server.json'):
        remove_ss_go_user(params.username)
    if os.path.isfile('/etc/v2ray/v2ray-server.json'):
        v2ray_del_user(params.username)
    if os.path.isfile('/etc/xray/xray-server.json'):
        xray_del_user(params.username)
    del content['users'][0][params.username]
    if content:
        LOG.debug("backup_config() in remove user")
        backup_config()
        with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json', 'w') as f:
            json.dump(content, f, indent=4)
    else:
        LOG.debug("Empty data for remover_user")
    if os.path.isfile('/etc/openvpn/tun0.conf'):
        subprocess.run(["./easyrsa", "--batch", "revoke", params.username], cwd="/etc/openvpn/ca", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        env = os.environ.copy()
        env['EASYRSA_CRL_DAYS'] = '3650'
        subprocess.run(["./easyrsa", "gen-crl"], cwd="/etc/openvpn/ca", env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        subprocess.run(["chmod", "644", "/etc/openvpn/ca/pki/crl.pem"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        req_file = f"/etc/openvpn/ca/pki/reqs/{params.username}.req"
        if os.path.isfile(req_file):
            os.remove(req_file)
        # Kill user via OpenVPN API
        try:
            ovpn_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ovpn_socket.settimeout(2)
            ovpn_socket.connect(("127.0.0.1", 65302))
            fd = ovpn_socket.makefile('rb')
            line = fd.readline()
            if not line.startswith('>INFO:OpenVPN'.encode()):
                ovpn_socket.close()
                LOG.debug("OpenVPN error")
            else:
                ovpn_socket.send(('kill ' + params.username + '\r\n').encode())
            ovpn_socket.close()
        except socket.timeout as err:
            LOG.debug("OpenVPN stats timeout (" + str(err) + ")")
        except socket.error as err:
            LOG.debug("OpenVPN stats error (" + str(err) + ")")
        #os.system("systemctl -q restart openvpn@tun0" + ' >/dev/null 2>&1')
    if os.path.isfile('/etc/glorytun-tcp/tun0'):
        remove_glorytun_tcp(userid)
    if os.path.isfile('/etc/glorytun-udp/tun0'):
        remove_glorytun_udp(userid)
    if os.path.isfile('/etc/dsvpn/dsvpn0'):
        remove_dsvpn(userid)
    if os.path.isfile('/etc/mqvpn/server.json'):
        remove_mqvpn(params.username)
    if os.path.isfile('/var/lib/softether/vpn_server.config'):
        remove_softether_user(params.username)
    LOG.info("User admin (IP: " + request.client.host + ") removed user " + params.username)
    #set_lastchange(30)
    #os.execv(__file__, sys.argv)
    #with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
    #    global fake_users_db
    #    omr_config_data = json.load(f)
    #    fake_users_db = omr_config_data['users'][0]
    return {'result': 'done', 'reason': 'user removed', 'route': 'remove_user'}

class ModifyUser(BaseModel):
    username: str = Query(..., title="Username")
    user_password: Optional[str] = Query(None, title="New password for the user")
    disabled: Optional[bool] = Query(None, title="Disable or enable the user")
    vpn: Optional[VPN] = Query(None, title="VPN for the user")
    proxy: Optional[PROXY] = Query(None, title="Proxy for the user")

@app.post('/modify_user', summary="Modify an existing user")
def modify_user(*, params: ModifyUser, current_user: User = Depends(get_current_user), request: Request):
    if not current_user.permissions == "admin":
        return {'result': 'permission', 'reason': 'Need admin user', 'route': 'modify_user'}
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        content = json.load(f)
    if params.username not in content['users'][0]:
        return {'result': 'error', 'reason': 'User doesnt exist', 'route': 'modify_user'}
    changes = {}
    if params.user_password is not None:
        changes['user_password'] = params.user_password
    if params.disabled is not None:
        changes['disabled'] = "true" if params.disabled else "false"
    if params.vpn is not None:
        changes['vpn'] = params.vpn
    if params.proxy is not None:
        changes['proxy'] = params.proxy
    if not changes:
        return {'result': 'error', 'reason': 'No changes provided', 'route': 'modify_user'}
    modif_config_user(params.username, changes)
    LOG.info("User admin (IP: " + request.client.host + ") modified user " + params.username)
    return {'result': 'done', 'reason': 'user modified', 'route': 'modify_user'}

class ClienttoClient(BaseModel):
    enable: bool = False

@app.post('/client2client', summary="Enable client 2 client communications")
def client2client(*, params: ClienttoClient, current_user: User = Depends(get_current_user)):
    if not current_user.permissions == "admin":
        return {'result': 'permission', 'reason': 'Need admin user', 'route': 'client2client'}
    set_global_param('client2client', params.enable)
    initial_md5 = hashlib.md5(file_as_bytes(open('/etc/openvpn/tun0.conf', 'rb'))).hexdigest()
    fd, tmpfile = mkstemp()
    if os.path.isfile('/etc/openvpn/tun0.conf'):
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
            subprocess.run(["systemctl", "-q", "restart", "openvpn@tun0"], check=False)
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
        subprocess.run(["systemctl", "-q", "reload", "shorewall"], check=False)
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

@app.get('/get-number-of-users', summary="Get the total number of users")
def get_number_of_users(current_user: User = Depends(get_current_user)):
    if not current_user.permissions == "admin":
        return {'result': 'permission', 'reason': 'Need admin user', 'route': 'get-number-of-users'}
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        content = json.load(f)
        users = len(content['users'][0]) - 1
    return {'users': users}

@app.get('/speedtest', summary="Test download speed from the server")
async def speedtest(request: Request, size: Optional[int] = Query(10), current_user: User = Depends(get_current_user)):
    size_bytes = min(max(size, 1), 100) * 1024 * 1024
    chunk = b'\x00' * 65536

    mptcp = _mptcp_status_for_ip(request.client.host)

    async def generate():
        remaining = size_bytes
        while remaining > 0:
            send = min(65536, remaining)
            yield chunk[:send]
            remaining -= send

    return StreamingResponse(
        generate(),
        media_type="application/octet-stream",
        headers={
            "Content-Length": str(size_bytes),
            "Cache-Control": "no-store",
            "Content-Disposition": "attachment; filename=speedtest.bin",
            "X-MPTCP": mptcp,
        }
    )

@app.post('/speedtest', summary="Test upload speed from the server")
async def speedtestul(request: Request, current_user: User = Depends(get_current_user)):
    mptcp = _mptcp_status_for_ip(request.client.host)

    start = time.time()
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
    elapsed = time.time() - start
    speed_mbps = round((size * 8) / (elapsed * 1_000_000), 2) if elapsed > 0 and size > 0 else 0
    return {'bytes': size, 'duration': round(elapsed, 3), 'speed_mbps': speed_mbps, 'mptcp': mptcp}

def ipv6_enabled():
    ipv6_enabled = False
    addrs = netifaces.ifaddresses('lo')
    ipv6_addr_list = addrs.get(netifaces.AF_INET6,[])
    for ip_info in ipv6_addr_list:
        addr = ip_info['addr']
        if IPAddress(addr).version == 6:
            return True
    return ipv6_enabled

# MPTCP support -----------------------------------------------------------

# Protocol number for MPTCP sockets (Linux ≥ 5.6).
IPPROTO_MPTCP = 262


def _mptcp_status_for_ip(client_ip: str) -> str:
    """Return 'active', 'inactive', or 'unknown' for *client_ip*."""
    try:
        addr = ip_address(client_ip)
        if isinstance(addr, IPv6Address):
            mapped = addr.ipv4_mapped
            if mapped is None:
                return 'unknown'
            addr = mapped
        if not isinstance(addr, IPv4Address):
            return 'unknown'
        ipr = list(reversed(str(addr).split('.')))
        iptohex = '{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ipr))
        if path.exists('/proc/net/mptcp_net/mptcp'):
            with open('/proc/net/mptcp_net/mptcp') as f:
                return 'active' if iptohex in f.read() else 'inactive'
        # Kernel ≥ 5.6 path
        result = subprocess.run(
            ['ss', '-MtnH'],
            capture_output=True, text=True, timeout=2
        )
        return 'active' if str(addr) in result.stdout else 'inactive'
    except Exception:
        return 'unknown'


class MPTCPServer(uvicorn.Server):
    """uvicorn Server that tries to bind with an MPTCP socket.

    Falls back to a normal TCP socket transparently if the kernel does
    not support MPTCP (i.e. ``IPPROTO_MPTCP`` is unavailable or the
    ``bind()`` call fails).
    """

    def _make_mptcp_socket(self, host: str, port: int) -> Optional[_socket.socket]:
        af = _socket.AF_INET6 if ':' in host else _socket.AF_INET
        try:
            sock = _socket.socket(af, _socket.SOCK_STREAM, IPPROTO_MPTCP)
            sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
            sock.setblocking(False)
            sock.bind((host, port))
            sock.listen(128)
            LOG.info("MPTCP server socket bound on %s:%d", host, port)
            return sock
        except OSError as exc:
            LOG.info("MPTCP socket unavailable (%s) – falling back to TCP", exc)
            return None

    async def serve(self, sockets=None):
        if sockets is None:
            host = self.config.host or '0.0.0.0'
            port = self.config.port
            sock = self._make_mptcp_socket(host, port)
            if sock is not None:
                sockets = [sock]
        await super().serve(sockets=sockets)


def main(omrport: int, omrhost: str, workers: int):
    LOG.debug("Main OMR-Admin launch")
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    ssl_opts = dict(
        ssl_certfile='/etc/openmptcprouter-vps-admin/cert.pem',
        ssl_keyfile='/etc/openmptcprouter-vps-admin/key.pem',
        ssl_version=5,
    )
    if workers <= 1:
        # Single-worker: use MPTCPServer so the listening socket is MPTCP-aware.
        config = uvicorn.Config(
            app,
            host=omrhost, port=omrport, log_level='info',
            loop="asyncio", **ssl_opts
        )
        server = MPTCPServer(config=config)
        loop.run_until_complete(server.serve())
    else:
        # Multi-worker: uvicorn spawns subprocesses; each worker creates its
        # own socket.  Pass factory=None and let each worker try MPTCP via
        # the regular uvicorn.run path (socket override is not supported for
        # multi-process mode, so we fall back to standard TCP here).
        uvicorn.run(
            "omradmin:app",
            host=omrhost, port=omrport, log_level='info',
            workers=workers, loop="asyncio", **ssl_opts
        )

if __name__ == '__main__':
    import sys
    # When compiled with Cython, multiprocessing re-executes the binary with
    # "-c <code>" to spawn worker/resource-tracker processes. Intercept that
    # here before argparse sees it.
    if len(sys.argv) >= 2 and sys.argv[1] == '-c':
        code = sys.argv[2]
        # Shift away '-c <code>' so remaining args (e.g. '--multiprocessing-fork')
        # are at the positions multiprocessing internals expect.
        sys.argv = [sys.argv[0]] + sys.argv[3:]
        exec(code)
        sys.exit(0)
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        omr_config_data = json.load(f)
    omrport = 65500
    if 'port' in omr_config_data:
        omrport = omr_config_data["port"]
    if ipv6_enabled():
        omrhost = '::'
    else:
        omrhost = '0.0.0.0'
    if 'host' in omr_config_data:
        omrhost = omr_config_data["host"]
    workers = 2
    if 'workers' in omr_config_data:
        workers = omr_config_data["workers"]
    parser = argparse.ArgumentParser(description="OpenMPTCProuter Server API")
    parser.add_argument("--port", type=int, help="Listening port", default=omrport)
    parser.add_argument("--host", type=str, help="Listening host", default=omrhost)
    parser.add_argument("--workers", type=int, help="Workers", default=workers)
    args = parser.parse_args()
    main(args.port, args.host, args.workers)
    #uvicorn.run("__main__:app", host=omrhost, port=omrport, log_level='error', ssl_certfile='/etc/openmptcprouter-vps-admin/cert.pem', ssl_keyfile='/etc/openmptcprouter-vps-admin/key.pem', ssl_version=5, workers=6)

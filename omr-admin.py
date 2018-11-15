#!/usr/bin/env python3

import json
import base64
import uuid
import configparser
import subprocess
import os
from tempfile import mkstemp
from shutil import move
from pprint import pprint
from flask import Flask, jsonify, request
from flask_jwt_simple import (
    JWTManager, jwt_required, create_jwt, get_jwt_identity
)

app = Flask(__name__)

# Setup the Flask-JWT-Simple extension

# Generate a random secret key
app.config['JWT_SECRET_KEY'] = uuid.uuid4().hex

jwt = JWTManager(app)

# Get main net interface
file = open('/etc/shorewall/params.net', "r")
read = file.read()
iface = None
for line in read.splitlines():
    if 'NET_IFACE=' in line:
        iface=line.split('=',1)[1]

# Get interface rx/tx
def get_bytes(t, iface='eth0'):
    with open('/sys/class/net/' + iface + '/statistics/' + t + '_bytes', 'r') as f:
        data = f.read();
    return int(data)

def ordered(obj):
    if isinstance(obj, dict):
        return sorted((k, ordered(v)) for k, v in obj.items())
    if isinstance(obj, list):
        return sorted(ordered(x) for x in obj)
    else:
        return obj

# Provide a method to create access tokens. The create_jwt()
# function is used to actually generate the token
@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    with open('omr-admin-config.json') as f:
        omr_config_data = json.load(f)

    params = request.get_json()
    username = params.get('username', None)
    password = params.get('password', None)

    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400

    if username != omr_config_data["user"] or password != omr_config_data["pass"]:
        return jsonify({"msg": "Bad username or password"}), 401

    # Identity can be any data that is json serializable
    ret = {'token': create_jwt(identity=username)}
    return jsonify(ret), 200


# Get VPS status
@app.route('/status', methods=['GET'])
@jwt_required
def status():
    if iface:
        return jsonify({'tx': get_bytes('tx',iface),'rx': get_bytes('rx',iface)}), 200
    else:
        return jsonify({'error': 'No iface defined'}), 200

# Get VPS config
@app.route('/config', methods=['GET'])
@jwt_required
def config():
    with open('/etc/shadowsocks-libev/config.json') as f:
        data = json.load(f)
    shadowsocks_key = data["key"]
    shadowsocks_port = data["server_port"]
    shadowsocks_method = data["method"]
    shadowsocks_fast_open = data["fast_open"]
    shadowsocks_reuse_port = data["reuse_port"]
    shadowsocks_no_delay = data["no_delay"]
    shadowsocks_mptcp = data["mptcp"]
    if "plugin" in data:
        shadowsocks_obfs = True
    else:
        shadowsocks_obfs = False
    glorytun_key = open('/etc/glorytun-tcp/tun0.key').readline().rstrip()
    with open('/etc/openvpn/server/static.key',"rb") as ovpnkey_file:
        openvpn_key = base64.b64encode(ovpnkey_file.read())
    mlvpn_config = configparser.ConfigParser()
    mlvpn_config.readfp(open(r'/etc/mlvpn/mlvpn0.conf'))
    mlvpn_key = mlvpn_config.get('general','password').strip('"')

    mptcp_checksum = os.popen('sysctl -n net.mptcp.mptcp_checksum').read().rstrip()
    mptcp_path_manager = os.popen('sysctl -n  net.mptcp.mptcp_path_manager').read().rstrip()
    mptcp_scheduler = os.popen('sysctl -n net.mptcp.mptcp_scheduler').read().rstrip()
    mptcp_syn_retries = os.popen('sysctl -n net.mptcp.mptcp_syn_retries').read().rstrip()

    congestion_control = os.popen('sysctl -n net.ipv4.tcp_congestion_control').read().rstrip()

    shorewall_redirect = "enable"
    with open('/etc/shorewall/rules','r') as f:
        for line in f:
            if '#DNAT		net		vpn:$OMR_ADDR	tcp	1-64999' in line:
                shorewall_redirect = "disable"

    return jsonify({'shadowsocks': {'key': shadowsocks_key,'port': shadowsocks_port,'method': shadowsocks_method,'fast_open': shadowsocks_fast_open,'reuse_port': shadowsocks_reuse_port,'no_delay': shadowsocks_no_delay,'mptcp': shadowsocks_mptcp,'obfs': shadowsocks_obfs},'glorytun': {'key': glorytun_key},'openvpn': {'key': openvpn_key},'mlvpn': {'key': mlvpn_key},'shorewall': {'redirect_ports': shorewall_redirect},'mptcp': {'checksum': mptcp_checksum,'path_manager': mptcp_path_manager,'scheduler': mptcp_scheduler, 'syn_retries': mptcp_syn_retries},'network': {'congestion_control': congestion_control}}), 200

# Set shadowsocks config
@app.route('/shadowsocks', methods=['POST'])
@jwt_required
def shadowsocks():
    with open('/etc/shadowsocks-libev/config.json') as f:
        data = json.load(f)
    key = data["key"]
    timeout = data["timeout"]
    verbose = data["verbose"]
    prefer_ipv6 = data["prefer_ipv6"]
    params = request.get_json()
    port = params.get('port', None)
    method = params.get('method', None)
    fast_open = params.get('fast_open', None)
    reuse_port = params.get('reuse_port', None)
    no_delay = params.get('no_delay', None)
    mptcp = params.get('mptcp', None)
    obfs = params.get('obfs', None)
    if not port or not method or not fast_open or not reuse_port or not no_delay or not mptcp:
        return jsonify({'result': 'error','reason': 'Invalid parameters'})
    if obfs:
        shadowsocks_config = {'server': ('[::0]', '0.0.0.0'),'server_port': port,'local_port': 1081,'mode': 'tcp_and_udp','key': key,'timeout': timeout,'method': method,'verbose': verbose,'prefer_ipv6': prefer_ipv6,'fast_open': fast_open,'no_delay': no_delay,'reuse_port': reuse_port,'mptcp': mptcp,'plugin': '/usr/local/bin/obfs-server','plugin_opts': 'obfs=http;mptcp;fast-open;t=400'}
    else:
        shadowsocks_config = {'server': ('[::0]', '0.0.0.0'),'server_port': port,'local_port': 1081,'mode': 'tcp_and_udp','key': key,'timeout': timeout,'method': method,'verbose': verbose,'prefer_ipv6': prefer_ipv6,'fast_open': fast_open,'no_delay': no_delay,'reuse_port': reuse_port,'mptcp': mptcp}

    if ordered(data) != ordered(json.loads(json.dumps(shadowsocks_config))):
        with open('/etc/shadowsocks-libev/config.json','w') as outfile:
            json.dump(shadowsocks_config,outfile,ident=4)
        os.system("systemctl restart shadowsocks-libev-server@config.service")
        for x in range (1,os.cpu_count()):
            os.system("systemctl restart shadowsocks-libev-server@config" + str(x) + ".service")
        return jsonify(**shadowsocks_config)
    else:
        return jsonify({'result': 'done'})

# Set shorewall config
@app.route('/shorewall', methods=['POST'])
@jwt_required
def shorewall():
    params = request.get_json()
    state = params.get('redirect_ports', None)
    if not state:
        return jsonify({'result': 'error','reason': 'Invalid parameters'})
    fd, tmpfile = mkstemp()
    with open('/etc/shorewall/rules','r') as f, open(tmpfile,'a+') as n:
        for line in f:
            if state == 'enable' and '#DNAT		net		vpn:$OMR_ADDR	tcp	1-64999' in line:
                n.write(line.replace(line[:1], ''))
            elif state == 'enable' and '#DNAT		net		vpn:$OMR_ADDR	udp	1-64999' in line:
                n.write(line.replace(line[:1], ''))
            elif state == 'disable' and 'DNAT		net		vpn:$OMR_ADDR	tcp	1-64999' in line:
                n.write('#' + line)
            elif state == 'disable' and 'DNAT		net		vpn:$OMR_ADDR	udp	1-64999' in line:
                n.write('#' + line)
            else:
                n.write(line)
    os.close(fd)
    move(tmpfile,'/etc/shorewall/rules.new')
    #os.system("systemctl reload shorewall")
    # Need to do the same for IPv6...
    return jsonify({'result': 'done'})

# Set MPTCP config
@app.route('/mptcp', methods=['POST'])
@jwt_required
def mptcp():
    params = request.get_json()
    checksum = params.get('checksum', None)
    path_manager = params.get('path_manager', None)
    scheduler = params.get('scheduler', None)
    syn_retries = params.get('syn_retries', None)
    congestion_control = params.get('congestion_control', None)
    if not checksum or not path_manager or not scheduler or not syn_retries or not congestion_control:
        return jsonify({'result': 'error','reason': 'Invalid parameters'})
    os.system('sysctl -w net.mptcp.mptcp_checksum=' + checksum)
    os.system('sysctl -w net.mptcp.mptcp_path_manager=' + path_manager)
    os.system('sysctl -w net.mptcp.mptcp_scheduler=' + scheduler)
    os.system('sysctl -w net.mptcp.mptcp_syn_retries=' + syn_retries)
    os.system('sysctl -w net.ipv4.tcp_congestion_control=' + congestion_control)
    return jsonify({'result': 'done'})


# Set VPN config
#@app.route('/vpn', methods=['POST'])
#@jwt_required
#def vpn():
#    params = request.get_json()
#    type = params.get('type', None)
#    mtu = params.get('mtu', None)
#    return jsonify({'result': 'done'})


if __name__ == '__main__':
    app.run(host='0.0.0.0',port=65500,ssl_context=('cert.pem','key.pem'))

#!/usr/bin/env python3
# Copyright (C) 2018 Ycarus (Yannick Chabanois) <ycarus@zugaina.org>
#
# This is free software, licensed under the GNU General Public License v3.0.
# See /LICENSE for more information.
#

import json
import base64
import uuid
import configparser
import subprocess
import os
import re
from datetime import timedelta
from tempfile import mkstemp
from shutil import move
from pprint import pprint
from flask import Flask, jsonify, request, session
from flask_jwt_simple import (
    JWTManager, jwt_required, create_jwt, get_jwt_identity
)

app = Flask(__name__)

import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
# Setup the Flask-JWT-Simple extension

# Generate a random secret key
app.config['SECRET_KEY'] = uuid.uuid4().hex
app.config['JWT_SECRET_KEY'] = uuid.uuid4().hex
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

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

def shorewall_port(port,proto,name):
    fd, tmpfile = mkstemp()
    with open('/etc/shorewall/rules','r') as f, open(tmpfile,'a+') as n:
        for line in f:
            if not '# OMR open ' + name + ' port ' + proto in line:
                n.write(line)
        n.write('ACCEPT		net		$FW	' + proto + '	' + port + '	# OMR open ' + name + ' port ' + proto)
    os.close(fd)
    move(tmpfile,'/etc/shorewall/rules')
    os.system("systemctl -q reload shorewall")



# Provide a method to create access tokens. The create_jwt()
# function is used to actually generate the token
@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    session.permanent = True
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
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
    vps_loadavg = os.popen("cat /proc/loadavg | awk '{print $1\" \"$2\" \"$3}'").read().rstrip()
    vps_uptime = os.popen("cat /proc/uptime | awk '{print $1}'").read().rstrip()
    mptcp_enabled = os.popen('sysctl -n net.mptcp.mptcp_enabled').read().rstrip()

    if iface:
        return jsonify({'vps': {'loadavg': vps_loadavg,'uptime': vps_uptime,'mptcp': mptcp_enabled}, 'network': {'tx': get_bytes('tx',iface),'rx': get_bytes('rx',iface)}}), 200
    else:
        return jsonify({'error': 'No iface defined','route': 'status'}), 200

# Get VPS config
@app.route('/config', methods=['GET'])
@jwt_required
def config():
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        try:
            omr_config_data = json.load(f)
        except ValueError as e:
            omr_config_data = {}
    with open('/etc/shadowsocks-libev/config.json') as f:
        content = f.read()
    content = re.sub(",\s*}","}",content)
    try:
        data = json.loads(content)
    except ValueError as e:
        data = {'key': '', 'server_port': 65101, 'method': 'chacha20'}
    shadowsocks_key = data["key"]
    shadowsocks_port = data["server_port"]
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
    if os.path.isfile('/etc/glorytun-tcp/tun0.key'):
        glorytun_key = open('/etc/glorytun-tcp/tun0.key').readline().rstrip()
    else:
        glorytun_key = ''
    glorytun_port = '65001'
    if os.path.isfile('/etc/glorytun-tcp/tun0'):
        with open('/etc/glorytun-tcp/tun0',"r") as glorytun_file:
            for line in glorytun_file:
                if 'PORT=' in line:
                    glorytun_port = line.replace(line[:5], '').rstrip()
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
    if 'glorytun_udp_type' in omr_config_data:
        if omr_config_data['glorytun_udp_type'] == 'static':
            glorytun_udp_host_ip = '10.255.255.1'
            glorytun_udp_client_ip = '10.255.255.2'
        else:
            glorytun_udp_host_ip = 'dhcp'
            glorytun_udp_client_ip = 'dhcp'
    else:
        glorytun_udp_host_ip = '10.255.255.1'
        glorytun_udp_client_ip = '10.255.255.2'
    available_vpn = ["glorytun-tcp", "glorytun-udp"]

    if os.path.isfile('/etc/iperf3/public.pem'):
        with open('/etc/iperf3/public.pem',"rb") as iperfkey_file:
            iperf_keyb = base64.b64encode(iperfkey_file.read())
            iperf3_key = iperf_keyb.decode('utf-8')
    else:
        iperf3_key = ''

    if os.path.isfile('/etc/pihole/setupVars.conf'):
        pihole = True
    else:
        pihole = False

    if os.path.isfile('/etc/openvpn/server/static.key'):
        with open('/etc/openvpn/server/static.key',"rb") as ovpnkey_file:
            openvpn_keyb = base64.b64encode(ovpnkey_file.read())
            openvpn_key = openvpn_keyb.decode('utf-8')
        available_vpn.append("openvpn")
    else:
        openvpn_key = ''
    openvpn_port = '65301'
    if os.path.isfile('/etc/openvpn/openvpn-tun0.conf'):
        with open('/etc/openvpn/openvpn-tun0.conf',"r") as openvpn_file:
            for line in openvpn_file:
                if 'port ' in line:
                    openvpn_port = line.replace(line[:5], '').rstrip()
    openvpn_host_ip = '10.255.253.1'
    openvpn_client_ip = '10.255.253.2'
    #openvpn_client_ip = 'dhcp'

    if os.path.isfile('/etc/mlvpn/mlvpn0.conf'):
        mlvpn_config = configparser.ConfigParser()
        mlvpn_config.readfp(open(r'/etc/mlvpn/mlvpn0.conf'))
        mlvpn_key = mlvpn_config.get('general','password').strip('"')
        available_vpn.append("mlvpn")
    else:
        mlvpn_key = ''
    mlvpn_host_ip = ''
    mlvpn_client_ip = ''


    mptcp_enabled = os.popen('sysctl -n net.mptcp.mptcp_enabled').read().rstrip()
    mptcp_checksum = os.popen('sysctl -n net.mptcp.mptcp_checksum').read().rstrip()
    mptcp_path_manager = os.popen('sysctl -n  net.mptcp.mptcp_path_manager').read().rstrip()
    mptcp_scheduler = os.popen('sysctl -n net.mptcp.mptcp_scheduler').read().rstrip()
    mptcp_syn_retries = os.popen('sysctl -n net.mptcp.mptcp_syn_retries').read().rstrip()

    congestion_control = os.popen('sysctl -n net.ipv4.tcp_congestion_control').read().rstrip()

    ipv6_network = os.popen('ip -6 addr show ' + iface +' | grep -oP "(?<=inet6 ).*(?= scope global)"').read().rstrip()
    #ipv6_addr = os.popen('wget -6 -qO- -T 2 ipv6.openmptcprouter.com').read().rstrip()
    ipv6_addr = os.popen('ip -6 addr show ' + iface +' | grep -oP "(?<=inet6 ).*(?= scope global)" | cut -d/ -f1').read().rstrip()
    ipv4_addr = os.popen('wget -4 -qO- -T 2 http://ip.openmptcprouter.com').read().rstrip()

    vps_kernel = os.popen('uname -r').read().rstrip()
    vps_machine = os.popen('uname -m').read().rstrip()
    vps_omr_version = os.popen("grep -s 'OpenMPTCProuter VPS' /etc/* | awk '{print $4}'").read().rstrip()
    vps_loadavg = os.popen("cat /proc/loadavg | awk '{print $1" "$2" "$3}'").read().rstrip()
    vps_uptime = os.popen("cat /proc/uptime | awk '{print $1}'").read().rstrip()
    vps_domain = os.popen('wget -4 -qO- -T 2 http://hostname.openmptcprouter.com').read().rstrip()

    shorewall_redirect = "enable"
    with open('/etc/shorewall/rules','r') as f:
        for line in f:
            if '#DNAT		net		vpn:$OMR_ADDR	tcp	1-64999' in line:
                shorewall_redirect = "disable"

    return jsonify({'vps': {'kernel': vps_kernel,'machine': vps_machine,'omr_version': vps_omr_version,'loadavg': vps_loadavg,'uptime': vps_uptime},'shadowsocks': {'key': shadowsocks_key,'port': shadowsocks_port,'method': shadowsocks_method,'fast_open': shadowsocks_fast_open,'reuse_port': shadowsocks_reuse_port,'no_delay': shadowsocks_no_delay,'mptcp': shadowsocks_mptcp,'ebpf': shadowsocks_ebpf,'obfs': shadowsocks_obfs,'obfs_plugin': shadowsocks_obfs_plugin,'obfs_type': shadowsocks_obfs_type},'glorytun': {'key': glorytun_key,'udp': {'host_ip': glorytun_udp_host_ip,'client_ip': glorytun_udp_client_ip},'tcp': {'host_ip': glorytun_tcp_host_ip,'client_ip': glorytun_tcp_client_ip},'port': glorytun_port},'openvpn': {'key': openvpn_key, 'host_ip': openvpn_host_ip, 'client_ip': openvpn_client_ip, 'port': openvpn_port},'mlvpn': {'key': mlvpn_key, 'host_ip': mlvpn_host_ip, 'client_ip': mlvpn_client_ip},'shorewall': {'redirect_ports': shorewall_redirect},'mptcp': {'enabled': mptcp_enabled,'checksum': mptcp_checksum,'path_manager': mptcp_path_manager,'scheduler': mptcp_scheduler, 'syn_retries': mptcp_syn_retries},'network': {'congestion_control': congestion_control,'ipv6_network': ipv6_network,'ipv6': ipv6_addr,'ipv4': ipv4_addr,'domain': vps_domain},'vpn': {'available': available_vpn},'iperf': {'user': 'openmptcprouter','password': 'openmptcprouter', 'key': iperf3_key},'pihole': {'state': pihole}}), 200

# Set shadowsocks config
@app.route('/shadowsocks', methods=['POST'])
@jwt_required
def shadowsocks():
    with open('/etc/shadowsocks-libev/config.json') as f:
        content = f.read()
    content = re.sub(",\s*}","}",content)
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
    params = request.get_json()
    port = params.get('port', None)
    method = params.get('method', None)
    fast_open = params.get('fast_open', None)
    reuse_port = params.get('reuse_port', None)
    no_delay = params.get('no_delay', None)
    mptcp = params.get('mptcp', None)
    obfs = params.get('obfs', False)
    obfs_plugin = params.get('obfs_plugin', False)
    obfs_type = params.get('obfs_type', None)
    ebpf = params.get('ebpf', False)
    key = params.get('key', None)
    if not key:
        if 'key' in data:
            key = data["key"]
    ipv4_addr = os.popen('wget -4 -qO- -T 2 http://ip.openmptcprouter.com').read().rstrip()
    vps_domain = os.popen('dig +noall +answer -x ' + ipv4_addr + " | awk '{print substr($5,1,length($5)-1)}'").read().rstrip()
    vps_domain_test = os.popen('dig +noall +answer ' + vps_domain).read().rstrip()
    if not vps_domain_test:
        vps_domain = ''

    if port is None or method is None or fast_open is None or reuse_port is None or no_delay is None or key is None:
        return jsonify({'result': 'error','reason': 'Invalid parameters','route': 'shadowsocks'})
    if obfs:
        if obfs_plugin == 'v2ray':
            if obfs_type == 'tls':
                if vps_domain == '':
                    shadowsocks_config = {'server': '::0','server_port': port,'local_port': 1081,'mode': 'tcp_and_udp','key': key,'timeout': timeout,'method': method,'verbose': verbose,'ipv6_first': True, 'prefer_ipv6': prefer_ipv6,'fast_open': fast_open,'no_delay': no_delay,'reuse_port': reuse_port,'mptcp': mptcp,'ebpf': ebpf,'plugin': '/usr/local/bin/v2ray-plugin','plugin_opts': 'server;tls'}
                else:
                    shadowsocks_config = {'server': '::0','server_port': port,'local_port': 1081,'mode': 'tcp_and_udp','key': key,'timeout': timeout,'method': method,'verbose': verbose,'ipv6_first': True, 'prefer_ipv6': prefer_ipv6,'fast_open': fast_open,'no_delay': no_delay,'reuse_port': reuse_port,'mptcp': mptcp,'ebpf': ebpf,'plugin': '/usr/local/bin/v2ray-plugin','plugin_opts': 'server;tls;host=' + vps_domain}
            else:
                shadowsocks_config = {'server': '::0','server_port': port,'local_port': 1081,'mode': 'tcp_and_udp','key': key,'timeout': timeout,'method': method,'verbose': verbose,'ipv6_first': True, 'prefer_ipv6': prefer_ipv6,'fast_open': fast_open,'no_delay': no_delay,'reuse_port': reuse_port,'mptcp': mptcp,'ebpf': ebpf,'plugin': '/usr/local/bin/v2ray-plugin','plugin_opts': 'server'}
        else:
            if obfs_type == 'tls':
                if vps_domain == '':
                    shadowsocks_config = {'server': ('[::0]', '0.0.0.0'),'server_port': port,'local_port': 1081,'mode': 'tcp_and_udp','key': key,'timeout': timeout,'method': method,'verbose': verbose,'ipv6_first': True, 'prefer_ipv6': prefer_ipv6,'fast_open': fast_open,'no_delay': no_delay,'reuse_port': reuse_port,'mptcp': mptcp,'ebpf': ebpf,'plugin': '/usr/local/bin/obfs-server','plugin_opts': 'obfs=tls;mptcp;fast-open;t=400'}
                else:
                    shadowsocks_config = {'server': ('[::0]', '0.0.0.0'),'server_port': port,'local_port': 1081,'mode': 'tcp_and_udp','key': key,'timeout': timeout,'method': method,'verbose': verbose,'ipv6_first': True, 'prefer_ipv6': prefer_ipv6,'fast_open': fast_open,'no_delay': no_delay,'reuse_port': reuse_port,'mptcp': mptcp,'ebpf': ebpf,'plugin': '/usr/local/bin/obfs-server','plugin_opts': 'obfs=tls;mptcp;fast-open;t=400;host=' + vps_domain}
            else:
                shadowsocks_config = {'server': ('[::0]', '0.0.0.0'),'server_port': port,'local_port': 1081,'mode': 'tcp_and_udp','key': key,'timeout': timeout,'method': method,'verbose': verbose,'ipv6_first': True, 'prefer_ipv6': prefer_ipv6,'fast_open': fast_open,'no_delay': no_delay,'reuse_port': reuse_port,'mptcp': mptcp,'ebpf': ebpf,'plugin': '/usr/local/bin/obfs-server','plugin_opts': 'obfs=http;mptcp;fast-open;t=400'}
    else:
        shadowsocks_config = {'server': ('[::0]', '0.0.0.0'),'server_port': port,'local_port': 1081,'mode': 'tcp_and_udp','key': key,'timeout': timeout,'method': method,'verbose': verbose,'ipv6_first': True, 'prefer_ipv6': prefer_ipv6,'fast_open': fast_open,'no_delay': no_delay,'reuse_port': reuse_port,'mptcp': mptcp,'ebpf': ebpf}

    if ordered(data) != ordered(json.loads(json.dumps(shadowsocks_config))):
        with open('/etc/shadowsocks-libev/config.json','w') as outfile:
            json.dump(shadowsocks_config,outfile,indent=4)
        os.system("systemctl restart shadowsocks-libev-server@config.service")
        for x in range (1,os.cpu_count()):
            os.system("systemctl restart shadowsocks-libev-server@config" + str(x) + ".service")
        shorewall_port(str(port),'tcp','shadowsocks')
        shorewall_port(str(port),'udp','shadowsocks')
        return jsonify({'result': 'done','reason': 'changes applied','route': 'shadowsocks'})
    else:
        return jsonify({'result': 'done','reason': 'no changes','route': 'shadowsocks'})

# Set shorewall config
@app.route('/shorewall', methods=['POST'])
@jwt_required
def shorewall():
    params = request.get_json()
    state = params.get('redirect_ports', None)
    if state is None:
        return jsonify({'result': 'error','reason': 'Invalid parameters','route': 'shorewall'})
    fd, tmpfile = mkstemp()
    with open('/etc/shorewall/rules','r') as f, open(tmpfile,'a+') as n:
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
    move(tmpfile,'/etc/shorewall/rules')
    os.system("systemctl -q reload shorewall")
    # Need to do the same for IPv6...
    return jsonify({'result': 'done','reason': 'changes applied'})

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
        return jsonify({'result': 'error','reason': 'Invalid parameters','route': 'mptcp'})
    os.system('sysctl -qw net.mptcp.mptcp_checksum=' + checksum)
    os.system('sysctl -qw net.mptcp.mptcp_path_manager=' + path_manager)
    os.system('sysctl -qw net.mptcp.mptcp_scheduler=' + scheduler)
    os.system('sysctl -qw net.mptcp.mptcp_syn_retries=' + syn_retries)
    os.system('sysctl -qw net.ipv4.tcp_congestion_control=' + congestion_control)
    return jsonify({'result': 'done','reason': 'changes applied'})


# Set Glorytun config
@app.route('/glorytun', methods=['POST'])
@jwt_required
def glorytun():
    params = request.get_json()
    key = params.get('key', None)
    port = params.get('port', None)
    if not key or port is None:
        return jsonify({'result': 'error','reason': 'Invalid parameters','route': 'glorytun'})
    with open('/etc/glorytun-tcp/tun0.key','w') as outfile:
        outfile.write(key)
    with open('/etc/glorytun-udp/tun0.key','w') as outfile:
        outfile.write(key)
    fd, tmpfile = mkstemp()
    with open('/etc/glorytun-tcp/tun0','r') as f, open(tmpfile,'a+') as n:
        for line in f:
            if 'PORT=' in line:
                n.write('PORT=' + str(port) + '\n')
            else:
                n.write(line)
    os.close(fd)
    move(tmpfile,'/etc/glorytun-tcp/tun0')
    os.system("systemctl -q restart glorytun-tcp@tun0")
    fd, tmpfile = mkstemp()
    with open('/etc/glorytun-udp/tun0','r') as f, open(tmpfile,'a+') as n:
        for line in f:
            if 'BIND_PORT=' in line:
                n.write('BIND_PORT=' + str(port) + '\n')
            else:
                n.write(line)
    os.close(fd)
    move(tmpfile,'/etc/glorytun-udp/tun0')
    os.system("systemctl -q restart glorytun-udp@tun0")
    shorewall_port(port,str(port),'glorytun')
    return jsonify({'result': 'done'})

# Set OpenVPN config
@app.route('/openvpn', methods=['POST'])
@jwt_required
def openvpn():
    params = request.get_json()
    key = params.get('key', None)
    if not key:
        return jsonify({'result': 'error','reason': 'Invalid parameters','route': 'openvpn'})
    with open('/etc/openvpn/server/static.key','w') as outfile:
        outfile.write(base64.b64decode(key))
    os.system("systemctl -q restart openvpn@tun0")
    return jsonify({'result': 'done'})

# Update VPS
@app.route('/update', methods=['GET'])
@jwt_required
def update():
    os.system("wget -O - http://www.openmptcprouter.com/server/debian9-x86_64.sh | sh")
    # Need to reboot if kernel change
    return jsonify({'result': 'done'})

if __name__ == '__main__':
    with open('/etc/openmptcprouter-vps-admin/omr-admin-config.json') as f:
        omr_config_data = json.load(f)
    omrport=65500
    if 'port' in omr_config_data:
        omrport = omr_config_data["port"]
    app.run(host='0.0.0.0',port=omrport,ssl_context=('/etc/openmptcprouter-vps-admin/cert.pem','/etc/openmptcprouter-vps-admin/key.pem'),threaded=True)

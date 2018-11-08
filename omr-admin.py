import json
import base64
import uuid
import configparser
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

    params = request.get_json()
    username = params.get('username', None)
    password = params.get('password', None)

    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400

    if username != 'test' or password != 'test':
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
    mlvpn_key = mlvpn_config.get('general','password')

    return jsonify({'shadowsocks': {'key': shadowsocks_key,'port': shadowsocks_port,'method': shadowsocks_method,'fast_open': shadowsocks_fast_open,'reuse_port': shadowsocks_reuse_port,'no_delay': shadowsocks_no_delay,'mptcp': shadowsocks_mptcp,'obfs': shadowsocks_obfs},'glorytun': {'key': glorytun_key},'openvpn': {'key': openvpn_key}}), 200

# Set shadowsocks config
@app.route('/shadowsocks', methods=['POST'])
@jwt_required
def shadowsocks():
    with open('/etc/shadowsocks-libev/config.json.new') as f:
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
    if obfs:
        shadowsocks_config = {'server': ('[::0]', '0.0.0.0'),'server_port': port,'local_port': 1081,'mode': 'tcp_and_udp','key': key,'timeout': timeout,'method': method,'verbose': verbose,'prefer_ipv6': prefer_ipv6,'fast_open': fast_open,'no_delay': no_delay,'reuse_port': reuse_port,'mptcp': mptcp,'plugin': '/usr/local/bin/obfs-server','plugin_opts': 'obfs=http;mptcp;fast-open;t=400'}
    else:
        shadowsocks_config = {'server': ('[::0]', '0.0.0.0'),'server_port': port,'local_port': 1081,'mode': 'tcp_and_udp','key': key,'timeout': timeout,'method': method,'verbose': verbose,'prefer_ipv6': prefer_ipv6,'fast_open': fast_open,'no_delay': no_delay,'reuse_port': reuse_port,'mptcp': mptcp}

    if ordered(data) != ordered(json.loads(json.dumps(shadowsocks_config))):
        with open('/etc/shadowsocks-libev/config.json.new','w') as outfile:
            json.dump(shadowsocks_config,outfile)
        return jsonify(**shadowsocks_config)
    else:
        return jsonify({'result': 'done'})

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=65500,ssl_context=('cert.pem','key.pem'))

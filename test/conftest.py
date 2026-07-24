"""
Shared pytest configuration for omr-admin API tests.

Strategy
--------
1. Patch ``builtins.open`` *before* importing the module so the three
   module-level file reads (shorewall params + config JSON) succeed.
2. Import the real module via importlib (the filename has a hyphen).
3. Provide client fixtures that inject mock users via FastAPI dependency
   overrides so tests never need a running filesystem.
4. An autouse fixture suppresses all filesystem writes and subprocess
   calls for every test.
"""

import builtins
import asyncio
import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta
from urllib.parse import urlencode, urlsplit
from unittest.mock import MagicMock, patch

import jwt
import pytest

# ---------------------------------------------------------------------------
# Mock configuration (mirrors omr-admin-config.json)
# ---------------------------------------------------------------------------

SECRET_KEY = "test_secret_key_long_enough_for_jwt_12345"
ALGORITHM = "HS256"

MOCK_CONFIG = {
    "port": 65500,
    "secret_key": SECRET_KEY,
    "gre_tunnels": False,   # skip add_gre_tunnels() at import time
    "users": [
        {
            "admin": {
                "username": "admin",
                "user_password": "adminpassword",
                "permissions": "admin",
                "disabled": False,
            },
            "openmptcprouter": {
                "userid": 0,
                "username": "openmptcprouter",
                "user_password": "userpassword",
                "shadowsocks_port": 65101,
                "disabled": False,
                "proxy": "shadowsocks",
                "vpn": "glorytun_tcp",
            },
            "readonly": {
                "userid": 2,
                "username": "readonly",
                "user_password": "ropassword",
                "shadowsocks_port": 65102,
                "permissions": "ro",
                "disabled": False,
            },
        }
    ],
    "debug": False,
}

_CONFIG_JSON = json.dumps(MOCK_CONFIG)
_SHOREWALL = "NET_IFACE=eth0\n"
_REAL_OPEN = builtins.open

MQVPN_CONFIG = {
    "mode": "server",
    "listen": "0.0.0.0:443",
    "subnet": "10.255.220.0/24",
    "subnet6": "fd00:abcd::/112",
    "cert_file": "/etc/mqvpn/server.crt",
    "key_file": "/etc/mqvpn/server.key",
    "auth_key": "test-auth-key",
    "users": [
        {"name": "openmptcprouter", "key": "user-mqvpn-key"},
    ],
    "max_clients": 64,
    "scheduler": "wlb",
    "cc": "bbr2",
    "reorder": {"enabled": "off", "max_wait_ms": 30, "cap_packets": 1024},
    "reorder_rules": [
        {"proto": "udp", "port": 443, "profile": "fiber_lte"},
    ],
}
_MQVPN_CONFIG_JSON = json.dumps(MQVPN_CONFIG)

_WG_CONF = (
    "[Interface]\n"
    "ListenPort = 65400\n"
    "PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
)

_MLVPN_CONF = (
    "[general]\n"
    'password = "oldpassword"\n'
    "timeout = 60\n"
    "reorder_buffer_size = 0\n"
    "loss_tolerence = 50\n"
    "cleartext_data = 0\n"
)


def _mock_open(path, mode="r", *args, **kwargs):
    """Route well-known paths to in-memory buffers; fall through for the rest."""
    sp = str(path)
    binary = "b" in str(mode)

    if sp in ("/etc/shorewall/params.net", "/etc/shorewall6/params.net"):
        return io.BytesIO(_SHOREWALL.encode()) if binary else io.StringIO(_SHOREWALL)

    if sp == "/etc/openmptcprouter-vps-admin/omr-admin-config.json":
        return io.BytesIO(_CONFIG_JSON.encode()) if binary else io.StringIO(_CONFIG_JSON)

    if sp == "/etc/mqvpn/server.json":
        return io.BytesIO(_MQVPN_CONFIG_JSON.encode()) if binary else io.StringIO(_MQVPN_CONFIG_JSON)

    if sp == "/etc/wireguard/wg0.conf":
        return io.BytesIO(_WG_CONF.encode()) if binary else io.StringIO(_WG_CONF)

    if sp == "/etc/mlvpn/mlvpn0.conf":
        return io.BytesIO(_MLVPN_CONF.encode()) if binary else io.StringIO(_MLVPN_CONF)

    # Silently discard all writes
    if "w" in str(mode) or "a" in str(mode):
        return io.BytesIO() if binary else io.StringIO()

    # Real files that actually exist (e.g. Python stdlib, pytest internals)
    try:
        return _REAL_OPEN(path, mode, *args, **kwargs)
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        return io.BytesIO() if binary else io.StringIO()


# ---------------------------------------------------------------------------
# Import the real module with file mocks active at import time
# ---------------------------------------------------------------------------

_PARENT_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
if _PARENT_DIR not in sys.path:
    sys.path.insert(0, _PARENT_DIR)

builtins.open = _mock_open
try:
    _module_path = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "omradmin.py")
    )
    _spec = importlib.util.spec_from_file_location("omr_admin", _module_path)
    omr_admin = importlib.util.module_from_spec(_spec)
    sys.modules["omr_admin"] = omr_admin
    _spec.loader.exec_module(omr_admin)
finally:
    builtins.open = _REAL_OPEN

app = omr_admin.app


@contextlib.asynccontextmanager
async def _test_lifespan(app):
    yield


app.router.lifespan_context = _test_lifespan


class _ASGIResponse:
    def __init__(self, status_code: int, headers: list, content: bytes):
        self.status_code = status_code
        self.headers = {
            k.decode("latin1").lower(): v.decode("latin1")
            for k, v in headers
        }
        self.content = content
        self.text = content.decode("utf-8", errors="replace")

    def json(self):
        return json.loads(self.text)


class _ResponseComplete(Exception):
    pass


class _ASGITestClient:
    """Small sync client for tests, avoiding TestClient's blocking portal."""

    def __init__(self, app, raise_server_exceptions: bool = False):
        self._app = app
        self._raise_server_exceptions = raise_server_exceptions

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def request(self, method, url, **kwargs):
        async def _request():
            body = b""
            headers = [
                (k.lower().encode("latin1"), str(v).encode("latin1"))
                for k, v in (kwargs.get("headers") or {}).items()
            ]
            if "json" in kwargs:
                body = json.dumps(kwargs["json"]).encode()
                headers.append((b"content-type", b"application/json"))
            elif "data" in kwargs:
                data = kwargs["data"]
                body = urlencode(data).encode() if isinstance(data, dict) else data
                headers.append((b"content-type", b"application/x-www-form-urlencoded"))
            elif "content" in kwargs:
                body = kwargs["content"]
                if isinstance(body, str):
                    body = body.encode()

            parts = urlsplit(url)
            query = parts.query
            params = kwargs.get("params")
            if params:
                extra = urlencode(params, doseq=True)
                query = f"{query}&{extra}" if query else extra

            scope = {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": method,
                "scheme": parts.scheme or "http",
                "path": parts.path or "/",
                "raw_path": (parts.path or "/").encode(),
                "query_string": query.encode(),
                "headers": headers,
                "client": ("testclient", 50000),
                "server": ("testserver", 80),
                "root_path": "",
                "extensions": {},
            }
            sent_request = False
            status = 500
            response_headers = []
            chunks = []

            async def receive():
                nonlocal sent_request
                if sent_request:
                    return {"type": "http.disconnect"}
                sent_request = True
                return {"type": "http.request", "body": body, "more_body": False}

            async def send(message):
                nonlocal status, response_headers
                if message["type"] == "http.response.start":
                    status = message["status"]
                    response_headers = message.get("headers", [])
                elif message["type"] == "http.response.body":
                    chunks.append(message.get("body", b""))
                    if not message.get("more_body", False):
                        raise _ResponseComplete

            try:
                await asyncio.wait_for(self._app(scope, receive, send), 0.2)
            except _ResponseComplete:
                pass
            except asyncio.TimeoutError:
                if not chunks:
                    raise
            except Exception:
                if self._raise_server_exceptions:
                    raise
                status = 500
                response_headers = [(b"content-type", b"text/plain; charset=utf-8")]
                chunks = [b"Internal Server Error"]
            return _ASGIResponse(status, response_headers, b"".join(chunks))

        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_request())
        finally:
            loop.close()

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def put(self, url, **kwargs):
        return self.request("PUT", url, **kwargs)

    def delete(self, url, **kwargs):
        return self.request("DELETE", url, **kwargs)


# ---------------------------------------------------------------------------
# Shared user objects (used in dependency overrides)
# ---------------------------------------------------------------------------

ADMIN_USER = omr_admin.User(
    username="admin", permissions="admin", disabled=False
)
RW_USER = omr_admin.User(
    username="openmptcprouter", userid=0, permissions="rw",
    shadowsocks_port=65101, disabled=False,
)
RO_USER = omr_admin.User(
    username="readonly", userid=2, permissions="ro",
    shadowsocks_port=65102, disabled=False,
)

# ---------------------------------------------------------------------------
# Token helpers (for auth-endpoint tests that exercise the real JWT path)
# ---------------------------------------------------------------------------

def make_token(username: str) -> str:
    exp = datetime.utcnow() + timedelta(hours=2)
    return jwt.encode({"sub": username, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)


ADMIN_TOKEN = make_token("admin")
USER_TOKEN  = make_token("openmptcprouter")
RO_TOKEN    = make_token("readonly")


def admin_headers():
    return {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def user_headers():
    return {"Authorization": f"Bearer {USER_TOKEN}"}


# ---------------------------------------------------------------------------
# Autouse fixture – suppress side-effects for every test
# ---------------------------------------------------------------------------

def _ospopen_factory(*args, **kwargs):
    """Mock for os.popen (legacy interface)."""
    m = MagicMock()
    m.read.return_value = ""
    m.readline.return_value = ""
    m.returncode = 1
    return m


def _subprocess_popen_factory(*args, **kwargs):
    """Mock for subprocess.Popen – returncode=1 means 'not found'."""
    m = MagicMock()
    m.communicate.return_value = (b"", b"")
    m.returncode = 1
    return m


def _requests_get_factory(*args, **kwargs):
    """Mock for requests.get – returns empty text so code stays on the happy path."""
    m = MagicMock()
    m.text = ""
    m.json.return_value = {}
    m.status_code = 200
    return m


@pytest.fixture(autouse=True)
def patch_env():
    """Prevent actual filesystem writes and subprocess calls in every test."""
    with (
        patch("builtins.open", side_effect=_mock_open),
        patch("os.system", return_value=0),
        patch("subprocess.run", return_value=MagicMock(returncode=0)),
        patch("os.popen", side_effect=_ospopen_factory),
        patch("shutil.copy2"),
        patch("omr_admin.move"),
        patch("os.remove"),
        patch("subprocess.check_output", return_value=b""),
        patch("subprocess.Popen", side_effect=_subprocess_popen_factory),
        patch("omr_admin.requests.get", side_effect=_requests_get_factory),
    ):
        yield


# ---------------------------------------------------------------------------
# Client fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def unauth_client():
    """No authentication – used to verify 403 on protected endpoints."""
    yield _ASGITestClient(app, raise_server_exceptions=False)


@pytest.fixture
def admin_client():
    """Admin user injected via dependency override."""
    app.dependency_overrides[omr_admin.get_current_user] = lambda: ADMIN_USER
    yield _ASGITestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.pop(omr_admin.get_current_user, None)


@pytest.fixture
def user_client():
    """Read-write user injected via dependency override."""
    app.dependency_overrides[omr_admin.get_current_user] = lambda: RW_USER
    yield _ASGITestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.pop(omr_admin.get_current_user, None)


@pytest.fixture
def ro_client():
    """Read-only user injected via dependency override."""
    app.dependency_overrides[omr_admin.get_current_user] = lambda: RO_USER
    yield _ASGITestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.pop(omr_admin.get_current_user, None)

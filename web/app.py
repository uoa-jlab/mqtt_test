import json
import os
import re
import sys
import threading
import uuid
from functools import wraps
from datetime import timedelta
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

# Patch standard library for Gevent concurrency (must be first)
# This makes requests.get() and time.sleep() non-blocking greenlets
from gevent import monkey
monkey.patch_all()

import requests
from flask import (
    Flask,
    Response,
    abort,
    g,
    jsonify,
    render_template,
    request,
    stream_with_context,
    send_from_directory,
    session,
    redirect,
    url_for,
    flash,
    send_file,
    after_this_request
)
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask_socketio import SocketIO as _SocketIO, emit as ws_emit, disconnect as ws_disconnect
import zipfile
import tempfile
from gevent.pywsgi import WSGIServer

import db_manager
from config_backend import ConfigValidationError, build_config_service_from_env
from discovery_backend import (
    DEFAULT_PORT as CONFIG_DEVICE_TCP_PORT,
    DEFAULT_TIMEOUT as DISCOVER_DEFAULT_TIMEOUT,
    collect_broadcast_addrs,
    discover_devices as discover_lan_devices,
    send_device_payload,
)
from license_backend import LicenseConfig, LicenseError, LicenseService

"""
Tiny Flask app that proxies data from the MQTT bridge to the browser UI.
轻量级 Flask 应用，用于将 MQTT 桥服务安全地代理到浏览器界面。
"""


BRIDGE_API_BASE_URL = os.getenv("BRIDGE_API_BASE_URL", "http://localhost:5001")
BRIDGE_TIMEOUT_CONNECT = float(os.getenv("BRIDGE_CONNECT_TIMEOUT", "5"))
BRIDGE_TIMEOUT_READ = os.getenv("BRIDGE_READ_TIMEOUT")  # 允许为空
if BRIDGE_TIMEOUT_READ is not None:
    try:
        BRIDGE_TIMEOUT_READ = float(BRIDGE_TIMEOUT_READ)
    except ValueError:
        BRIDGE_TIMEOUT_READ = None  # 非法值视为 None（不设读超时）

CONFIG_CONSOLE_PORT = int(os.getenv("CONFIG_CONSOLE_PORT", "5002"))
CONFIG_CONSOLE_ENABLED = os.getenv("CONFIG_CONSOLE_ENABLED", "1") != "0"

LICENSE_ENABLED = os.getenv("LICENSE_ENABLED", "1") != "0"
_LICENSE_DIR_FALLBACK = Path(__file__).resolve().parent.parent / "license"
LICENSE_KEY_PATH = Path(os.getenv("LICENSE_KEY_PATH", _LICENSE_DIR_FALLBACK / "priv.pem"))
LICENSE_HISTORY_PATH_RAW = os.getenv("LICENSE_HISTORY_PATH", str(_LICENSE_DIR_FALLBACK / "licenses_history.json"))
LICENSE_TCP_PORT = int(os.getenv("LICENSE_TCP_PORT", os.getenv("CONFIG_DEVICE_TCP_PORT", "22345")))
LICENSE_TCP_TIMEOUT = float(os.getenv("LICENSE_TCP_TIMEOUT", "5"))
LICENSE_DEFAULT_DAYS = int(os.getenv("LICENSE_DEFAULT_DAYS", "365"))
LICENSE_DEFAULT_TIER = os.getenv("LICENSE_DEFAULT_TIER", "basic")
DISCOVER_DEFAULT_ATTEMPTS = int(os.getenv("CONFIG_DISCOVER_ATTEMPTS", "2"))
DISCOVER_DEFAULT_GAP = float(os.getenv("CONFIG_DISCOVER_GAP", "0.2"))

# 擁有全設備可見性的帳號（等同 admin 權限，不受 user_group 過濾）
_SUPERUSER_IDS: frozenset[str] = frozenset({"admin", "user"})

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")
if not app.secret_key:
    # Generates a random key each restart (secure, but invalidates sessions on restart)
    app.secret_key = os.urandom(24).hex()
    print("[SECURITY WARNING] FLASK_SECRET_KEY not set. Using random key.", file=sys.stderr)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# --- Token auth ---
TOKEN_EXPIRY = int(os.getenv("API_TOKEN_EXPIRY", str(24 * 3600)))  # 默认 24 小时
_token_serializer: URLSafeTimedSerializer | None = None

def _get_token_serializer() -> URLSafeTimedSerializer:
    global _token_serializer
    if _token_serializer is None:
        _token_serializer = URLSafeTimedSerializer(app.secret_key, salt="api-token")
    return _token_serializer

def _get_current_user() -> dict | None:
    """从 session 或 Authorization: Bearer header 获取当前用户。"""
    if 'sso_id' in session:
        return {'sso_id': session['sso_id']}
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        raw = auth_header[7:].strip()
        try:
            data = _get_token_serializer().loads(raw, max_age=TOKEN_EXPIRY)
            return {'sso_id': data['sso_id']}
        except (BadSignature, SignatureExpired, KeyError):
            pass
    return None

def _current_sso_id() -> str | None:
    """从 g.current_user（由 login_required 设置）或 session 取得 sso_id。"""
    cu = getattr(g, 'current_user', None)
    if cu:
        return cu.get('sso_id')
    return session.get('sso_id')

# --- WebSocket (Socket.IO) ---
socketio = _SocketIO(app, cors_allowed_origins="*", async_mode="gevent")
_ws_users: dict[str, str] = {}  # sid -> sso_id

if CONFIG_CONSOLE_ENABLED:
    try:
        config_service = build_config_service_from_env()
    except Exception as exc:  # pragma: no cover - 初始化容错
        print(f"[config-web] failed to start MQTT service: {exc}", file=sys.stderr)
        config_service = None
else:
    config_service = None

_license_history_path = Path(LICENSE_HISTORY_PATH_RAW) if LICENSE_HISTORY_PATH_RAW else None

# --- Auth & Middleware ---

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = _get_current_user()
        if not user:
            # API 客户端（携带 Authorization 头或 JSON）返回 401，浏览器重定向登录页
            if request.headers.get("Authorization") or request.is_json:
                abort(401)
            return redirect(url_for('login', next=request.url))
        g.current_user = user
        return f(*args, **kwargs)
    return decorated_function

def _check_device_permission_for_user(sso_id: str, dn: str) -> bool:
    """给定 sso_id 直接检查设备权限（不依赖 session/g，供 WebSocket 处理器调用）。"""
    if not dn:
        return False
    if sso_id in _SUPERUSER_IDS:
        return True
    allowed_devices = db_manager.get_user_allowed_devices(sso_id)
    target_dn_norm = _normalize_dn(dn)
    for d in allowed_devices:
        if _normalize_dn(d.get('mac_address')) == target_dn_norm:
            return True
        if str(d.get('device_id')) == dn:
            return True
    return False

def _check_device_permission(dn: str | None) -> bool:
    """Check if current user (session or Bearer token) has permission for the given device DN."""
    if not dn:
        return False
    user_sso = _current_sso_id()
    if not user_sso:
        return False
    return _check_device_permission_for_user(user_sso, dn)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = db_manager.authenticate_user(username, password)
        if user:
            session.permanent = True
            session['user_id'] = user['id']
            session['sso_id'] = user['sso_id']
            # Cache allowed devices in session to reduce DB hits? 
            # Better to query fresh on page load, but maybe cache for streams.
            return redirect(request.args.get("next") or url_for("index"))
        else:
            return render_template("login.html", error="Invalid username or password")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/api/token", methods=["POST"])
def api_token():
    """用户名+密码换取 Bearer token，供 API / WebSocket 客户端使用。"""
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or request.form.get("username") or "").strip()
    password = data.get("password") or request.form.get("password") or ""
    if not username or not password:
        return jsonify({"error": "username_and_password_required"}), 400
    user = db_manager.authenticate_user(username, password)
    if not user:
        return jsonify({"error": "invalid_credentials"}), 401
    token = _get_token_serializer().dumps({"sso_id": user["sso_id"]})
    return jsonify({"token": token, "expires_in": TOKEN_EXPIRY, "token_type": "Bearer"})

@app.route("/api/user/info")
@login_required
def api_user_info():
    user = _current_sso_id()
    is_admin = (user in _SUPERUSER_IDS)
    # Return session timeout in seconds (static config)
    timeout = app.config['PERMANENT_SESSION_LIFETIME'].total_seconds()
    return jsonify({
        "username": user,
        "is_admin": is_admin,
        "timeout_seconds": timeout
    })

@app.route("/api/session/renew", methods=["POST"])
@login_required
def api_session_renew():
    session.modified = True # Refresh the session cookie
    return jsonify({"status": "renewed"})

@app.route("/downloads")
@login_required
def downloads():
    user = _current_sso_id()
    mac = request.args.get('mac')
    date_str = request.args.get('date')
    
    # Check permission for MAC
    if mac and user not in _SUPERUSER_IDS:
        allowed = db_manager.get_user_allowed_devices(user)
        allowed_macs = [d['mac_address'] for d in allowed]
        if mac not in allowed_macs:
            abort(403)

    if mac and date_str:
        # Step 3: Files
        files = db_manager.get_device_files(mac, date_str)
        # Fallback: scan physical disk if DB has no records for this mac+date
        if not files:
            try:
                _JST = timezone(timedelta(hours=9))
                date_dir = _REPLAY_DATA_ROOT / mac / date_str
                if date_dir.is_dir():
                    for p in sorted(date_dir.iterdir(), reverse=True):
                        if p.is_file() and p.suffix.lower() == '.csv':
                            try:
                                dt = datetime.strptime(date_str + p.stem, "%Y%m%d%H%M%S").replace(tzinfo=_JST)
                            except Exception:
                                dt = datetime.fromtimestamp(p.stat().st_mtime, _JST)
                            files.append({
                                'file_name': p.name,
                                'file_path': f"{mac}/{date_str}/",
                                'file_size': p.stat().st_size,
                                'file_time': dt.strftime("%H:%M:%S"),
                            })
            except Exception:
                pass
        return render_template("downloads.html", step="files", mac=mac, date=date_str, files=files)
    elif mac:
        # Step 2: Dates
        dates = db_manager.get_device_dates(mac)
        # Fallback: scan physical disk if DB has no records
        if not dates:
            try:
                mac_dir = _REPLAY_DATA_ROOT / mac
                if mac_dir.is_dir():
                    dates = sorted(
                        [p.name for p in mac_dir.iterdir() if p.is_dir() and re.match(r'^\d{8}$', p.name)],
                        reverse=True
                    )
            except Exception:
                pass
        return render_template("downloads.html", step="dates", mac=mac, dates=dates)
    else:
        # Step 1: Devices
        # Admin: merge device_info + physical mqtt_store dirs (may have unregistered MACs)
        if user in _SUPERUSER_IDS:
            db_devices = {d['mac_address']: d for d in db_manager.get_user_allowed_devices(user)}
            try:
                disk_macs = sorted(
                    p.name for p in _REPLAY_DATA_ROOT.iterdir()
                    if p.is_dir() and re.match(r'^[0-9A-Fa-f]{6,17}$', p.name)
                )
            except Exception:
                disk_macs = []
            devices = []
            seen = set()
            for mac_addr in disk_macs:
                seen.add(mac_addr)
                d = db_devices.get(mac_addr)
                devices.append({
                    'mac_address': mac_addr,
                    'device_id': d['device_id'] if d else mac_addr,
                })
            # Also include DB devices not on disk
            for mac_addr, d in db_devices.items():
                if mac_addr not in seen:
                    devices.append(d)
        else:
            devices = db_manager.get_user_allowed_devices(user)
        return render_template("downloads.html", step="devices", devices=devices)

@app.route("/download/<path:filepath>")
@login_required
def download_file(filepath):
    # Normalize path: replace backslash with slash for Linux container
    # DB stores Windows-style paths, but we are in Linux.
    filepath = filepath.replace('\\', '/')
    
    # Security Check: Ensure user has permission for this file's MAC
    # The filepath is relative to mqtt_store root, e.g. "MAC/Date/file.csv"
    parts = filepath.split('/')
    if not parts: # Simple check
         abort(404)
    
    # Extract MAC from path (First component)
    target_mac = parts[0]
    
    # Verify permission
    user = _current_sso_id()
    if user not in _SUPERUSER_IDS:
        allowed = db_manager.get_user_allowed_devices(user)
        allowed_macs = [d['mac_address'] for d in allowed]
        if target_mac not in allowed_macs:
            abort(403)

    return send_from_directory('/mqtt_store', filepath, as_attachment=True)

@app.route("/download/batch", methods=["POST", "GET"])
@login_required
def download_batch():
    target_files = []
    
    if request.method == "POST":
        rel_paths = request.form.getlist("files")
    else:
        mac = request.args.get("mac")
        date = request.args.get("date")
        if mac and date:
            files = db_manager.get_device_files(mac, date)
            # Combine path and name
            rel_paths = [f['file_path'] + f['file_name'] for f in files]
        else:
            return "Missing mac/date parameters", 400

    if not rel_paths:
        return "No files selected", 400

    # Permission Check
    user = _current_sso_id()
    if user not in _SUPERUSER_IDS:
        allowed = db_manager.get_user_allowed_devices(user)
        allowed_macs = set(d['mac_address'] for d in allowed)

    clean_targets = []
    for rp in rel_paths:
        # Normalize
        rp = rp.replace('\\', '/')
        parts = rp.split('/')
        if not parts: continue

        # Check MAC permission
        if user not in _SUPERUSER_IDS and parts[0] not in allowed_macs:
            continue 
            
        abs_path = os.path.join('/mqtt_store', rp)
        if os.path.exists(abs_path):
            clean_targets.append((abs_path, rp))

    if not clean_targets:
        return "No accessible files found", 404

    # Create Zip
    try:
        fd, temp_path = tempfile.mkstemp(suffix='.zip')
        os.close(fd)
        
        with zipfile.ZipFile(temp_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for abs_p, arc_n in clean_targets:
                zf.write(abs_p, arc_n)
        
        @after_this_request
        def remove_temp(response):
            try:
                os.remove(temp_path)
            except Exception:
                pass
            return response
            
        filename = f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        return send_file(temp_path, as_attachment=True, download_name=filename)
        
    except Exception as e:
        return f"Zip error: {e}", 500

if LICENSE_ENABLED:
    try:
        license_config = LicenseConfig(
            key_path=LICENSE_KEY_PATH,
            history_path=_license_history_path,
            default_port=LICENSE_TCP_PORT,
            timeout=LICENSE_TCP_TIMEOUT,
            tier_default=LICENSE_DEFAULT_TIER or "basic",
        )
        license_service = LicenseService(license_config)
    except Exception as exc:  # pragma: no cover - 初始化容错
        print(f"[config-web] failed to start license service: {exc}", file=sys.stderr)
        license_service = None
else:
    license_service = None


_direct_results = deque(maxlen=200)


def _bridge_url(path: str) -> str:
    # Build absolute path lazily so deployments can override the base URL.
    # 延迟构建绝对路径，便于不同环境覆写基础地址。
    return f"{BRIDGE_API_BASE_URL.rstrip('/')}{path}"


def _require_config_service():
    if config_service is None:
        abort(503, description="config service unavailable")
    return config_service


def _require_license_service():
    if license_service is None:
        abort(503, description="license service unavailable")
    return license_service


def _resolve_ip_from_dn(dn: str) -> str | None:
    if not dn or config_service is None:
        return None
    device = config_service.get_device(dn.strip())
    if not device:
        return None
    return device.get("ip")


def _parse_pins(value):
    if value is None:
        return None
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        tokens = [item.strip() for item in value.replace("\n", ",").split(",")]
        return [int(token) for token in tokens if token]
    raise ValueError("pin list must be array or comma separated string")


def _normalize_dn(value: str | None) -> str:
    if not value:
        return ""
    return value.replace(":", "").replace("-", "").strip().upper()


def _parse_broadcast_inputs(raw) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, str):
        parts = [part.strip() for part in raw.split(",")]
    elif isinstance(raw, (list, tuple, set)):
        parts = [str(item).strip() for item in raw]
    else:
        parts = [str(raw).strip()]
    return [item for item in parts if item]


def _resolve_ip_from_discovery(dn: str | None, target_ip: str | None, devices: list[dict]) -> str | None:
    if target_ip:
        return target_ip
    dn_key = _normalize_dn(dn or "")
    if dn_key:
        for item in devices:
            mac = _normalize_dn(item.get("dn") or item.get("mac") or item.get("device_code"))
            if mac and mac == dn_key:
                return item.get("ip") or item.get("from")
    if len(devices) == 1:
        return devices[0].get("ip") or devices[0].get("from")
    return None


def _extract_direct_payload(data: dict):
    payload_section = data.get("payload") if isinstance(data.get("payload"), dict) else {}
    if payload_section:
        return payload_section
    analog_raw = data.get("analog") if data.get("analog") is not None else payload_section.get("analog")
    select_raw = data.get("select") if data.get("select") is not None else payload_section.get("select")
    try:
        analog = _parse_pins(analog_raw)
        select = _parse_pins(select_raw)
    except Exception as exc:
        raise ConfigValidationError(str(exc))
    if analog is None and select is None:
        return None
    return {
        "analog": analog or [],
        "select": select or [],
        "model": data.get("model") or payload_section.get("model"),
    }


def _timestamp_to_epoch(value) -> float:
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        ts = float(value)
        if ts > 1e12:  # epoch milliseconds
            ts /= 1000.0
        return ts
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return 0.0
        try:
            num = float(text)
        except Exception:
            num = None
        if num is not None:
            if num > 1e12:
                num /= 1000.0
            return float(num)
        try:
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            return datetime.fromisoformat(text).timestamp()
        except Exception:
            return 0.0
    return 0.0


def _coerce_timestamp_iso(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    ts = _timestamp_to_epoch(value)
    if ts <= 0:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _merge_results() -> list[dict]:
    items: list[dict] = []
    items.extend([dict(item) for item in _direct_results if isinstance(item, dict)])
    if config_service:
        items.extend([dict(item) for item in config_service.list_results() if isinstance(item, dict)])
    for item in items:
        if "timestamp" in item:
            item["timestamp"] = _coerce_timestamp_iso(item.get("timestamp")) or item.get("timestamp")
        else:
            ts = item.get("ts") or item.get("time")
            if ts is not None:
                item["timestamp"] = _coerce_timestamp_iso(ts) or ts
    items.sort(key=lambda item: _timestamp_to_epoch(item.get("timestamp")), reverse=True)
    return items[:50]


@app.route("/")
@login_required
def index() -> str:
    user = _current_sso_id()
    device_map = {}
    
    if user in _SUPERUSER_IDS:
        # Admin gets full visibility
        allowed_dns = None
        # Fetch mapping for all known devices
        all_devs = db_manager.get_user_allowed_devices(user)
        device_map = {d['mac_address']: d['device_id'] for d in all_devs}
    else:
        allowed = db_manager.get_user_allowed_devices(user)
        allowed_dns = [d['mac_address'] for d in allowed]
        device_map = {d['mac_address']: d['device_id'] for d in allowed}
    
    return render_template(
        "index.html",
        bridge_api_base=BRIDGE_API_BASE_URL,
        allowed_dns=json.dumps(allowed_dns),
        device_map=json.dumps(device_map),
        is_admin=(user == 'admin')
    )


@app.route("/OTA/<path:filename>")
def serve_ota_file(filename):
    """Serve OTA firmware files from the mounted /ota directory."""
    return send_from_directory("/ota", filename)


@app.route("/console/OTA/<path:filename>")
@login_required
def config_serve_ota_file(filename):
    """Serve OTA firmware files from the config console path as well."""
    return send_from_directory("/ota", filename)


@app.route("/api/latest")
@login_required
def proxy_latest() -> Response:
    # Proxy the latest cache endpoint without altering payload format.
    # 透明转发最新缓存接口，保持数据格式完全一致。
    try:
        resp = requests.get(
            _bridge_url("/api/latest"),
            timeout=(BRIDGE_TIMEOUT_CONNECT, BRIDGE_TIMEOUT_READ or 10),
        )
        resp.raise_for_status()
    except requests.RequestException as exc:  # pragma: no cover
        return jsonify({"error": "bridge_unavailable", "detail": str(exc)}), 502
    return jsonify(resp.json())


def _stream_proxy_common(remote_path: str) -> Response:
    """Helper to stream from a specific bridge path.
    Performance Note: We use iter_content (raw bytes) instead of iter_lines + json parsing
    to avoid CPU bottlenecks in Python. Filtering is delegated to the client side.
    """
    def generate() -> Iterator[bytes]:
        headers = {
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
        try:
            with requests.get(
                _bridge_url(remote_path),
                headers=headers,
                stream=True,
                timeout=(BRIDGE_TIMEOUT_CONNECT, None),
            ) as upstream:
                upstream.raise_for_status()

                yield b": proxy connected\n\n"
                
                # Revert to raw chunk streaming for maximum performance
                for chunk in upstream.iter_content(chunk_size=4096):
                    if not chunk:
                        continue
                    yield chunk

        except requests.RequestException as exc:
            payload = json.dumps({"error": "bridge_unavailable", "detail": str(exc)})
            yield f"event: error\ndata: {payload}\n\n".encode("utf-8")

    response = Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
    )
    response.headers["Content-Type"] = "text/event-stream; charset=utf-8"
    response.headers["Cache-Control"] = "no-cache, no-transform"
    response.headers["X-Accel-Buffering"] = "no"
    response.headers["Connection"] = "keep-alive"
    return response


@app.route("/stream")
@login_required
def proxy_stream() -> Response:
    # Client-side filtering is used for performance
    return _stream_proxy_common("/stream")


@app.route("/stream/<dn>")
@login_required
def proxy_stream_dn(dn: str) -> Response:
    # Strict server-side check for direct single-device access
    if not _check_device_permission(dn):
        abort(403)
            
    return _stream_proxy_common(f"/stream/{dn}")


@app.route("/api/record", methods=["POST"])
def api_record() -> Response:
    if config_service is None:
        return jsonify({"error": "config_service_disabled", "detail": "Backend configuration service is not enabled."} ), 503
    
    data = request.get_json(silent=True) or {}
    dn = data.get("dn")
    record = data.get("record")
    
    if not dn:
        return jsonify({"error": "dn_required"}), 400
    if record is None:
        return jsonify({"error": "record_status_required"}), 400
        
    try:
        result = config_service.publish_record_control(dn, bool(record))
        return jsonify({"status": "ok", "data": result})
    except Exception as exc:
        return jsonify({"error": "publish_failed", "detail": str(exc)}), 500


@app.route("/healthz")
def healthz() -> Response:
    return jsonify({
        "status": "ok",
        "bridge": BRIDGE_API_BASE_URL,
        "config_console": "ready" if config_service else "disabled",
    })


@app.route("/console")
@login_required
def config_index() -> str:
    return render_template(
        "config_console.html",
        config_enabled=config_service is not None,
        license_enabled=license_service is not None,
        license_default_days=LICENSE_DEFAULT_DAYS,
        license_default_tier=LICENSE_DEFAULT_TIER,
        license_port=LICENSE_TCP_PORT,
    )


@app.route("/api/devices")
@login_required
def config_devices() -> Response:
    svc = _require_config_service()
    all_devices = svc.list_devices()
    
    user = _current_sso_id()
    if user in _SUPERUSER_IDS:
        return jsonify({"items": all_devices})
    
    # Filter for non-admin
    allowed_db = db_manager.get_user_allowed_devices(user)
    allowed_dns = set()
    for d in allowed_db:
        if d.get('mac_address'):
            allowed_dns.add(_normalize_dn(d['mac_address']))
    
    filtered = []
    for dev in all_devices:
        if dev.get('dn') in allowed_dns:
            filtered.append(dev)
            
    return jsonify({"items": filtered})


@app.route("/api/discover", methods=["POST"])
@login_required
def config_discover() -> Response:
    # Restrict discovery to admin only
    if _current_sso_id() != 'admin':
        abort(403, description="Access denied: Discovery is admin-only.")

    svc = _require_config_service()
    payload = request.get_json(silent=True) or {}
    attempts = payload.get("attempts")
    gap = payload.get("gap")
    timeout = payload.get("timeout")
    broadcast = _parse_broadcast_inputs(payload.get("broadcast") or payload.get("broadcast_addrs"))
    try:
        result = svc.publish_discover(
            attempts=int(attempts) if attempts is not None else None,
            gap=float(gap) if gap is not None else None,
            timeout=float(timeout) if timeout is not None else None,
            broadcast=broadcast or None,
            requested_by=payload.get("requested_by"),
        )
    except RuntimeError as exc:
        return jsonify({"error": "mqtt_publish_failed", "detail": str(exc)}), 502
    return jsonify({
        "status": "queued",
        **result,
        "attempts": attempts,
        "gap": gap,
        "timeout": timeout,
        "broadcast": broadcast or [],
    })


@app.route("/api/commands/latest")
@login_required
def config_results() -> Response:
    try:
        # TODO: Filter results based on permission?
        # For now, we assume results might contain shared info, 
        # but ideally we should filter 'items' by checking 'dn' against allowed list.
        # Since this wasn't explicitly strictly detailed beyond generic RBAC, 
        # and checking every result might be expensive, we'll leave as is or add simple filter.
        # Let's add simple filter for safety.
        items = _merge_results()
        
        user = _current_sso_id()
        if user not in _SUPERUSER_IDS:
            allowed_db = db_manager.get_user_allowed_devices(user)
            allowed_dns = set(_normalize_dn(d['mac_address']) for d in allowed_db if d.get('mac_address'))
            
            filtered_items = []
            for item in items:
                # Results have 'dn' or 'target_dn'
                item_dn = item.get('dn') or item.get('target_dn')
                if not item_dn or _normalize_dn(item_dn) in allowed_dns:
                    filtered_items.append(item)
            items = filtered_items
            
    except Exception as exc:  # pragma: no cover
        return jsonify({"error": "results_failed", "detail": str(exc)}), 500
    return jsonify({"items": items})


@app.route("/api/config/control", methods=["POST"])
@login_required
def config_control() -> Response:
    svc = _require_config_service()
    data = request.get_json(silent=True) or {}
    dn = (data.get("dn") or data.get("target_dn") or data.get("device_dn") or data.get("mac") or "").strip()
    if not dn:
        return jsonify({"error": "dn_required"}), 400
        
    if not _check_device_permission(dn):
        abort(403, description="Access denied for this device.")
        
    payload_obj = data.get("payload")
    if not isinstance(payload_obj, dict):
        return jsonify({"error": "payload_required"}), 400
    target_ip = (data.get("target_ip") or data.get("ip") or payload_obj.get("target_ip") or "").strip() or None
    try:
        result = svc.publish_custom(
            dn,
            payload_obj,
            requested_by=data.get("requested_by"),
            target_ip=target_ip,
        )
    except RuntimeError as exc:
        return jsonify({"error": "mqtt_publish_failed", "detail": str(exc)}), 502
    return jsonify({"status": "queued", **result})


@app.route("/api/config/apply", methods=["POST"])
@login_required
def config_apply() -> Response:
    svc = _require_config_service()
    data = request.get_json(silent=True) or {}
    dn = (data.get("dn") or data.get("target_dn") or "").strip()
    if not dn:
        return jsonify({"error": "dn_required"}), 400
        
    if not _check_device_permission(dn):
        abort(403, description="Access denied for this device.")

    payload_section = data.get("payload") if isinstance(data.get("payload"), dict) else {}
    try:
        analog = _parse_pins(data.get("analog") if data.get("analog") is not None else payload_section.get("analog"))
        select = _parse_pins(data.get("select") if data.get("select") is not None else payload_section.get("select"))
    except Exception as exc:
        return jsonify({"error": "invalid_pins", "detail": str(exc)}), 400
    if analog is None or select is None:
        return jsonify({"error": "pins_required"}), 400
    target_ip = (data.get("target_ip") or data.get("ip") or payload_section.get("target_ip") or "").strip() or None
    model = data.get("model") or payload_section.get("model")
    try:
        result = svc.publish_command(
            dn,
            analog,
            select,
            model=model,
            requested_by=data.get("requested_by"),
            target_ip=target_ip,
        )
    except ConfigValidationError as exc:
        return jsonify({"error": "validation_failed", "detail": str(exc)}), 422
    except RuntimeError as exc:
        return jsonify({"error": "mqtt_publish_failed", "detail": str(exc)}), 502
    return jsonify({"status": "queued", **result})


@app.route("/api/config/direct", methods=["POST"])
@login_required
def config_apply_direct() -> Response:
    data = request.get_json(silent=True) or {}
    dn_raw = data.get("dn") or data.get("target_dn") or data.get("device_dn") or data.get("mac")
    dn = _normalize_dn(dn_raw or "")
    
    # Direct mode usually involves discovery or direct IP connection.
    # If a DN is provided, check permission.
    if dn and not _check_device_permission(dn):
         abort(403, description="Access denied for this device.")
    
    # Note: Direct mode can theoretically talk to any IP. 
    # If the user is not admin, we should probably restrict this feature or 
    # ensure the resolved IP belongs to an allowed device.
    # However, 'direct' is often used for initial setup of devices not yet in DB?
    # Requirement: "In calling MQTT publish / control ... must check permission."
    # Direct mode uses `send_device_payload` (TCP), not MQTT.
    # But for safety, if not admin, maybe restrict? 
    # Let's enforce DN check if DN is present. If only IP is present, it's risky.
    # User requirement: "ensure all migrated routes have login_required" and "check device permission".
    # If user is not admin, they shouldn't be poking random IPs.
    if _current_sso_id() != 'admin':
         # If not admin, we MUST match against a known allowed device
         if not dn:
             # Try to resolve IP to a DN from discovery? Hard.
             # Easiest: Only allow 'direct' if DN is provided and valid.
             abort(403, description="Non-admins must provide valid Device Code/MAC for direct control.")
    
    target_ip = (data.get("target_ip") or data.get("ip") or "").strip()
    try:
        port = int(data.get("port") or CONFIG_DEVICE_TCP_PORT)
    except Exception:
        return jsonify({"error": "port_invalid"}), 400

    try:
        payload_obj = _extract_direct_payload(data)
    except ConfigValidationError as exc:
        return jsonify({"error": "invalid_payload", "detail": str(exc)}), 400
    if payload_obj is None:
        return jsonify({"error": "payload_required"}), 400

    attempts = int(data.get("attempts") or DISCOVER_DEFAULT_ATTEMPTS)
    gap = float(data.get("gap") or DISCOVER_DEFAULT_GAP)
    timeout = float(data.get("timeout") or DISCOVER_DEFAULT_TIMEOUT)
    broadcast = _parse_broadcast_inputs(data.get("broadcast") or data.get("broadcast_addrs"))

    devices, broadcast_targets = discover_lan_devices(
        broadcast_addrs=broadcast or collect_broadcast_addrs(),
        attempts=max(1, attempts),
        gap=max(0.0, gap),
        timeout=max(0.1, timeout),
    )
    resolved_ip = _resolve_ip_from_discovery(dn, target_ip, devices)
    if not resolved_ip:
        return jsonify({
            "error": "ip_unresolved",
            "detail": "未能通过广播匹配到目标 IP，请手动填写或检查设备响应。",
            "discoveries": devices,
            "broadcast": broadcast_targets,
        }), 400

    status = "ok"
    reply = {}
    try:
        send_result = send_device_payload(resolved_ip, payload_obj, port=port, timeout=timeout)
        reply = send_result.get("json") if isinstance(send_result.get("json"), dict) else {}
        if not reply:
            raw = send_result.get("raw")
            if raw:
                reply = {"raw": raw}
        reply.setdefault("status", "ok")
    except Exception as exc:
        status = "error"
        reply = {"status": "error", "error": str(exc)}

    entry = {
        "command_id": data.get("command_id") or str(uuid.uuid4()),
        "dn": dn or None,
        "status": status,
        "ip": resolved_ip,
        "port": port,
        "payload": payload_obj,
        "reply": reply,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "method": "direct",
        "broadcast": broadcast_targets,
    }
    _direct_results.appendleft(entry)
    return jsonify({**entry, "discoveries": devices}), (200 if status == "ok" else 502)


@app.route("/api/license/apply", methods=["POST"])
@login_required
def config_license_apply() -> Response:
    cfg_svc = _require_config_service()
    lic_svc = _require_license_service()
    data = request.get_json(silent=True) or {}
    dn = (data.get("dn") or data.get("target_dn") or data.get("device_dn") or "").strip().upper()
    device_code = (data.get("device_code") or data.get("mac") or dn).replace(":", "").strip()
    if not device_code:
        return jsonify({"error": "device_code_required"}), 400
        
    if not _check_device_permission(dn or device_code):
        abort(403, description="Access denied for this device.")

    try:
        days_val = int(data.get("days") or data.get("duration_days") or data.get("duration") or LICENSE_DEFAULT_DAYS)
    except Exception:
        return jsonify({"error": "days_invalid"}), 400
    if days_val <= 0:
        return jsonify({"error": "days_invalid"}), 400
    tier = (data.get("tier") or LICENSE_DEFAULT_TIER).strip().lower() or LICENSE_DEFAULT_TIER
    port_raw = data.get("port")
    try:
        port_val = int(port_raw) if port_raw is not None else LICENSE_TCP_PORT
    except Exception:
        return jsonify({"error": "port_invalid"}), 400
    try:
        token_entry = lic_svc.generate_token(device_code, days_val, tier)
    except LicenseError as exc:
        return jsonify({"error": "license_unavailable", "detail": str(exc)}), 503
    except Exception as exc:
        return jsonify({"error": "license_generate_failed", "detail": str(exc)}), 400
    target_ip = (data.get("target_ip") or data.get("ip") or "").strip()
    if not target_ip and dn:
        target_ip = _resolve_ip_from_dn(dn)
    try:
        result = cfg_svc.publish_license(
            dn=dn or device_code,
            token=token_entry["token"],
            requested_by=data.get("requested_by"),
            target_ip=target_ip,
            port=port_val,
            query=False,
        )
    except RuntimeError as exc:
        return jsonify({"error": "mqtt_publish_failed", "detail": str(exc)}), 502
    result.update({
        "status": "queued",
        "dn": dn or device_code,
        "target_ip": target_ip or None,
        "port": port_val,
        **token_entry,
    })
    return jsonify(result)


@app.route("/api/license/query")
@login_required
def config_license_query() -> Response:
    cfg_svc = _require_config_service()
    dn = (request.args.get("dn") or request.args.get("target_dn") or request.args.get("device_dn") or "").strip().upper()
    
    if dn and not _check_device_permission(dn):
         abort(403, description="Access denied for this device.")
         
    target_ip = (request.args.get("target_ip") or request.args.get("ip") or "").strip()
    
    # If no DN provided, admin might be querying by IP.
    if not dn and _current_sso_id() != 'admin':
        abort(403, description="Access denied. DN required.")
        
    port_raw = request.args.get("port")
    try:
        port_val = int(port_raw) if port_raw else LICENSE_TCP_PORT
    except Exception:
        return jsonify({"error": "port_invalid"}), 400
    if not target_ip and dn:
        target_ip = _resolve_ip_from_dn(dn)
    if not target_ip and not dn:
        return jsonify({"error": "ip_required"}), 400
    try:
        result = cfg_svc.publish_license(
            dn=dn or target_ip,
            token="?",
            requested_by=None,
            target_ip=target_ip or None,
            port=port_val,
            query=True,
        )
    except RuntimeError as exc:
        return jsonify({"error": "mqtt_publish_failed", "detail": str(exc)}), 502
    result.update({
        "status": "queued",
        "dn": dn or None,
        "target_ip": target_ip or None,
        "port": port_val,
    })
    return jsonify(result)


# --- Profile 管理 ---

PROFILES_DIR = Path(__file__).resolve().parent / "profiles"
PROFILES_DIR.mkdir(exist_ok=True)

def _sanitize_profile_name(name: str) -> str:
    return re.sub(r'[^\w\-]', '_', name)

@app.route("/profile_editor")
@login_required
def profile_editor():
    return render_template("profile_editor.html")

@app.route("/api/profiles", methods=["GET"])
@login_required
def api_profiles_list():
    profiles = []
    for f in sorted(PROFILES_DIR.glob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            profiles.append({
                "name": f.stem,
                "displayName": data.get("name", f.stem)
            })
        except Exception:
            pass
    return jsonify(profiles)

@app.route("/api/profiles/<name>", methods=["GET"])
@login_required
def api_profile_get(name):
    safe = _sanitize_profile_name(name)
    if not safe:
        abort(400)
    path = PROFILES_DIR / f"{safe}.json"
    if not path.exists():
        abort(404)
    return Response(path.read_bytes(), mimetype="application/json")

@app.route("/api/profiles/<name>", methods=["POST"])
@login_required
def api_profile_save(name):
    safe = _sanitize_profile_name(name)
    if not safe:
        abort(400)
    try:
        data = request.get_json(force=True)
        if data is None:
            abort(400)
    except Exception:
        abort(400)
    path = PROFILES_DIR / f"{safe}.json"
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return jsonify({"status": "saved", "name": safe})

@app.route("/api/profiles/<name>", methods=["DELETE"])
@login_required
def api_profile_delete(name):
    safe = _sanitize_profile_name(name)
    if not safe:
        abort(400)
    path = PROFILES_DIR / f"{safe}.json"
    if not path.exists():
        abort(404)
    path.unlink()
    return jsonify({"status": "deleted"})


# ---------------------------------------------------------------------------
# Admin: 重新掃描文件索引（背景執行，非阻塞）
# ---------------------------------------------------------------------------

_rescan_state = {"running": False, "result": None}

@app.route("/api/admin/rescan", methods=["POST"])
@login_required
def api_admin_rescan():
    if _current_sso_id() != 'admin':
        abort(403)
    if _rescan_state["running"]:
        return jsonify({"running": True, "message": "Rescan already in progress"}), 202

    def _run():
        _rescan_state["running"] = True
        _rescan_state["result"] = None
        try:
            _rescan_state["result"] = db_manager.rebuild_file_index(str(_REPLAY_DATA_ROOT))
        except Exception as e:
            _rescan_state["result"] = {"inserted": 0, "error": str(e)}
        finally:
            _rescan_state["running"] = False

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return jsonify({"running": True, "message": "Rescan started"}), 202


@app.route("/api/admin/rescan/status", methods=["GET"])
@login_required
def api_admin_rescan_status():
    if _current_sso_id() != 'admin':
        abort(403)
    if _rescan_state["running"]:
        return jsonify({"running": True})
    result = _rescan_state["result"]
    if result is None:
        return jsonify({"running": False, "result": None})
    return jsonify({"running": False, "result": result})


# ---------------------------------------------------------------------------
# 數據重放 (Data Replay)
# ---------------------------------------------------------------------------

# CSV 存儲根目錄（與 sink.py 保持一致）
_REPLAY_DATA_ROOT = Path(os.getenv("DATA_ROOT", "/mqtt_store"))
# 允許的文件名格式：HHMMSS.csv 或任意安全字符的 .csv 文件名（支持手動放置）
_REPLAY_FILE_RE = re.compile(r'^[A-Za-z0-9_\-\.]+\.csv$')
# 允許的日期格式：YYYYMMDD 或 YYYY-MM-DD 或任意安全目錄名（支持手動放置）
_REPLAY_DATE_RE = re.compile(r'^[A-Za-z0-9_\-\.]+$')
# 允許的目錄名格式：十六進位 MAC 或任意安全字母數字名稱（支持 test/ 等手動目錄）
_REPLAY_MAC_RE = re.compile(r'^[A-Za-z0-9_\-\.]{1,64}$')


@app.route("/replay")
@login_required
def replay_page():
    return render_template("replay.html")


@app.route("/api/replay/browse")
@login_required
def api_replay_browse():
    """
    瀏覽 mqtt_store 目錄結構。
    ?path= 為相對路徑（空 = 根目錄）。
    根目錄層只返回當前用戶允許的 MAC。
    """
    raw_path = request.args.get("path", "").strip().strip("/")

    # 各路徑段白名單校驗，拒絕 .. 或含特殊字符的段
    _SEG_RE = re.compile(r'^[A-Za-z0-9_\-\.]+$')
    if raw_path:
        segments = raw_path.split("/")
        for seg in segments:
            if not seg or not _SEG_RE.match(seg):
                abort(400)
    else:
        segments = []

    # 解析物理路徑，確保不越界
    target = (_REPLAY_DATA_ROOT / raw_path).resolve() if raw_path else _REPLAY_DATA_ROOT.resolve()
    try:
        target.relative_to(_REPLAY_DATA_ROOT.resolve())
    except ValueError:
        abort(403)

    if not target.exists():
        abort(404)

    user = _current_sso_id()
    is_admin = (user in _SUPERUSER_IDS)

    # 根目錄層：列出允許的 MAC 子目錄
    if not segments:
        allowed = db_manager.get_user_allowed_devices(user)
        allowed_macs = {d['mac_address'] for d in allowed} if not is_admin else None
        entries = []
        for p in sorted(target.iterdir()):
            if not p.is_dir():
                continue
            if allowed_macs is not None and p.name not in allowed_macs:
                continue
            entries.append({"name": p.name, "type": "dir"})
        return jsonify({"path": "", "entries": entries})

    # 其餘層：先驗證 MAC 權限（admin 可瀏覽任意目錄，包括手動放置的測試資料）
    mac = segments[0]
    if not is_admin and not _check_device_permission(mac):
        abort(403)

    entries = []
    depth = len(segments)

    if depth == 1:
        # 日期目錄層（降序）
        for p in sorted(target.iterdir(), reverse=True):
            if p.is_dir():
                entries.append({"name": p.name, "type": "dir"})
    elif depth == 2:
        # CSV 文件層（降序）
        for p in sorted(target.iterdir(), reverse=True):
            if p.is_file() and p.suffix.lower() == '.csv':
                entries.append({"name": p.name, "type": "file", "size": p.stat().st_size})
    else:
        abort(400)

    return jsonify({"path": raw_path, "entries": entries})


@app.route("/api/replay/devices")
@login_required
def api_replay_devices():
    user = _current_sso_id()
    devices = db_manager.get_user_allowed_devices(user)
    return jsonify(devices)


@app.route("/api/replay/dates")
@login_required
def api_replay_dates():
    mac = request.args.get("mac", "").strip()
    if not mac or not _REPLAY_MAC_RE.match(mac):
        abort(400)
    if _current_sso_id() not in _SUPERUSER_IDS and not _check_device_permission(mac):
        abort(403)
    dates = db_manager.get_device_dates(mac)
    # file_date 可能是 date 物件或字符串，統一轉為字符串
    return jsonify([str(d) for d in dates])


@app.route("/api/replay/files")
@login_required
def api_replay_files():
    mac = request.args.get("mac", "").strip()
    date = request.args.get("date", "").strip()
    if not mac or not _REPLAY_MAC_RE.match(mac):
        abort(400)
    if not date or not _REPLAY_DATE_RE.match(date):
        abort(400)
    if _current_sso_id() not in _SUPERUSER_IDS and not _check_device_permission(mac):
        abort(403)
    files = db_manager.get_device_files(mac, date)
    return jsonify(files)


@app.route("/api/replay/data")
@login_required
def api_replay_data():
    import csv as _csv

    mac = request.args.get("mac", "").strip()
    date = request.args.get("date", "").strip()
    file = request.args.get("file", "").strip()

    # 輸入校驗（防路徑注入）
    if not mac or not _REPLAY_MAC_RE.match(mac):
        abort(400)
    if not date or not _REPLAY_DATE_RE.match(date):
        abort(400)
    if not file or not _REPLAY_FILE_RE.match(file):
        abort(400)
    is_admin = (_current_sso_id() in _SUPERUSER_IDS)
    if not is_admin and not _check_device_permission(mac):
        abort(403)

    # 目錄格式為 YYYYMMDD，去除日期中的連字符（若是其他格式則原樣使用）
    date_dir = date.replace('-', '') if re.match(r'^\d{4}-\d{2}-\d{2}$', date) else date
    csv_path = _REPLAY_DATA_ROOT / mac / date_dir / file
    # 解析確保不越出根目錄
    try:
        csv_path = csv_path.resolve()
        _REPLAY_DATA_ROOT.resolve()
    except Exception:
        abort(400)
    if not str(csv_path).startswith(str(_REPLAY_DATA_ROOT.resolve())):
        abort(403)
    if not csv_path.exists():
        abort(404)

    dn = mac
    sn = 0
    frames = []
    try:
        with open(csv_path, newline='', encoding='utf-8') as f:
            reader = _csv.reader(f)
            header = None
            p_start = None
            p_end = None
            gyro_cols = None
            acc_cols = None
            ts_col = 0
            for row in reader:
                if not row:
                    continue
                # 首行注釋：// DN: ..., SN: ...
                raw = row[0].strip()
                if raw.startswith('//'):
                    m = re.search(r'SN:\s*(\d+)', raw)
                    if m:
                        sn = int(m.group(1))
                    m2 = re.search(r'DN:\s*([0-9A-Fa-f]+)', raw)
                    if m2:
                        dn = m2.group(1)
                    continue
                # 標題行
                if header is None:
                    header = [c.strip() for c in row]
                    # 找壓力列範圍（P1...Pn）
                    p_indices = [i for i, c in enumerate(header) if re.match(r'^P\d+$', c)]
                    if p_indices:
                        p_start = p_indices[0]
                        p_end = p_indices[-1] + 1
                    # 找 Gyro 和 Acc 列
                    try:
                        gi = header.index('Gyro_x')
                        gyro_cols = [gi, gi+1, gi+2]
                    except ValueError:
                        gyro_cols = None
                    try:
                        ai = header.index('Acc_x')
                        acc_cols = [ai, ai+1, ai+2]
                    except ValueError:
                        acc_cols = None
                    # 找 Timestamp 列
                    try:
                        ts_col = header.index('Timestamp')
                    except ValueError:
                        ts_col = 0  # fallback
                    continue
                # 數據行
                if p_start is None:
                    continue
                try:
                    ts = float(row[ts_col])
                    pressures = [float(v) for v in row[p_start:p_end]]
                    gyro = [float(row[i]) for i in gyro_cols] if gyro_cols else None
                    acc  = [float(row[i]) for i in acc_cols]  if acc_cols  else None
                    frames.append({"ts": ts, "p": pressures, "gyro": gyro, "acc": acc})
                except (ValueError, IndexError):
                    continue
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    if sn == 0 and frames:
        sn = len(frames[0]["p"])

    return jsonify({"dn": dn, "sn": sn, "frames": frames})


# ---------------------------------------------------------------------------
# WebSocket (Socket.IO) — 实时数据推送，认证通过 Bearer token
# ---------------------------------------------------------------------------

@socketio.on("connect")
def handle_ws_connect(auth):
    """客户端连接时验证 Bearer token。auth = {'token': '...'}"""
    token = (auth or {}).get("token") or request.args.get("token", "")
    if not token:
        return False  # 拒绝连接
    try:
        data = _get_token_serializer().loads(token, max_age=TOKEN_EXPIRY)
        sso_id = data["sso_id"]
    except (BadSignature, SignatureExpired, KeyError):
        return False
    _ws_users[request.sid] = sso_id


@socketio.on("disconnect")
def handle_ws_disconnect():
    _ws_users.pop(request.sid, None)


@socketio.on("subscribe")
def handle_ws_subscribe(data):
    """订阅指定设备的实时数据流。data = {'dn': '...'}"""
    sid = request.sid
    sso_id = _ws_users.get(sid)
    if not sso_id:
        ws_emit("error", {"msg": "not_authenticated"})
        ws_disconnect()
        return
    dn = (data.get("dn") or "").strip()
    if not dn:
        ws_emit("error", {"msg": "dn_required"})
        return
    dn_clean = _normalize_dn(dn)
    if not _check_device_permission_for_user(sso_id, dn_clean):
        ws_emit("error", {"msg": "forbidden"})
        return
    socketio.start_background_task(_relay_sse_to_ws, sid, dn_clean)
    ws_emit("subscribed", {"dn": dn_clean})


def _relay_sse_to_ws(sid: str, dn: str) -> None:
    """后台 greenlet：从 bridge SSE 读取数据并转发给 WebSocket 客户端。"""
    url = _bridge_url(f"/stream/{dn}")
    try:
        with requests.get(
            url,
            stream=True,
            headers={"Accept": "text/event-stream", "Cache-Control": "no-cache"},
            timeout=(BRIDGE_TIMEOUT_CONNECT, None),
        ) as resp:
            resp.raise_for_status()
            event_name: str | None = None
            data_lines: list[str] = []
            for raw_line in resp.iter_lines(decode_unicode=True):
                # 如果客户端已断开，终止循环
                if not socketio.server.manager.is_connected(sid, "/"):
                    break
                if raw_line is None:
                    continue
                if raw_line.startswith("event:"):
                    event_name = raw_line[6:].strip()
                    data_lines = []
                elif raw_line.startswith("data:"):
                    data_lines.append(raw_line[5:].strip())
                elif raw_line == "" and event_name and data_lines:
                    try:
                        payload = json.loads("\n".join(data_lines))
                        socketio.emit(event_name, payload, to=sid)
                    except (json.JSONDecodeError, Exception):
                        pass
                    event_name = None
                    data_lines = []
    except Exception:
        pass
    # 通知客户端流已结束
    try:
        socketio.emit("stream_ended", {"dn": dn}, to=sid)
    except Exception:
        pass


if __name__ == "__main__":
    web_port = int(os.getenv("WEB_PORT", "5000"))
    ssl_enabled = os.getenv("WEB_SSL_ENABLED", "0") not in ("0", "", "false", "False", "FALSE")
    ssl_cert = os.getenv("WEB_SSL_CERT")
    ssl_key = os.getenv("WEB_SSL_KEY")
    
    # Gevent WSGI SSL configuration
    ssl_args = {}
    if ssl_enabled:
        if ssl_cert and ssl_key and os.path.exists(ssl_cert) and os.path.exists(ssl_key):
            print(f"[web] starting with SSL: {ssl_cert}")
            ssl_args = {"certfile": ssl_cert, "keyfile": ssl_key}
        else:
            print("[web] WEB_SSL_ENABLED is set but WEB_SSL_CERT/WEB_SSL_KEY missing or invalid; falling back to HTTP.")

    print(f"[web] serving on port {web_port} (gevent + websocket)")
    from geventwebsocket.handler import WebSocketHandler
    http_server = WSGIServer(("0.0.0.0", web_port), app, handler_class=WebSocketHandler, **ssl_args)
    http_server.serve_forever()
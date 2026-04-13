"""
white_checker.py  —  реальная проверка «белого списка» через xray.
Адаптировано для работы с main.py
Оптимизированная версия с улучшенным поиском xray и отладкой
Добавлена поддержка XHTTP транспорта, SpiderX, Mldsa65Verify, XTLS Vision
"""

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from base64 import b64decode
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Semaphore
from typing import Optional
from urllib.parse import unquote, parse_qs

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =============================================================================
# Публичные константы / конфигурация
# =============================================================================

# Якорные домены РФ белого списка + запасные
WHITE_TEST_DOMAINS = [
    "alfabank.ru",
    "mironline.ru", 
    "vkusvill.ru",
    "google.com",
    "cloudflare.com"
]
WHITE_THRESHOLD = 2
HTTP_TIMEOUT = 10
XRAY_STARTUP_TIMEOUT = 10.0
XRAY_POLL_INTERVAL = 0.1
WHITE_CHECK_TIMEOUT = 30.0
WHITE_WORKERS = 5
WHITE_CACHE_HOURS = 24

# Путь к бинарнику xray (по умолчанию рядом со скриптом)
XRAY_BIN = os.environ.get(
    "XRAY_BIN",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "xray"),
)

# =============================================================================
# Внутренний глобальный семафор
# =============================================================================
_sem = Semaphore(WHITE_WORKERS)


# =============================================================================
# Утилиты
# =============================================================================

def xray_available() -> bool:
    """Возвращает True, если бинарник xray найден и исполняем."""
    result = _xray_binary() is not None
    return result


def _xray_binary() -> Optional[str]:
    """Ищет бинарник xray: корень репозитория → рядом со скриптом → PATH."""
    # 1. Проверяем переменную окружения
    if os.path.isfile(XRAY_BIN) and os.access(XRAY_BIN, os.X_OK):
        return XRAY_BIN
    
    # 2. Ищем в корне репозитория (../xray)
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    root_xray = os.path.join(base_dir, "xray")
    if os.path.isfile(root_xray) and os.access(root_xray, os.X_OK):
        return root_xray
    
    # 3. Ищем рядом со скриптом
    script_dir = os.path.dirname(os.path.abspath(__file__))
    for name in ("xray", "xray-linux-64", "xray-linux-arm64", "xray.exe"):
        cand = os.path.join(script_dir, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    
    # 4. Ищем в PATH
    return shutil.which("xray")


def _free_port() -> int:
    """Находит свободный TCP-порт на 127.0.0.1."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, timeout: float) -> bool:
    """Активно опрашивает порт до его открытия."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(XRAY_POLL_INTERVAL)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(XRAY_POLL_INTERVAL)
    return False


def _check_dns(domain: str) -> bool:
    """Проверяет, что домен резолвится"""
    try:
        socket.gethostbyname(domain)
        return True
    except:
        return False


# =============================================================================
# Парсинг URI → xray outbound
# =============================================================================

def _p(params: dict, key: str, default: str = "") -> str:
    """Получает первое значение из parse_qs-словаря."""
    return params.get(key, [default])[0]


def _stream_settings(params: dict, net: str, security: str, host: str) -> dict:
    """Универсальный строитель streamSettings с поддержкой XHTTP."""
    sni = _p(params, "sni", host)
    fp = _p(params, "fp", "chrome")
    pbk = _p(params, "pbk", "")
    sid = _p(params, "sid", "")
    path = unquote(_p(params, "path", "/"))
    h_header = unquote(_p(params, "host", host))
    alpn_raw = _p(params, "alpn", "")

    ss: dict = {"network": net}

    # Настройки безопасности (TLS / REALITY)
    if security == "tls":
        tls_cfg: dict = {
            "allowInsecure": True,
            "serverName": sni,
            "fingerprint": fp or "chrome",
        }
        if alpn_raw:
            tls_cfg["alpn"] = [a.strip() for a in alpn_raw.split(",") if a.strip()]
        ss["security"] = "tls"
        ss["tlsSettings"] = tls_cfg
    elif security == "reality":
        reality_settings = {
            "serverName": sni,
            "fingerprint": fp or "chrome",
            "publicKey": pbk,
            "shortId": sid,
        }
        # ========== НОВЫЕ ПОЛЯ REALITY ==========
        spider_x = _p(params, "spiderX", "")
        if spider_x:
            reality_settings["spiderX"] = spider_x
        
        mldsa65_verify = _p(params, "mldsa65Verify", "")
        if mldsa65_verify:
            reality_settings["mldsa65Verify"] = mldsa65_verify.lower() == "true"
        # ========================================
        ss["security"] = "reality"
        ss["realitySettings"] = reality_settings
    else:
        ss["security"] = "none"

    # Настройки транспорта
    if net == "ws":
        ss["wsSettings"] = {"path": path, "headers": {"Host": h_header}}
    elif net == "grpc":
        ss["grpcSettings"] = {
            "serviceName": _p(params, "serviceName", ""),
            "multiMode": False,
        }
    elif net == "h2":
        ss["httpSettings"] = {"path": path, "host": [h_header] if h_header else []}
    elif net == "httpupgrade":
        ss["httpupgradeSettings"] = {"path": path, "host": h_header}
    # ========== БЛОК ДЛЯ XHTTP ==========
    elif net == "xhttp":
        # Парсим XHTTP-специфичные параметры
        mode = _p(params, "mode", "auto")  # auto, packet-up, stream-up, stream-one
        xhttp_host = _p(params, "xhttp_host", h_header) or h_header
        xhttp_path = _p(params, "xhttp_path", path) or "/"
        
        # Дополнительные параметры для маскировки
        max_bytes = _p(params, "maxBytes", "")
        max_concurrency = _p(params, "maxConcurrency", "")
        min_upload_interval = _p(params, "minUploadInterval", "")
        
        # XHTTP extra JSON (может быть передан как строка JSON)
        extra_json = _p(params, "extra", "")
        
        xhttp_settings = {
            "path": xhttp_path,
            "host": xhttp_host,
            "mode": mode,
        }
        
        # Добавляем опциональные параметры если они указаны
        if max_bytes:
            try:
                xhttp_settings["maxBytes"] = int(max_bytes)
            except ValueError:
                pass
        if max_concurrency:
            try:
                xhttp_settings["maxConcurrency"] = int(max_concurrency)
            except ValueError:
                pass
        if min_upload_interval:
            try:
                xhttp_settings["minUploadInterval"] = int(min_upload_interval)
            except ValueError:
                pass
        if extra_json:
            try:
                xhttp_settings["extra"] = json.loads(extra_json)
            except json.JSONDecodeError:
                pass  # Игнорируем невалидный JSON
                
        ss["xhttpSettings"] = xhttp_settings
    # ==========================================

    return ss


def _parse_vless(uri: str) -> Optional[dict]:
    try:
        body = uri[len("vless://"):]
        user_id, rest = body.split("@", 1)
        host_port = rest.split("?")[0]
        qs = rest.split("?", 1)[1] if "?" in rest else ""
        qs = qs.split("#")[0]
        host, port_s = host_port.rsplit(":", 1)
        host = host.strip("[]")
        port = int(port_s)
        params = parse_qs(qs)

        security = _p(params, "security", "none")
        net = _p(params, "type", "tcp")
        flow = _p(params, "flow", "")

        # ========== АВТО-FLOW ДЛЯ REALITY ==========
        if security == "reality" and not flow:
            # Если flow не указан, но это REALITY + TCP → ставим xtls-rprx-vision
            if net == "tcp":
                flow = "xtls-rprx-vision"
        # ==========================================

        ss = _stream_settings(params, net, security, host)

        user: dict = {"id": user_id, "encryption": "none"}
        if flow:
            user["flow"] = flow

        return {
            "protocol": "vless",
            "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
            "streamSettings": ss,
        }
    except Exception:
        return None


def _parse_trojan(uri: str) -> Optional[dict]:
    try:
        body = uri[len("trojan://"):]
        password, rest = body.split("@", 1)
        password = unquote(password)
        host_port = rest.split("?")[0]
        qs = rest.split("?", 1)[1] if "?" in rest else ""
        qs = qs.split("#")[0]
        host, port_s = host_port.rsplit(":", 1)
        host = host.strip("[]")
        port = int(port_s)
        params = parse_qs(qs)

        security = _p(params, "security", "tls")
        net = _p(params, "type", "tcp")

        ss = _stream_settings(params, net, security, host)

        return {
            "protocol": "trojan",
            "settings": {"servers": [{"address": host, "port": port, "password": password}]},
            "streamSettings": ss,
        }
    except Exception:
        return None


def _parse_vmess(uri: str) -> Optional[dict]:
    try:
        enc = uri[len("vmess://"):]
        enc += "=" * (-len(enc) % 4)
        data = json.loads(b64decode(enc).decode("utf-8", errors="ignore"))

        host = str(data.get("add", ""))
        port = int(data.get("port", 443))
        uid = str(data.get("id", ""))
        aid = int(data.get("aid", 0))
        net = str(data.get("net", "tcp"))
        tls = str(data.get("tls", ""))
        sni = str(data.get("sni", host))
        path = str(data.get("path", "/"))
        h_host = str(data.get("host", host))
        fp = str(data.get("fp", "chrome"))
        alpn = str(data.get("alpn", ""))
        
        # REALITY поля в VMess JSON
        pbk = str(data.get("pbk", ""))
        sid = str(data.get("sid", ""))
        spider_x = str(data.get("spiderX", ""))
        mldsa65_verify = str(data.get("mldsa65Verify", ""))

        ss: dict = {"network": net}
        
        if tls == "tls":
            tls_cfg: dict = {
                "allowInsecure": True,
                "serverName": sni,
                "fingerprint": fp or "chrome",
            }
            if alpn:
                tls_cfg["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
            ss["security"] = "tls"
            ss["tlsSettings"] = tls_cfg
        elif tls == "reality":
            reality_settings = {
                "serverName": sni,
                "fingerprint": fp or "chrome",
                "publicKey": pbk,
                "shortId": sid,
            }
            if spider_x:
                reality_settings["spiderX"] = spider_x
            if mldsa65_verify:
                reality_settings["mldsa65Verify"] = mldsa65_verify.lower() == "true"
            ss["security"] = "reality"
            ss["realitySettings"] = reality_settings
        else:
            ss["security"] = "none"

        if net == "ws":
            ss["wsSettings"] = {"path": path, "headers": {"Host": h_host}}
        elif net == "grpc":
            ss["grpcSettings"] = {"serviceName": path, "multiMode": False}
        elif net == "h2":
            ss["httpSettings"] = {"path": path, "host": [h_host] if h_host else []}
        elif net == "httpupgrade":
            ss["httpupgradeSettings"] = {"path": path, "host": h_host}
        # ========== БЛОК ДЛЯ XHTTP В VMESS ==========
        elif net == "xhttp":
            mode = str(data.get("mode", "auto"))
            max_bytes = data.get("maxBytes")
            max_concurrency = data.get("maxConcurrency")
            min_upload_interval = data.get("minUploadInterval")
            extra = data.get("extra")
            
            xhttp_settings = {
                "path": path,
                "host": h_host,
                "mode": mode,
            }
            if max_bytes:
                try:
                    xhttp_settings["maxBytes"] = int(max_bytes)
                except (ValueError, TypeError):
                    pass
            if max_concurrency:
                try:
                    xhttp_settings["maxConcurrency"] = int(max_concurrency)
                except (ValueError, TypeError):
                    pass
            if min_upload_interval:
                try:
                    xhttp_settings["minUploadInterval"] = int(min_upload_interval)
                except (ValueError, TypeError):
                    pass
            if extra:
                try:
                    if isinstance(extra, str):
                        xhttp_settings["extra"] = json.loads(extra)
                    else:
                        xhttp_settings["extra"] = extra
                except json.JSONDecodeError:
                    pass
            ss["xhttpSettings"] = xhttp_settings
        # =================================================

        return {
            "protocol": "vmess",
            "settings": {"vnext": [{
                "address": host,
                "port": port,
                "users": [{"id": uid, "alterId": aid, "security": "auto"}],
            }]},
            "streamSettings": ss,
        }
    except Exception:
        return None


def _parse_ss(uri: str) -> Optional[dict]:
    try:
        body = uri[len("ss://"):]
        body = body.split("#")[0].split("?")[0]

        if "@" in body:
            cred_part, host_port = body.rsplit("@", 1)
            try:
                pad = cred_part + "=" * (-len(cred_part) % 4)
                decoded_cred = b64decode(pad).decode("utf-8")
                if ":" in decoded_cred:
                    method, password = decoded_cred.split(":", 1)
                else:
                    method, password = cred_part, ""
            except Exception:
                if ":" in cred_part:
                    method, password = cred_part.split(":", 1)
                else:
                    return None
        else:
            pad = body + "=" * (-len(body) % 4)
            decoded = b64decode(pad).decode("utf-8")
            if "@" not in decoded:
                return None
            cred_part, host_port = decoded.rsplit("@", 1)
            if ":" not in cred_part:
                return None
            method, password = cred_part.split(":", 1)

        host, port_s = host_port.rsplit(":", 1)
        host = host.strip("[]")
        port = int(port_s)

        return {
            "protocol": "shadowsocks",
            "settings": {"servers": [{
                "address": host,
                "port": port,
                "method": method,
                "password": password,
                "uot": False,
            }]},
            "streamSettings": {"network": "tcp", "security": "none"},
        }
    except Exception:
        return None


def _build_outbound(vpn_uri: str) -> Optional[dict]:
    uri = vpn_uri.split("#")[0].strip()
    if uri.startswith("vless://"):   return _parse_vless(uri)
    if uri.startswith("trojan://"):  return _parse_trojan(uri)
    if uri.startswith("vmess://"):   return _parse_vmess(uri)
    if uri.startswith("ss://"):      return _parse_ss(uri)
    return None


def _build_xray_config(outbound: dict, socks_port: int) -> dict:
    """Минимальный xray-конфиг: SOCKS5-прокси → один VPN-outbound."""
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
            "sniffing": {"enabled": False},
        }],
        "outbounds": [
            {**outbound, "tag": "proxy"},
            {"protocol": "freedom", "settings": {}, "tag": "direct"},
            {"protocol": "blackhole", "settings": {}, "tag": "block"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "outboundTag": "proxy", "port": "0-65535"},
            ],
        },
    }


# =============================================================================
# Основные функции
# =============================================================================

def is_white_key(vpn_uri: str, timeout: float = WHITE_CHECK_TIMEOUT) -> bool:
    """Проверяет, является ли vpn_uri «белым» ключом."""
    if _xray_binary() is None:
        return False

    with _sem:
        return _check_one(vpn_uri, timeout)


def _check_one(vpn_uri: str, timeout: float) -> bool:
    xray_bin = _xray_binary()
    if not xray_bin:
        return False

    outbound = _build_outbound(vpn_uri)
    if outbound is None:
        return False

    socks_port = _free_port()
    config = _build_xray_config(outbound, socks_port)

    proc: Optional[subprocess.Popen] = None
    tmp_cfg: Optional[str] = None
    t_start = time.monotonic()

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as tf:
            json.dump(config, tf)
            tmp_cfg = tf.name

        proc = subprocess.Popen(
            [xray_bin, "run", "-config", tmp_cfg],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        if not _wait_for_port(socks_port, XRAY_STARTUP_TIMEOUT):
            return False

        if proc.poll() is not None:
            return False

        elapsed = time.monotonic() - t_start
        remaining = max(1.0, timeout - elapsed)
        per_req = min(HTTP_TIMEOUT, max(2.0, remaining / len(WHITE_TEST_DOMAINS)))

        proxies = {
            "http": f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}",
        }
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,*/*",
        }

        success = 0
        for domain in WHITE_TEST_DOMAINS:
            if time.monotonic() - t_start > timeout - 1:
                break
            
            # Пробуем HTTPS, если не работает - HTTP
            for scheme in ["https", "http"]:
                try:
                    resp = requests.get(
                        f"{scheme}://{domain}/",
                        proxies=proxies,
                        timeout=per_req,
                        allow_redirects=True,
                        verify=False,
                        headers=headers,
                    )
                    if resp.status_code < 600:
                        success += 1
                        break
                except Exception:
                    continue

        return success >= WHITE_THRESHOLD

    except Exception:
        return False

    finally:
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except:
                try:
                    proc.kill()
                except:
                    pass
        if tmp_cfg and os.path.exists(tmp_cfg):
            try:
                os.unlink(tmp_cfg)
            except:
                pass


# =============================================================================
# Пакетная проверка с прогрессом и кешем
# =============================================================================

def batch_white_check(
    keys: list,
    history: dict,
    *,
    workers: int = WHITE_WORKERS,
    cache_hours: float = WHITE_CACHE_HOURS,
    label: str = "",
) -> tuple[list, list]:
    """Пакетная WHITE/BLACK проверка списка ключей."""
    if _xray_binary() is None:
        print(f"  [{label}] ⚠️ xray не найден, все ключи → WHITE")
        return list(keys), []

    now = time.time()
    white_keys: list = []
    black_keys: list = []

    cached_white, cached_black, to_test = [], [], []
    for k in keys:
        k_id = k.split("#")[0]
        h = history.get(k_id, {})
        w = h.get("white")
        w_time = h.get("white_time", 0)
        if w is not None and (now - w_time) < cache_hours * 3600:
            (cached_white if w else cached_black).append(k)
        else:
            to_test.append(k)

    if cached_white or cached_black:
        print(f"  [{label}] Из кеша: WHITE={len(cached_white)} BLACK={len(cached_black)}")

    white_keys.extend(cached_white)
    black_keys.extend(cached_black)

    if not to_test:
        return white_keys, black_keys

    print(f"  [{label}] Белый чек: {len(to_test)} ключей | воркеры={workers}")

    completed = 0
    total = len(to_test)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_key = {
            executor.submit(is_white_key, k.split("#")[0]): k
            for k in to_test
        }
        for future in as_completed(future_to_key):
            k = future_to_key[future]
            k_id = k.split("#")[0]
            try:
                result = future.result()
            except Exception:
                result = False

            if k_id in history:
                history[k_id]["white"] = result
                history[k_id]["white_time"] = time.time()

            if result:
                white_keys.append(k)
            else:
                black_keys.append(k)

            completed += 1
            if completed % 10 == 0 or completed == total:
                pct = completed * 100 // total
                print(
                    f"  [{label}] {completed}/{total} ({pct}%) "
                    f"WHITE={len(white_keys)} BLACK={len(black_keys)}"
                )

    return white_keys, black_keys

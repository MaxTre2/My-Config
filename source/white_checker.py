"""
white_checker.py — проверка «белого списка» через xray-core v2.0
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from base64 import b64decode
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Semaphore
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, parse_qs

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__all__ = [
    "WhiteChecker",
    "WHITE_WORKERS",
    "WHITE_CHECK_TIMEOUT",
    "WHITE_CACHE_HOURS",
]

# =============================================================================
# Константы
# =============================================================================

# Домены для тестирования «белого» доступа (российские ресурсы, которые должны
# быть доступны через VPN без ограничений)
WHITE_TEST_DOMAINS = [
    "alfabank.ru",      # Альфа-Банк — стабильный HTTPS
    "mironline.ru",     # Мир — платёжная система
    "gosuslugi.ru",     # Госуслуги — надёжный ориентир
    "vkusvill.ru",      # eCommerce — дополнительная точка
]
WHITE_THRESHOLD   = 2       # Минимум успешных ответов из WHITE_TEST_DOMAINS
HTTP_TIMEOUT      = 6       # Таймаут одного HTTP-запроса через SOCKS5
XRAY_STARTUP_WAIT = 6.0     # Ждём запуска xray (секунды)
XRAY_POLL_INTERVAL = 0.12   # Интервал опроса порта
WHITE_CHECK_TIMEOUT = 25.0  # Общий таймаут одной проверки
WHITE_WORKERS     = 6       # Параллельных проверок
WHITE_CACHE_HOURS = 24      # Кэш результата (часы)

# Задержка между попытками HTTP — снижает ложные FAIL при медленном старте
POST_START_DELAY  = 0.5


# =============================================================================
# Утилиты
# =============================================================================

def _free_port() -> int:
    """Получить свободный TCP-порт."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]


def _wait_for_port(port: int, timeout: float) -> bool:
    """Ждать пока порт откроется."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=XRAY_POLL_INTERVAL):
                return True
        except (ConnectionRefusedError, OSError, socket.timeout):
            time.sleep(XRAY_POLL_INTERVAL)
    return False


# =============================================================================
# URI → xray outbound config
# =============================================================================

def _p(params: Dict[str, List[str]], key: str, default: str = "") -> str:
    return params.get(key, [default])[0]


def _build_stream_settings(
    params: Dict[str, List[str]], net: str, security: str, host: str
) -> Dict[str, Any]:
    """Собрать streamSettings для xray outbound."""
    sni      = _p(params, "sni", host)
    fp       = _p(params, "fp", "chrome") or "chrome"
    pbk      = _p(params, "pbk", "")
    sid      = _p(params, "sid", "")
    path     = unquote(_p(params, "path", "/")) or "/"
    h_header = unquote(_p(params, "host", host)) or host
    alpn_raw = _p(params, "alpn", "")
    mode     = _p(params, "mode", "auto")

    ss: Dict[str, Any] = {"network": net}

    # ── TLS ──────────────────────────────────────────────────────────────────
    if security == "tls":
        tls_cfg: Dict[str, Any] = {
            "allowInsecure": True,  # Нужно для анонимных серверов
            "serverName": sni or host,
            "fingerprint": fp,
        }
        if alpn_raw:
            tls_cfg["alpn"] = [a.strip() for a in alpn_raw.split(",") if a.strip()]
        ss["security"]    = "tls"
        ss["tlsSettings"] = tls_cfg

    # ── REALITY ───────────────────────────────────────────────────────────────
    elif security == "reality":
        ss["security"]        = "reality"
        ss["realitySettings"] = {
            "serverName":  sni or host,
            "fingerprint": fp,
            "publicKey":   pbk,
            "shortId":     sid,
            "show":        False,
        }

    else:
        ss["security"] = "none"

    # ── Транспорт ─────────────────────────────────────────────────────────────
    if net == "ws":
        ss["wsSettings"] = {
            "path":    path,
            "headers": {"Host": h_header},
        }
    elif net in ("grpc", "gun"):
        ss["grpcSettings"] = {
            "serviceName": _p(params, "serviceName", path.lstrip("/")),
            "multiMode":   False,
            "authority":   h_header,
        }
    elif net == "h2":
        ss["httpSettings"] = {
            "path": path,
            "host": [h_header] if h_header else [],
        }
    elif net in ("httpupgrade", "h2upgrade"):
        ss["httpupgradeSettings"] = {
            "path": path,
            "host": h_header,
        }
    elif net in ("xhttp", "splithttp"):
        # SplitHTTP — для обхода жёсткого DPI
        xhttp_cfg: Dict[str, Any] = {
            "path": path,
            "host": h_header,
            "mode": mode,
        }
        extra = _p(params, "extra", "")
        if extra:
            try:
                xhttp_cfg["extra"] = json.loads(unquote(extra))
            except Exception:
                pass
        ss["xhttpSettings"] = xhttp_cfg
        # xhttp использует своё имя в network
        ss["network"] = "xhttp"
    elif net == "tcp":
        # TCP может иметь HTTP-обфускацию
        header_type = _p(params, "headerType", "none")
        if header_type == "http":
            ss["tcpSettings"] = {
                "header": {
                    "type": "http",
                    "request": {"path": [path], "headers": {"Host": [h_header]}},
                }
            }

    return ss


def _parse_vless(uri: str) -> Optional[Dict[str, Any]]:
    try:
        body    = uri[len("vless://"):]
        user_id, rest = body.split("@", 1)
        host_port = rest.split("?")[0]
        qs        = rest.split("?", 1)[1] if "?" in rest else ""
        qs        = qs.split("#")[0]
        host, port_s = host_port.rsplit(":", 1)
        host = host.strip("[]")
        port = int(port_s)
        params = parse_qs(qs)

        security = _p(params, "security", "none")
        net      = _p(params, "type", "tcp")
        flow     = _p(params, "flow", "")

        ss   = _build_stream_settings(params, net, security, host)
        user: Dict[str, Any] = {"id": user_id, "encryption": "none"}
        if flow:
            user["flow"] = flow

        return {
            "protocol": "vless",
            "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
            "streamSettings": ss,
        }
    except Exception:
        return None


def _parse_trojan(uri: str) -> Optional[Dict[str, Any]]:
    try:
        body = uri[len("trojan://"):]
        password, rest = body.split("@", 1)
        password  = unquote(password)
        host_port = rest.split("?")[0]
        qs        = rest.split("?", 1)[1] if "?" in rest else ""
        qs        = qs.split("#")[0]
        host, port_s = host_port.rsplit(":", 1)
        host = host.strip("[]")
        port = int(port_s)
        params = parse_qs(qs)

        security = _p(params, "security", "tls")
        net      = _p(params, "type", "tcp")
        ss       = _build_stream_settings(params, net, security, host)

        return {
            "protocol": "trojan",
            "settings": {"servers": [{
                "address":  host,
                "port":     port,
                "password": password,
            }]},
            "streamSettings": ss,
        }
    except Exception:
        return None


def _parse_vmess(uri: str) -> Optional[Dict[str, Any]]:
    try:
        enc  = uri[len("vmess://"):]
        enc += "=" * (-len(enc) % 4)
        data = json.loads(b64decode(enc).decode("utf-8", errors="ignore"))

        host    = str(data.get("add", ""))
        port    = int(data.get("port", 443))
        uid     = str(data.get("id", ""))
        aid     = int(data.get("aid", 0))
        net     = str(data.get("net", "tcp"))
        tls_val = str(data.get("tls", ""))
        sni     = str(data.get("sni", host))
        path    = str(data.get("path", "/"))
        h_host  = str(data.get("host", host))
        fp      = str(data.get("fp", "chrome"))
        alpn    = str(data.get("alpn", ""))

        ss: Dict[str, Any] = {"network": net}
        if tls_val == "tls":
            tls_cfg: Dict[str, Any] = {
                "allowInsecure": True,
                "serverName":    sni or host,
                "fingerprint":   fp or "chrome",
            }
            if alpn:
                tls_cfg["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
            ss["security"]    = "tls"
            ss["tlsSettings"] = tls_cfg
        else:
            ss["security"] = "none"

        if net == "ws":
            ss["wsSettings"] = {"path": path, "headers": {"Host": h_host}}
        elif net in ("grpc", "gun"):
            ss["grpcSettings"] = {"serviceName": path, "multiMode": False}
        elif net == "h2":
            ss["httpSettings"] = {"path": path, "host": [h_host] if h_host else []}
        elif net in ("xhttp", "splithttp"):
            ss["xhttpSettings"] = {"path": path, "host": h_host, "mode": "auto"}
            ss["network"] = "xhttp"
        elif net in ("httpupgrade", "h2upgrade"):
            ss["httpupgradeSettings"] = {"path": path, "host": h_host}

        return {
            "protocol": "vmess",
            "settings": {"vnext": [{
                "address": host,
                "port":    port,
                "users":   [{"id": uid, "alterId": aid, "security": "auto"}],
            }]},
            "streamSettings": ss,
        }
    except Exception:
        return None


def _parse_ss(uri: str) -> Optional[Dict[str, Any]]:
    try:
        body = uri[len("ss://"):]
        body = body.split("#")[0].split("?")[0]

        if "@" in body:
            cred_part, host_port = body.rsplit("@", 1)
            # Может быть base64
            try:
                cred_dec = b64decode(cred_part + "==").decode("utf-8")
            except Exception:
                cred_dec = unquote(cred_part)
            method, password = cred_dec.split(":", 1)
        else:
            # Старый формат: base64(method:password@host:port)
            decoded = b64decode(body + "==").decode("utf-8")
            creds, host_port = decoded.rsplit("@", 1)
            method, password = creds.split(":", 1)

        host, port_s = host_port.rsplit(":", 1)
        host = host.strip("[]")
        port = int(port_s)

        return {
            "protocol": "shadowsocks",
            "settings": {"servers": [{
                "address":  host,
                "port":     port,
                "method":   method.strip(),
                "password": password.strip(),
            }]},
            "streamSettings": {"network": "tcp", "security": "none"},
        }
    except Exception:
        return None


def _build_outbound(vpn_uri: str) -> Optional[Dict[str, Any]]:
    uri = vpn_uri.split("#")[0].strip()
    if uri.startswith("vless://"):
        return _parse_vless(uri)
    elif uri.startswith("trojan://"):
        return _parse_trojan(uri)
    elif uri.startswith("vmess://"):
        return _parse_vmess(uri)
    elif uri.startswith("ss://"):
        return _parse_ss(uri)
    return None


def _build_xray_config(outbound: Dict[str, Any], socks_port: int) -> Dict[str, Any]:
    return {
        "log":      {"loglevel": "none"},
        "inbounds": [{
            "port":     socks_port,
            "listen":   "127.0.0.1",
            "protocol": "socks",
            "settings": {
                "auth":      "noauth",
                "udp":       True,
                "userLevel": 0,
            },
            "sniffing": {
                "enabled":      True,
                "destOverride": ["http", "tls"],
            },
        }],
        "outbounds": [
            {**outbound, "tag": "proxy"},
            {"protocol": "freedom", "tag": "direct"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{"type": "field", "outboundTag": "proxy", "network": "tcp,udp"}],
        },
    }


# =============================================================================
# WhiteChecker — основной класс
# =============================================================================

class WhiteChecker:
    """
    Проверяет VPN-конфиг на «белый список» — доступность российских доменов.
    Запускает локальный xray как SOCKS5-прокси, затем делает HTTP-запросы через него.
    """

    def __init__(
        self,
        xray_path: Optional[str] = None,
        workers: int = WHITE_WORKERS,
        cache_hours: float = WHITE_CACHE_HOURS,
        check_timeout: float = WHITE_CHECK_TIMEOUT,
        logger: Optional[logging.Logger] = None,
    ):
        self.xray_bin      = self._find_xray(xray_path)
        self.workers       = workers
        self.cache_hours   = cache_hours
        self.check_timeout = check_timeout
        self.logger        = logger or logging.getLogger("white_checker")
        self._sem          = Semaphore(workers)

        if self.xray_bin:
            self.logger.info(f"WhiteChecker: xray = {self.xray_bin}")
        else:
            self.logger.warning("WhiteChecker: xray не найден — white check отключён")

    # ── поиск бинарника ───────────────────────────────────────────────────────

    @staticmethod
    def _find_xray(xray_path: Optional[str]) -> Optional[str]:
        candidates = []
        if xray_path:
            candidates.append(os.path.expanduser(xray_path))

        # Переменная среды
        env_bin = os.environ.get("XRAY_BIN", "")
        if env_bin:
            candidates.append(os.path.expanduser(env_bin))

        # Рядом со скриптом и выше
        here = os.path.dirname(os.path.abspath(__file__))
        parent = os.path.dirname(here)
        candidates += [
            os.path.join(here,   "xray"),
            os.path.join(here,   "xray-linux-64"),
            os.path.join(here,   "xray.exe"),
            os.path.join(parent, "xray"),
            os.path.join(parent, "xray-linux-64"),
        ]

        for cand in candidates:
            if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand

        return shutil.which("xray")

    def xray_available(self) -> bool:
        return self.xray_bin is not None

    # ── внутренний контекст-менеджер для процесса xray ───────────────────────

    class _XrayProcess:
        def __init__(self, xray_bin: str, config_path: str, socks_port: int,
                     logger: logging.Logger):
            self.xray_bin    = xray_bin
            self.config_path = config_path
            self.socks_port  = socks_port
            self.logger      = logger
            self.proc: Optional[subprocess.Popen] = None

        def __enter__(self) -> "WhiteChecker._XrayProcess":
            self.proc = subprocess.Popen(
                [self.xray_bin, "run", "-config", self.config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
            if not _wait_for_port(self.socks_port, XRAY_STARTUP_WAIT):
                self._kill()
                raise RuntimeError("xray не запустился вовремя")
            if self.proc.poll() is not None:
                raise RuntimeError("xray завершился сразу после старта")
            time.sleep(POST_START_DELAY)
            return self

        def __exit__(self, *_: Any) -> None:
            self._kill()

        def _kill(self) -> None:
            if not self.proc:
                return
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3)
            except Exception:
                try:
                    self.proc.kill()
                    self.proc.wait(timeout=2)
                except Exception:
                    pass

    # ── одна проверка ─────────────────────────────────────────────────────────

    def is_white_key(
        self,
        vpn_uri: str,
        timeout: Optional[float] = None,
        shutdown_event: Optional[threading.Event] = None,
    ) -> bool:
        """Проверить один VPN URI через xray. Возвращает True если «белый»."""
        if not self.xray_bin:
            return False
        if shutdown_event and shutdown_event.is_set():
            return False

        with self._sem:
            return self._check_one(vpn_uri, timeout or self.check_timeout, shutdown_event)

    def _check_one(
        self,
        vpn_uri: str,
        effective_timeout: float,
        shutdown_event: Optional[threading.Event],
    ) -> bool:
        outbound = _build_outbound(vpn_uri)
        if outbound is None:
            return False

        socks_port = _free_port()
        config     = _build_xray_config(outbound, socks_port)
        t_start    = time.monotonic()
        tmp_cfg: Optional[str] = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False, encoding="utf-8"
            ) as tf:
                json.dump(config, tf, ensure_ascii=False)
                tmp_cfg = tf.name

            with self._XrayProcess(self.xray_bin, tmp_cfg, socks_port, self.logger):
                if shutdown_event and shutdown_event.is_set():
                    return False

                elapsed   = time.monotonic() - t_start
                remaining = max(2.0, effective_timeout - elapsed)
                per_req   = min(HTTP_TIMEOUT, max(2.5, remaining / len(WHITE_TEST_DOMAINS)))

                proxies = {
                    "http":  f"socks5h://127.0.0.1:{socks_port}",
                    "https": f"socks5h://127.0.0.1:{socks_port}",
                }
                headers = {
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/124.0.0.0 Safari/537.36"
                    ),
                    "Accept":          "text/html,application/xhtml+xml,*/*",
                    "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8",
                    "Connection":      "close",
                }

                success = 0
                for domain in WHITE_TEST_DOMAINS:
                    if shutdown_event and shutdown_event.is_set():
                        return False
                    if time.monotonic() - t_start > effective_timeout - 1.5:
                        break
                    try:
                        resp = requests.get(
                            f"https://{domain}/",
                            proxies=proxies,
                            timeout=per_req,
                            allow_redirects=True,
                            verify=False,
                            headers=headers,
                            stream=False,
                        )
                        # Любой ответ (включая ошибки сервера) означает
                        # что туннель работает и домен доступен
                        if resp.status_code < 600:
                            success += 1
                            if success >= WHITE_THRESHOLD:
                                return True
                    except requests.exceptions.ProxyError:
                        # Прокси не может подключиться — явный FAIL
                        pass
                    except requests.exceptions.Timeout:
                        pass
                    except Exception:
                        pass

                return success >= WHITE_THRESHOLD

        except RuntimeError:
            # xray не запустился
            return False
        except Exception as e:
            self.logger.debug(f"white check error: {e}")
            return False
        finally:
            if tmp_cfg and os.path.exists(tmp_cfg):
                try:
                    os.unlink(tmp_cfg)
                except OSError:
                    pass

    # ── пакетная проверка ─────────────────────────────────────────────────────

    def batch_white_check(
        self,
        keys: List[str],
        history: Dict[str, Any],
        *,
        label: str = "",
        shutdown_event: Optional[threading.Event] = None,
    ) -> Tuple[List[str], List[str]]:
        """
        Проверить список URI. Возвращает (white_list, black_list).
        Использует кэш из history для уже проверенных ключей.
        """
        if not self.xray_bin:
            self.logger.warning(f"[{label}] xray не найден → все ключи в WHITE")
            return list(keys), []

        now = time.time()
        cached_white: List[str] = []
        cached_black: List[str] = []
        to_test:      List[str] = []

        for k in keys:
            k_id = k.split("#")[0]
            h    = history.get(k_id, {})
            w    = h.get("white")
            w_t  = h.get("white_time", 0)
            if w is not None and (now - w_t) < self.cache_hours * 3600:
                (cached_white if w else cached_black).append(k)
            else:
                to_test.append(k)

        if cached_white or cached_black:
            self.logger.info(
                f"[{label}] Кэш: WHITE={len(cached_white)} BLACK={len(cached_black)}"
            )

        white_keys = list(cached_white)
        black_keys = list(cached_black)

        if not to_test:
            return white_keys, black_keys

        self.logger.info(
            f"[{label}] Белый чек: {len(to_test)} ключей | workers={self.workers}"
        )

        completed = 0
        total     = len(to_test)
        lock      = threading.Lock()

        def _check(k: str) -> Tuple[str, bool]:
            uri = k.split("#")[0]
            try:
                result = self.is_white_key(uri, shutdown_event=shutdown_event)
            except Exception:
                result = False
            return k, result

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {executor.submit(_check, k): k for k in to_test}

            for future in as_completed(futures):
                if shutdown_event and shutdown_event.is_set():
                    for f in futures:
                        f.cancel()
                    break

                try:
                    k, result = future.result()
                except Exception:
                    k      = futures[future]
                    result = False

                k_id = k.split("#")[0]
                with lock:
                    if k_id in history:
                        history[k_id]["white"]      = result
                        history[k_id]["white_time"] = time.time()
                    if result:
                        white_keys.append(k)
                    else:
                        black_keys.append(k)
                    completed += 1

                if completed % 10 == 0 or completed == total:
                    pct = completed * 100 // total
                    self.logger.info(
                        f"[{label}] {completed}/{total} ({pct}%) "
                        f"WHITE={len(white_keys)} BLACK={len(black_keys)}"
                    )

        return white_keys, black_keys

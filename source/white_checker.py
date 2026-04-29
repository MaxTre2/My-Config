from __future__ import annotations

import json
import logging
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
from base64 import b64decode
from concurrent.futures import ThreadPoolExecutor, wait as futures_wait, FIRST_COMPLETED
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

WHITE_TEST_DOMAINS  = ["alfabank.ru", "gosuslugi.ru", "mironline.ru"]
WHITE_THRESHOLD     = 2        # из WHITE_TEST_DOMAINS должны ответить хотя бы 2

HTTP_TIMEOUT        = 4        # таймаут одного HTTP-запроса через SOCKS5
XRAY_STARTUP_WAIT   = 4.0      # максимум ждём, пока xray откроет порт
XRAY_POLL_INTERVAL  = 0.08

WHITE_CHECK_TIMEOUT = 16.0     # жёсткий таймаут ОДНОЙ проверки (сек)
BATCH_TIMEOUT_SEC   = 480      # жёсткий таймаут ВСЕГО батча (8 минут)
WHITE_WORKERS       = 8        # параллельных потоков (xray-процессов)
WHITE_CACHE_HOURS   = 24

POST_START_DELAY    = 0.3


# =============================================================================
# Утилиты
# =============================================================================

def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]


def _wait_for_port(port: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=XRAY_POLL_INTERVAL):
                return True
        except OSError:
            time.sleep(XRAY_POLL_INTERVAL)
    return False


def _kill_proc(proc: subprocess.Popen) -> None:
    """Убить процесс немедленно — SIGKILL, без ожидания."""
    try:
        proc.kill()          # SIGKILL — мгновенная смерть
        proc.wait(timeout=2)
    except Exception:
        pass


# =============================================================================
# URI → xray outbound config
# =============================================================================

def _p(params: Dict[str, List[str]], key: str, default: str = "") -> str:
    return params.get(key, [default])[0]


def _build_stream_settings(
    params: Dict[str, List[str]], net: str, security: str, host: str
) -> Dict[str, Any]:
    sni      = _p(params, "sni", host)
    fp       = _p(params, "fp", "chrome") or "chrome"
    pbk      = _p(params, "pbk", "")
    sid      = _p(params, "sid", "")
    path     = unquote(_p(params, "path", "/")) or "/"
    h_header = unquote(_p(params, "host", host)) or host
    alpn_raw = _p(params, "alpn", "")
    mode     = _p(params, "mode", "auto")

    ss: Dict[str, Any] = {"network": net}

    if security == "tls":
        tls_cfg: Dict[str, Any] = {
            "allowInsecure": True,
            "serverName":    sni or host,
            "fingerprint":   fp,
        }
        if alpn_raw:
            tls_cfg["alpn"] = [a.strip() for a in alpn_raw.split(",") if a.strip()]
        ss["security"]    = "tls"
        ss["tlsSettings"] = tls_cfg

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

    if net == "ws":
        ss["wsSettings"] = {"path": path, "headers": {"Host": h_header}}
    elif net in ("grpc", "gun"):
        ss["grpcSettings"] = {
            "serviceName": _p(params, "serviceName", path.lstrip("/")),
            "multiMode":   False,
            "authority":   h_header,
        }
    elif net == "h2":
        ss["httpSettings"] = {"path": path, "host": [h_header] if h_header else []}
    elif net in ("httpupgrade", "h2upgrade"):
        ss["httpupgradeSettings"] = {"path": path, "host": h_header}
    elif net in ("xhttp", "splithttp"):
        xhttp_cfg: Dict[str, Any] = {"path": path, "host": h_header, "mode": mode}
        extra = _p(params, "extra", "")
        if extra:
            try:
                xhttp_cfg["extra"] = json.loads(unquote(extra))
            except Exception:
                pass
        ss["xhttpSettings"] = xhttp_cfg
        ss["network"]       = "xhttp"
    elif net == "tcp":
        if _p(params, "headerType", "none") == "http":
            ss["tcpSettings"] = {
                "header": {
                    "type":    "http",
                    "request": {"path": [path], "headers": {"Host": [h_header]}},
                }
            }
    return ss


def _parse_vless(uri: str) -> Optional[Dict[str, Any]]:
    try:
        body    = uri[len("vless://"):]
        user_id, rest = body.split("@", 1)
        qs      = rest.split("?", 1)[1].split("#")[0] if "?" in rest else ""
        hp      = rest.split("?")[0]
        host, port_s = hp.rsplit(":", 1)
        host    = host.strip("[]")
        params  = parse_qs(qs)
        security = _p(params, "security", "none")
        net      = _p(params, "type", "tcp")
        flow     = _p(params, "flow", "")
        ss       = _build_stream_settings(params, net, security, host)
        user: Dict[str, Any] = {"id": user_id, "encryption": "none"}
        if flow:
            user["flow"] = flow
        return {
            "protocol": "vless",
            "settings": {"vnext": [{"address": host, "port": int(port_s), "users": [user]}]},
            "streamSettings": ss,
        }
    except Exception:
        return None


def _parse_trojan(uri: str) -> Optional[Dict[str, Any]]:
    try:
        body = uri[len("trojan://"):]
        password, rest = body.split("@", 1)
        password = unquote(password)
        qs   = rest.split("?", 1)[1].split("#")[0] if "?" in rest else ""
        hp   = rest.split("?")[0]
        host, port_s = hp.rsplit(":", 1)
        host = host.strip("[]")
        params   = parse_qs(qs)
        security = _p(params, "security", "tls")
        net      = _p(params, "type", "tcp")
        ss       = _build_stream_settings(params, net, security, host)
        return {
            "protocol": "trojan",
            "settings": {"servers": [{"address": host, "port": int(port_s), "password": password}]},
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
                "allowInsecure": True, "serverName": sni or host, "fingerprint": fp or "chrome",
            }
            if alpn:
                tls_cfg["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
            ss["security"] = "tls"
            ss["tlsSettings"] = tls_cfg
        else:
            ss["security"] = "none"
        if net == "ws":
            ss["wsSettings"] = {"path": path, "headers": {"Host": h_host}}
        elif net in ("grpc", "gun"):
            ss["grpcSettings"] = {"serviceName": path, "multiMode": False}
        elif net in ("xhttp", "splithttp"):
            ss["xhttpSettings"] = {"path": path, "host": h_host, "mode": "auto"}
            ss["network"] = "xhttp"
        return {
            "protocol": "vmess",
            "settings": {"vnext": [{"address": host, "port": port,
                                    "users": [{"id": uid, "alterId": aid, "security": "auto"}]}]},
            "streamSettings": ss,
        }
    except Exception:
        return None


def _parse_ss(uri: str) -> Optional[Dict[str, Any]]:
    try:
        body = uri[len("ss://"):].split("#")[0].split("?")[0]
        if "@" in body:
            cred_part, host_port = body.rsplit("@", 1)
            try:
                cred_dec = b64decode(cred_part + "==").decode("utf-8")
            except Exception:
                cred_dec = unquote(cred_part)
            method, password = cred_dec.split(":", 1)
        else:
            decoded = b64decode(body + "==").decode("utf-8")
            creds, host_port = decoded.rsplit("@", 1)
            method, password = creds.split(":", 1)
        host, port_s = host_port.rsplit(":", 1)
        host = host.strip("[]")
        return {
            "protocol": "shadowsocks",
            "settings": {"servers": [{"address": host, "port": int(port_s),
                                       "method": method.strip(), "password": password.strip()}]},
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
        "log": {"loglevel": "none"},
        "inbounds": [{
            "port": socks_port, "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [{**outbound, "tag": "proxy"}, {"protocol": "freedom", "tag": "direct"}],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{"type": "field", "outboundTag": "proxy", "network": "tcp,udp"}],
        },
    }


# =============================================================================
# WhiteChecker
# =============================================================================

class WhiteChecker:
    """
    Проверяет VPN-конфиг: запускает xray как SOCKS5, делает HTTP-запросы.
    Ключевой принцип: ни один поток не зависнет дольше WHITE_CHECK_TIMEOUT.
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
        self._sem          = threading.Semaphore(workers)

        if self.xray_bin:
            self.logger.info(f"WhiteChecker: xray={self.xray_bin} workers={workers} timeout={check_timeout}s")
        else:
            self.logger.warning("WhiteChecker: xray не найден — white check отключён")

    @staticmethod
    def _find_xray(xray_path: Optional[str]) -> Optional[str]:
        candidates = []
        if xray_path:
            candidates.append(os.path.expanduser(xray_path))
        env_bin = os.environ.get("XRAY_BIN", "")
        if env_bin:
            candidates.append(os.path.expanduser(env_bin))
        here   = os.path.dirname(os.path.abspath(__file__))
        parent = os.path.dirname(here)
        candidates += [
            os.path.join(here,   "xray"),
            os.path.join(parent, "xray"),
            os.path.join(here,   "xray-linux-64"),
        ]
        for cand in candidates:
            if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
        return shutil.which("xray")

    def xray_available(self) -> bool:
        return self.xray_bin is not None

    # ── одна проверка ─────────────────────────────────────────────────────────

    def is_white_key(
        self,
        vpn_uri: str,
        shutdown_event: Optional[threading.Event] = None,
    ) -> bool:
        if not self.xray_bin:
            return False
        if shutdown_event and shutdown_event.is_set():
            return False
        with self._sem:
            return self._check_one_safe(vpn_uri, self.check_timeout, shutdown_event)

    def _check_one_safe(
        self,
        vpn_uri: str,
        timeout: float,
        shutdown_event: Optional[threading.Event],
    ) -> bool:
        """Обёртка с гарантией завершения через timeout секунд."""
        result_holder: List[bool] = [False]
        proc_holder:   List[Optional[subprocess.Popen]] = [None]

        def _run() -> None:
            result_holder[0] = self._check_one(vpn_uri, timeout, shutdown_event, proc_holder)

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        t.join(timeout=timeout + 2.0)  # +2 сек запас поверх таймаута

        if t.is_alive():
            # Поток завис — убиваем xray и возвращаем False
            self.logger.debug(f"check_one TIMEOUT for {vpn_uri[:40]}")
            proc = proc_holder[0]
            if proc:
                _kill_proc(proc)
            # Поток завершится сам когда xray умрёт

        return result_holder[0]

    def _check_one(
        self,
        vpn_uri: str,
        effective_timeout: float,
        shutdown_event: Optional[threading.Event],
        proc_holder: List[Optional[subprocess.Popen]],
    ) -> bool:
        outbound = _build_outbound(vpn_uri)
        if outbound is None:
            return False

        socks_port = _free_port()
        config     = _build_xray_config(outbound, socks_port)
        t_start    = time.monotonic()
        tmp_cfg: Optional[str] = None
        proc: Optional[subprocess.Popen] = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False, encoding="utf-8"
            ) as tf:
                json.dump(config, tf, ensure_ascii=False)
                tmp_cfg = tf.name

            # Запуск xray
            proc = subprocess.Popen(
                [self.xray_bin, "run", "-config", tmp_cfg],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
            proc_holder[0] = proc

            if not _wait_for_port(socks_port, XRAY_STARTUP_WAIT):
                _kill_proc(proc)
                return False

            if proc.poll() is not None:
                return False

            if shutdown_event and shutdown_event.is_set():
                _kill_proc(proc)
                return False

            time.sleep(POST_START_DELAY)

            # HTTP-проверка через SOCKS5
            elapsed   = time.monotonic() - t_start
            remaining = max(2.0, effective_timeout - elapsed)
            per_req   = min(HTTP_TIMEOUT, max(2.0, remaining / len(WHITE_TEST_DOMAINS)))

            proxies = {
                "http":  f"socks5h://127.0.0.1:{socks_port}",
                "https": f"socks5h://127.0.0.1:{socks_port}",
            }
            headers = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
                ),
                "Connection": "close",
            }

            success = 0
            for domain in WHITE_TEST_DOMAINS:
                if shutdown_event and shutdown_event.is_set():
                    break
                if time.monotonic() - t_start > effective_timeout - 1.0:
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
                    if resp.status_code < 600:
                        success += 1
                        if success >= WHITE_THRESHOLD:
                            return True
                except requests.exceptions.ProxyError:
                    pass   # SOCKS отказал — явный FAIL
                except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                    pass
                except Exception:
                    pass

            return success >= WHITE_THRESHOLD

        except Exception as e:
            self.logger.debug(f"check_one error: {e}")
            return False
        finally:
            # ОБЯЗАТЕЛЬНО убиваем xray — SIGKILL, мгновенно
            if proc:
                _kill_proc(proc)
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
        Жёсткий глобальный таймаут BATCH_TIMEOUT_SEC — батч ВСЕГДА завершится.
        """
        if not self.xray_bin:
            self.logger.warning(f"[{label}] xray нет → все в WHITE")
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

        self.logger.info(
            f"[{label}] Кэш: WHITE={len(cached_white)} BLACK={len(cached_black)} "
            f"| Проверить: {len(to_test)}"
        )

        white_keys = list(cached_white)
        black_keys = list(cached_black)

        if not to_test:
            return white_keys, black_keys

        self.logger.info(
            f"[{label}] White check: {len(to_test)} ключей | "
            f"workers={self.workers} timeout/key={self.check_timeout}s | "
            f"batch_max={BATCH_TIMEOUT_SEC}s"
        )

        completed = 0
        total     = len(to_test)
        lock      = threading.Lock()
        t_batch   = time.monotonic()

        def _check(k: str) -> Tuple[str, bool]:
            if shutdown_event and shutdown_event.is_set():
                return k, False
            uri    = k.split("#")[0]
            result = self._check_one_safe(uri, self.check_timeout, shutdown_event)
            return k, result

        with ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="wc") as executor:
            future_to_key = {executor.submit(_check, k): k for k in to_test}
            pending       = set(future_to_key.keys())

            while pending:
                # ── Жёсткий таймаут всего батча ──────────────────────────
                batch_elapsed = time.monotonic() - t_batch
                if batch_elapsed >= BATCH_TIMEOUT_SEC:
                    self.logger.warning(
                        f"[{label}] BATCH TIMEOUT {BATCH_TIMEOUT_SEC}s — "
                        f"отменяем {len(pending)} оставшихся (WHITE={len(white_keys)} BLACK={len(black_keys)})"
                    )
                    for f in pending:
                        f.cancel()
                    break

                if shutdown_event and shutdown_event.is_set():
                    for f in pending:
                        f.cancel()
                    break

                # Ждём любого завершённого future, не дольше 5 сек
                done, pending = futures_wait(pending, timeout=5.0, return_when=FIRST_COMPLETED)

                for future in done:
                    try:
                        k, result = future.result(timeout=0)
                    except Exception:
                        k      = future_to_key.get(future, "?")
                        result = False

                    k_id = k.split("#")[0]
                    with lock:
                        if k_id in history:
                            history[k_id]["white"]      = result
                            history[k_id]["white_time"] = time.time()
                        (white_keys if result else black_keys).append(k)
                        completed += 1

                if completed % 5 == 0 and completed > 0:
                    elapsed = time.monotonic() - t_batch
                    rate    = completed / elapsed if elapsed > 0 else 0.01
                    eta     = (total - completed) / rate
                    self.logger.info(
                        f"[{label}] {completed}/{total} ({completed*100//total}%) "
                        f"WHITE={len(white_keys)} BLACK={len(black_keys)} "
                        f"rate={rate:.1f}/s ETA={min(eta, BATCH_TIMEOUT_SEC - elapsed):.0f}s"
                    )

        elapsed = time.monotonic() - t_batch
        self.logger.info(
            f"[{label}] Готово за {elapsed:.0f}s: "
            f"WHITE={len(white_keys)} BLACK={len(black_keys)}"
        )
        return white_keys, black_keys

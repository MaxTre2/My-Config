#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
white_checker.py — Async White/Black checker via Xray-Core.
Проверяет, что прокси реально открывает российские сайты через SOCKS5-туннель.
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import shutil
import socket
import tempfile
import time
from base64 import b64decode
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote

from aiohttp import ClientSession, ClientTimeout
from aiohttp_socks import ProxyConnector

# =============================================================================
# НАСТРОЙКИ ПО УМОЛЧАНИЮ
# =============================================================================

WHITE_TEST_DOMAINS = [
    "alfabank.ru",
    "mironline.ru",
    "vkusvill.ru",
    "sberbank.ru",
    "yandex.ru",
]
WHITE_THRESHOLD = 2
XRAY_STARTUP_TIMEOUT = 10.0
XRAY_POLL_INTERVAL = 0.1


# =============================================================================
# МОДЕЛЬ (дублируем для автономности, main.py использует такую же)
# =============================================================================

@dataclass(frozen=True, slots=True)
class ProxyConfig:
    uri: str
    protocol: str
    host: str
    port: int
    fingerprint: str
    raw_params: Dict[str, str]


# =============================================================================
# WHITE CHECKER
# =============================================================================

class WhiteChecker:
    """
    Асинхронная проверка прокси через Xray-Core.
    Запускает локальный xray → SOCKS5 → проверяет доступность российских сайтов.
    """

    def __init__(
        self,
        xray_path: Optional[Path] = None,
        workers: int = 5,
        check_timeout: float = 20.0,
        test_domains: Optional[List[str]] = None,
        threshold: int = WHITE_THRESHOLD,
        allow_insecure: bool = False,
        logger: Optional[Any] = None,
    ):
        self.xray_path = self._resolve_xray(xray_path)
        self.semaphore = asyncio.Semaphore(workers)
        self.check_timeout = check_timeout
        self.test_domains = test_domains or list(WHITE_TEST_DOMAINS)
        self.threshold = threshold
        self.allow_insecure = allow_insecure
        self.logger = logger

    # -------------------------------------------------------------------------
    # Утилиты
    # -------------------------------------------------------------------------

    def _log(self, level: str, msg: str) -> None:
        if self.logger and hasattr(self.logger, level):
            getattr(self.logger, level)(msg)

    @staticmethod
    def _resolve_xray(explicit: Optional[Path]) -> Optional[Path]:
        if explicit and explicit.exists() and os.access(explicit, os.X_OK):
            return explicit

        script_dir = Path(__file__).parent
        for name in ("xray", "xray-linux-64", "xray-linux-arm64", "xray.exe"):
            cand = script_dir / name
            if cand.exists():
                cand.chmod(0o755)
                if os.access(cand, os.X_OK):
                    return cand

        env_bin = os.environ.get("XRAY_BIN", "")
        if env_bin and Path(env_bin).exists() and os.access(env_bin, os.X_OK):
            return Path(env_bin)

        w = shutil.which("xray")
        return Path(w) if w else None

    def is_available(self) -> bool:
        return self.xray_path is not None

    # -------------------------------------------------------------------------
    # Парсинг URI → Xray outbound (сохраняем полную логику оригинала)
    # -------------------------------------------------------------------------

    @staticmethod
    def _p(params: Dict[str, List[str]], key: str, default: str = "") -> str:
        return params.get(key, [default])[0]

    def _stream_settings(
        self, params: Dict[str, List[str]], net: str, security: str, host: str
    ) -> Dict[str, Any]:
        sni = self._p(params, "sni", host)
        fp = self._p(params, "fp", "chrome")
        pbk = self._p(params, "pbk", "")
        sid = self._p(params, "sid", "")
        path = unquote(self._p(params, "path", "/"))
        h_header = unquote(self._p(params, "host", host))
        alpn_raw = self._p(params, "alpn", "")

        ss: Dict[str, Any] = {"network": net}

        if security == "tls":
            tls_cfg: Dict[str, Any] = {
                "allowInsecure": self.allow_insecure,
                "serverName": sni,
                "fingerprint": fp or "chrome",
            }
            if alpn_raw:
                tls_cfg["alpn"] = [a.strip() for a in alpn_raw.split(",") if a.strip()]
            ss["security"] = "tls"
            ss["tlsSettings"] = tls_cfg
        elif security == "reality":
            reality_settings: Dict[str, Any] = {
                "serverName": sni,
                "fingerprint": fp or "chrome",
                "publicKey": pbk,
                "shortId": sid,
            }
            spider_x = self._p(params, "spiderX", "")
            if spider_x:
                reality_settings["spiderX"] = spider_x
            mldsa65_verify = self._p(params, "mldsa65Verify", "")
            if mldsa65_verify:
                reality_settings["mldsa65Verify"] = mldsa65_verify.lower() == "true"
            ss["security"] = "reality"
            ss["realitySettings"] = reality_settings
        else:
            ss["security"] = "none"

        if net == "ws":
            ss["wsSettings"] = {"path": path, "headers": {"Host": h_header}}
        elif net == "grpc":
            ss["grpcSettings"] = {
                "serviceName": self._p(params, "serviceName", ""),
                "multiMode": False,
            }
        elif net == "h2":
            ss["httpSettings"] = {"path": path, "host": [h_header] if h_header else []}
        elif net == "httpupgrade":
            ss["httpupgradeSettings"] = {"path": path, "host": h_header}
        elif net == "xhttp":
            mode = self._p(params, "mode", "auto")
            xhttp_host = self._p(params, "xhttp_host", h_header) or h_header
            xhttp_path = self._p(params, "xhttp_path", path) or "/"

            xhttp_settings: Dict[str, Any] = {
                "path": xhttp_path,
                "host": xhttp_host,
                "mode": mode,
            }
            for key in ("maxBytes", "maxConcurrency", "minUploadInterval"):
                val = self._p(params, key, "")
                if val:
                    try:
                        xhttp_settings[key] = int(val)
                    except ValueError:
                        pass
            extra_json = self._p(params, "extra", "")
            if extra_json:
                try:
                    xhttp_settings["extra"] = json.loads(extra_json)
                except json.JSONDecodeError:
                    pass
            ss["xhttpSettings"] = xhttp_settings

        return ss

    def _parse_vless(self, uri: str) -> Optional[Dict[str, Any]]:
        try:
            body = uri[len("vless://") :]
            user_id, rest = body.split("@", 1)
            host_port = rest.split("?")[0]
            qs = rest.split("?", 1)[1] if "?" in rest else ""
            qs = qs.split("#")[0]
            host, port_s = host_port.rsplit(":", 1)
            host = host.strip("[]")
            port = int(port_s)
            params = parse_qs(qs)

            security = self._p(params, "security", "none")
            net = self._p(params, "type", "tcp")
            flow = self._p(params, "flow", "")

            ss = self._stream_settings(params, net, security, host)

            user: Dict[str, Any] = {"id": user_id, "encryption": "none"}
            if flow:
                user["flow"] = flow

            return {
                "protocol": "vless",
                "settings": {
                    "vnext": [{"address": host, "port": port, "users": [user]}]
                },
                "streamSettings": ss,
            }
        except Exception:
            return None

    def _parse_trojan(self, uri: str) -> Optional[Dict[str, Any]]:
        try:
            body = uri[len("trojan://") :]
            password, rest = body.split("@", 1)
            password = unquote(password)
            host_port = rest.split("?")[0]
            qs = rest.split("?", 1)[1] if "?" in rest else ""
            qs = qs.split("#")[0]
            host, port_s = host_port.rsplit(":", 1)
            host = host.strip("[]")
            port = int(port_s)
            params = parse_qs(qs)

            security = self._p(params, "security", "tls")
            net = self._p(params, "type", "tcp")

            ss = self._stream_settings(params, net, security, host)

            return {
                "protocol": "trojan",
                "settings": {
                    "servers": [{"address": host, "port": port, "password": password}]
                },
                "streamSettings": ss,
            }
        except Exception:
            return None

    def _parse_vmess(self, uri: str) -> Optional[Dict[str, Any]]:
        try:
            enc = uri[len("vmess://") :]
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
            pbk = str(data.get("pbk", ""))
            sid = str(data.get("sid", ""))
            spider_x = str(data.get("spiderX", ""))
            mldsa65_verify = str(data.get("mldsa65Verify", ""))

            ss: Dict[str, Any] = {"network": net}

            if tls == "tls":
                tls_cfg: Dict[str, Any] = {
                    "allowInsecure": self.allow_insecure,
                    "serverName": sni,
                    "fingerprint": fp or "chrome",
                }
                if alpn:
                    tls_cfg["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
                ss["security"] = "tls"
                ss["tlsSettings"] = tls_cfg
            elif tls == "reality":
                reality_settings: Dict[str, Any] = {
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
            elif net == "xhttp":
                mode = str(data.get("mode", "auto"))
                xhttp_settings: Dict[str, Any] = {
                    "path": path,
                    "host": h_host,
                    "mode": mode,
                }
                for key in ("maxBytes", "maxConcurrency", "minUploadInterval"):
                    val = data.get(key)
                    if val is not None:
                        try:
                            xhttp_settings[key] = int(val)
                        except (ValueError, TypeError):
                            pass
                extra = data.get("extra")
                if extra:
                    try:
                        xhttp_settings["extra"] = (
                            json.loads(extra) if isinstance(extra, str) else extra
                        )
                    except json.JSONDecodeError:
                        pass
                ss["xhttpSettings"] = xhttp_settings

            return {
                "protocol": "vmess",
                "settings": {
                    "vnext": [
                        {
                            "address": host,
                            "port": port,
                            "users": [{"id": uid, "alterId": aid, "security": "auto"}],
                        }
                    ]
                },
                "streamSettings": ss,
            }
        except Exception:
            return None

    def _parse_ss(self, uri: str) -> Optional[Dict[str, Any]]:
        try:
            body = uri[len("ss://") :]
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
                "settings": {
                    "servers": [
                        {
                            "address": host,
                            "port": port,
                            "method": method,
                            "password": password,
                            "uot": False,
                        }
                    ]
                },
                "streamSettings": {"network": "tcp", "security": "none"},
            }
        except Exception:
            return None

    def _build_outbound(self, uri: str) -> Optional[Dict[str, Any]]:
        uri = uri.split("#")[0].strip()
        if uri.startswith("vless://"):
            return self._parse_vless(uri)
        if uri.startswith("trojan://"):
            return self._parse_trojan(uri)
        if uri.startswith("vmess://"):
            return self._parse_vmess(uri)
        if uri.startswith("ss://"):
            return self._parse_ss(uri)
        return None

    def _build_xray_config(
        self, outbound: Dict[str, Any], socks_port: int
    ) -> Dict[str, Any]:
        return {
            "log": {"loglevel": "none"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": socks_port,
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": False},
                    "sniffing": {"enabled": False},
                }
            ],
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

    # -------------------------------------------------------------------------
    # Управление процессом Xray
    # -------------------------------------------------------------------------

    @staticmethod
    def _free_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    async def _wait_for_port(self, port: int, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                r, w = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", port),
                    timeout=XRAY_POLL_INTERVAL,
                )
                w.close()
                await w.wait_closed()
                return True
            except (asyncio.TimeoutError, OSError):
                await asyncio.sleep(XRAY_POLL_INTERVAL)
        return False

    async def _start_xray(
        self, outbound: Dict[str, Any]
    ) -> Tuple[asyncio.subprocess.Process, int, Path]:
        socks_port = self._free_port()
        config = self._build_xray_config(outbound, socks_port)

        fd, tmp_path = tempfile.mkstemp(suffix=".json", prefix="xray_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(config, f)
        except Exception:
            os.unlink(tmp_path)
            raise

        cmd = [str(self.xray_path), "run", "-config", tmp_path]
        kwargs: Dict[str, Any] = {}
        if platform.system() != "Windows":
            kwargs["start_new_session"] = True

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
            **kwargs,
        )

        if not await self._wait_for_port(socks_port, XRAY_STARTUP_TIMEOUT):
            await self._stop_xray(process, Path(tmp_path))
            raise RuntimeError("Xray failed to open SOCKS port")

        if process.returncode is not None:
            await self._stop_xray(process, Path(tmp_path))
            raise RuntimeError("Xray exited immediately")

        return process, socks_port, Path(tmp_path)

    async def _stop_xray(
        self, process: asyncio.subprocess.Process, config_path: Path
    ) -> None:
        if process.returncode is None:
            try:
                process.terminate()
                await asyncio.wait_for(process.wait(), timeout=3.0)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    process.kill()
                    await process.wait()
                except ProcessLookupError:
                    pass

        if config_path.exists():
            try:
                config_path.unlink()
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # Проверка доменов через SOCKS
    # -------------------------------------------------------------------------

    async def _probe_domains(
        self, socks_port: int, domains: List[str], deadline: float
    ) -> int:
        connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{socks_port}")
        session_timeout = ClientTimeout(total=max(1.0, deadline - time.monotonic()))

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,*/*",
        }

        success = 0
        async with ClientSession(
            connector=connector, timeout=session_timeout
        ) as session:
            for domain in domains:
                if time.monotonic() >= deadline - 0.5:
                    break

                for scheme in ("https", "http"):
                    try:
                        async with session.get(
                            f"{scheme}://{domain}/",
                            headers=headers,
                            allow_redirects=True,
                            ssl=True,  # verify включён — это правильно
                        ) as resp:
                            # Любой ответ означает работающий туннель
                            if resp.status < 600:
                                success += 1
                                break
                    except Exception:
                        continue

                if success >= self.threshold:
                    break

        return success

    # -------------------------------------------------------------------------
    # Публичный API
    # -------------------------------------------------------------------------

    async def check(self, uri: str) -> bool:
        """Проверяет один прокси. Возвращает True если открылось ≥ threshold сайтов."""
        if not self.xray_path:
            return False

        async with self.semaphore:
            outbound = self._build_outbound(uri)
            if outbound is None:
                return False

            process: Optional[asyncio.subprocess.Process] = None
            cfg_path: Optional[Path] = None
            t_start = time.monotonic()

            try:
                process, socks_port, cfg_path = await self._start_xray(outbound)
                deadline = t_start + self.check_timeout

                success = await asyncio.wait_for(
                    self._probe_domains(socks_port, self.test_domains, deadline),
                    timeout=self.check_timeout + 2,
                )
                return success >= self.threshold

            except Exception as exc:
                self._log("debug", f"White check failed for {uri[:60]}: {exc}")
                return False

            finally:
                if process and cfg_path:
                    await self._stop_xray(process, cfg_path)

    async def batch_check(
        self,
        keys: List[str],
        cache: Optional[Dict[str, Any]] = None,
        cache_hours: float = 24.0,
    ) -> Tuple[List[str], List[str]]:
        """
        Массовая проверка с кэшированием.
        Возвращает (white_keys, black_keys).
        """
        if not self.xray_path:
            self._log("warning", "xray not found, all keys -> WHITE")
            return list(keys), []

        cache = cache or {}
        now = time.time()
        white: List[str] = []
        black: List[str] = []
        to_test: List[str] = []

        for k in keys:
            k_id = k.split("#")[0]
            entry = cache.get(k_id, {})
            cached_white = entry.get("white")
            cached_time = entry.get("white_time", 0)

            if cached_white is not None and (now - cached_time) < cache_hours * 3600:
                (white if cached_white else black).append(k)
            else:
                to_test.append(k)

        self._log(
            "info",
            f"White cache: WHITE={len(white)} BLACK={len(black)} | to_test={len(to_test)}",
        )

        if not to_test:
            return white, black

        completed = 0
        total = len(to_test)

        async def _check_one(key: str) -> None:
            nonlocal completed
            result = await self.check(key.split("#")[0])
            k_id = key.split("#")[0]

            if k_id in cache:
                cache[k_id]["white"] = result
                cache[k_id]["white_time"] = now

            if result:
                white.append(key)
            else:
                black.append(key)

            completed += 1
            if completed % 10 == 0 or completed == total:
                self._log(
                    "info",
                    f"White check {completed}/{total} | WHITE={len(white)} BLACK={len(black)}",
                )

        await asyncio.gather(*[_check_one(k) for k in to_test])
        return white, black


# =============================================================================
# СИНХРОННЫЕ АДАПТЕРЫ (обратная совместимость со старым main.py)
# =============================================================================

def is_white_key(vpn_uri: str, timeout: float = 20.0) -> bool:
    """Синхронная обёртка."""
    checker = WhiteChecker(check_timeout=timeout)
    return asyncio.run(checker.check(vpn_uri))


def batch_white_check(
    keys: List[str],
    history: Dict[str, Any],
    *,
    workers: int = 5,
    cache_hours: float = 24.0,
    label: str = "",
) -> Tuple[List[str], List[str]]:
    """Синхронная обёртка для старого интерфейса."""
    checker = WhiteChecker(workers=workers)
    return asyncio.run(checker.batch_check(keys, history, cache_hours))
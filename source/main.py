#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
main.py — MaxTre VPN Config Collector v2.0 (Production Grade)
Async/await, Pydantic Settings, structured logging, retry, atomic file ops,
proper SSL context, real Xray-Core white checking.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import logging
import os
import random
import re
import shutil
import signal
import socket
import ssl
import sys
import tempfile
import time
import urllib.parse
import zoneinfo
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import aiofiles
import aiohttp
import tenacity
from pydantic import Field
from pydantic_settings import BaseSettings
from github import Github, Auth, GithubException

import white_checker as wc


# =============================================================================
# 1. КОНФИГУРАЦИЯ
# =============================================================================

class LogFormat(str, Enum):
    JSON = "json"
    PRETTY = "pretty"


class Settings(BaseSettings):
    github_token: Optional[str] = Field(None, env="MY_TOKEN")
    repo_name: str = "MaxTre2/My-Config"

    max_keys_to_check: int = 4000
    concurrency: int = 25
    timeout: int = 12
    max_ping_ms: int = 5000
    fast_limit: int = 2000
    chunk_limit: int = 1000
    euro_chunk_limit: int = 500
    bypass_test_limit: int = 300
    max_white_test: int = 200
    cache_hours: int = 6
    max_history_age: int = 48 * 3600

    xray_path: Path = Path("../xray")
    output_dir: Path = Path("githubmirror")
    folder_ru: Path = Path("githubmirror/RU_Best")
    folder_euro: Path = Path("githubmirror/My_Euro")

    dry_run: bool = False
    log_level: str = "INFO"
    log_format: LogFormat = LogFormat.PRETTY

    my_channel: str = "@vlesstrojan"
    timezone: str = "Europe/Moscow"

    sources: List[str] = Field(default_factory=lambda: [
        # === ОСНОВНЫЕ ИСТОЧНИКИ ===
        "https://github.com/sakha1370/OpenRay/raw/refs/heads/main/output/all_valid_proxies.txt",
        "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",
        "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt",
        "https://raw.githubusercontent.com/acymz/AutoVPN/refs/heads/main/data/V2.txt",
        "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/sub.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
        "https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/trojan.txt",
        "https://raw.githubusercontent.com/CidVpn/cid-vpn-config/refs/heads/main/general.txt",
        "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",
        "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/vless",
        "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
        "https://raw.githubusercontent.com/expressalaki/ExpressVPN/refs/heads/main/configs3.txt",
        "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/refs/heads/main/xray_final.txt",
        "https://github.com/LalatinaHub/Mineral/raw/refs/heads/master/result/nodes",
        "https://raw.githubusercontent.com/miladtahanian/Config-Collector/refs/heads/main/vless_iran.txt",
        "https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub",
        "https://github.com/MhdiTaheri/V2rayCollector_Py/raw/refs/heads/main/sub/Mix/mix.txt",
        "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
        "https://github.com/MhdiTaheri/V2rayCollector/raw/refs/heads/main/sub/mix",
        "https://github.com/Argh94/Proxy-List/raw/refs/heads/main/All_Config.txt",
        "https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt",
        "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",
        "https://raw.githubusercontent.com/zipvpn/FreeVPNNodes/refs/heads/main/free_v2ray_xray_nodes.txt",
        "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR.BYPASS#STR.BYPASS%F0%9F%91%BE",
        "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
        "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt",
        "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vmess.txt",
        "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/trojan.txt",
        "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vless.txt",
        "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vmess.txt",
        "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/trojan.txt",
        "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/ss.txt",
        "https://raw.githubusercontent.com/sashalsk/V2Ray/main/VLESS.txt",
        "https://raw.githubusercontent.com/sashalsk/V2Ray/main/VMESS.txt",
        "https://raw.githubusercontent.com/sashalsk/V2Ray/main/TROJAN.txt",
        "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/vless",
        "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/vmess",
        "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/trojan",
        "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/ss",
        "https://raw.githubusercontent.com/NiREvil/vless/main/vless.txt",
        "https://raw.githubusercontent.com/NiREvil/vless/main/vmess.txt",
        "https://raw.githubusercontent.com/NiREvil/vless/main/trojan.txt",
        # === REALITY + gRPC ===
        "https://raw.githubusercontent.com/alanbobs999/TopFreeProxies/master/REALITY",
        "https://raw.githubusercontent.com/AzadNet/channel/main/REALITY",
        "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/reality",
        "https://raw.githubusercontent.com/NiREvil/vless/main/reality.txt",
        "https://raw.githubusercontent.com/amini8k/Free-Configs/main/reality.txt",
        "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/reality.txt",
        "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/reality.txt",
        "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/reality.txt",
        # === XHTTP ===
        "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/all.txt",
        "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/xhttp",
        "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/splitted/xhttp.txt",
        # === XTLS VISION ===
        "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",
        "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/splitted/vless.txt",
        "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/vless",
        # === ДОБАВЛЕНО: igareck Vless Reality White Lists Rus Mobile ===
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    ])

    extra_bypass_sources: List[str] = Field(default_factory=lambda: [
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
        "https://raw.githubusercontent.com/zieng2/wl/main/vless.txt",
        "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
        "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
        "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/2",
        "https://raw.githubusercontent.com/gbwltg/gbwl/refs/heads/main/m3EsPqwmlc",
        "https://whiteprime.github.io/xraycheck/configs/white-list_available",
        "https://wlrus.lol/confs/selected.txt",
        "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/xhttp.txt",
        "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/reality",
    ])

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# =============================================================================
# 2. МОДЕЛИ
# =============================================================================

@dataclass(frozen=True, slots=True)
class ProxyConfig:
    uri: str
    protocol: str
    host: str
    port: int
    fingerprint: str
    raw_params: Dict[str, str] = field(default_factory=dict, repr=False)

    @classmethod
    def from_uri(cls, uri: str) -> Optional[ProxyConfig]:
        if not uri or "://" not in uri:
            return None
        try:
            parsed = urllib.parse.urlparse(uri.strip())
            protocol = parsed.scheme.lower()
            if protocol not in {"vless", "vmess", "trojan", "ss", "ssr"}:
                return None
            host = parsed.hostname or ""
            port = parsed.port or (443 if protocol in {"vless", "trojan", "vmess"} else 80)
            id_part = parsed.path.lstrip("/").split("@")[0] if "@" in uri else parsed.netloc
            fingerprint = hashlib.sha256(
                f"{protocol}:{host}:{port}:{id_part}".encode()
            ).hexdigest()[:16]
            params = dict(urllib.parse.parse_qsl(parsed.query))
            return cls(uri=uri.split("#")[0], protocol=protocol, host=host, port=port,
                       fingerprint=fingerprint, raw_params=params)
        except Exception:
            return None

    def is_insecure(self) -> bool:
        q = urllib.parse.urlparse(self.uri).query.lower()
        return any(f"{k}=1" in q or f"{k}=true" in q
                   for k in ("allowinsecure", "allow_insecure", "insecure"))

    def is_reality(self) -> bool:
        return self.raw_params.get("security", "").lower() == "reality"

    def is_xtls_vision(self) -> bool:
        flow = self.raw_params.get("flow", "").lower()
        return "xtls-rprx-vision" in flow

    def is_xhttp(self) -> bool:
        net = self.raw_params.get("type", self.raw_params.get("net", "")).lower()
        return net == "xhttp"

    def is_ws(self) -> bool:
        net = self.raw_params.get("type", self.raw_params.get("net", "")).lower()
        return net == "ws"


@dataclass(frozen=True, slots=True)
class CheckResult:
    proxy: ProxyConfig
    latency_ms: int
    country: str
    reachable: bool = True
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_cache_dict(self) -> Dict[str, Any]:
        return {
            "latency": self.latency_ms,
            "country": self.country,
            "time": self.checked_at.timestamp(),
            "alive": self.reachable,
        }


# =============================================================================
# 3. ЛОГГИРОВАНИЕ
# =============================================================================

def setup_logging(level: str, fmt: LogFormat) -> logging.Logger:
    logger = logging.getLogger("vpn_collector")
    logger.setLevel(getattr(logging, level.upper()))
    if fmt == LogFormat.JSON:
        formatter = logging.Formatter(
            '{"time":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}'
        )
    else:
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(message)s", datefmt="%H:%M:%S"
        )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    logger.handlers = []
    logger.addHandler(handler)
    return logger


# =============================================================================
# 4. HTTP КЛИЕНТ
# =============================================================================

class AsyncHTTPClient:
    USER_AGENTS: Tuple[str, ...] = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    )

    def __init__(self, timeout: int, logger: logging.Logger):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.logger = logger
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> AsyncHTTPClient:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        connector = aiohttp.TCPConnector(
            limit=100, limit_per_host=10, enable_cleanup_closed=True,
            force_close=True, ssl=ssl_ctx,
        )
        self._session = aiohttp.ClientSession(
            connector=connector, timeout=self.timeout,
            headers={"Accept-Encoding": "gzip, deflate"},
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._session:
            await self._session.close()

    def _headers(self) -> Dict[str, str]:
        return {
            "User-Agent": random.choice(self.USER_AGENTS),
            "Accept": "text/plain,application/octet-stream,*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
        }

    @tenacity.retry(
        stop=tenacity.stop_after_attempt(3),
        wait=tenacity.wait_exponential(multiplier=1, min=1, max=10),
        retry=tenacity.retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError)),
    )
    async def fetch_text(self, url: str) -> str:
        if not self._session:
            raise RuntimeError("Client not opened")
        if "github.com" in url and "/blob/" in url:
            url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        async with self._session.get(url, headers=self._headers(), allow_redirects=True) as resp:
            resp.raise_for_status()
            return await resp.text()


# =============================================================================
# 5. ПАРСЕР
# =============================================================================

class ProxyParser:
    INSECURE_RE = re.compile(
        r'(?:[?&;]|3%[Bb])(allowinsecure|allow_insecure|insecure)=(?:1|true|yes)',
        re.IGNORECASE,
    )
    BAD_MARKERS = {"CN", "IR", "KR", "BR", "IN", "RELAY", "POOL", "🇨🇳", "🇮🇷", "🇰🇷"}

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def _decode_base64_lines(self, data: str) -> List[str]:
        try:
            cleaned = data.strip()
            missing = len(cleaned) % 4
            if missing:
                cleaned += "=" * (4 - missing)
            decoded = base64.b64decode(cleaned).decode("utf-8", errors="ignore")
            return [l.strip() for l in decoded.splitlines() if l.strip()]
        except Exception:
            return []

    def _is_garbage(self, line: str) -> bool:
        upper = line.upper()
        if any(m in upper for m in self.BAD_MARKERS):
            return True
        if ".ir" in line or ".cn" in line or "127.0.0.1" in line:
            return True
        if len(line) > 2000:
            return True
        return False

    def parse_raw(self, raw_data: str) -> List[ProxyConfig]:
        if "://" not in raw_data[:100]:
            lines = self._decode_base64_lines(raw_data)
        else:
            lines = [l.strip() for l in raw_data.splitlines() if l.strip()]

        configs: List[ProxyConfig] = []
        for line in lines:
            if line.startswith("#"):
                continue
            if self._is_garbage(line):
                continue
            if self.INSECURE_RE.search(urllib.parse.unquote(line)):
                continue
            cfg = ProxyConfig.from_uri(line)
            if cfg:
                configs.append(cfg)
        return configs

    def deduplicate(self, configs: List[ProxyConfig]) -> List[ProxyConfig]:
        seen: Dict[str, ProxyConfig] = {}
        for cfg in configs:
            existing = seen.get(cfg.fingerprint)
            if not existing or len(cfg.uri) > len(existing.uri):
                seen[cfg.fingerprint] = cfg
        return list(seen.values())


# =============================================================================
# 6. ПРОВЕРЯЛЬЩИК (TCP/TLS/WS/XHTTP)
# =============================================================================

class ProxyChecker:
    RU_TLD = {".ru", ".moscow", ".msk"}
    RU_MARKERS = ("moscow", "msk", "spb", "saint-peter", "russia", "россия", "москва")
    EURO_CODES = {
        "NL", "DE", "FI", "GB", "FR", "SE", "PL", "CZ", "AT", "CH",
        "IT", "ES", "NO", "DK", "BE", "IE", "LU", "EE", "LV", "LT",
    }

    def __init__(self, settings: Settings, logger: logging.Logger):
        self.settings = settings
        self.logger = logger
        self.semaphore = asyncio.Semaphore(settings.concurrency)

    def detect_country(self, host: str, key_name: str) -> str:
        h = host.lower()
        if any(h.endswith(tld) for tld in self.RU_TLD):
            return "RU"
        tld_map = {
            ".de": "DE", ".nl": "NL", ".uk": "GB", ".co.uk": "GB",
            ".fr": "FR", ".fi": "FI", ".se": "SE", ".no": "NO",
            ".dk": "DK", ".pl": "PL", ".cz": "CZ", ".at": "AT",
            ".ch": "CH", ".it": "IT", ".es": "ES", ".be": "BE",
            ".ie": "IE", ".lu": "LU", ".ee": "EE", ".lv": "LV", ".lt": "LT",
        }
        for tld, code in tld_map.items():
            if h.endswith(tld):
                return code
        n = key_name.upper()
        for code in self.EURO_CODES:
            if code in n:
                return code
        return "UNKNOWN"

    async def _tcp_check(self, host: str, port: int) -> Optional[int]:
        start = time.monotonic()
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.settings.timeout,
            )
            w.close()
            await w.wait_closed()
            return int((time.monotonic() - start) * 1000)
        except (asyncio.TimeoutError, OSError):
            return None

    async def _tls_check(self, host: str, port: int, sni: Optional[str] = None) -> Optional[int]:
        start = time.monotonic()
        try:
            ctx = ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni or host),
                timeout=self.settings.timeout,
            )
            w.close()
            await w.wait_closed()
            return int((time.monotonic() - start) * 1000)
        except (asyncio.TimeoutError, OSError, ssl.SSLError):
            return None

    async def _ws_check(self, host: str, port: int, path: str, tls: bool) -> Optional[int]:
        protocol = "wss" if tls else "ws"
        uri = f"{protocol}://{host}:{port}{path}"
        start = time.monotonic()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(
                    uri,
                    ssl=ssl.create_default_context() if tls else False,
                    timeout=aiohttp.ClientTimeout(total=self.settings.timeout),
                ) as ws:
                    await ws.close()
            return int((time.monotonic() - start) * 1000)
        except Exception:
            return None

    async def check(self, proxy: ProxyConfig) -> Optional[CheckResult]:
        async with self.semaphore:
            latency: Optional[int] = None
            if proxy.is_ws():
                path = proxy.raw_params.get("path", "/")
                latency = await self._ws_check(proxy.host, proxy.port, path, tls=True)
            elif proxy.is_xhttp():
                latency = await self._tls_check(proxy.host, proxy.port)
            elif proxy.is_reality() or proxy.raw_params.get("security") == "tls":
                latency = await self._tls_check(proxy.host, proxy.port)
            else:
                latency = await self._tcp_check(proxy.host, proxy.port)

            if latency is None or latency > self.settings.max_ping_ms:
                return None

            country = self.detect_country(proxy.host, proxy.uri)
            return CheckResult(proxy=proxy, latency_ms=latency, country=country)


# =============================================================================
# 7. КЭШ
# =============================================================================

class CacheManager:
    def __init__(self, cache_file: Path, ttl_hours: int, max_age: int, logger: logging.Logger):
        self.cache_file = cache_file
        self.ttl = ttl_hours * 3600
        self.max_age = max_age
        self.logger = logger
        self._data: Dict[str, Dict[str, Any]] = {}

    async def load(self) -> None:
        if not self.cache_file.exists():
            return
        try:
            async with aiofiles.open(self.cache_file, "r", encoding="utf-8") as f:
                self._data = json.loads(await f.read())
        except Exception as e:
            self.logger.warning(f"Cache load failed: {e}")
            self._data = {}

    async def save(self) -> None:
        now = time.time()
        cleaned = {k: v for k, v in self._data.items()
                   if now - v.get("time", 0) < self.max_age}
        tmp = Path(tempfile.gettempdir()) / f"{self.cache_file.name}.tmp"
        try:
            async with aiofiles.open(tmp, "w", encoding="utf-8") as f:
                await f.write(json.dumps(cleaned, ensure_ascii=False, indent=2))
            shutil.move(str(tmp), str(self.cache_file))
            self._data = cleaned
        except Exception as e:
            self.logger.error(f"Cache save failed: {e}")

    def get(self, fingerprint: str) -> Optional[CheckResult]:
        entry = self._data.get(fingerprint)
        if not entry:
            return None
        if time.time() - entry.get("time", 0) > self.ttl:
            return None
        if not entry.get("alive"):
            return None
        return CheckResult(
            proxy=ProxyConfig(uri="", protocol="", host="", port=0, fingerprint=fingerprint),
            latency_ms=entry["latency"],
            country=entry.get("country", "UNKNOWN"),
            checked_at=datetime.fromtimestamp(entry["time"], tz=timezone.utc),
        )

    def put(self, result: CheckResult) -> None:
        self._data[result.proxy.fingerprint] = result.to_cache_dict()


# =============================================================================
# 8. GITHUB UPLOADER
# =============================================================================

class GitHubUploader:
    def __init__(self, settings: Settings, logger: logging.Logger):
        self.settings = settings
        self.logger = logger
        self._repo: Optional[Any] = None
        if settings.github_token:
            self.client = Github(auth=Auth.Token(settings.github_token))
            self._repo = self.client.get_repo(settings.repo_name)
        else:
            self.client = Github()
            self.logger.warning("GitHub token not set, upload disabled")

    @tenacity.retry(
        stop=tenacity.stop_after_attempt(5),
        wait=tenacity.wait_exponential(multiplier=1, min=1, max=30),
        retry=tenacity.retry_if_exception_type((GithubException,)),
    )
    async def upload(self, local_path: Path, remote_path: str, message: str) -> bool:
        if not self._repo or self.settings.dry_run:
            return False
        try:
            content = local_path.read_text(encoding="utf-8")
        except Exception as e:
            self.logger.error(f"Cannot read {local_path}: {e}")
            return False

        try:
            try:
                file_in_repo = self._repo.get_contents(remote_path)
                if hasattr(file_in_repo, "decoded_content"):
                    remote_content = file_in_repo.decoded_content.decode("utf-8", errors="replace")
                    if remote_content == content:
                        self.logger.info(f"No changes for {remote_path}")
                        return True
                self._repo.update_file(path=remote_path, message=message, content=content, sha=file_in_repo.sha)
                self.logger.info(f"Updated {remote_path}")
            except GithubException as e:
                if getattr(e, "status", None) == 404:
                    self._repo.create_file(path=remote_path, message=f"Create {remote_path}", content=content)
                    self.logger.info(f"Created {remote_path}")
                else:
                    raise
            return True
        except Exception as e:
            self.logger.error(f"Upload failed for {remote_path}: {e}")
            raise


# =============================================================================
# 9. ГЕНЕРАТОР ФАЙЛОВ
# =============================================================================

class FileGenerator:
    def __init__(self, settings: Settings, logger: logging.Logger):
        self.settings = settings
        self.logger = logger

    @staticmethod
    def country_to_flag(country: str) -> str:
        flags = {
            "RU": "🇷🇺", "NL": "🇳🇱", "DE": "🇩🇪", "FI": "🇫🇮", "GB": "🇬🇧",
            "FR": "🇫🇷", "SE": "🇸🇪", "PL": "🇵🇱", "CZ": "🇨🇿", "AT": "🇦🇹",
            "CH": "🇨🇭", "IT": "🇮🇹", "ES": "🇪🇸", "NO": "🇳🇴", "DK": "🇩🇰",
            "BE": "🇧🇪", "IE": "🇮🇪", "LU": "🇱🇺", "EE": "🇪🇪", "LV": "🇱🇻",
            "LT": "🇱🇹", "US": "🇺🇸", "UA": "🇺🇦", "BY": "🇧🇾", "KZ": "🇰🇿",
            "TR": "🇹🇷", "JP": "🇯🇵", "SG": "🇸🇬", "HK": "🇭🇰", "CA": "🇨🇦",
            "AU": "🇦🇺", "NZ": "🇳🇿",
        }
        return flags.get(country.upper(), "🏳️")

    def format_key(self, proxy: ProxyConfig, latency: int, country: str) -> str:
        flag = self.country_to_flag(country)
        info = f"[{latency}ms {flag} {country} {self.settings.my_channel}]"
        return f"{proxy.uri}#{urllib.parse.quote(info, safe='')}"

    def _write_file(self, path: Path, lines: List[str], title: str) -> None:
        header = ""
        if title:
            b64_title = base64.b64encode(title.encode()).decode()
            header += f"#profile-title: base64:{b64_title}\n"
            header += "#profile-update-interval: 6\n"
            header += f"# {title}\n\n"
        content = header + "\n".join(lines) if lines else header + "# Нет рабочих ключей\n"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(content, encoding="utf-8")
        shutil.move(str(tmp), str(path))

    def save_exact(self, keys: List[str], folder: Path, filename: str, title: str) -> Path:
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / filename
        self._write_file(path, [k for k in keys if k and k.strip()], title)
        self.logger.info(f"Saved {filename}: {len(keys)} keys")
        return path

    def save_chunked(
        self, keys: List[str], folder: Path, base_name: str,
        chunk_size: int, title_template: str,
    ) -> List[Path]:
        folder.mkdir(parents=True, exist_ok=True)
        valid = [k.strip() for k in keys if k and k.strip()]
        chunks = [valid[i:i + chunk_size] for i in range(0, len(valid), chunk_size)]
        paths: List[Path] = []
        for idx, chunk in enumerate(chunks, start=1):
            fname = f"{base_name}_part{idx}.txt"
            path = folder / fname
            self._write_file(path, chunk, title_template.format(idx=idx))
            paths.append(path)
            self.logger.info(f"Saved {fname}: {len(chunk)} keys")
        return paths


# =============================================================================
# 10. BYPASS ГЕНЕРАТОР
# =============================================================================

class BypassGenerator:
    def __init__(self, settings: Settings, logger: logging.Logger, parser: ProxyParser, checker: ProxyChecker):
        self.settings = settings
        self.logger = logger
        self.parser = parser
        self.checker = checker

    async def generate(self, client: AsyncHTTPClient) -> Path:
        self.logger.info(f"Building bypass file (limit={self.settings.bypass_test_limit})...")
        all_lines: List[str] = []

        async def fetch_one(url: str) -> List[str]:
            try:
                raw = await client.fetch_text(url)
                data, _ = self._filter_insecure(raw)
                if "://" not in data[:200]:
                    lines = self._try_decode_base64(data)
                else:
                    lines = [l.strip() for l in data.splitlines() if l.strip()]
                return lines
            except Exception as e:
                self.logger.warning(f"Bypass source failed {url[:60]}: {e}")
                return []

        results = await asyncio.gather(*[fetch_one(u) for u in self.settings.extra_bypass_sources])
        for r in results:
            all_lines.extend(r)

        seen: Dict[str, str] = {}
        for line in all_lines:
            cfg = ProxyConfig.from_uri(line)
            if not cfg:
                continue
            if cfg.fingerprint not in seen or len(line) > len(seen[cfg.fingerprint]):
                seen[cfg.fingerprint] = line

        unique = list(seen.values())
        self.logger.info(f"Bypass unique configs: {len(unique)}")

        limit = min(self.settings.bypass_test_limit, len(unique))
        to_test = unique[:limit]

        working: List[Tuple[int, str, str, str]] = []
        checked = 0

        async def check_one(uri: str) -> Optional[Tuple[int, str, str, str]]:
            nonlocal checked
            cfg = ProxyConfig.from_uri(uri)
            if not cfg:
                return None
            result = await self.checker.check(cfg)
            checked += 1
            if checked % 20 == 0:
                self.logger.info(f"  Bypass checked {checked}/{limit}")
            if result:
                return (result.latency_ms, result.country, cfg.host, uri.split("#")[0])
            return None

        results = await asyncio.gather(*[check_one(u) for u in to_test])
        for r in results:
            if r:
                working.append(r)

        self.logger.info(f"Bypass working: {len(working)}")
        working.sort(key=lambda x: x[0])
        top = working[:200]

        gen = FileGenerator(self.settings, self.logger)
        final_keys = [
            f"{uri}#{urllib.parse.quote(f'[{lat}ms {gen.country_to_flag(c)} {c} {self.settings.my_channel}]', safe='')}"
            for lat, c, h, uri in top
        ]

        title = "MaxTre - VPN Bypass (ПОЛНАЯ проверка)"
        header = f"#profile-title: base64:{base64.b64encode(title.encode()).decode()}\n"
        header += "#profile-update-interval: 3\n"
        header += f"# {title}\n"
        header += f"# Проверено: TCP+TLS/REALITY/WS/XHTTP/XTLS-Vision\n"
        header += f"# Лимит проверки: {limit} | Рабочих: {len(final_keys)}\n"
        header += f"# Обновлено: {datetime.now(zoneinfo.ZoneInfo(self.settings.timezone)).strftime('%H:%M | %d.%m.%Y')}\n\n"

        path = self.settings.output_dir / "ByPassVpnLera.txt"
        content = header + "\n".join(final_keys) if final_keys else header + "# Нет рабочих конфигов\n"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(content, encoding="utf-8")
        shutil.move(str(tmp), str(path))
        self.logger.info(f"Bypass file saved: {path} ({len(final_keys)} keys)")
        return path

    @staticmethod
    def _filter_insecure(data: str) -> Tuple[str, int]:
        INSECURE_PATTERN = re.compile(
            r'(?:[?&;]|3%[Bb])(allowinsecure|allow_insecure|insecure)=(?:1|true|yes)(?:[&;#]|$|(?=\s|$))',
            re.IGNORECASE,
        )
        lines = data.splitlines()
        filtered = []
        removed = 0
        for line in lines:
            processed = urllib.parse.unquote(line.strip())
            if INSECURE_PATTERN.search(processed):
                removed += 1
                continue
            filtered.append(line)
        return "\n".join(filtered), removed

    @staticmethod
    def _try_decode_base64(data: str) -> List[str]:
        try:
            cleaned = data.strip()
            missing = len(cleaned) % 4
            if missing:
                cleaned += "=" * (4 - missing)
            decoded = base64.b64decode(cleaned).decode("utf-8", errors="ignore")
            return [l.strip() for l in decoded.splitlines() if l.strip()]
        except Exception:
            return []


# =============================================================================
# 11. ORCHESTRATOR
# =============================================================================

class CollectorOrchestrator:
    def __init__(self, settings: Settings, logger: logging.Logger):
        self.settings = settings
        self.logger = logger
        self.shutdown_event = asyncio.Event()
        self._setup_signal_handlers()

    def _setup_signal_handlers(self) -> None:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                asyncio.get_event_loop().add_signal_handler(
                    sig, lambda: asyncio.create_task(self._shutdown())
                )
            except (NotImplementedError, RuntimeError):
                pass

    async def _shutdown(self) -> None:
        self.logger.warning("Shutdown signal received, finishing gracefully...")
        self.shutdown_event.set()

    def _is_russian_exit(self, key_str: str, host: str, country: str) -> bool:
        if country == "RU":
            return True
        host_lower = host.lower()
        key_upper = key_str.upper()
        if host_lower.endswith(".ru"):
            return True
        markers = [".ru", "moscow", "msk", "spb", "saint-peter", "russia",
                   "россия", "москва", "питер", "ru-", "-ru.",
                   "178.154.", "77.88.", "5.255.", "87.250.",
                   "95.108.", "213.180.", "195.208.", "91.108.", "149.154."]
        for marker in markers:
            if marker.lower() in host_lower or marker.upper() in key_upper:
                return True
        return False

    @staticmethod
    def calculate_priority(key: str, latency: int) -> int:
        priority = latency
        lower = key.lower()
        if "type=xhttp" in lower or "net=xhttp" in lower:
            priority = max(1, latency - 100)
        if "security=reality" in lower:
            priority = max(1, priority - 50)
        if "flow=xtls-rprx-vision" in lower:
            priority = max(1, priority - 30)
        good_sni = ["m.vk.com", "gosuslugi.ru", "sberbank.ru", "yandex.ru", "mail.ru", "ads.x5.ru"]
        for sni in good_sni:
            if f"sni={sni}" in lower:
                priority = max(1, priority - 30)
                break
        return priority

    async def _fetch_all(self, client: AsyncHTTPClient, parser: ProxyParser) -> List[ProxyConfig]:
        self.logger.info(f"Fetching {len(self.settings.sources)} sources...")

        async def fetch_one(url: str) -> List[ProxyConfig]:
            if self.shutdown_event.is_set():
                return []
            try:
                raw = await client.fetch_text(url)
                parsed = parser.parse_raw(raw)
                self.logger.info(f"  {urllib.parse.urlparse(url).path[-40:]:40} +{len(parsed)}")
                return parsed
            except Exception as e:
                self.logger.warning(f"  Failed {url[:60]}: {e}")
                return []

        results = await asyncio.gather(*[fetch_one(u) for u in self.settings.sources])
        configs: List[ProxyConfig] = []
        for r in results:
            configs.extend(r)

        deduped = parser.deduplicate(configs)
        self.logger.info(f"Total unique configs: {len(deduped)}")
        return deduped[: self.settings.max_keys_to_check]

    async def _check_all(
        self, configs: List[ProxyConfig], checker: ProxyChecker, cache: CacheManager
    ) -> Tuple[List[CheckResult], List[CheckResult]]:
        ru_results: List[CheckResult] = []
        euro_results: List[CheckResult] = []

        self.logger.info(f"Checking {len(configs)} configs...")

        async def check_one(cfg: ProxyConfig) -> Optional[CheckResult]:
            if self.shutdown_event.is_set():
                return None
            cached = cache.get(cfg.fingerprint)
            if cached:
                return cached
            result = await checker.check(cfg)
            if result:
                cache.put(result)
            return result

        checked = 0
        for coro in asyncio.as_completed([check_one(c) for c in configs]):
            result = await coro
            if result is None:
                continue
            checked += 1
            if checked % 100 == 0:
                self.logger.info(f"  Checked: {checked}")

            if result.country == "RU" or self._is_russian_exit(result.proxy.uri, result.proxy.host, result.country):
                ru_results.append(result)
            elif result.country in checker.EURO_CODES:
                euro_results.append(result)

        ru_results.sort(key=lambda x: self.calculate_priority(
            FileGenerator(self.settings, self.logger).format_key(x.proxy, x.latency_ms, x.country),
            x.latency_ms
        ))
        euro_results.sort(key=lambda x: self.calculate_priority(
            FileGenerator(self.settings, self.logger).format_key(x.proxy, x.latency_ms, x.country),
            x.latency_ms
        ))

        return ru_results, euro_results

    async def run(self) -> None:
        start = time.monotonic()
        zone = zoneinfo.ZoneInfo(self.settings.timezone)
        offset = datetime.now(zone).strftime("%H:%M | %d.%m.%Y")

        cache = CacheManager(
            self.settings.cache_file, self.settings.cache_hours,
            self.settings.max_history_age, self.logger,
        )
        await cache.load()

        async with AsyncHTTPClient(self.settings.timeout, self.logger) as client:
            parser = ProxyParser(self.logger)
            checker = ProxyChecker(self.settings, self.logger)
            gen = FileGenerator(self.settings, self.logger)
            uploader = GitHubUploader(self.settings, self.logger)

            # Очистка
            for folder in (self.settings.folder_ru, self.settings.folder_euro):
                if folder.exists():
                    shutil.rmtree(folder)
                folder.mkdir(parents=True, exist_ok=True)

            # 1. Сбор
            configs = await self._fetch_all(client, parser)
            if self.shutdown_event.is_set():
                return

            # 2. Проверка
            ru_results, euro_results = await self._check_all(configs, checker, cache)
            await cache.save()

            self.logger.info(f"Working: RU={len(ru_results)}, EU={len(euro_results)}")

            # 3. Форматирование
            ru_keys = [gen.format_key(r.proxy, r.latency_ms, r.country) for r in ru_results]
            eu_keys = [gen.format_key(r.proxy, r.latency_ms, r.country) for r in euro_results]

            ru_fast = ru_keys[: self.settings.fast_limit]
            eu_fast = eu_keys[: self.settings.fast_limit]
            ru_all = ru_keys
            eu_all = eu_keys

            # 4. Сохранение FAST / ALL
            self.logger.info("Saving RU FAST...")
            gen.save_chunked(ru_fast, self.settings.folder_ru, "ru_white", self.settings.chunk_limit,
                             "MaxTre - VPN RUSSIA FAST ⚡ Part {idx}")
            self.logger.info("Saving EU FAST...")
            gen.save_chunked(eu_fast, self.settings.folder_euro, "my_euro", self.settings.euro_chunk_limit,
                             "MaxTre - VPN EUROPE FAST ⚡ Part {idx}")
            self.logger.info("Saving RU ALL...")
            gen.save_chunked(ru_all, self.settings.folder_ru, "ru_white_all", self.settings.chunk_limit,
                             "MaxTre - VPN RUSSIA ALL 🇷🇺 Part {idx}")
            self.logger.info("Saving EU ALL...")
            gen.save_chunked(eu_all, self.settings.folder_euro, "my_euro_all", self.settings.euro_chunk_limit,
                             "MaxTre - VPN EUROPE ALL 🇪🇺 Part {idx}")

            # 5. WHITE / BLACK split
            ru_white, ru_black = ru_all, []
            euro_white, euro_black = eu_all, []

            if not self.settings.dry_run:
                if wc.xray_available():
                    ru_test = ru_all[: self.settings.max_white_test]
                    ru_rest = ru_all[self.settings.max_white_test:]
                    eu_test = eu_all[: self.settings.max_white_test]
                    eu_rest = eu_all[self.settings.max_white_test:]

                    self.logger.info(f"White check: RU={len(ru_test)} EU={len(eu_test)}")

                    ru_white, ru_black = wc.batch_white_check(
                        ru_test, cache._data, cache_hours=24, label="RU"
                    )
                    euro_white, euro_black = wc.batch_white_check(
                        eu_test, cache._data, cache_hours=24, label="EU"
                    )

                    ru_black.extend(ru_rest)
                    euro_black.extend(eu_rest)

                    self.logger.info(
                        f"WHITE/BLACK: RU {len(ru_white)}/{len(ru_black)} | "
                        f"EU {len(euro_white)}/{len(euro_black)}"
                    )
                else:
                    self.logger.warning("xray not found, skipping white/black split")

                gen.save_exact(ru_white, self.settings.folder_ru, "ru_white_all_WHITE.txt",
                               "MaxTre - VPN RUSSIA WHITE ✅")
                gen.save_exact(ru_black, self.settings.folder_ru, "ru_white_all_BLACK.txt",
                               "MaxTre - VPN RUSSIA BLACK ⚠️")
                gen.save_exact(euro_white, self.settings.folder_euro, "my_euro_all_WHITE.txt",
                               "MaxTre - VPN EUROPE WHITE ✅")
                gen.save_exact(euro_black, self.settings.folder_euro, "my_euro_all_BLACK.txt",
                               "MaxTre - VPN EUROPE BLACK ⚠️")

            # 6. Bypass
            bypass_path = None
            if not self.settings.dry_run:
                bypass_gen = BypassGenerator(self.settings, self.logger, parser, checker)
                bypass_path = await bypass_gen.generate(client)

            # 7. Subscriptions list
            sub_path = self._generate_subscriptions_list()

            # 8. Upload
            if not self.settings.dry_run:
                self.logger.info("Uploading to GitHub...")
                uploads = []

                for folder in (self.settings.folder_ru, self.settings.folder_euro):
                    for f in folder.glob("*.txt"):
                        remote = f"githubmirror/{folder.name}/{f.name}"
                        uploads.append(uploader.upload(f, remote, f"🚀 Обновление {f.name} {offset}"))

                if bypass_path:
                    uploads.append(uploader.upload(
                        bypass_path, "githubmirror/ByPassVpnLera.txt",
                        f"🚀 Обновление ByPassVpnLera.txt {offset}"
                    ))

                uploads.append(uploader.upload(
                    self.settings.cache_file, "githubmirror/history.json",
                    f"🚀 Обновление history.json {offset}"
                ))
                uploads.append(uploader.upload(
                    sub_path, "githubmirror/subscriptions_list.txt",
                    f"🚀 Обновление subscriptions_list.txt {offset}"
                ))

                await asyncio.gather(*uploads, return_exceptions=True)

            elapsed = time.monotonic() - start
            self.logger.info("=" * 50)
            self.logger.info("SUCCESS")
            self.logger.info(f"RU  FAST : {len(ru_fast)}")
            self.logger.info(f"RU  ALL  : {len(ru_all)}")
            self.logger.info(f"RU  WHITE: {len(ru_white)}")
            self.logger.info(f"RU  BLACK: {len(ru_black)}")
            self.logger.info(f"EU  FAST : {len(eu_fast)}")
            self.logger.info(f"EU  ALL  : {len(eu_all)}")
            self.logger.info(f"EU  WHITE: {len(euro_white)}")
            self.logger.info(f"EU  BLACK: {len(euro_black)}")
            self.logger.info(f"Time     : {elapsed:.1f}s")
            self.logger.info("=" * 50)

    def _generate_subscriptions_list(self) -> Path:
        base_raw = f"https://raw.githubusercontent.com/{self.settings.repo_name}/main"
        lines: List[str] = []

        def add_section(title: str, folder: Path, pattern: str, limit: Optional[int] = None):
            lines.append(f"=== {title} ===")
            files = sorted(folder.glob(pattern))
            for f in (files[:limit] if limit else files):
                lines.append(f"{base_raw}/githubmirror/{folder.name}/{f.name}")
            lines.append("")

        add_section("🇷🇺 RUSSIA (FAST)", self.settings.folder_ru, "ru_white_part*.txt")
        add_section("🇪🇺 EUROPE (FAST)", self.settings.folder_euro, "my_euro_part*.txt")
        add_section("🇷🇺 RUSSIA (ALL)", self.settings.folder_ru, "ru_white_all_part*.txt", 2)
        add_section("🇪🇺 EUROPE (ALL)", self.settings.folder_euro, "my_euro_all_part*.txt", 2)

        lines.append("=== ✅ WHITE RUSSIA (ALL) ===")
        lines.append(f"{base_raw}/githubmirror/{self.settings.folder_ru.name}/ru_white_all_WHITE.txt")
        lines.append("")
        lines.append("=== ✅ WHITE EUROPE (ALL) ===")
        lines.append(f"{base_raw}/githubmirror/{self.settings.folder_euro.name}/my_euro_all_WHITE.txt")
        lines.append("")
        lines.append("=== ⚠️ BLACK RUSSIA (ALL) ===")
        lines.append(f"{base_raw}/githubmirror/{self.settings.folder_ru.name}/ru_white_all_BLACK.txt")
        lines.append("")
        lines.append("=== ⚠️ BLACK EUROPE (ALL) ===")
        lines.append(f"{base_raw}/githubmirror/{self.settings.folder_euro.name}/my_euro_all_BLACK.txt")
        lines.append("")
        lines.append("=== 🛡️ BYPASS (ПОЛНАЯ ПРОВЕРКА) ===")
        lines.append(f"{base_raw}/githubmirror/ByPassVpnLera.txt")

        path = self.settings.output_dir / "subscriptions_list.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines), encoding="utf-8")
        self.logger.info(f"Subscriptions list: {len([l for l in lines if l.startswith('http')])} links")
        return path


# =============================================================================
# ENTRY POINT
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(description="MaxTre VPN Config Collector v2.0")
    parser.add_argument("--dry-run", action="store_true", help="Только проверка без сохранения")
    parser.add_argument("--bypass-limit", type=int, default=300, help="Лимит проверки bypass")
    args = parser.parse_args()

    settings = Settings()
    settings.dry_run = args.dry_run
    settings.bypass_test_limit = args.bypass_limit

    logger = setup_logging(settings.log_level, settings.log_format)
    logger.info("=" * 60)
    logger.info("VPN Collector v2.0 starting")
    logger.info(f"Mode: {'DRY-RUN' if settings.dry_run else 'PRODUCTION'}")
    logger.info(f"Bypass limit: {settings.bypass_test_limit}")
    logger.info("=" * 60)

    orchestrator = CollectorOrchestrator(settings, logger)
    try:
        asyncio.run(orchestrator.run())
    except Exception:
        logger.exception("Fatal error")
        sys.exit(1)


if __name__ == "__main__":
    main()
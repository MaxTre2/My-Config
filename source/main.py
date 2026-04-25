"""
main.py — MaxTre VPN Config Collector v4.0
Категоризация конфигов по 4 приоритетам маскировки:
  TIER-1: VLESS + REALITY + xtls-rprx-vision + TCP 443   (макс. маскировка)
  TIER-2: VLESS + TLS + xtls-rprx-vision + HTTPUpgrade/gRPC 443 + CDN (скрыть IP)
  TIER-3: VLESS + REALITY + xtls-rprx-vision + TCP 443   (баланс)
  TIER-4: VLESS + TLS + SplitHTTP/xhttp 443 | REALITY уник. dest (жёсткий DPI)
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
import threading
import time
import urllib.parse
import zoneinfo
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from functools import partial
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import aiofiles
import aiohttp
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


class ConfigTier(Enum):
    """Уровень маскировки конфигурации."""
    TIER1_REALITY_VISION   = auto()  # VLESS+REALITY+xtls-rprx-vision+TCP443
    TIER2_TLS_CDN_VISION   = auto()  # VLESS+TLS+Vision+HTTPUpgrade/gRPC+CDN
    TIER3_REALITY_BALANCE  = auto()  # VLESS+REALITY+Vision (любой транспорт)
    TIER4_DPI_RESISTANT    = auto()  # SplitHTTP/xhttp или REALITY уник.dest
    TIER5_OTHER            = auto()  # Всё остальное рабочее


TIER_LABELS = {
    ConfigTier.TIER1_REALITY_VISION:  "T1-REALITY-VISION",
    ConfigTier.TIER2_TLS_CDN_VISION:  "T2-CDN-VISION",
    ConfigTier.TIER3_REALITY_BALANCE: "T3-REALITY",
    ConfigTier.TIER4_DPI_RESISTANT:   "T4-SPLITHTTP",
    ConfigTier.TIER5_OTHER:           "T5-OTHER",
}

# CDN-провайдеры по SNI/Host
CDN_SNI_MARKERS = (
    "cloudflare", "cdn.cloudflare", "workers.dev",
    "azureedge", "akamai", "fastly",
    "amazonaws", "cloudfront",
    "bunnycdn", "b-cdn",
    "vercel.app", "netlify.app",
)

# Хорошие SNI для REALITY (популярные сайты)
GOOD_SNI = frozenset({
    "www.microsoft.com", "microsoft.com", "www.apple.com", "apple.com",
    "www.google.com", "google.com", "discord.com", "www.discord.com",
    "telegram.org", "www.telegram.org", "github.com", "www.github.com",
    "addons.mozilla.org", "www.addons.mozilla.org",
    "www.amazon.com", "amazon.com", "www.cloudflare.com", "cloudflare.com",
    "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "www.speedtest.net", "speed.cloudflare.com",
})


class Settings(BaseSettings):
    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "case_sensitive": False}

    github_token: Optional[str] = Field(None, validation_alias="MY_TOKEN")
    repo_name: str = "MaxTre2/My-Config"

    max_keys_to_check: int = 2500   # TCP-проверка ~3 мин
    concurrency: int = 60           # параллелизм
    timeout: int = 6                # таймаут TCP/TLS соединения
    max_ping_ms: int = 3000         # только быстрые серверы
    fast_limit: int = 1500
    chunk_limit: int = 1000
    euro_chunk_limit: int = 500
    bypass_test_limit: int = 150    # ↓ экономим время в bypass
    max_white_test: int = 60        # ↓ 60 ключей × 16с / 8 воркеров = ~2 мин
    cache_hours: int = 6
    max_history_age: int = 48 * 3600

    xray_path: Path = Path("../xray")
    output_dir: Path = Path("githubmirror")
    cache_file: Path = Path("githubmirror/history.json")
    folder_ru: Path = Path("githubmirror/RU_Best")
    folder_euro: Path = Path("githubmirror/My_Euro")
    folder_tiers: Path = Path("githubmirror/Tiers")

    dry_run: bool = False
    log_level: str = "INFO"
    log_format: LogFormat = LogFormat.PRETTY

    my_channel: str = "@vlesstrojan"
    timezone: str = "Europe/Moscow"

    sources: List[str] = Field(default_factory=lambda: [
        # === REALITY-специфичные источники (TIER1/TIER3 приоритет) ===
        "https://raw.githubusercontent.com/alanbobs999/TopFreeProxies/master/REALITY",
        "https://raw.githubusercontent.com/AzadNet/channel/main/REALITY",
        "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/reality",
        "https://raw.githubusercontent.com/NiREvil/vless/main/reality.txt",
        "https://raw.githubusercontent.com/amini8k/Free-Configs/main/reality.txt",
        "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/reality.txt",
        "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/reality.txt",
        "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/reality.txt",
        "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/reality",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
        # === xhttp/SplitHTTP (TIER4 — жёсткий DPI) ===
        "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/xhttp",
        "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/splitted/xhttp.txt",
        "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/xhttp.txt",
        # === VLESS общий (Vision+TLS/CDN — TIER2) ===
        "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",
        "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",
        "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/vless",
        "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
        "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt",
        "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vless.txt",
        "https://raw.githubusercontent.com/NiREvil/vless/main/vless.txt",
        "https://raw.githubusercontent.com/sashalsk/V2Ray/main/VLESS.txt",
        "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/vless",
        "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",
        "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/splitted/vless.txt",
        "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/vless",
        "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/sub.txt",
        "https://raw.githubusercontent.com/miladtahanian/Config-Collector/refs/heads/main/vless_iran.txt",
        # === Mix/All (любые протоколы) ===
        "https://github.com/sakha1370/OpenRay/raw/refs/heads/main/output/all_valid_proxies.txt",
        "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt",
        "https://raw.githubusercontent.com/acymz/AutoVPN/refs/heads/main/data/V2.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
        "https://raw.githubusercontent.com/CidVpn/cid-vpn-config/refs/heads/main/general.txt",
        "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
        "https://raw.githubusercontent.com/expressalaki/ExpressVPN/refs/heads/main/configs3.txt",
        "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/refs/heads/main/xray_final.txt",
        "https://github.com/LalatinaHub/Mineral/raw/refs/heads/master/result/nodes",
        "https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub",
        "https://github.com/MhdiTaheri/V2rayCollector_Py/raw/refs/heads/main/sub/Mix/mix.txt",
        "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
        "https://github.com/MhdiTaheri/V2rayCollector/raw/refs/heads/main/sub/mix",
        "https://github.com/Argh94/Proxy-List/raw/refs/heads/main/All_Config.txt",
        "https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt",
        "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",
        "https://raw.githubusercontent.com/zipvpn/FreeVPNNodes/refs/heads/main/free_v2ray_xray_nodes.txt",
        "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR.BYPASS#STR.BYPASS%F0%9F%91%BE",
        "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/all.txt",
        # === Trojan (работает через TLS) ===
        "https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/trojan.txt",
        "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/trojan.txt",
        "https://raw.githubusercontent.com/NiREvil/vless/main/trojan.txt",
        "https://raw.githubusercontent.com/sashalsk/V2Ray/main/TROJAN.txt",
        "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/trojan",
        # === VMess ===
        "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vmess.txt",
        "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vmess.txt",
        "https://raw.githubusercontent.com/NiREvil/vless/main/vmess.txt",
        "https://raw.githubusercontent.com/sashalsk/V2Ray/main/VMESS.txt",
        "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/vmess",
        # === SS ===
        "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/ss.txt",
        "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/ss",
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
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    ])


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

            if "@" in parsed.netloc:
                id_part = parsed.netloc.split("@")[0]
            elif "@" in parsed.path:
                id_part = parsed.path.split("@")[0].lstrip("/")
            else:
                id_part = parsed.netloc

            fingerprint = hashlib.sha256(
                f"{protocol}:{host}:{port}:{id_part}".encode()
            ).hexdigest()[:16]

            params = dict(urllib.parse.parse_qsl(parsed.query))
            return cls(
                uri=uri.split("#")[0], protocol=protocol,
                host=host, port=port,
                fingerprint=fingerprint, raw_params=params,
            )
        except Exception:
            return None

    # ── геттеры параметров ────────────────────────────────────────────────────

    def get_security(self) -> str:
        return self.raw_params.get("security", "").lower()

    def get_network(self) -> str:
        return self.raw_params.get("type", self.raw_params.get("net", "tcp")).lower()

    def get_flow(self) -> str:
        return self.raw_params.get("flow", "").lower()

    def get_sni(self) -> str:
        return self.raw_params.get("sni", self.host).lower()

    def get_fp(self) -> str:
        return self.raw_params.get("fp", "").lower()

    # ── предикаты ────────────────────────────────────────────────────────────

    def is_reality(self) -> bool:
        return self.get_security() == "reality"

    def is_xtls_vision(self) -> bool:
        return "xtls-rprx-vision" in self.get_flow()

    def is_xhttp(self) -> bool:
        return self.get_network() in ("xhttp", "splithttp")

    def is_ws(self) -> bool:
        return self.get_network() == "ws"

    def is_grpc(self) -> bool:
        return self.get_network() in ("grpc", "gun")

    def is_httpupgrade(self) -> bool:
        return self.get_network() in ("httpupgrade", "h2upgrade")

    def is_h2(self) -> bool:
        return self.get_network() in ("h2", "http")

    def is_tcp(self) -> bool:
        return self.get_network() in ("tcp", "")

    def is_tls(self) -> bool:
        return self.get_security() == "tls"

    def is_insecure(self) -> bool:
        q = urllib.parse.urlparse(self.uri).query.lower()
        return any(f"{k}=1" in q or f"{k}=true" in q
                   for k in ("allowinsecure", "allow_insecure", "insecure"))

    def has_cdn_sni(self) -> bool:
        sni = self.get_sni()
        return any(m in sni for m in CDN_SNI_MARKERS)

    def has_good_sni(self) -> bool:
        return self.get_sni() in GOOD_SNI

    def has_unique_dest(self) -> bool:
        """REALITY с нестандартным dest (не только google/microsoft)."""
        sni = self.get_sni()
        common = {"www.google.com", "google.com", "www.microsoft.com", "microsoft.com"}
        return self.is_reality() and bool(sni) and sni not in common

    def classify(self) -> ConfigTier:
        """Определить уровень маскировки конфигурации."""
        proto = self.protocol
        vision = self.is_xtls_vision()
        reality = self.is_reality()
        tls = self.is_tls()
        port_ok = self.port == 443

        # TIER-1: максимальная маскировка — VLESS+REALITY+Vision+TCP443
        if (proto == "vless" and reality and vision
                and self.is_tcp() and port_ok):
            return ConfigTier.TIER1_REALITY_VISION

        # TIER-2: скрыть IP — VLESS+TLS+Vision+HTTPUpgrade/gRPC+CDN
        if (proto == "vless" and tls and vision and port_ok
                and (self.is_httpupgrade() or self.is_grpc() or self.is_h2())):
            return ConfigTier.TIER2_TLS_CDN_VISION

        # TIER-3: баланс — VLESS+REALITY+Vision (любой транспорт/порт)
        if proto == "vless" and reality and vision:
            return ConfigTier.TIER3_REALITY_BALANCE

        # TIER-4: жёсткий DPI — xhttp/SplitHTTP или REALITY с уник. dest
        if self.is_xhttp() and port_ok:
            return ConfigTier.TIER4_DPI_RESISTANT
        if reality and self.has_unique_dest():
            return ConfigTier.TIER4_DPI_RESISTANT

        return ConfigTier.TIER5_OTHER

    def score(self) -> int:
        """Чем МЕНЬШЕ — тем лучше (для сортировки вместе с latency)."""
        tier = self.classify()
        base = {
            ConfigTier.TIER1_REALITY_VISION:  0,
            ConfigTier.TIER2_TLS_CDN_VISION:  200,
            ConfigTier.TIER3_REALITY_BALANCE: 400,
            ConfigTier.TIER4_DPI_RESISTANT:   600,
            ConfigTier.TIER5_OTHER:           1000,
        }[tier]

        bonus = 0
        if self.has_good_sni():
            bonus -= 30
        if self.has_cdn_sni():
            bonus -= 20
        fp = self.get_fp()
        if fp in ("chrome", "firefox", "safari", "edge"):
            bonus -= 15
        if self.port == 443:
            bonus -= 10
        if self.is_insecure():
            bonus += 150  # штраф за insecure

        return base + bonus


@dataclass(frozen=True, slots=True)
class CheckResult:
    proxy: ProxyConfig
    latency_ms: int
    country: str
    reachable: bool = True
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def priority(self) -> int:
        """Итоговый приоритет для сортировки (меньше = лучше)."""
        return self.proxy.score() + self.latency_ms

    def to_cache_dict(self) -> Dict[str, Any]:
        return {
            "latency": self.latency_ms,
            "country": self.country,
            "time": self.checked_at.timestamp(),
            "alive": self.reachable,
            "tier": self.proxy.classify().name,
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
        self.timeout = aiohttp.ClientTimeout(total=timeout, connect=8, sock_read=timeout)
        self.logger = logger
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> AsyncHTTPClient:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        connector = aiohttp.TCPConnector(
            limit=120, limit_per_host=10,
            enable_cleanup_closed=True, force_close=True, ssl=ssl_ctx,
        )
        self._session = aiohttp.ClientSession(
            connector=connector, timeout=self.timeout,
            headers={"Accept-Encoding": "gzip, deflate, br"},
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._session:
            await self._session.close()

    @property
    def session(self) -> aiohttp.ClientSession:
        if self._session is None:
            raise RuntimeError("Client not opened")
        return self._session

    def _headers(self) -> Dict[str, str]:
        return {
            "User-Agent": random.choice(self.USER_AGENTS),
            "Accept": "text/plain,application/octet-stream,*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }

    async def fetch_text(self, url: str, retries: int = 2) -> str:
        if not self._session:
            raise RuntimeError("Client not opened")
        if "github.com" in url and "/blob/" in url:
            url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")

        last_exc: Optional[Exception] = None
        for attempt in range(retries + 1):
            try:
                async with self._session.get(
                    url, headers=self._headers(), allow_redirects=True
                ) as resp:
                    resp.raise_for_status()
                    raw = await resp.read()
                    # Попробовать UTF-8, затем latin-1
                    try:
                        return raw.decode("utf-8")
                    except UnicodeDecodeError:
                        return raw.decode("latin-1", errors="replace")
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                last_exc = e
                if attempt < retries:
                    await asyncio.sleep(1.5 * (attempt + 1))
        raise last_exc or RuntimeError("fetch failed")


# =============================================================================
# 5. ПАРСЕР
# =============================================================================

class ProxyParser:
    # Стоп-маркеры: эти конфиги игнорируем
    BAD_COUNTRY_MARKERS = frozenset({
        "CN", "IR", "KR", "BR", "IN",
        "🇨🇳", "🇮🇷", "🇰🇷", "RELAY", "POOL",
    })

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    # ── декодирование ─────────────────────────────────────────────────────────

    def _try_base64(self, data: str) -> List[str]:
        """Попробовать декодировать как base64."""
        try:
            cleaned = data.strip().rstrip("=")
            cleaned += "=" * (-len(cleaned) % 4)
            decoded = base64.b64decode(cleaned).decode("utf-8", errors="ignore")
            lines = [l.strip() for l in decoded.splitlines() if l.strip()]
            # Проверяем — есть ли хоть один URI
            if any("://" in l for l in lines[:5]):
                return lines
        except Exception:
            pass
        return []

    # ── фильтрация мусора ─────────────────────────────────────────────────────

    def _is_garbage(self, line: str) -> bool:
        if len(line) > 2500 or len(line) < 20:
            return True
        upper = line.upper()
        if any(m in upper for m in self.BAD_COUNTRY_MARKERS):
            return True
        if any(bad in line for bad in (".ir", ".cn", "127.0.0.1", "0.0.0.0")):
            return True
        return False

    def _extract_uris(self, raw: str) -> List[str]:
        """Извлечь URI из любого формата (plain, base64, mixed)."""
        PROTO_PREFIXES = ("vless://", "vmess://", "trojan://", "ss://", "ssr://")

        lines = raw.splitlines()
        result: List[str] = []

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if any(line.startswith(p) for p in PROTO_PREFIXES):
                result.append(line)
                continue
            # Попробовать как base64 строку
            if len(line) > 40 and not " " in line:
                decoded = self._try_base64(line)
                for dl in decoded:
                    if any(dl.startswith(p) for p in PROTO_PREFIXES):
                        result.append(dl)

        # Если ничего не нашли — попробовать весь блок как base64
        if not result:
            decoded = self._try_base64(raw)
            for dl in decoded:
                if any(dl.startswith(p) for p in PROTO_PREFIXES):
                    result.append(dl)

        return result

    def parse_raw(self, raw: str) -> List[ProxyConfig]:
        uris = self._extract_uris(raw)
        configs: List[ProxyConfig] = []
        for uri in uris:
            if self._is_garbage(uri):
                continue
            cfg = ProxyConfig.from_uri(uri)
            if cfg and cfg.host and not cfg.is_insecure():
                configs.append(cfg)
        return configs

    def deduplicate(self, configs: List[ProxyConfig]) -> List[ProxyConfig]:
        """Дедупликация + оставить лучший экземпляр (по score)."""
        best: Dict[str, ProxyConfig] = {}
        for cfg in configs:
            fp = cfg.fingerprint
            if fp not in best or cfg.score() < best[fp].score():
                best[fp] = cfg
        return list(best.values())

    @staticmethod
    def _is_valid_host(host: str) -> bool:
        if not host or len(host) > 253:
            return False
        for label in host.split("."):
            if not label or len(label) > 63:
                return False
        return True


# =============================================================================
# 6. ЧЕКЕР
# =============================================================================

class ProxyChecker:
    RU_MARKERS = frozenset({
        "moscow", "msk", "russia", "spb", "saint", "piter",
        "yandex", "mail.ru", "vk.com", "beeline", "mts", "megafon",
        "rostelecom", "ttk", "dom.ru",
    })
    EURO_CODES = frozenset({
        "DE", "NL", "GB", "FR", "FI", "SE", "NO", "DK",
        "PL", "CZ", "AT", "CH", "IT", "ES", "BE", "IE",
        "LU", "EE", "LV", "LT", "UA", "BY", "TR",
    })
    RU_TLD = frozenset({".ru", ".рф", ".su", ".москва"})

    def __init__(self, settings: Settings, logger: logging.Logger, session: aiohttp.ClientSession):
        self.settings = settings
        self.logger = logger
        self.session = session
        self.semaphore = asyncio.Semaphore(settings.concurrency)
        # Thread pool для sync socket checks — concurrency*2 потоков
        self._executor = __import__('concurrent.futures', fromlist=['ThreadPoolExecutor']).ThreadPoolExecutor(
            max_workers=settings.concurrency * 2,
            thread_name_prefix='sock_check',
        )

    @staticmethod
    def _is_valid_host(host: str) -> bool:
        if not host or len(host) > 253:
            return False
        for label in host.split("."):
            if not label or len(label) > 63:
                return False
        return True

    def detect_country(self, host: str, uri: str) -> str:
        h = host.lower()
        if any(h.endswith(tld) for tld in self.RU_TLD):
            return "RU"
        if any(m in h for m in self.RU_MARKERS):
            return "RU"
        tld_map = {
            ".de": "DE", ".nl": "NL", ".uk": "GB", ".co.uk": "GB",
            ".fr": "FR", ".fi": "FI", ".se": "SE", ".no": "NO",
            ".dk": "DK", ".pl": "PL", ".cz": "CZ", ".at": "AT",
            ".ch": "CH", ".it": "IT", ".es": "ES", ".be": "BE",
            ".ie": "IE", ".lu": "LU", ".ee": "EE", ".lv": "LV", ".lt": "LT",
            ".ua": "UA", ".by": "BY", ".tr": "TR",
        }
        for tld, code in tld_map.items():
            if h.endswith(tld):
                return code
        # Поиск в метке конфига
        u_upper = uri.upper()
        for code in self.EURO_CODES | {"RU"}:
            if f" {code} " in u_upper or f"|{code}|" in u_upper or f"[{code}]" in u_upper:
                return code
        return "UNKNOWN"

    # ── Sync socket checks (thread-executor) ────────────────────────────────
    # asyncio.open_connection + w.wait_closed() зависают навсегда на:
    #   - тарпит-серверах (accept TCP но не закрывают соединение)
    #   - TLS: ждёт close_notify от удалённой стороны
    # socket.create_connection(timeout=N) — таймаут на уровне ОС, всегда завершается.

    @staticmethod
    def _sync_tcp(host: str, port: int, timeout: int) -> Optional[int]:
        start = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return int((time.monotonic() - start) * 1000)
        except Exception:
            return None

    @staticmethod
    def _sync_tls(host: str, port: int, sni: str, timeout: int) -> Optional[int]:
        start = time.monotonic()
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.settimeout(timeout)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            tls = ctx.wrap_socket(sock, server_hostname=sni or host,
                                   do_handshake_on_connect=False)
            tls.settimeout(timeout)
            try:
                tls.do_handshake()
            except ssl.SSLError:
                pass  # TLS reject — но TCP сервер живой
            finally:
                try: tls.close()
                except Exception: pass
            return int((time.monotonic() - start) * 1000)
        except Exception:
            return None

    async def _run_sync(self, fn, *args) -> Optional[int]:
        """Запустить sync-проверку в executor с дополнительным asyncio-таймаутом."""
        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(self._executor, fn, *args),
                timeout=self.settings.timeout + 4,
            )
        except Exception:
            return None

    async def check(self, proxy: ProxyConfig) -> Optional[CheckResult]:
        if not self._is_valid_host(proxy.host):
            return None
        async with self.semaphore:
            try:
                t    = self.settings.timeout
                host = proxy.host
                port = proxy.port
                sni  = proxy.get_sni() or host
                sec  = proxy.get_security()

                if proxy.is_reality():
                    # REALITY: TLS по SNI (проверяем что сервер живой), fallback TCP
                    lat = await self._run_sync(self._sync_tls, host, port, sni, t)
                    if lat is None:
                        lat = await self._run_sync(self._sync_tcp, host, port, t)
                elif proxy.is_xhttp():
                    if port == 443:
                        lat = await self._run_sync(self._sync_tls, host, port, sni, t)
                    else:
                        lat = await self._run_sync(self._sync_tcp, host, port, t)
                elif proxy.is_ws() or proxy.is_grpc() or proxy.is_httpupgrade() or proxy.is_h2():
                    lat = await self._run_sync(self._sync_tls, host, port, sni, t)
                elif sec == "tls":
                    lat = await self._run_sync(self._sync_tls, host, port, sni, t)
                else:
                    lat = await self._run_sync(self._sync_tcp, host, port, t)
            except Exception as e:
                self.logger.debug(f"check error {proxy.host}: {e}")
                return None

            if lat is None or lat > self.settings.max_ping_ms:
                return None

            country = self.detect_country(proxy.host, proxy.uri)
            return CheckResult(proxy=proxy, latency_ms=lat, country=country)


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
            self.logger.info(f"Cache loaded: {len(self._data)} entries")
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
            await asyncio.get_event_loop().run_in_executor(
                None, shutil.move, str(tmp), str(self.cache_file)
            )
            self._data = cleaned
            self.logger.info(f"Cache saved: {len(cleaned)} entries")
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
            proxy=ProxyConfig(
                uri="", protocol="", host="", port=0,
                fingerprint=fingerprint, raw_params={},
            ),
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
            self.logger.warning("GitHub token not set — upload disabled")

    async def upload(self, local_path: Path, remote_path: str, message: str) -> bool:
        if not self._repo or self.settings.dry_run:
            return False
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._upload_sync, local_path, remote_path, message
        )

    def _upload_sync(self, local_path: Path, remote_path: str, message: str) -> bool:
        try:
            content = local_path.read_text(encoding="utf-8")
        except Exception as e:
            self.logger.error(f"Cannot read {local_path}: {e}")
            return False

        for attempt in range(3):
            try:
                try:
                    file_in_repo = self._repo.get_contents(remote_path)
                    if hasattr(file_in_repo, "decoded_content"):
                        remote_content = file_in_repo.decoded_content.decode(
                            "utf-8", errors="replace"
                        )
                        if remote_content == content:
                            self.logger.info(f"No changes: {remote_path}")
                            return True
                    self._repo.update_file(
                        path=remote_path, message=message,
                        content=content, sha=file_in_repo.sha,
                    )
                    self.logger.info(f"Updated: {remote_path}")
                    return True
                except GithubException as e:
                    status = getattr(e, "status", None)
                    if status == 404:
                        self._repo.create_file(
                            path=remote_path,
                            message=f"Create {remote_path}",
                            content=content,
                        )
                        self.logger.info(f"Created: {remote_path}")
                        return True
                    elif status == 409 and attempt < 2:
                        self.logger.warning(f"Conflict on {remote_path}, retrying...")
                        time.sleep(1.5)
                        continue
                    else:
                        raise
            except Exception as e:
                self.logger.error(f"Upload failed {remote_path}: {e}")
                if attempt == 2:
                    raise
        return False


# =============================================================================
# 9. ГЕНЕРАТОР ФАЙЛОВ
# =============================================================================

COUNTRY_FLAGS: Dict[str, str] = {
    "RU": "🇷🇺", "NL": "🇳🇱", "DE": "🇩🇪", "FI": "🇫🇮", "GB": "🇬🇧",
    "FR": "🇫🇷", "SE": "🇸🇪", "PL": "🇵🇱", "CZ": "🇨🇿", "AT": "🇦🇹",
    "CH": "🇨🇭", "IT": "🇮🇹", "ES": "🇪🇸", "NO": "🇳🇴", "DK": "🇩🇰",
    "BE": "🇧🇪", "IE": "🇮🇪", "LU": "🇱🇺", "EE": "🇪🇪", "LV": "🇱🇻",
    "LT": "🇱🇹", "US": "🇺🇸", "UA": "🇺🇦", "BY": "🇧🇾", "KZ": "🇰🇿",
    "TR": "🇹🇷", "JP": "🇯🇵", "SG": "🇸🇬", "HK": "🇭🇰", "CA": "🇨🇦",
    "AU": "🇦🇺",
}

TIER_EMOJI = {
    ConfigTier.TIER1_REALITY_VISION:  "🛡️",
    ConfigTier.TIER2_TLS_CDN_VISION:  "☁️",
    ConfigTier.TIER3_REALITY_BALANCE: "⚡",
    ConfigTier.TIER4_DPI_RESISTANT:   "🔬",
    ConfigTier.TIER5_OTHER:           "🔗",
}


class FileGenerator:
    def __init__(self, settings: Settings, logger: logging.Logger):
        self.settings = settings
        self.logger = logger

    @staticmethod
    def country_to_flag(country: str) -> str:
        return COUNTRY_FLAGS.get(country.upper(), "🏳️")

    def format_key(self, proxy: ProxyConfig, latency: int, country: str) -> str:
        flag = self.country_to_flag(country)
        tier = proxy.classify()
        tier_emoji = TIER_EMOJI[tier]
        tier_label = TIER_LABELS[tier]
        info = f"[{latency}ms {flag}{country} {tier_emoji}{tier_label} {self.settings.my_channel}]"
        return f"{proxy.uri}#{urllib.parse.quote(info, safe='')}"

    async def _write_file(self, path: Path, lines: List[str], title: str,
                          extra_meta: str = "") -> None:
        b64_title = base64.b64encode(title.encode()).decode()
        header = (
            f"#profile-title: base64:{b64_title}\n"
            f"#profile-update-interval: 6\n"
            f"# {title}\n"
        )
        if extra_meta:
            header += extra_meta
        header += "\n"
        content = header + "\n".join(lines) if lines else header + "# Нет рабочих ключей\n"
        tmp = path.with_suffix(".tmp")
        async with aiofiles.open(tmp, "w", encoding="utf-8") as f:
            await f.write(content)
        await asyncio.get_event_loop().run_in_executor(
            None, shutil.move, str(tmp), str(path)
        )

    async def save_exact(self, keys: List[str], folder: Path,
                         filename: str, title: str, extra_meta: str = "") -> Path:
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / filename
        valid = [k for k in keys if k and k.strip()]
        await self._write_file(path, valid, title, extra_meta)
        self.logger.info(f"Saved {filename}: {len(valid)} keys")
        return path

    async def save_chunked(
        self, keys: List[str], folder: Path, base_name: str,
        chunk_size: int, title_template: str,
    ) -> List[Path]:
        folder.mkdir(parents=True, exist_ok=True)
        valid = [k.strip() for k in keys if k and k.strip()]
        chunks = [valid[i:i + chunk_size] for i in range(0, max(len(valid), 1), chunk_size)]
        paths: List[Path] = []
        for idx, chunk in enumerate(chunks, start=1):
            fname = f"{base_name}_part{idx}.txt"
            path = folder / fname
            await self._write_file(path, chunk, title_template.format(idx=idx))
            paths.append(path)
            self.logger.info(f"Saved {fname}: {len(chunk)} keys")
        return paths

    async def save_tiers(
        self,
        results: List[CheckResult],
        folder: Path,
        prefix: str,
        label: str,
    ) -> None:
        """Сохранить отдельный файл для каждого tier."""
        folder.mkdir(parents=True, exist_ok=True)
        by_tier: Dict[ConfigTier, List[str]] = {t: [] for t in ConfigTier}
        for r in results:
            key = self.format_key(r.proxy, r.latency_ms, r.country)
            by_tier[r.proxy.classify()].append(key)

        tier_descriptions = {
            ConfigTier.TIER1_REALITY_VISION:  "🛡️ TIER-1: REALITY+Vision+TCP443 (макс. маскировка)",
            ConfigTier.TIER2_TLS_CDN_VISION:  "☁️ TIER-2: TLS+Vision+CDN+HTTPUpgrade/gRPC (скрыть IP)",
            ConfigTier.TIER3_REALITY_BALANCE: "⚡ TIER-3: REALITY+Vision (баланс)",
            ConfigTier.TIER4_DPI_RESISTANT:   "🔬 TIER-4: SplitHTTP/xhttp | REALITY-уник.dest (DPI)",
            ConfigTier.TIER5_OTHER:           "🔗 TIER-5: Прочие рабочие",
        }

        for tier, keys in by_tier.items():
            if not keys:
                continue
            fname = f"{prefix}_{tier.name.lower()}.txt"
            desc = tier_descriptions[tier]
            title = f"MaxTre — {label} {desc}"
            await self.save_exact(keys, folder, fname, title)


# =============================================================================
# 10. BYPASS ГЕНЕРАТОР
# =============================================================================

class BypassGenerator:
    def __init__(self, settings: Settings, logger: logging.Logger,
                 parser: ProxyParser, checker: ProxyChecker):
        self.settings = settings
        self.logger = logger
        self.parser = parser
        self.checker = checker

    async def generate(self, client: AsyncHTTPClient) -> Path:
        self.logger.info(f"Building bypass file (limit={self.settings.bypass_test_limit})...")

        async def fetch_one(url: str) -> List[str]:
            try:
                raw = await client.fetch_text(url)
                cfgs = self.parser.parse_raw(raw)
                return [c.uri for c in cfgs]
            except Exception as e:
                self.logger.warning(f"Bypass source failed {url[:60]}: {e}")
                return []

        results = await asyncio.gather(*[fetch_one(u) for u in self.settings.extra_bypass_sources])
        all_uris: List[str] = []
        for r in results:
            all_uris.extend(r)

        # Дедупликация
        seen: Dict[str, ProxyConfig] = {}
        for uri in all_uris:
            cfg = ProxyConfig.from_uri(uri)
            if not cfg:
                continue
            fp = cfg.fingerprint
            if fp not in seen or cfg.score() < seen[fp].score():
                seen[fp] = cfg

        # Сортируем по score (лучшие — первыми)
        unique = sorted(seen.values(), key=lambda c: c.score())
        self.logger.info(f"Bypass unique configs: {len(unique)} (sorted by tier)")

        # Приоритет: сначала TIER1/TIER2/TIER3
        priority_first = [c for c in unique
                          if c.classify() in (ConfigTier.TIER1_REALITY_VISION,
                                              ConfigTier.TIER2_TLS_CDN_VISION,
                                              ConfigTier.TIER3_REALITY_BALANCE,
                                              ConfigTier.TIER4_DPI_RESISTANT)]
        rest = [c for c in unique if c not in set(priority_first)]
        sorted_unique = priority_first + rest

        limit = min(self.settings.bypass_test_limit, len(sorted_unique))
        to_test = sorted_unique[:limit]

        working: List[Tuple[int, str, ProxyConfig]] = []
        checked = 0

        async def check_one(cfg: ProxyConfig) -> Optional[Tuple[int, str, ProxyConfig]]:
            nonlocal checked
            result = await self.checker.check(cfg)
            checked += 1
            if checked % 25 == 0:
                self.logger.info(f"  Bypass: {checked}/{limit} | found {len(working)}")
            if result:
                return (result.latency_ms, result.country, cfg)
            return None

        check_results = await asyncio.gather(*[check_one(c) for c in to_test])
        for r in check_results:
            if r:
                working.append(r)

        self.logger.info(f"Bypass working: {len(working)}")
        # Сортировка: по приоритету = score + latency
        working.sort(key=lambda x: x[2].score() + x[0])
        top = working[:200]

        gen = FileGenerator(self.settings, self.logger)
        final_keys = [
            gen.format_key(cfg, lat, country)
            for lat, country, cfg in top
        ]

        now_str = datetime.now(zoneinfo.ZoneInfo(self.settings.timezone)).strftime("%H:%M | %d.%m.%Y")
        title = "MaxTre — VPN Bypass (WHITE полная проверка)"
        header = (
            f"#profile-title: base64:{base64.b64encode(title.encode()).decode()}\n"
            f"#profile-update-interval: 3\n"
            f"# {title}\n"
            f"# Проверено: TCP+TLS/REALITY/WS/XHTTP/XTLS-Vision\n"
            f"# Лимит: {limit} | Рабочих: {len(final_keys)}\n"
            f"# Обновлено: {now_str}\n\n"
        )

        path = self.settings.output_dir / "ByPassVpnLera.txt"
        content = header + "\n".join(final_keys) if final_keys else header + "# Нет рабочих конфигов\n"

        tmp = path.with_suffix(".tmp")
        async with aiofiles.open(tmp, "w", encoding="utf-8") as f:
            await f.write(content)
        await asyncio.get_event_loop().run_in_executor(
            None, shutil.move, str(tmp), str(path)
        )
        self.logger.info(f"Bypass saved: {path} ({len(final_keys)} keys)")
        return path


# =============================================================================
# 11. ORCHESTRATOR
# =============================================================================

class CollectorOrchestrator:
    def __init__(self, settings: Settings, logger: logging.Logger):
        self.settings = settings
        self.logger = logger
        self.shutdown_event = asyncio.Event()
        self._threading_shutdown_event = threading.Event()

    def _setup_signals(self) -> None:
        def _handle(sig: int, _: Any) -> None:
            self.logger.warning(f"Signal {sig} received, shutting down...")
            self.shutdown_event.set()
            self._threading_shutdown_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, _handle)

    def _is_russian_exit(self, proxy: ProxyConfig, country: str) -> bool:
        if country == "RU":
            return True
        host_lower = proxy.host.lower()
        if host_lower.endswith(".ru"):
            return True
        if any(m in host_lower for m in ProxyChecker.RU_MARKERS):
            return True
        key_upper = proxy.uri.upper()
        # Известные RU IP-префиксы (Yandex, VK, Rostelecom, etc.)
        ip_markers = (
            "178.154.", "77.88.", "5.255.", "87.250.", "95.108.",
            "213.180.", "195.208.", "91.108.", "149.154.", "185.246.",
        )
        return any(m in key_upper for m in ip_markers)

    async def _fetch_all(self, client: AsyncHTTPClient,
                         parser: ProxyParser) -> List[ProxyConfig]:
        self.logger.info(f"Fetching {len(self.settings.sources)} sources...")

        async def fetch_one(url: str) -> List[ProxyConfig]:
            if self.shutdown_event.is_set():
                return []
            try:
                raw = await client.fetch_text(url)
                parsed = parser.parse_raw(raw)
                self.logger.info(
                    f"  {urllib.parse.urlparse(url).path[-40:]:40} +{len(parsed)}"
                )
                return parsed
            except Exception as e:
                self.logger.warning(f"  Failed {url[:60]}: {e}")
                return []

        batch_results = await asyncio.gather(*[fetch_one(u) for u in self.settings.sources])
        configs: List[ProxyConfig] = []
        for r in batch_results:
            configs.extend(r)

        # Дедупликация
        deduped = parser.deduplicate(configs)
        self.logger.info(f"Total unique configs: {len(deduped)}")

        # Сортировка: лучшие tier — первыми (проверяем их раньше)
        deduped.sort(key=lambda c: c.score())
        return deduped[: self.settings.max_keys_to_check]

    async def _check_all(
        self, configs: List[ProxyConfig],
        checker: ProxyChecker, cache: CacheManager,
        deadline_sec: float = 1500.0,
    ) -> Tuple[List[CheckResult], List[CheckResult]]:
        """TCP/TLS проверка с hard deadline и ETA-прогрессом."""
        ru_results:   List[CheckResult] = []
        euro_results: List[CheckResult] = []
        total   = len(configs)
        t_start = time.monotonic()

        self.logger.info(
            f"Checking {total} configs "
            f"(concurrency={self.settings.concurrency}, deadline={deadline_sec:.0f}s)..."
        )

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

        # Жёсткий per-task таймаут = timeout + 6 сек
        # Защита от w.wait_closed() зависания и прочих edge-cases
        TASK_LIMIT = self.settings.timeout + 6

        async def safe_check(cfg: ProxyConfig) -> Optional[CheckResult]:
            try:
                return await asyncio.wait_for(check_one(cfg), timeout=TASK_LIMIT)
            except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
                return None

        # Создаём Tasks явно — лучший контроль чем as_completed
        tasks = [asyncio.ensure_future(safe_check(c)) for c in configs]
        pending = set(tasks)
        checked = 0

        while pending:
            if time.monotonic() - t_start > deadline_sec:
                self.logger.warning(
                    f"Deadline {deadline_sec:.0f}s hit at {checked}/{total} — "
                    f"cancelling {len(pending)} pending"
                )
                for t in pending:
                    t.cancel()
                break

            # Ждём любого готового, не дольше 10 сек
            done, pending = await asyncio.wait(pending, timeout=10.0,
                                               return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                checked += 1
                try:
                    result = task.result()
                except Exception:
                    result = None

                if result is None:
                    continue

                if checked % 50 == 0 or checked == total:
                    elapsed = time.monotonic() - t_start
                    rate    = checked / elapsed if elapsed > 0 else 0.01
                    eta     = (total - checked) / rate
                    self.logger.info(
                        f"  {checked}/{total} ({checked*100//total}%) "
                        f"RU={len(ru_results)} EU={len(euro_results)} "
                        f"rate={rate:.1f}/s ETA={eta:.0f}s"
                    )

                if self._is_russian_exit(result.proxy, result.country):
                    ru_results.append(result)
                elif result.country in checker.EURO_CODES:
                    euro_results.append(result)

        elapsed = time.monotonic() - t_start
        self.logger.info(
            f"Check done in {elapsed:.0f}s: RU={len(ru_results)} EU={len(euro_results)}"
        )
        ru_results.sort(key=lambda x: x.priority())
        euro_results.sort(key=lambda x: x.priority())
        return ru_results, euro_results

    def _log_tier_stats(self, label: str, results: List[CheckResult]) -> None:
        from collections import Counter
        counts: Counter = Counter(r.proxy.classify() for r in results)
        self.logger.info(f"  [{label}] Tier stats:")
        for tier in ConfigTier:
            cnt = counts.get(tier, 0)
            if cnt:
                self.logger.info(f"    {TIER_LABELS[tier]}: {cnt}")

    def _generate_subscriptions_list(self, tier_counts: Dict[str, int]) -> Path:
        base_raw = f"https://raw.githubusercontent.com/{self.settings.repo_name}/main"
        lines: List[str] = []

        def add_section(title: str, folder: Path, pattern: str, limit: Optional[int] = None):
            lines.append(f"=== {title} ===")
            files = sorted(folder.glob(pattern))
            for f in (files[:limit] if limit else files):
                lines.append(f"{base_raw}/githubmirror/{folder.name}/{f.name}")
            lines.append("")

        add_section("🇷🇺 RUSSIA FAST", self.settings.folder_ru, "ru_white_part*.txt")
        add_section("🇪🇺 EUROPE FAST", self.settings.folder_euro, "my_euro_part*.txt")
        add_section("🇷🇺 RUSSIA ALL", self.settings.folder_ru, "ru_white_all_part*.txt", 2)
        add_section("🇪🇺 EUROPE ALL", self.settings.folder_euro, "my_euro_all_part*.txt", 2)

        # Tier-файлы
        tier_folder = self.settings.folder_tiers
        for tier in ConfigTier:
            for region_prefix in ("ru", "eu"):
                fname = f"{region_prefix}_{tier.name.lower()}.txt"
                path = tier_folder / fname
                if path.exists():
                    desc = TIER_LABELS[tier]
                    flag = "🇷🇺" if region_prefix == "ru" else "🇪🇺"
                    lines.append(f"=== {flag} {desc} ===")
                    lines.append(f"{base_raw}/githubmirror/Tiers/{fname}")
                    lines.append("")

        lines.append("=== ✅ WHITE RU ===")
        lines.append(f"{base_raw}/githubmirror/{self.settings.folder_ru.name}/ru_white_all_WHITE.txt")
        lines.append("")
        lines.append("=== ✅ WHITE EU ===")
        lines.append(f"{base_raw}/githubmirror/{self.settings.folder_euro.name}/my_euro_all_WHITE.txt")
        lines.append("")
        lines.append("=== ⚠️ BLACK RU ===")
        lines.append(f"{base_raw}/githubmirror/{self.settings.folder_ru.name}/ru_white_all_BLACK.txt")
        lines.append("")
        lines.append("=== ⚠️ BLACK EU ===")
        lines.append(f"{base_raw}/githubmirror/{self.settings.folder_euro.name}/my_euro_all_BLACK.txt")
        lines.append("")
        lines.append("=== 🛡️ BYPASS (ПОЛНАЯ ПРОВЕРКА) ===")
        lines.append(f"{base_raw}/githubmirror/ByPassVpnLera.txt")

        path = self.settings.output_dir / "subscriptions_list.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines), encoding="utf-8")
        http_count = sum(1 for l in lines if l.startswith("http"))
        self.logger.info(f"Subscriptions list: {http_count} links")
        return path

    async def run(self) -> None:
        self._setup_signals()
        start = time.monotonic()
        zone = zoneinfo.ZoneInfo(self.settings.timezone)
        offset = datetime.now(zone).strftime("%H:%M | %d.%m.%Y")

        cache = CacheManager(
            self.settings.cache_file, self.settings.cache_hours,
            self.settings.max_history_age, self.logger,
        )
        await cache.load()

        # Найти xray
        xray_path = None
        for candidate in (
            self.settings.xray_path,
            Path("xray"),
            Path("source/xray"),
            Path(os.environ.get("XRAY_BIN", "")),
        ):
            if candidate and candidate.exists() and os.access(candidate, os.X_OK):
                xray_path = str(candidate)
                self.logger.info(f"xray found: {xray_path}")
                break

        white_checker = wc.WhiteChecker(
            xray_path=xray_path,
            workers=wc.WHITE_WORKERS,
            cache_hours=24,
            check_timeout=wc.WHITE_CHECK_TIMEOUT,
        )

        async with AsyncHTTPClient(self.settings.timeout, self.logger) as client:
            parser = ProxyParser(self.logger)
            checker = ProxyChecker(self.settings, self.logger, client.session)
            gen = FileGenerator(self.settings, self.logger)
            uploader = GitHubUploader(self.settings, self.logger)

            # Очистить output директории
            for folder in (self.settings.folder_ru, self.settings.folder_euro, self.settings.folder_tiers):
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
            self._log_tier_stats("RU", ru_results)
            self._log_tier_stats("EU", euro_results)

            # 3. Форматирование
            ru_keys = [gen.format_key(r.proxy, r.latency_ms, r.country) for r in ru_results]
            eu_keys = [gen.format_key(r.proxy, r.latency_ms, r.country) for r in euro_results]

            ru_fast = ru_keys[: self.settings.fast_limit]
            eu_fast = eu_keys[: self.settings.fast_limit]

            # 4. FAST / ALL чанки
            await gen.save_chunked(ru_fast, self.settings.folder_ru, "ru_white",
                                   self.settings.chunk_limit, "MaxTre — RU FAST ⚡ Part {idx}")
            await gen.save_chunked(eu_fast, self.settings.folder_euro, "my_euro",
                                   self.settings.euro_chunk_limit, "MaxTre — EU FAST ⚡ Part {idx}")
            await gen.save_chunked(ru_keys, self.settings.folder_ru, "ru_white_all",
                                   self.settings.chunk_limit, "MaxTre — RU ALL 🇷🇺 Part {idx}")
            await gen.save_chunked(eu_keys, self.settings.folder_euro, "my_euro_all",
                                   self.settings.euro_chunk_limit, "MaxTre — EU ALL 🇪🇺 Part {idx}")

            # 5. Tier-файлы (по категориям маскировки)
            await gen.save_tiers(ru_results, self.settings.folder_tiers, "ru", "🇷🇺 RU")
            await gen.save_tiers(euro_results, self.settings.folder_tiers, "eu", "🇪🇺 EU")

            # 6. WHITE / BLACK split через xray
            ru_white, ru_black = ru_keys, []
            euro_white, euro_black = eu_keys, []

            if not self.settings.dry_run:
                if white_checker.xray_available():
                    ru_test = ru_keys[: self.settings.max_white_test]
                    ru_rest = ru_keys[self.settings.max_white_test:]
                    eu_test = eu_keys[: self.settings.max_white_test]
                    eu_rest = eu_keys[self.settings.max_white_test:]

                    self.logger.info(f"White check: RU={len(ru_test)} EU={len(eu_test)}")
                    loop = asyncio.get_event_loop()
                    WC_TIMEOUT = 600  # 10 мин абсолютный таймаут на каждый регион

                    try:
                        ru_white, ru_black = await asyncio.wait_for(
                            loop.run_in_executor(
                                None,
                                partial(
                                    white_checker.batch_white_check,
                                    ru_test, cache._data,
                                    label="RU",
                                    shutdown_event=self._threading_shutdown_event,
                                ),
                            ),
                            timeout=WC_TIMEOUT,
                        )
                    except asyncio.TimeoutError:
                        self.logger.error(f"White check RU: TIMEOUT {WC_TIMEOUT}s — пропускаем")
                        ru_white, ru_black = ru_test, []

                    try:
                        euro_white, euro_black = await asyncio.wait_for(
                            loop.run_in_executor(
                                None,
                                partial(
                                    white_checker.batch_white_check,
                                    eu_test, cache._data,
                                    label="EU",
                                    shutdown_event=self._threading_shutdown_event,
                                ),
                            ),
                            timeout=WC_TIMEOUT,
                        )
                    except asyncio.TimeoutError:
                        self.logger.error(f"White check EU: TIMEOUT {WC_TIMEOUT}s — пропускаем")
                        euro_white, euro_black = eu_test, []
                    ru_black.extend(ru_rest)
                    euro_black.extend(eu_rest)
                    self.logger.info(
                        f"WHITE/BLACK: RU {len(ru_white)}/{len(ru_black)} | "
                        f"EU {len(euro_white)}/{len(euro_black)}"
                    )
                else:
                    self.logger.warning("xray not found — skipping white/black split")

            now_str = datetime.now(zone).strftime("%H:%M | %d.%m.%Y")
            meta = f"# Обновлено: {now_str} | Всего: {{count}}\n"

            await gen.save_exact(
                ru_white, self.settings.folder_ru, "ru_white_all_WHITE.txt",
                "MaxTre — VPN RUSSIA WHITE ✅",
                meta.format(count=len(ru_white)),
            )
            await gen.save_exact(
                ru_black, self.settings.folder_ru, "ru_white_all_BLACK.txt",
                "MaxTre — VPN RUSSIA BLACK ⚠️",
                meta.format(count=len(ru_black)),
            )
            await gen.save_exact(
                euro_white, self.settings.folder_euro, "my_euro_all_WHITE.txt",
                "MaxTre — VPN EUROPE WHITE ✅",
                meta.format(count=len(euro_white)),
            )
            await gen.save_exact(
                euro_black, self.settings.folder_euro, "my_euro_all_BLACK.txt",
                "MaxTre — VPN EUROPE BLACK ⚠️",
                meta.format(count=len(euro_black)),
            )

            # 7. Bypass
            bypass_path = None
            if not self.settings.dry_run:
                bypass_gen = BypassGenerator(self.settings, self.logger, parser, checker)
                bypass_path = await bypass_gen.generate(client)

            # 8. Subscriptions list
            tier_counts = {
                TIER_LABELS[t]: sum(
                    1 for r in (ru_results + euro_results) if r.proxy.classify() == t
                )
                for t in ConfigTier
            }
            sub_path = self._generate_subscriptions_list(tier_counts)

            # 9. Upload
            if not self.settings.dry_run:
                self.logger.info("Uploading to GitHub...")
                uploads = []

                for folder in (self.settings.folder_ru, self.settings.folder_euro,
                               self.settings.folder_tiers):
                    for f in folder.glob("*.txt"):
                        remote = f"githubmirror/{folder.name}/{f.name}"
                        uploads.append(
                            uploader.upload(f, remote, f"🚀 Update {f.name} {offset}")
                        )

                if bypass_path:
                    uploads.append(uploader.upload(
                        bypass_path, "githubmirror/ByPassVpnLera.txt",
                        f"🚀 Update ByPassVpnLera.txt {offset}",
                    ))
                uploads.append(uploader.upload(
                    self.settings.cache_file, "githubmirror/history.json",
                    f"🚀 Update history.json {offset}",
                ))
                uploads.append(uploader.upload(
                    sub_path, "githubmirror/subscriptions_list.txt",
                    f"🚀 Update subscriptions_list.txt {offset}",
                ))

                await asyncio.gather(*uploads, return_exceptions=True)

            elapsed = time.monotonic() - start
            self.logger.info("=" * 55)
            self.logger.info("✅ SUCCESS")
            self.logger.info(f"  RU  FAST : {len(ru_fast)}")
            self.logger.info(f"  RU  ALL  : {len(ru_keys)}")
            self.logger.info(f"  RU  WHITE: {len(ru_white)}")
            self.logger.info(f"  EU  FAST : {len(eu_fast)}")
            self.logger.info(f"  EU  ALL  : {len(eu_keys)}")
            self.logger.info(f"  EU  WHITE: {len(euro_white)}")
            for tier, cnt in tier_counts.items():
                if cnt:
                    self.logger.info(f"  {tier}: {cnt}")
            self.logger.info(f"  Time     : {elapsed:.1f}s")
            self.logger.info("=" * 55)


# =============================================================================
# ENTRY POINT
# =============================================================================

def main() -> None:
    arg_parser = argparse.ArgumentParser(description="MaxTre VPN Config Collector v4.0")
    arg_parser.add_argument("--dry-run", action="store_true",
                            help="Проверка без сохранения и загрузки")
    arg_parser.add_argument("--bypass-limit", type=int, default=400,
                            help="Лимит проверки bypass (default: 400)")
    arg_parser.add_argument("--log", choices=["pretty", "json"], default="pretty",
                            help="Формат логов")
    args = arg_parser.parse_args()

    settings = Settings()
    settings.dry_run = args.dry_run
    settings.bypass_test_limit = args.bypass_limit
    settings.log_format = LogFormat(args.log)

    logger = setup_logging(settings.log_level, settings.log_format)
    logger.info("=" * 60)
    logger.info("MaxTre VPN Collector v4.0 — Tier-based masquerade")
    logger.info(f"Mode       : {'DRY-RUN' if settings.dry_run else 'PRODUCTION'}")
    logger.info(f"Concurrency: {settings.concurrency}")
    logger.info(f"Max check  : {settings.max_keys_to_check}")
    logger.info(f"Bypass lim : {settings.bypass_test_limit}")
    logger.info("=" * 60)

    orchestrator = CollectorOrchestrator(settings, logger)
    try:
        asyncio.run(orchestrator.run())
    except Exception:
        logger.exception("Fatal error")
        sys.exit(1)


if __name__ == "__main__":
    main()

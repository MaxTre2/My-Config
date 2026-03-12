"""
VPN-конфигуратор: сбор, фильтрация, тестирование и публикация конфигов в GitHub.
Совместим с приложениями happ (формат subscription URL).
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import html
import http.client
import json
import os
import re
import socket
import threading
import time
import urllib.parse
import zoneinfo
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import requests
import urllib3
from github import Auth, Github, GithubException
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ─────────────────────────── КОНСТАНТЫ ───────────────────────────

REPO_NAME = "MaxTre2/My-Config"
CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/143.0.0.0 Safari/537.36"
)
DEFAULT_MAX_WORKERS: int = int(os.environ.get("MAX_WORKERS", "16"))
EXTRA_URL_TIMEOUT: int = int(os.environ.get("EXTRA_URL_TIMEOUT", "6"))
EXTRA_URL_MAX_ATTEMPTS: int = int(os.environ.get("EXTRA_URL_MAX_ATTEMPTS", "2"))

# ─────────────────────────── ИСТОЧНИКИ ───────────────────────────

URLS: list[str] = [
    "https://github.com/sakha1370/OpenRay/raw/refs/heads/main/output/all_valid_proxies.txt",           # 1
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",                   # 2
    "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt",            # 3
    "https://raw.githubusercontent.com/acymz/AutoVPN/refs/heads/main/data/V2.txt",                    # 4
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/sub.txt",          # 5
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",                  # 6
    "https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/trojan.txt",             # 7
    "https://raw.githubusercontent.com/CidVpn/cid-vpn-config/refs/heads/main/general.txt",            # 8
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",  # 9
    "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/vless",                      # 10
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",               # 11
    "https://raw.githubusercontent.com/expressalaki/ExpressVPN/refs/heads/main/configs3.txt",          # 12
    "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/refs/heads/main/xray_final.txt",     # 13
    "https://github.com/LalatinaHub/Mineral/raw/refs/heads/master/result/nodes",                      # 14
    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/refs/heads/main/vless_iran.txt", # 15
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub",                    # 16
    "https://github.com/MhdiTaheri/V2rayCollector_Py/raw/refs/heads/main/sub/Mix/mix.txt",             # 17
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",                           # 18
    "https://github.com/MhdiTaheri/V2rayCollector/raw/refs/heads/main/sub/mix",                       # 19
    "https://github.com/Argh94/Proxy-List/raw/refs/heads/main/All_Config.txt",                        # 20
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt",                         # 21
    "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",      # 22
    "https://raw.githubusercontent.com/zipvpn/FreeVPNNodes/refs/heads/main/free_v2ray_xray_nodes.txt", # 23
    "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR.BYPASS#STR.BYPASS%F0%9F%91%BE",  # 24
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",        # 25
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt",   # 26
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vmess.txt",   # 27
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/trojan.txt",  # 28
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vless.txt",   # 29
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vmess.txt",   # 30
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/trojan.txt",  # 31
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/ss.txt",      # 32
    "https://raw.githubusercontent.com/sashalsk/V2Ray/main/VLESS.txt",                                # 33
    "https://raw.githubusercontent.com/sashalsk/V2Ray/main/VMESS.txt",                                # 34
    "https://raw.githubusercontent.com/sashalsk/V2Ray/main/TROJAN.txt",                               # 35
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/vless",                     # 36
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/vmess",                     # 37
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/trojan",                    # 38
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/ss",                        # 39
    "https://raw.githubusercontent.com/NiREvil/vless/main/vless.txt",                                 # 40
    "https://raw.githubusercontent.com/NiREvil/vless/main/vmess.txt",                                 # 41
    "https://raw.githubusercontent.com/NiREvil/vless/main/trojan.txt",                                # 42
    "https://raw.githubusercontent.com/amini8k/Free-Configs/main/vless.txt",                          # 43
    "https://raw.githubusercontent.com/amini8k/Free-Configs/main/vmess.txt",                          # 44
    "https://raw.githubusercontent.com/amini8k/Free-Configs/main/trojan.txt",                         # 45
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/vless.txt",                      # 46
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/vmess.txt",                      # 47
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/trojan.txt",                     # 48
]

XHTTP_REALITY_SOURCES: list[str] = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/XHTTP_Reality.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/xhttp_reality.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/xhttp.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/xhttp",
    "https://raw.githubusercontent.com/NiREvil/vless/main/xhttp.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/xhttp.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/xhttp.txt",
    "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/xhttp",
    "https://raw.githubusercontent.com/sashalsk/V2Ray/main/XHTTP.txt",
]

EXTRA_URLS_FOR_BYPASS: list[str] = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/2",
    "https://raw.githubusercontent.com/gbwltg/gbwl/refs/heads/main/m3EsPqwmlc",
    "https://whiteprime.github.io/xraycheck/configs/white-list_available",
    "https://wlrus.lol/confs/selected.txt",
]

# Добавляем XHTTP источники в общий список
URLS.extend(XHTTP_REALITY_SOURCES)

# Пути к файлам
_MIRROR_COUNT = len(URLS)
REMOTE_PATHS: list[str] = [f"githubmirror/{i+1}.txt" for i in range(_MIRROR_COUNT)]
LOCAL_PATHS:  list[str] = [f"githubmirror/{i+1}.txt" for i in range(_MIRROR_COUNT)]

# Специальные файлы
_SPECIAL_FILES: list[tuple[str, str]] = [
    ("ByPassVpnLera.txt",   "Обход SNI/CIDR"),
    ("XHTTP_Reality.txt",   "XHTTP+Reality (отобранные)"),
    ("REALITY_WORKING.txt", "Reality (рабочие, резерв)"),
    ("TOP_FASTEST_10.txt",  "ТОП-10 самых быстрых"),
    ("TOP_FASTEST_50.txt",  "ТОП-50 самых быстрых"),
    ("TOP_FASTEST_100.txt", "ТОП-100 самых быстрых"),
    ("VIDEO_OPTIMIZED.txt", "Для видео"),
    ("LOW_PING.txt",        "Низкий пинг"),
]

for fname, _ in _SPECIAL_FILES:
    REMOTE_PATHS.append(fname)
    LOCAL_PATHS.append(fname)

def _remote_path_to_label(remote_path: str) -> Optional[str]:
    """Возвращает метку специального файла или None для зеркальных файлов."""
    for fname, label in _SPECIAL_FILES:
        if fname in remote_path:
            return label
    return None

# ─────────────────────────── ЛОГИРОВАНИЕ ─────────────────────────

LOGS_BY_FILE: dict[int, list[str]] = defaultdict(list)
_LOG_LOCK = threading.Lock()
_UPDATED_FILES_LOCK = threading.Lock()
_GITHUBMIRROR_INDEX_RE = re.compile(r"githubmirror/(\d+)\.txt")

updated_files: set[int] = set()


def _extract_index(msg: str) -> int:
    m = _GITHUBMIRROR_INDEX_RE.search(msg)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            pass
    return 0


def log(message: str) -> None:
    idx = _extract_index(message)
    with _LOG_LOCK:
        LOGS_BY_FILE[idx].append(message)


# ─────────────────────────── ВРЕМЯ И GITHUB ──────────────────────

def _make_offset() -> str:
    zone = zoneinfo.ZoneInfo("Europe/Moscow")
    return datetime.now(zone).strftime("%H:%M | %d.%m.%Y")


def _init_github() -> tuple[Github, object]:
    """Инициализирует соединение с GitHub. Выполняется в main()."""
    token = os.environ.get("MY_TOKEN")
    g = Github(auth=Auth.Token(token)) if token else Github()
    repo = g.get_repo(REPO_NAME)
    try:
        remaining, limit = g.rate_limiting
        if remaining < 100:
            log(f"⚠️ Внимание: осталось {remaining}/{limit} запросов к GitHub API")
        else:
            log(f"ℹ️ Доступно запросов к GitHub API: {remaining}/{limit}")
    except Exception as e:
        log(f"⚠️ Не удалось проверить лимиты GitHub API: {e}")
    return g, repo


# ─────────────────────────── HTTP-СЕССИЯ ─────────────────────────

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _build_session(max_pool_size: int) -> requests.Session:
    session = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=max_pool_size,
        pool_maxsize=max_pool_size,
        max_retries=Retry(
            total=1,
            backoff_factor=0.2,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("HEAD", "GET", "OPTIONS"),
        ),
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": CHROME_UA})
    return session


REQUESTS_SESSION: requests.Session = _build_session(max(DEFAULT_MAX_WORKERS, len(URLS)))


def fetch_data(
    url: str,
    timeout: int = 10,
    max_attempts: int = 3,
    session: Optional[requests.Session] = None,
    allow_http_downgrade: bool = True,
) -> str:
    sess = session or REQUESTS_SESSION
    last_exc: Exception = RuntimeError("No attempts made")
    for attempt in range(1, max_attempts + 1):
        modified_url = url
        verify = True
        if attempt == 2:
            verify = False
        elif attempt == 3:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme == "https" and allow_http_downgrade:
                modified_url = parsed._replace(scheme="http").geturl()
                log(f"⚠️ HTTP downgrade для {url}")
            verify = False
        try:
            response = sess.get(modified_url, timeout=timeout, verify=verify)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as exc:
            last_exc = exc
    raise last_exc


def _format_fetch_error(exc: Exception) -> str:
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return "Connect timeout"
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return "Read timeout"
    if isinstance(exc, requests.exceptions.Timeout):
        return "Timeout"
    if isinstance(exc, requests.exceptions.SSLError):
        return "TLS error"
    if isinstance(exc, requests.exceptions.HTTPError):
        try:
            return f"HTTP {exc.response.status_code}"
        except Exception:
            return "HTTP error"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "Connection error"
    msg = str(exc)
    return msg[:160] + "…" if len(msg) > 160 else msg


# ─────────────────────────── ВСПОМОГАТЕЛЬНЫЕ ─────────────────────

def save_to_local_file(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    log(f"📁 Данные сохранены локально в {path}")


def extract_source_name(url: str) -> str:
    try:
        parts = urllib.parse.urlparse(url).path.split("/")
        if len(parts) > 2:
            return f"{parts[1]}/{parts[2]}"
        return urllib.parse.urlparse(url).netloc
    except Exception:
        return "Источник"


def _b64_title(title: str) -> str:
    return base64.b64encode(title.encode("utf-8")).decode("utf-8")


def _happ_header(title: str, interval: int, extra_lines: list[str] | None = None) -> str:
    """
    Генерирует заголовок, совместимый с приложениями happ/v2rayNG/Hiddify.
    """
    lines = [
        f"#profile-title: base64:{_b64_title(title)}",
        f"#profile-update-interval: {interval}",
        f"#subscription-userinfo: upload=0; download=0; total=0; expire=0",
        f"# {title}",
    ]
    if extra_lines:
        lines.extend(extra_lines)
    return "\n".join(lines) + "\n\n"


# ─────────────────────────── ФИЛЬТРАЦИЯ ──────────────────────────

INSECURE_PATTERN = re.compile(
    r'(?:[?&;]|%3[Bb])'
    r'(allowinsecure|allow_insecure|insecure)'
    r'=(?:1|true|yes)'
    r'(?:[&;#]|$|(?=\s|$))',
    re.IGNORECASE,
)

PROTO_SPLIT_RE = re.compile(
    r'(?=(?:vmess|vless|trojan|ss|ssr|tuic|hysteria2?)://)',
    re.IGNORECASE,
)


def filter_insecure_configs(
    local_path: str, data: str, log_enabled: bool = True
) -> tuple[str, int]:
    result = []
    for line in data.splitlines():
        processed = urllib.parse.unquote(html.unescape(line.strip()))
        if INSECURE_PATTERN.search(processed):
            continue
        result.append(line)
    filtered_count = data.count("\n") + 1 - len(result)
    if filtered_count > 0 and log_enabled:
        log(f"ℹ️ Отфильтровано {filtered_count} небезопасных конфигов для {local_path}")
    return "\n".join(result), max(0, filtered_count)


def _split_configs(text: str) -> list[str]:
    """Разбивает текст на отдельные конфиги."""
    lines = PROTO_SPLIT_RE.sub("\n", text).splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]


# ─────────────────────────── ПАРСИНГ HOST:PORT ───────────────────

def _extract_host_port(line: str) -> Optional[tuple[str, str]]:
    if not line:
        return None
    if line.startswith("vmess://"):
        try:
            payload = line[8:]
            payload += "=" * (-len(payload) % 4)
            decoded = base64.b64decode(payload).decode("utf-8", errors="ignore")
            if decoded.startswith("{"):
                j = json.loads(decoded)
                host = j.get("add") or j.get("host") or j.get("ip")
                port = j.get("port")
                if host and port:
                    return str(host), str(port)
        except Exception:
            pass
    m = re.search(r"@([\w.\-\[\]:]+):(\d{1,5})", line)
    if m:
        return m.group(1), m.group(2)
    m = re.search(r"(?:@|//)([\w.\-]+):(\d{1,5})", line)
    if m:
        return m.group(1), m.group(2)
    return None


# ─────────────────────────── ТЕСТИРОВАНИЕ КОНФИГОВ ───────────────

@dataclass
class ConfigResult:
    config: str
    working: bool = False
    ping_ms: Optional[int] = None
    speed_kbps: float = 0.0
    score: float = 0.0

    def compute_score(self) -> None:
        ping_score = max(0.0, 100.0 - (self.ping_ms / 3.0)) if self.ping_ms else 0.0
        speed_score = min(100.0, self.speed_kbps / 10.0)
        self.score = ping_score * 0.6 + speed_score * 0.4


def test_config_ping(config_str: str, timeout: int = 3) -> tuple[bool, Optional[int]]:
    """TCP-проверка доступности конфига и измерение задержки."""
    hostport = _extract_host_port(config_str)
    if not hostport:
        return False, None
    host, port = hostport
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            start = time.monotonic()
            if sock.connect_ex((host, int(port))) == 0:
                return True, int((time.monotonic() - start) * 1000)
    except Exception:
        pass
    return False, None


def test_config_speed(config_str: str, timeout: int = 4) -> float:
    """
    Оценка пропускной способности через TCP.
    Для VPN-протоколов возвращает реальные данные о буфере,
    а не скорость туннеля — используется как вспомогательная метрика.
    """
    hostport = _extract_host_port(config_str)
    if not hostport:
        return 0.0
    host, port = hostport
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, int(port)))
            sock.send(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n")
            total = 0
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                try:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    total += len(chunk)
                except socket.timeout:
                    break
            elapsed = 2.0 - max(0.0, deadline - time.monotonic())
            if elapsed > 0 and total > 0:
                return round((total / 1024) / elapsed, 2)
    except Exception:
        pass
    return 0.0


def _test_one_config(cfg: str) -> ConfigResult:
    r = ConfigResult(config=cfg)
    working, ping = test_config_ping(cfg, timeout=2)
    if not working:
        return r
    r.working = True
    r.ping_ms = ping
    r.speed_kbps = test_config_speed(cfg)
    r.compute_score()
    return r


def find_fastest_configs(
    configs_list: list[str], max_to_test: int = 800, top_n: int = 100
) -> list[ConfigResult]:
    """Параллельное тестирование и ранжирование конфигов по пингу + скорости."""
    to_test = configs_list[:max_to_test]
    log(f"🚀 Тестирование {len(to_test)} конфигов (параллельно)...")

    results: list[ConfigResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as ex:
        futures = {ex.submit(_test_one_config, cfg): cfg for cfg in to_test}
        done = 0
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            try:
                r = fut.result(timeout=10)
                if r.working:
                    results.append(r)
            except Exception:
                pass
            if done % 100 == 0:
                log(f"📊 Протестировано: {done}/{len(to_test)}, рабочих: {len(results)}")

    results.sort(key=lambda r: r.score, reverse=True)
    top = results[:top_n]
    if top:
        log(f"🏆 Топ-{len(top)} конфигов. Лучший балл: {top[0].score:.1f}, пинг: {top[0].ping_ms}ms")
    else:
        log("⚠️ Нет рабочих конфигов после тестирования")
    return top


# ─────────────────────────── XHTTP + REALITY ─────────────────────

_XHTTP_RE = re.compile(
    r"type=xhttp|type%3Dxhttp|xhttpMode=|network=xhttp|network%3Dxhttp",
    re.IGNORECASE,
)


def _is_xhttp_reality(cfg: str) -> bool:
    return bool(_XHTTP_RE.search(cfg)) and (
        "security=reality" in cfg or "security%3Dreality" in cfg
    )


def _is_reality_tcp(cfg: str) -> bool:
    return ("security=reality" in cfg or "security%3Dreality" in cfg) and (
        "type=tcp" in cfg or "type%3Dtcp" in cfg
    )


def test_xhttp_config(config_str: str, timeout: int = 5) -> bool:
    hostport = _extract_host_port(config_str)
    if not hostport:
        return False
    host, port = hostport
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((host, int(port))) != 0:
                return False
        # Дополнительная проверка через HTTP
        try:
            conn = http.client.HTTPConnection(host, int(port), timeout=3)
            conn.request("HEAD", "/")
            conn.getresponse()
            conn.close()
        except Exception:
            pass
        return True
    except Exception:
        return False


def find_xhttp_reality_configs(all_configs: list[str]) -> list[str]:
    log("🔍 Поиск XHTTP+Reality конфигов...")
    found = [c for c in all_configs if isinstance(c, str) and _is_xhttp_reality(c)]
    log(f"📊 Найдено {len(found)} XHTTP+Reality конфигов")
    return found


def test_and_filter_xhttp_configs(xhttp_configs: list[str]) -> list[str]:
    if not xhttp_configs:
        log("⚠️ Нет XHTTP конфигов для тестирования")
        return []
    log(f"🔄 Тестирование {len(xhttp_configs)} XHTTP+Reality конфигов...")
    working: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(test_xhttp_config, cfg): cfg for cfg in xhttp_configs[:200]}
        for fut in concurrent.futures.as_completed(futures):
            cfg = futures[fut]
            try:
                if fut.result(timeout=8):
                    working.append(cfg)
                    if len(working) % 10 == 0:
                        log(f"✅ XHTTP рабочих: {len(working)}")
            except Exception:
                pass
    unique = list(dict.fromkeys(working))
    log(f"📊 Рабочих XHTTP+Reality: {len(unique)}")
    return unique


def find_and_test_reality_configs(all_configs: list[str]) -> list[str]:
    log("🔍 Поиск Reality-TCP конфигов...")
    candidates = [c for c in all_configs if isinstance(c, str) and _is_reality_tcp(c)]
    log(f"📊 Кандидатов Reality-TCP: {len(candidates)}")
    if not candidates:
        return []
    working: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(test_config_ping, cfg, 3): cfg for cfg in candidates[:300]}
        for fut in concurrent.futures.as_completed(futures):
            cfg = futures[fut]
            try:
                ok, _ = fut.result(timeout=5)
                if ok:
                    working.append(cfg)
            except Exception:
                pass
    unique = list(dict.fromkeys(working))
    log(f"📊 Рабочих Reality-TCP: {len(unique)}")
    return unique


# ─────────────────────────── СОЗДАНИЕ ФАЙЛОВ ─────────────────────

def _write_config_file(
    file_path: str,
    title: str,
    interval: int,
    configs: list[str],
    extra_comment_lines: list[str] | None = None,
) -> str:
    header = _happ_header(title, interval, extra_comment_lines)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(header + "\n".join(configs))
    log(f"📁 Создан файл {file_path} ({len(configs)} конфигов)")
    return file_path


def create_fastest_configs_files(
    results: list[ConfigResult], base_configs: list[str]
) -> list[str]:
    if not results:
        log("⚠️ Нет результатов для создания файлов быстрых конфигов")
        return []

    top_cfgs = [r.config for r in results]
    # Дополняем до 100 из базового списка, если нужно
    if len(top_cfgs) < 100:
        existing = set(top_cfgs)
        for c in base_configs:
            if c not in existing:
                top_cfgs.append(c)
                existing.add(c)
            if len(top_cfgs) >= 100:
                break

    created: list[str] = []
    specs = [
        ("TOP_FASTEST_10.txt",  "MaxTre - ТОП-10 быстрых конфигов",  3, 10),
        ("TOP_FASTEST_50.txt",  "MaxTre - ТОП-50 быстрых конфигов",  4, 50),
        ("TOP_FASTEST_100.txt", "MaxTre - ТОП-100 быстрых конфигов", 5, 100),
    ]
    for path, title, interval, n in specs:
        if len(top_cfgs) >= n:
            _write_config_file(path, title, interval, top_cfgs[:n])
            created.append(path)
    return created


def create_video_optimized_configs(
    results: list[ConfigResult], base_configs: list[str]
) -> Optional[str]:
    if not results:
        return None
    video = [r.config for r in sorted(results, key=lambda r: r.speed_kbps, reverse=True)
             if r.speed_kbps > 50][:30]
    if len(video) < 20:
        existing = set(video)
        for c in base_configs:
            if c not in existing:
                video.append(c)
                existing.add(c)
            if len(video) >= 30:
                break
    if not video:
        return None
    return _write_config_file(
        "VIDEO_OPTIMIZED.txt",
        "MaxTre - Для видео (YouTube, стриминг)",
        4, video,
        ["# Высокая скорость, оптимизировано для видео"],
    )


def create_low_ping_configs(results: list[ConfigResult]) -> Optional[str]:
    if not results:
        return None
    low = sorted(results, key=lambda r: (r.ping_ms or 9999))[:20]
    cfgs = [r.config for r in low]
    avg = sum(r.ping_ms for r in low if r.ping_ms) / max(1, len([r for r in low if r.ping_ms]))
    return _write_config_file(
        "LOW_PING.txt",
        "MaxTre - Низкий пинг (игры, звонки)",
        3, cfgs,
        [f"# Средний пинг: {avg:.0f}ms", "# Идеально для игр и видеозвонков"],
    )


def create_xhttp_configs_file(xhttp_configs: list[str]) -> Optional[str]:
    if not xhttp_configs:
        return None
    return _write_config_file(
        "XHTTP_Reality.txt",
        "MaxTre - XHTTP+Reality (рабочие)",
        5, xhttp_configs,
        [f"# Всего: {len(xhttp_configs)}"],
    )


def create_reality_configs_file(reality_configs: list[str]) -> Optional[str]:
    if not reality_configs:
        return None
    return _write_config_file(
        "REALITY_WORKING.txt",
        "MaxTre - Reality (рабочие, резерв)",
        5, reality_configs[:100],
        [f"# Резерв, если XHTTP недоступен", f"# Всего: {min(100, len(reality_configs))}"],
    )


# ─────────────────────────── SNI-ФИЛЬТР ──────────────────────────

_SNI_DOMAINS: list[str] = [
    "00.img.avito.st", "01.img.avito.st", "02.img.avito.st", "03.img.avito.st",
    "04.img.avito.st", "05.img.avito.st", "06.img.avito.st", "07.img.avito.st",
    "08.img.avito.st", "09.img.avito.st", "10.img.avito.st", "11.img.avito.st",
    "12.img.avito.st", "13.img.avito.st", "14.img.avito.st", "15.img.avito.st",
    "16.img.avito.st", "17.img.avito.st", "18.img.avito.st", "19.img.avito.st",
    "20.img.avito.st", "21.img.avito.st", "22.img.avito.st", "23.img.avito.st",
    "24.img.avito.st", "25.img.avito.st", "26.img.avito.st", "27.img.avito.st",
    "28.img.avito.st", "29.img.avito.st", "30.img.avito.st", "31.img.avito.st",
    "32.img.avito.st", "33.img.avito.st", "34.img.avito.st", "35.img.avito.st",
    "36.img.avito.st", "37.img.avito.st", "38.img.avito.st", "39.img.avito.st",
    "40.img.avito.st", "41.img.avito.st", "42.img.avito.st", "43.img.avito.st",
    "44.img.avito.st", "45.img.avito.st", "46.img.avito.st", "47.img.avito.st",
    "48.img.avito.st", "49.img.avito.st", "50.img.avito.st", "51.img.avito.st",
    "52.img.avito.st", "53.img.avito.st", "54.img.avito.st", "55.img.avito.st",
    "56.img.avito.st", "57.img.avito.st", "58.img.avito.st", "59.img.avito.st",
    "60.img.avito.st", "61.img.avito.st", "62.img.avito.st", "63.img.avito.st",
    "64.img.avito.st", "65.img.avito.st", "66.img.avito.st", "67.img.avito.st",
    "68.img.avito.st", "69.img.avito.st", "70.img.avito.st", "71.img.avito.st",
    "72.img.avito.st", "73.img.avito.st", "74.img.avito.st", "742231.ms.ok.ru",
    "75.img.avito.st", "76.img.avito.st", "77.img.avito.st", "78.img.avito.st",
    "79.img.avito.st", "80.img.avito.st", "81.img.avito.st", "82.img.avito.st",
    "83.img.avito.st", "84.img.avito.st", "85.img.avito.st", "86.img.avito.st",
    "87.img.avito.st", "88.img.avito.st", "89.img.avito.st", "8mar.mail.ru",
    "90.img.avito.st", "91.img.avito.st", "92.img.avito.st", "93.img.avito.st",
    "94.img.avito.st", "95.img.avito.st", "96.img.avito.st", "97.img.avito.st",
    "98.img.avito.st", "99.img.avito.st", "9may.mail.ru", "a.auth-nsdi.ru",
    "a.res-nsdi.ru", "a.wb.ru", "aa.mail.ru", "ad.adriver.ru", "ad.mail.ru",
    "adm.digital.gov.ru", "adm.mp.rzd.ru", "admin.cs7777.vk.ru", "admin.tau.vk.ru",
    "ads.vk.ru", "adv.ozon.ru", "afisha.mail.ru", "agent.mail.ru",
    "akashi.vk-portal.net", "alfabank.ru", "alfabank.servicecdn.ru", "alfabank.st",
    "alpha3.minigames.mail.ru", "alpha4.minigames.mail.ru", "amigo.mail.ru",
    "ams2-cdn.2gis.com", "an.yandex.ru", "analytics.predict.mail.ru",
    "analytics.vk.ru", "answer.mail.ru", "answers.mail.ru", "api-maps.yandex.ru",
    "api.2gis.ru", "api.a.mts.ru", "api.apteka.ru", "api.avito.ru",
    "api.browser.yandex.com", "api.browser.yandex.ru", "api.cs7777.vk.ru",
    "api.events.plus.yandex.net", "api.expf.ru", "api.max.ru", "api.mindbox.ru",
    "api.ok.ru", "api.photo.2gis.com", "api.plus.kinopoisk.ru",
    "api.predict.mail.ru", "api.reviews.2gis.com", "api.s3.yandex.net",
    "api.tau.vk.ru", "api.uxfeedback.yandex.net", "api.vk.ru", "api2.ivi.ru",
    "apps.research.mail.ru", "authdl.mail.ru", "auto.mail.ru", "auto.ru",
    "av.mail.ru", "avatars.mds.yandex.com", "avatars.mds.yandex.net",
    "avito.ru", "avito.st", "aw.mail.ru", "away.cs7777.vk.ru", "away.tau.vk.ru",
    "bank.ozon.ru", "banners-website.wildberries.ru", "bb.mail.ru", "bd.mail.ru",
    "beeline.api.flocktory.com", "beko.dom.mail.ru", "bender.mail.ru",
    "beta.mail.ru", "bfds.sberbank.ru", "bitva.mail.ru", "biz.mail.ru",
    "blackfriday.mail.ru", "blog.mail.ru", "bot.gosuslugi.ru", "botapi.max.ru",
    "browser.mail.ru", "browser.yandex.com", "browser.yandex.ru",
    "business.vk.ru", "c.dns-shop.ru", "calendar.mail.ru", "capsula.mail.ru",
    "cargo.rzd.ru", "cars.mail.ru", "catalog.api.2gis.com", "cdn.connect.mail.ru",
    "cdn.gpb.ru", "cdn.lemanapro.ru", "cdn.newyear.mail.ru", "cdn.rosbank.ru",
    "cdn.s3.yandex.net", "cdn.tbank.ru", "cdn.uxfeedback.ru", "cdn.yandex.ru",
    "cdn1.tu-tu.ru", "cdnn21.img.ria.ru", "cf.mail.ru", "chat-ct.pochta.ru",
    "chat-prod.wildberries.ru", "chat3.vtb.ru", "cloud.cdn.yandex.com",
    "cloud.cdn.yandex.net", "cloud.cdn.yandex.ru", "cloud.mail.ru",
    "cloud.vk.com", "cloud.vk.ru", "code.mail.ru", "codefest.mail.ru",
    "cog.mail.ru", "collections.yandex.com", "collections.yandex.ru",
    "comba.mail.ru", "combu.mail.ru", "commba.mail.ru", "company.rzd.ru",
    "compute.mail.ru", "connect.cs7777.vk.ru", "contacts.rzd.ru",
    "contract.gosuslugi.ru", "corp.mail.ru", "counter.yadro.ru", "cpa.hh.ru",
    "cpg.money.mail.ru", "crazypanda.mail.ru", "cs.avito.ru", "cs7777.vk.ru",
    "csp.yandex.net", "ctlog.mail.ru", "ctlog2023.mail.ru", "ctlog2024.mail.ru",
    "d-assets.2gis.ru", "da.biz.mail.ru", "data.amigo.mail.ru", "dating.ok.ru",
    "deti.mail.ru", "dev.cs7777.vk.ru", "dev.max.ru", "dev.tau.vk.ru",
    "dev1.mail.ru", "dev2.mail.ru", "dev3.mail.ru", "digital.gov.ru",
    "disk.2gis.com", "disk.rzd.ru", "dk.mail.ru", "dl.mail.ru",
    "dl.marusia.mail.ru", "dn.mail.ru", "dnd.wb.ru", "dobro.mail.ru",
    "doc.mail.ru", "dom.mail.ru", "download.max.ru", "dr.yandex.net",
    "dr2.yandex.net", "dragonpals.mail.ru", "ds.mail.ru", "duck.mail.ru",
    "duma.gov.ru", "dzen.ru", "e.mail.ru", "education.mail.ru",
    "egress.yandex.net", "eh.vk.com", "enterprise.api-maps.yandex.ru",
    "et.mail.ru", "expert.vk.ru", "eye.targetads.io", "favicon.yandex.com",
    "favicon.yandex.net", "favicon.yandex.ru", "favorites.api.2gis.com",
    "fe.mail.ru", "finance.mail.ru", "finance.wb.ru", "foto.mail.ru",
    "frontend.vh.yandex.ru", "fw.wb.ru", "games-bamboo.mail.ru",
    "games-fisheye.mail.ru", "games.mail.ru", "gazeta.ru", "genesis.mail.ru",
    "get4click.ru", "go.mail.ru", "golos.mail.ru", "gosuslugi.ru",
    "gosweb.gosuslugi.ru", "government.ru", "goya.rutube.ru",
    "graphql-web.kinopoisk.ru", "graphql.kinopoisk.ru", "guns.mail.ru",
    "hb-bidder.skcrtxr.com", "hd.kinopoisk.ru", "health.mail.ru", "help.max.ru",
    "help.mcs.mail.ru", "hh.ru", "hhcdn.ru", "hi-tech.mail.ru", "horo.mail.ru",
    "hrc.tbank.ru", "hs.mail.ru", "i.hh.ru", "i.max.ru", "i.rdrom.ru",
    "i0.photo.2gis.com", "i1.photo.2gis.com", "i2.photo.2gis.com",
    "i3.photo.2gis.com", "i4.photo.2gis.com", "i5.photo.2gis.com",
    "i6.photo.2gis.com", "i7.photo.2gis.com", "i8.photo.2gis.com",
    "i9.photo.2gis.com", "id.cs7777.vk.ru", "id.sber.ru", "id.tau.vk.ru",
    "id.tbank.ru", "id.vk.ru", "identitystatic.mts.ru", "images.apteka.ru",
    "imgproxy.cdn-tinkoff.ru", "imperia.mail.ru", "informer.yandex.ru",
    "infra.mail.ru", "internet.mail.ru", "invest.ozon.ru", "io.ozone.ru",
    "ir.ozone.ru", "it.mail.ru", "izbirkom.ru", "jam.api.2gis.com",
    "jd.mail.ru", "jitsi.wb.ru", "journey.mail.ru",
    "jsons.injector.3ebra.net", "juggermobile.mail.ru", "junior.mail.ru",
    "keys.api.2gis.com", "kicker.mail.ru", "kiks.yandex.com", "kiks.yandex.ru",
    "kino.mail.ru", "kp.ru", "kremlin.ru", "kz.mcs.mail.ru", "la.mail.ru",
    "lady.mail.ru", "landing.mail.ru", "le.tbank.ru", "learning.ozon.ru",
    "legal.max.ru", "lemanapro.ru", "lenta.ru", "link.max.ru", "link.mp.rzd.ru",
    "live.ok.ru", "lk.gosuslugi.ru", "loa.mail.ru", "log.strm.yandex.ru",
    "login.cs7777.vk.ru", "login.mts.ru", "login.tau.vk.ru", "login.vk.com",
    "login.vk.ru", "love.mail.ru", "m.47news.ru", "m.avito.ru",
    "m.cs7777.vk.ru", "m.ok.ru", "m.tau.vk.ru", "m.vk.ru",
    "ma.kinopoisk.ru", "mail.yandex.com", "mail.yandex.ru", "mailer.mail.ru",
    "mailexpress.mail.ru", "man.mail.ru", "map.gosuslugi.ru", "mapgl.2gis.com",
    "maps.mail.ru", "market.rzd.ru", "marusia.mail.ru", "max.ru",
    "mc.yandex.com", "mc.yandex.ru", "mcs.mail.ru", "mddc.tinkoff.ru",
    "me.cs7777.vk.ru", "media.mail.ru", "mediafeeds.yandex.com",
    "mediafeeds.yandex.ru", "mediapro.mail.ru", "metrics.alfabank.ru",
    "microapps.kinopoisk.ru", "minigames.mail.ru", "mkb.ru", "mking.mail.ru",
    "mobfarm.mail.ru", "money.mail.ru", "moscow.megafon.ru", "moskva.beeline.ru",
    "moskva.taximaxim.ru", "mowar.mail.ru", "mp.rzd.ru", "ms.cs7777.vk.ru",
    "msk.t2.ru", "mtscdn.ru", "music.vk.ru", "my.mail.ru", "my.rzd.ru",
    "myteam.mail.ru", "nebogame.mail.ru", "net.mail.ru",
    "neuro.translate.yandex.ru", "new.mail.ru", "news.mail.ru",
    "notes.mail.ru", "novorossiya.gosuslugi.ru", "nspk.ru",
    "oauth.cs7777.vk.ru", "oauth.tau.vk.ru", "oauth2.cs7777.vk.ru",
    "ok.ru", "online.sberbank.ru", "operator.mail.ru", "ord.ozon.ru",
    "ord.vk.ru", "otvet.mail.ru", "otvety.mail.ru", "owa.ozon.ru",
    "ozon.ru", "ozone.ru", "park.mail.ru", "partners.gosuslugi.ru",
    "partners.lemanapro.ru", "passport.pochta.ru", "pay.mail.ru",
    "pay.ozon.ru", "payment-widget.kinopoisk.ru",
    "payment-widget.plus.kinopoisk.ru", "pets.mail.ru", "pic.rutubelist.ru",
    "pikabu.ru", "pms.mail.ru", "pochta.ru", "pochtabank.mail.ru",
    "pogoda.mail.ru", "polis.mail.ru", "pos.gosuslugi.ru", "pp.mail.ru",
    "predict.mail.ru", "preview.rutube.ru", "privacy-cs.mail.ru",
    "prodvizhenie.rzd.ru", "ptd.predict.mail.ru", "public-api.reviews.2gis.com",
    "pulse.mail.ru", "pulse.mp.rzd.ru", "push.vk.ru", "pw.mail.ru",
    "px.adhigh.net", "quantum.mail.ru", "queuev4.vk.com",
    "quiz.kinopoisk.ru", "r.vk.ru", "r0.mradx.net", "rambler.ru",
    "rap.skcrtxr.com", "rate.mail.ru", "rbc.ru", "rebus.calls.mail.ru",
    "rebus.octavius.mail.ru", "receive-sentry.lmru.tech", "restapi.dns-shop.ru",
    "rev.mail.ru", "rl.mail.ru", "rm.mail.ru", "rs.mail.ru",
    "rutube.ru", "rzd.ru", "s.rbk.ru", "s.vtb.ru", "s0.bss.2gis.com",
    "s1.bss.2gis.com", "s11.auto.drom.ru", "s3.babel.mail.ru",
    "s3.mail.ru", "s3.t2.ru", "s3.yandex.net", "sales.mail.ru",
    "sba.yandex.com", "sba.yandex.net", "sba.yandex.ru", "sberbank.ru",
    "scitylana.apteka.ru", "sdk.money.mail.ru", "secure-cloud.rzd.ru",
    "secure.rzd.ru", "securepay.ozon.ru", "security.mail.ru",
    "seller.ozon.ru", "sentry.hh.ru", "service.amigo.mail.ru",
    "servicepipe.ru", "serving.a.mts.ru", "sfd.gosuslugi.ru",
    "sntr.avito.ru", "socdwar.mail.ru", "sphere.mail.ru", "splitter.wb.ru",
    "sport.mail.ru", "sso-app4.vtb.ru", "sso-app5.vtb.ru", "sso.auto.ru",
    "sso.dzen.ru", "sso.kinopoisk.ru", "ssp.rutube.ru", "st-gismeteo.st",
    "st-im.kinopoisk.ru", "st-ok.cdn-vk.ru", "st.avito.ru",
    "st.gismeteo.st", "st.kinopoisk.ru", "st.max.ru", "st.okcdn.ru",
    "st.ozone.ru", "startrek.mail.ru", "stat-api.gismeteo.net", "statad.ru",
    "static-mon.yandex.net", "static.apteka.ru", "static.beeline.ru",
    "static.dl.mail.ru", "static.lemanapro.ru", "static.operator.mail.ru",
    "static.rutube.ru", "stats.avito.ru", "stats.vk-portal.net",
    "status.mcs.mail.ru", "storage.ape.yandex.net", "storage.yandexcloud.net",
    "stream.mail.ru", "strm.yandex.net", "strm.yandex.ru",
    "styles.api.2gis.com", "suggest.dzen.ru", "suggest.sso.dzen.ru",
    "sync.browser.yandex.net", "sync.rambler.ru", "tag.a.mts.ru",
    "tamtam.ok.ru", "target.smi2.net", "target.vk.ru", "team.mail.ru",
    "team.rzd.ru", "tech.mail.ru", "tech.vk.ru", "tera.mail.ru",
    "ticket.rzd.ru", "tickets.widget.kinopoisk.ru",
    "tile0.maps.2gis.com", "tile1.maps.2gis.com", "tile2.maps.2gis.com",
    "tile3.maps.2gis.com", "tile4.maps.2gis.com", "tiles.maps.mail.ru",
    "tmsg.tbank.ru", "tns-counter.ru", "todo.mail.ru", "top-fwz1.mail.ru",
    "touch.kinopoisk.ru", "travel.rzd.ru", "travel.yandex.ru",
    "travel.yastatic.net", "trk.mail.ru", "tutu.ru", "tv.mail.ru",
    "typewriter.mail.ru", "u.corp.mail.ru", "ufo.mail.ru",
    "ui.cs7777.vk.ru", "ui.tau.vk.ru", "user-geo-data.wildberries.ru",
    "uslugi.yandex.ru", "uxfeedback.yandex.ru", "vk-portal.net", "vk.com",
    "vk.mail.ru", "vkdoc.mail.ru", "vkvideo.cs7777.vk.ru", "voina.mail.ru",
    "voter.gosuslugi.ru", "vt-1.ozone.ru", "wap.yandex.com", "wap.yandex.ru",
    "wb.ru", "wcm.weborama-tech.ru", "web-static.mindbox.ru", "web.max.ru",
    "webagent.mail.ru", "weblink.predict.mail.ru", "webstore.mail.ru",
    "welcome.mail.ru", "welcome.rzd.ru", "wf.mail.ru", "whatsnew.mail.ru",
    "widgets.cbonds.ru", "widgets.kinopoisk.ru", "wok.mail.ru", "wos.mail.ru",
    "ws.seller.ozon.ru", "www.avito.ru", "www.avito.st", "www.biz.mail.ru",
    "www.cikrf.ru", "www.drive2.ru", "www.drom.ru", "www.farpost.ru",
    "www.gazprombank.ru", "www.gosuslugi.ru", "www.ivi.ru",
    "www.kinopoisk.ru", "www.kp.ru", "www.magnit.com", "www.mail.ru",
    "www.mcs.mail.ru", "www.open.ru", "www.ozon.ru", "www.pochta.ru",
    "www.psbank.ru", "www.raiffeisen.ru", "www.rbc.ru", "www.rzd.ru",
    "www.sberbank.ru", "www.t2.ru", "www.tbank.ru", "www.tutu.ru",
    "www.unicreditbank.ru", "www.vtb.ru", "www.wildberries.ru",
    "www.x5.ru", "xapi.ozon.ru", "ya.ru", "yabs.yandex.ru",
    "yandex.com", "yandex.net", "yandex.ru", "yastatic.net",
    "zen.yandex.com", "zen.yandex.net", "zen.yandex.ru", "честныйзнак.рф",
]


def _build_sni_regex() -> Optional[re.Pattern]:
    """Строит оптимизированный regex из SNI-доменов (удаляет поддомены)."""
    sorted_d = sorted(_SNI_DOMAINS, key=len)
    optimized: list[str] = []
    for d in sorted_d:
        if not any(existing in d for existing in optimized):
            optimized.append(d)
    try:
        return re.compile(
            r"(?:" + "|".join(re.escape(d) for d in optimized) + r")",
            re.IGNORECASE,
        )
    except Exception as e:
        log(f"❌ Ошибка компиляции SNI regex: {e}")
        return None


def create_filtered_configs(offset: str) -> tuple[str, list[ConfigResult], list[str], list[str]]:
    """Создаёт ByPassVpnLera.txt с конфигами под SNI/CIDR белые списки."""
    sni_regex = _build_sni_regex()
    if sni_regex is None:
        return "ByPassVpnLera.txt", [], [], []

    def _collect_from_mirror(file_idx: int) -> list[str]:
        path = f"githubmirror/{file_idx}.txt"
        if not os.path.exists(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            return [ln for ln in _split_configs(content) if sni_regex.search(ln)]
        except Exception:
            return []

    all_configs: list[str] = []
    for i in range(1, len(URLS) + 1):
        all_configs.extend(_collect_from_mirror(i))

    # Загрузка дополнительных bypass-конфигов
    def _load_extra(url: str) -> tuple[list[str], int]:
        try:
            data = fetch_data(url, timeout=EXTRA_URL_TIMEOUT,
                              max_attempts=EXTRA_URL_MAX_ATTEMPTS, allow_http_downgrade=False)
            data, cnt = filter_insecure_configs("ByPassVpnLera.txt", data, log_enabled=False)
            return _split_configs(data), cnt
        except Exception as e:
            log(f"⚠️ Ошибка при загрузке {url}: {_format_fetch_error(e)}")
            return [], 0

    extra: list[str] = []
    total_filtered = 0
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(4, len(EXTRA_URLS_FOR_BYPASS))
    ) as ex:
        for cfgs, cnt in ex.map(_load_extra, EXTRA_URLS_FOR_BYPASS):
            extra.extend(cfgs)
            total_filtered += cnt

    if total_filtered > 0:
        log(f"ℹ️ Отфильтровано {total_filtered} небезопасных конфигов для ByPassVpnLera.txt")
    all_configs.extend(extra)

    # Дедупликация
    seen_full: set[str] = set()
    seen_hostport: set[str] = set()
    unique: list[str] = []
    for c in all_configs:
        if not c or c in seen_full:
            continue
        seen_full.add(c)
        hp = _extract_host_port(c)
        if hp:
            key = f"{hp[0].lower()}:{hp[1]}"
            if key in seen_hostport:
                continue
            seen_hostport.add(key)
        unique.append(c)

    log(f"📊 После дедупликации: {len(unique)} уникальных конфигов")

    # Тестирование
    all_results = find_fastest_configs(unique, max_to_test=800, top_n=100)
    working_configs = [r.config for r in all_results] if all_results else unique[:100]
    if not all_results:
        log("⚠️ Тестирование не дало результатов, используем первые 100")

    bypass_path = "ByPassVpnLera.txt"
    _write_config_file(
        bypass_path,
        "MaxTre - VPN",
        9,
        working_configs,
        [f"# Всего конфигов: {len(working_configs)}"],
    )
    return bypass_path, all_results, working_configs, unique


# ─────────────────────────── GITHUB ──────────────────────────────

def _get_repo_stats(repo) -> Optional[dict]:
    stats: dict = {}
    try:
        views = repo.get_views_traffic()
        if hasattr(views, "count"):
            stats["views_count"] = views.count
            stats["views_uniques"] = views.uniques
        elif isinstance(views, dict):
            stats["views_count"] = views.get("count", 0)
            stats["views_uniques"] = views.get("uniques", 0)
        else:
            stats["views_count"] = stats["views_uniques"] = 0
    except Exception as e:
        log(f"⚠️ Не удалось получить просмотры: {e}")
        return None

    try:
        clones = repo.get_clones_traffic()
        if hasattr(clones, "count"):
            stats["clones_count"] = clones.count
            stats["clones_uniques"] = clones.uniques
        elif isinstance(clones, dict):
            stats["clones_count"] = clones.get("count", 0)
            stats["clones_uniques"] = clones.get("uniques", 0)
        else:
            stats["clones_count"] = stats["clones_uniques"] = 0
    except Exception as e:
        log(f"⚠️ Не удалось получить клоны: {e}")
        return None

    return stats


def _build_repo_stats_table(stats: dict) -> str:
    def _fmt(v):
        try:
            return f"{int(v):,}"
        except Exception:
            return str(v)
    rows = [
        f"| Просмотры (14Д) | {_fmt(stats['views_count'])} |",
        f"| Клоны (14Д) | {_fmt(stats['clones_count'])} |",
        f"| Уникальные клоны (14Д) | {_fmt(stats['clones_uniques'])} |",
        f"| Уникальные посетители (14Д) | {_fmt(stats['views_uniques'])} |",
    ]
    return "| Показатель | Значение |\n|--|--|\n" + "\n".join(rows)


def upload_to_github(local_path: str, remote_path: str, repo, offset: str) -> None:
    if not os.path.exists(local_path):
        log(f"❌ Файл {local_path} не найден.")
        return

    with open(local_path, "r", encoding="utf-8") as f:
        content = f.read()

    max_retries = 5
    basename = os.path.basename(remote_path)

    for attempt in range(1, max_retries + 1):
        try:
            # Попытка получить текущий файл
            try:
                file_in_repo = repo.get_contents(remote_path)
                current_sha = file_in_repo.sha
            except GithubException as e_get:
                if getattr(e_get, "status", None) == 404:
                    repo.create_file(
                        path=remote_path,
                        message=f"🆕 Первый коммит {basename} (МСК): {offset}",
                        content=content,
                    )
                    log(f"🆕 Файл {remote_path} создан.")
                    _mark_updated(remote_path)
                    return
                msg = e_get.data.get("message", str(e_get)) if hasattr(e_get, "data") else str(e_get)
                log(f"⚠️ Ошибка при получении {remote_path}: {msg}")
                return

            # Проверяем, изменился ли контент
            try:
                remote_content = file_in_repo.decoded_content.decode("utf-8", errors="replace")
                if remote_content == content:
                    log(f"🔄 Изменений для {remote_path} нет.")
                    return
            except Exception:
                pass

            repo.update_file(
                path=remote_path,
                message=f"🚀 Обновление {basename} (МСК): {offset}",
                content=content,
                sha=current_sha,
            )
            log(f"🚀 Файл {remote_path} обновлён.")
            _mark_updated(remote_path)
            return

        except GithubException as e_upd:
            if getattr(e_upd, "status", None) == 409 and attempt < max_retries:
                wait_time = 0.5 * (2 ** (attempt - 1))
                log(f"⚠️ SHA-конфликт для {remote_path}, попытка {attempt}/{max_retries}, ждём {wait_time:.1f}с")
                time.sleep(wait_time)
                continue
            msg = e_upd.data.get("message", str(e_upd)) if hasattr(e_upd, "data") else str(e_upd)
            log(f"⚠️ Ошибка загрузки {remote_path}: {msg}")
            return
        except Exception as e_general:
            short = str(e_general)[:200]
            log(f"⚠️ Непредвиденная ошибка {remote_path}: {short}")
            return

    log(f"❌ Не удалось обновить {remote_path} после {max_retries} попыток")


def _mark_updated(remote_path: str) -> None:
    """Помечает файл как обновлённый для обновления таблицы README."""
    idx: Optional[int] = None
    m = _GITHUBMIRROR_INDEX_RE.search(remote_path)
    if m:
        try:
            idx = int(m.group(1))
        except ValueError:
            pass
    else:
        for i, (fname, _) in enumerate(_SPECIAL_FILES, start=_MIRROR_COUNT + 1):
            if fname in remote_path:
                idx = i
                break
    if idx is not None:
        with _UPDATED_FILES_LOCK:
            updated_files.add(idx)


def update_readme_table(repo, offset: str) -> None:
    try:
        try:
            readme_file = repo.get_contents("README.md")
            old_content = readme_file.decoded_content.decode("utf-8")
        except GithubException as e:
            status = getattr(e, "status", None)
            log(f"{'❌ README.md не найден' if status == 404 else f'⚠️ Ошибка при получении README.md: {e}'}")
            return

        time_part, date_part = offset.split(" | ")
        table_header = "| № | Файл | Источник | Время | Дата |\n|--|--|--|--|--|"
        rows: list[str] = []

        for i, remote_path in enumerate(REMOTE_PATHS, 1):
            filename = os.path.basename(remote_path)
            raw_url = f"https://github.com/{REPO_NAME}/raw/refs/heads/main/{remote_path}"

            if i <= len(URLS):
                src_name = extract_source_name(URLS[i - 1])
                source_col = f"[{src_name}]({URLS[i - 1]})"
            else:
                label = _remote_path_to_label(remote_path) or "Источник"
                source_col = f"[{label}]({raw_url})"

            if i in updated_files:
                upd_time, upd_date = time_part, date_part
            else:
                pattern = rf"\|\s*{i}\s*\|\s*\[`{re.escape(filename)}`\].*?\|.*?\|\s*(.*?)\s*\|\s*(.*?)\s*\|"
                match = re.search(pattern, old_content)
                if match:
                    upd_time = match.group(1).strip() or "Никогда"
                    upd_date = match.group(2).strip() or "Никогда"
                else:
                    upd_time = upd_date = "Никогда"

            rows.append(f"| {i} | [`{filename}`]({raw_url}) | {source_col} | {upd_time} | {upd_date} |")

        new_table = table_header + "\n" + "\n".join(rows)
        table_pattern = r"\| № \| Файл \| Источник \| Время \| Дата \|[\s\S]*?\|--\|--\|--\|--\|--\|[\s\S]*?(\n\n## |$)"
        new_content = re.sub(table_pattern, new_table + r"\1", old_content)

        repo_stats = _get_repo_stats(repo)
        if repo_stats:
            stats_section = "## 📊 Статистика репозитория\n" + _build_repo_stats_table(repo_stats) + "\n"
            stats_pattern = r"## 📊 Статистика репозитория\s*\n[\s\S]*?(?=\n## |\Z)"
            if re.search(stats_pattern, new_content):
                new_content = re.sub(stats_pattern, stats_section, new_content)
            else:
                new_content = new_content.rstrip() + "\n\n" + stats_section + "\n"
        else:
            log("⚠️ Статистика репозитория недоступна.")

        if new_content != old_content:
            repo.update_file(
                path="README.md",
                message=f"📝 Обновление README.md (МСК): {offset}",
                content=new_content,
                sha=readme_file.sha,
            )
            log("📝 README.md обновлён")
        else:
            log("📝 README.md не требует изменений")

    except Exception as e:
        log(f"⚠️ Ошибка при обновлении README.md: {e}")


# ─────────────────────────── ЗАГРУЗКА ────────────────────────────

def download_and_save(idx: int) -> Optional[tuple[str, str]]:
    url = URLS[idx]
    local_path = LOCAL_PATHS[idx]
    try:
        data = fetch_data(url)
        data, _ = filter_insecure_configs(local_path, data)

        if os.path.exists(local_path):
            try:
                with open(local_path, "r", encoding="utf-8") as f:
                    if f.read() == data:
                        log(f"🔄 Изменений для {local_path} нет. Пропуск.")
                        return None
            except Exception:
                pass

        save_to_local_file(local_path, data)
        return local_path, REMOTE_PATHS[idx]
    except Exception as e:
        short = str(e)[:200]
        log(f"⚠️ Ошибка при скачивании {url}: {short}")
        return None


# ─────────────────────────── MAIN ────────────────────────────────

def main(dry_run: bool = False) -> None:
    os.makedirs("githubmirror", exist_ok=True)

    offset = _make_offset()

    # Инициализация GitHub (только в main)
    _, repo = _init_github()

    max_dl = min(DEFAULT_MAX_WORKERS, max(1, len(URLS)))
    max_ul = max(2, min(6, len(URLS)))

    # ── 1. Параллельная загрузка зеркал ──
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_dl) as dl_pool, \
         concurrent.futures.ThreadPoolExecutor(max_workers=max_ul) as ul_pool:

        dl_futures = [dl_pool.submit(download_and_save, i) for i in range(len(URLS))]
        ul_futures: list[concurrent.futures.Future] = []

        for fut in concurrent.futures.as_completed(dl_futures):
            result = fut.result()
            if result:
                local_p, remote_p = result
                if dry_run:
                    log(f"ℹ️ Dry-run: пропуск загрузки {remote_p}")
                else:
                    ul_futures.append(
                        ul_pool.submit(upload_to_github, local_p, remote_p, repo, offset)
                    )

        for uf in concurrent.futures.as_completed(ul_futures):
            uf.result()

    # ── 2. ByPass файл ──
    bypass_path, all_results, working_configs, unique_configs = create_filtered_configs(offset)
    if not dry_run:
        upload_to_github(bypass_path, "ByPassVpnLera.txt", repo, offset)

    # ── 3. XHTTP+Reality ──
    xhttp_configs = find_xhttp_reality_configs(unique_configs)
    working_xhttp = test_and_filter_xhttp_configs(xhttp_configs)
    xhttp_file = create_xhttp_configs_file(working_xhttp)
    if xhttp_file and not dry_run:
        upload_to_github(xhttp_file, "XHTTP_Reality.txt", repo, offset)

    # ── 4. Reality-TCP резерв ──
    reality_configs = find_and_test_reality_configs(unique_configs)
    reality_file = create_reality_configs_file(reality_configs)
    if reality_file and not dry_run:
        upload_to_github(reality_file, "REALITY_WORKING.txt", repo, offset)

    # ── 5. ТОП-файлы ──
    if all_results and working_configs:
        fast_files = create_fastest_configs_files(all_results, working_configs)
        for fp in fast_files:
            if not dry_run:
                upload_to_github(fp, fp, repo, offset)

        video_file = create_video_optimized_configs(all_results, working_configs)
        if video_file and not dry_run:
            upload_to_github(video_file, video_file, repo, offset)

        low_ping_file = create_low_ping_configs(all_results)
        if low_ping_file and not dry_run:
            upload_to_github(low_ping_file, low_ping_file, repo, offset)

    # ── 6. README ──
    if not dry_run:
        update_readme_table(repo, offset)

    # ── 7. Вывод логов ──
    output: list[str] = []
    for k in sorted(k for k in LOGS_BY_FILE if k != 0):
        output.append(f"----- {k}.txt -----")
        output.extend(LOGS_BY_FILE[k])
    if LOGS_BY_FILE.get(0):
        output.append("----- Общие сообщения -----")
        output.extend(LOGS_BY_FILE[0])
    print("\n".join(output))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Сбор VPN-конфигов и публикация в GitHub")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Только скачивать и сохранять локально, без загрузки в GitHub"
    )
    args = parser.parse_args()
    main(dry_run=args.dry_run)
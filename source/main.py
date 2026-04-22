"""
main.py — ФИНАЛЬНАЯ ВЕРСИЯ
- Сбор из 50+ источников (включая REALITY, XHTTP и XTLS Vision)
- Параллельная загрузка источников
- Массовая GeoIP-резолвка (IPv4 + IPv6) через ip-api.com
- Безопасная фильтрация мусора (только в тегах)
- Исправление бага с кэшированием "UNKNOWN"
- Глубокая Xray-проверка топ-конфигов (Решение Handshake Error)
- WHITE/BLACK сплит (только топ-200)
"""

import os
import re
import socket
import ssl
import time
import json
import requests
import base64
import websocket
import shutil
import urllib.parse
import urllib3
import concurrent.futures
import threading
import zoneinfo
import signal
import sys
import subprocess
import tempfile
import ipaddress
from datetime import datetime
from github import Github, Auth, GithubException
from urllib.parse import quote, unquote
from collections import defaultdict

# =============================================================================
# ОПТИМИЗИРОВАННЫЕ НАСТРОЙКИ
# =============================================================================

MAX_KEYS_TO_CHECK = 4000        
TIMEOUT = 12                    
THREADS = 25                    
MAX_PING_MS = 5000              
FAST_LIMIT = 2000               
CHUNK_LIMIT = 1000              
EURO_CHUNK_LIMIT = 500
CACHE_HOURS = 6
MAX_HISTORY_AGE = 2 * 24 * 3600
MAX_WHITE_TEST = 200            
BYPASS_TEST_LIMIT = 300         

# =============================================================================
# ПРОВЕРКА ОКРУЖЕНИЯ
# =============================================================================

if hasattr(signal, 'SIGALRM'):
    def timeout_handler(signum, frame):
        print("⚠️ Скрипт выполнялся слишком долго, прерываем...")
        sys.exit(1)
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(5400)  
    print("✅ Таймаут 90 минут установлен")

XRAY_AVAILABLE = False
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
xray_path = os.path.join(SCRIPT_DIR, "xray")

if os.path.exists(xray_path):
    try:
        os.chmod(xray_path, 0o755)
        XRAY_AVAILABLE = True
        print(f"✅ xray найден рядом со скриптом: {xray_path}")
    except Exception:
        print("⚠️ Не удалось установить права на xray")
else:
    print(f"⚠️ xray не найден. Ожидал по пути: {xray_path}")

WHITE_CHECK_AVAILABLE = False
try:
    from white_checker import batch_white_check, xray_available
    if XRAY_AVAILABLE and xray_available():
        WHITE_CHECK_AVAILABLE = True
        print("✅ white_checker.py + xray готовы к работе")
    else:
        print("⚠️ xray не доступен, WHITE/BLACK сплит работать не будет")
except Exception:
    print("⚠️ white_checker.py не найден или ошибка в нем, WHITE/BLACK сплит работать не будет")

# =============================================================================
# GitHub настройки
# =============================================================================

GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "MaxTre2/My-Config"

if GITHUB_TOKEN:
    g = Github(auth=Auth.Token(GITHUB_TOKEN))
else:
    g = Github()
REPO = g.get_repo(REPO_NAME)

if GITHUB_TOKEN:
    try:
        REPO.get_contents("README.md")
        print("✅ GitHub токен работает!")
    except Exception as e:
        print(f"❌ Ошибка GitHub токена: {e}")
else:
    print("❌ GitHub токен не найден в переменных окружения MY_TOKEN")

zone = zoneinfo.ZoneInfo("Europe/Moscow")
thistime = datetime.now(zone)
offset = thistime.strftime("%H:%M | %d.%m.%Y")

# =============================================================================
# Структура папок
# =============================================================================

def get_repo_root() -> str:
    try:
        git_root = subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], stderr=subprocess.DEVNULL).decode('utf-8').strip()
        if os.path.isdir(git_root):
            return git_root
    except Exception:
        pass
    current_dir = os.path.dirname(os.path.abspath(__file__))
    while current_dir != os.path.dirname(current_dir):
        if os.path.exists(os.path.join(current_dir, '.git')):
            return current_dir
        current_dir = os.path.dirname(current_dir)
    return current_dir 

REPO_ROOT = get_repo_root()
BASE_DIR = os.path.join(REPO_ROOT, "githubmirror")
FOLDER_RU = os.path.join(BASE_DIR, "RU_Best")
FOLDER_EURO = os.path.join(BASE_DIR, "My_Euro")

if os.path.exists(FOLDER_RU):
    shutil.rmtree(FOLDER_RU)
if os.path.exists(FOLDER_EURO):
    shutil.rmtree(FOLDER_EURO)
os.makedirs(FOLDER_RU, exist_ok=True)
os.makedirs(FOLDER_EURO, exist_ok=True)
os.makedirs(BASE_DIR, exist_ok=True)

RU_FILES = ["ru_white_part1.txt", "ru_white_part2.txt", "ru_white_part3.txt", "ru_white_part4.txt"]
EURO_FILES = ["my_euro_part1.txt", "my_euro_part2.txt", "my_euro_part3.txt"]

HISTORY_FILE = os.path.join(BASE_DIR, "history.json")
MY_CHANNEL = "@vlesstrojan"

# =============================================================================
# Флаги стран
# =============================================================================

def country_to_flag(country: str) -> str:
    flags = {
        "RU": "🇷🇺", "NL": "🇳🇱", "DE": "🇩🇪", "FI": "🇫🇮",
        "GB": "🇬🇧", "FR": "🇫🇷", "SE": "🇸🇪", "PL": "🇵🇱",
        "CZ": "🇨🇿", "AT": "🇦🇹", "CH": "🇨🇭", "IT": "🇮🇹",
        "ES": "🇪🇸", "NO": "🇳🇴", "DK": "🇩🇰", "BE": "🇧🇪",
        "IE": "🇮🇪", "LU": "🇱🇺", "EE": "🇪🇪", "LV": "🇱🇻",
        "LT": "🇱🇹", "US": "🇺🇸", "UA": "🇺🇦", "BY": "🇧🇾",
        "KZ": "🇰🇿", "TR": "🇹🇷", "JP": "🇯🇵", "SG": "🇸🇬",
        "HK": "🇭🇰", "CA": "🇨🇦", "AU": "🇦🇺", "NZ": "🇳🇿",
    }
    return flags.get(country.upper(), "🏳️")

# =============================================================================
# ИСТОЧНИКИ
# =============================================================================

URLS = [
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
    "https://raw.githubusercontent.com/alanbobs999/TopFreeProxies/master/REALITY",
    "https://raw.githubusercontent.com/AzadNet/channel/main/REALITY",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/reality",
    "https://raw.githubusercontent.com/NiREvil/vless/main/reality.txt",
    "https://raw.githubusercontent.com/amini8k/Free-Configs/main/reality.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/reality.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/reality.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/reality.txt",
    "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/all.txt",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/xhttp",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/splitted/xhttp.txt",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/splitted/vless.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/vless",
]

EXTRA_URLS_FOR_BYPASS = [
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
]

# =============================================================================
# ЖЁСТКИЙ ФИЛЬТР
# =============================================================================

RU_MARKERS_STRICT = [
    ".ru", "moscow", "msk", "spb", "saint-peter", "russia",
    "россия", "москва", "питер", "ru-", "-ru.",
    "178.154.", "77.88.", "5.255.", "87.250.",
    "95.108.", "213.180.", "195.208.",
    "91.108.", "149.154.",
]

EURO_CODES = {
    "NL", "DE", "FI", "GB", "FR", "SE", "PL", "CZ",
    "AT", "CH", "IT", "ES", "NO", "DK", "BE", "IE",
    "LU", "EE", "LV", "LT",
}

BAD_MARKERS = ["CN", "IR", "KR", "BR", "IN", "RELAY", "POOL", "🇨🇳", "🇮🇷", "🇰🇷"]

# =============================================================================
# HTTP клиент
# =============================================================================
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"

def _build_session(max_pool_size: int):
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    session = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=max_pool_size,
        pool_maxsize=max_pool_size,
        max_retries=Retry(total=1, backoff_factor=0.2, status_forcelist=(429, 500, 502, 503, 504))
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": CHROME_UA})
    return session

REQUESTS_SESSION = _build_session(50)

def fetch_data(url, timeout=10, max_attempts=3):
    for attempt in range(1, max_attempts + 1):
        try:
            modified_url = url
            verify = True
            if "github.com" in url and "/blob/" in url:
                modified_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            if attempt == 2:
                verify = False
            elif attempt == 3:
                parsed = urllib.parse.urlparse(url)
                if parsed.scheme == "https":
                    modified_url = parsed._replace(scheme="http").geturl()
                verify = False
            response = REQUESTS_SESSION.get(modified_url, timeout=timeout, verify=verify)
            response.raise_for_status()
            return response.text
        except Exception as e:
            if attempt == max_attempts:
                raise e
            continue

# =============================================================================
# ФИЛЬТРЫ (ИСПРАВЛЕННЫЕ)
# =============================================================================

def is_russian_exit(key_str: str, host: str, country: str) -> bool:
    if country == "RU":
        return True
    host_lower = host.lower()
    key_tag = key_str.split("#")[-1].upper() if "#" in key_str else ""
    
    if host_lower.endswith(".ru"):
        return True
    for marker in RU_MARKERS_STRICT:
        if marker.lower() in host_lower:
            return True
        if marker.upper() in key_tag:
            return True
    return False

def is_garbage_text(key_str: str) -> bool:
    fragment = ""
    if "#" in key_str:
        fragment = key_str.split("#", 1)[1].upper()
    else:
        return False 
    for m in BAD_MARKERS:
        if m in fragment:
            return True
    if ".IR" in fragment or ".CN" in fragment:
        return True
    return False

def filter_insecure_configs(data, log_enabled=True):
    INSECURE_PATTERN = re.compile(
        r'(?:[?&;]|3%[Bb])(allowinsecure|allow_insecure|insecure)=(?:1|true|yes)(?:[&;#]|$|(?=\s|$))',
        re.IGNORECASE
    )
    result = []
    splitted = data.splitlines()
    for line in splitted:
        original_line = line
        processed = line.strip()
        processed = urllib.parse.unquote(processed)
        if INSECURE_PATTERN.search(processed):
            continue
        result.append(original_line)
    return "\n".join(result), len(splitted) - len(result)

# =============================================================================
# ПРИОРИТИЗАЦИЯ КЛЮЧЕЙ
# =============================================================================

def calculate_priority(key: str, latency: int) -> int:
    priority = latency
    if "type=xhttp" in key.lower() or "net=xhttp" in key.lower():
        priority = max(1, latency - 100)
    if "security=reality" in key.lower():
        priority = max(1, priority - 50)
    if "flow=xtls-rprx-vision" in key.lower():
        priority = max(1, priority - 30)
    good_sni = ["m.vk.com", "gosuslugi.ru", "sberbank.ru", "yandex.ru", "mail.ru", "ads.x5.ru"]
    for sni in good_sni:
        if f"sni={sni}" in key.lower():
            priority = max(1, priority - 30)
            break
    return priority

# =============================================================================
# JSON-КЕШ
# =============================================================================

def load_json(path: str) -> dict:
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_json(path: str, data: dict) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"⚠️ Ошибка сохранения кеша: {e}")

# =============================================================================
# ОПРЕДЕЛЕНИЕ СТРАНЫ (ИСПРАВЛЕНО)
# =============================================================================

def get_country_fast(host: str, key_name: str) -> str:
    try:
        h = host.lower()
        n = key_name.split("#")[-1].upper() if "#" in key_name else ""
        
        if h.endswith(".ru"): return "RU"
        if h.endswith(".de"): return "DE"
        if h.endswith(".nl"): return "NL"
        if h.endswith(".uk") or h.endswith(".co.uk"): return "GB"
        if h.endswith(".fr"): return "FR"
        if h.endswith(".fi"): return "FI"
        if h.endswith(".se"): return "SE"
        if h.endswith(".no"): return "NO"
        if h.endswith(".dk"): return "DK"
        if h.endswith(".pl"): return "PL"
        if h.endswith(".cz"): return "CZ"
        if h.endswith(".at"): return "AT"
        if h.endswith(".ch"): return "CH"
        if h.endswith(".it"): return "IT"
        if h.endswith(".es"): return "ES"
        if h.endswith(".be"): return "BE"
        if h.endswith(".ie"): return "IE"
        if h.endswith(".lu"): return "LU"
        if h.endswith(".ee"): return "EE"
        if h.endswith(".lv"): return "LV"
        if h.endswith(".lt"): return "LT"
        
        for code in EURO_CODES:
            if code in n:
                return code
        if "RU" in n:
            return "RU"
    except Exception:
        pass
    return "UNKNOWN"

# =============================================================================
# МАССОВАЯ GEOIP РЕЗОЛВКА
# =============================================================================

def resolve_ip_countries(ips: set) -> dict:
    if not ips:
        return {}
    
    mapping = {}
    ip_list = list(ips)
    print(f"🌍 GeoIP-резолвка {len(ip_list)} IP-адресов через ip-api.com...")
    
    for i in range(0, len(ip_list), 100):
        chunk = ip_list[i:i+100]
        try:
            resp = REQUESTS_SESSION.post(
                "http://ip-api.com/batch?fields=status,countryCode,query",
                json=chunk,
                timeout=15
            )
            if resp.status_code == 200:
                for item in resp.json():
                    if item.get("status") == "success":
                        mapping[item["query"]] = item["countryCode"]
            if i + 100 < len(ip_list):
                time.sleep(4.5)
        except Exception as e:
            print(f"  ⚠️ Ошибка GeoIP: {e}")
            
    print(f"  ✅ Определено стран по IP: {len(mapping)}")
    return mapping

# =============================================================================
# ЗАГРУЗКА КЛЮЧЕЙ (ПАРАЛЛЕЛЬНАЯ)
# =============================================================================

def _process_url(url):
    try:
        data = fetch_data(url, timeout=15, max_attempts=2)
        if not data:
            return []
        
        data, _ = filter_insecure_configs(data, log_enabled=False)
        
        if "://" not in data:
            try:
                missing_padding = len(data) % 4
                if missing_padding:
                    data += "=" * (4 - missing_padding)
                lines = base64.b64decode(data).decode("utf-8", errors="ignore").splitlines()
            except Exception:
                lines = data.splitlines()
        else:
            lines = data.splitlines()
        
        added = []
        for line in lines:
            line = line.strip()
            if len(line) > 2000:
                continue
            if line.startswith(("vless://", "vmess://", "trojan://", "ss://")):
                if not is_garbage_text(line):
                    added.append(line)
        return added
    except Exception:
        return []

def fetch_keys(urls: list) -> list:
    out = []
    print(f"📥 Параллельная загрузка {len(urls)} источников (15 потоков)...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        future_to_url = {executor.submit(_process_url, url): url for url in urls}
        for i, future in enumerate(concurrent.futures.as_completed(future_to_url), 1):
            url = future_to_url[future]
            try:
                keys = future.result()
                out.extend(keys)
                print(f"  {i}. {url.split('/')[-1][:40]}: +{len(keys)}")
            except Exception as e:
                print(f"  ⚠️  {i}. Ошибка: {str(e)[:50]}")
                
    return out

# =============================================================================
# TCP/TLS/WS/XHTTP/XTLS ПРОВЕРКА
# =============================================================================

def check_single_key(key: str, ip_country_map: dict = None):
    try:
        parsed = urllib.parse.urlparse(key)
        if not parsed.hostname or not parsed.port:
            return None, None, None, None
        
        host = parsed.hostname
        port = parsed.port

        country = get_country_fast(host, key)
        if country == "UNKNOWN" and ip_country_map and host in ip_country_map:
            country = ip_country_map[host]

        is_tls = (
            "security=tls" in key
            or "security=reality" in key
            or key.startswith("trojan://")
            or key.startswith("vmess://")
        )
        is_ws = "type=ws" in key or "net=ws" in key
        is_xhttp = "type=xhttp" in key or "net=xhttp" in key
        is_tcp = not (is_ws or is_xhttp)

        path = "/"
        m = re.search(r"path=([^&]+)", key)
        if m:
            path = unquote(m.group(1))

        start = time.time()

        if "security=reality" in key and key.startswith("vless://") and is_tcp:
            with socket.create_connection((host, port), timeout=TIMEOUT):
                pass
            latency = int((time.time() - start) * 1000)
            return latency, country, host, key

        if is_ws:
            protocol = "wss" if is_tls else "ws"
            ws_url = f"{protocol}://{host}:{port}{path}"
            ws = websocket.create_connection(
                ws_url,
                timeout=TIMEOUT,
                sslopt={"cert_reqs": ssl.CERT_NONE, "socket_timeout": TIMEOUT},
            )
            ws.close()
        elif is_xhttp or is_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.settimeout(3)
                    ssock.recv(1)
        else:
            with socket.create_connection((host, port), timeout=TIMEOUT):
                pass

        latency = int((time.time() - start) * 1000)
        return latency, country, host, key

    except (socket.timeout, ssl.SSLError, ConnectionRefusedError, ConnectionResetError, OSError):
        return None, None, None, None
    except Exception:
        return None, None, None, None

# =============================================================================
# ФОРМИРОВАНИЕ ФИНАЛЬНОГО КЛЮЧА
# =============================================================================

def make_final_key(k_id: str, latency: int, country: str) -> str:
    flag = country_to_flag(country)
    info_str = f"[{latency}ms {flag} {country} {MY_CHANNEL}]"
    return f"{k_id}#{quote(info_str, safe='')}"

def extract_ping(key_str: str):
    try:
        label = unquote(key_str).split("#")[-1]
        m = re.search(r"(\d+)ms", label)
        return int(m.group(1)) if m else None
    except Exception:
        return None

def extract_ping_from_uri(uri: str) -> int:
    try:
        label = unquote(uri).split("#")[-1]
        m = re.search(r"\[(\d+)ms", label)
        return int(m.group(1)) if m else 9999
    except Exception:
        return 9999

# =============================================================================
# ГЛУБОКАЯ ПРОВЕРКА ТОП-КОНФИГОВ ЧЕРЕЗ XRAY (HANDSHAKE FIX + SAFE FALLBACK)
# =============================================================================

def xray_fast_check(keys: list, limit: int = 150) -> list:
    if not XRAY_AVAILABLE:
        print("  ⚠️ Xray не доступен, пропускаем глубокую проверку рукопожатия")
        return keys
        
    try:
        from white_checker import _xray_binary, _build_outbound, _build_xray_config, _free_port, _wait_for_port
    except Exception as e:
        print(f"  ⚠️ Ошибка импорта white_checker: {e}")
        return keys

    xray_bin = _xray_binary()
    if not xray_bin:
        print("  ⚠️ Бинарник xray не найден")
        return keys

    keys_to_test = keys[:limit]
    print(f"\n🛡️ Глубокая проверка рукопожатия (XRAY) для {len(keys_to_test)} топ-конфигов...")

    valid_keys = []
    tested = 0
    parse_errors = 0

    for key in keys_to_test:
        k_id = key.split("#")[0]
        outbound = _build_outbound(key)
        
        # ДЕБАГ: Ловим ошибки парсинга конфигов
        if not outbound:
            parse_errors += 1
            if parse_errors <= 3:
                print(f"  ⚠️ Ошибка парсинга Xray конфига: {k_id[:100]}...")
            continue

        socks_port = _free_port()
        config = _build_xray_config(outbound, socks_port)
        proc = None
        tmp_cfg = None

        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as tf:
                json.dump(config, tf)
                tmp_cfg = tf.name

            # ИСПРАВЛЕНИЕ: Ловим stderr чтобы увидеть почему падает xray (например, нет libc.musl)
            proc = subprocess.Popen(
                [xray_bin, "run", "-config", tmp_cfg],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, 
                start_new_session=True
            )

            if not _wait_for_port(socks_port, 5.0):
                err_msg = ""
                try:
                    _, stderr = proc.communicate(timeout=2)
                    if stderr:
                        err_msg = stderr.decode('utf-8', errors='ignore')[:200]
                except Exception:
                    pass
                    
                if parse_errors < 3 and err_msg:
                    print(f"  ⚠️ Xray не поднялся. Причина: {err_msg}")
                raise Exception("Xray не поднялся")

            proxies = {"http": f"socks5h://127.0.0.1:{socks_port}", "https": f"socks5h://127.0.0.1:{socks_port}"}
            resp = REQUESTS_SESSION.get("http://1.1.1.1/generate_204", proxies=proxies, timeout=8)
            
            if resp.status_code in (204, 200):
                valid_keys.append(key)
            
        except Exception:
            pass
        finally:
            if proc and proc.poll() is None:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    proc.wait(timeout=2)
                except Exception:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except Exception:
                        pass
            if tmp_cfg and os.path.exists(tmp_cfg):
                try: 
                    os.unlink(tmp_cfg)
                except Exception:
                    pass
                    
        tested += 1
        if tested % 20 == 0:
            print(f"  Проверено Xray: {tested}/{len(keys_to_test)} | Рабочих: {len(valid_keys)}")

    dropped = len(keys_to_test) - valid_keys
    
    # ЗАЩИТА ОТ ПУСТЫХ ФАЙЛОВ: Если Xray отверг 100% конфигов, значит проблема в самом Xray или парсере.
    # Отменяем результаты проверки и возвращаем оригинальные ключи.
    if dropped == len(keys_to_test) and len(keys_to_test) > 5:
        print(f"⚠️ ВНИМАНИЕ: Xray отверг 100% конфигов (Ошибок парсинга: {parse_errors}).")
        print(f"⚠️ Проблема в бинарнике Xray или формате ключей. Пропускаем фильтрацию, чтобы не оставить вас без конфигов.")
        return keys

    print(f"✅ Xray-проверка завершена. Отсеяно фейков: {dropped}")
    
    return valid_keys + keys[limit:]

# =============================================================================
# СОХРАНЕНИЕ ФАЙЛОВ
# =============================================================================

def save_exact(keys: list, folder: str, filename: str, title: str = None) -> str:
    path = os.path.join(folder, filename)
    with open(path, "w", encoding="utf-8") as f:
        if title:
            title_base64 = base64.b64encode(title.encode('utf-8')).decode('utf-8')
            f.write(f"#profile-title: base64:{title_base64}\n")
            f.write(f"#profile-update-interval: 6\n")
            f.write(f"# {title}\n\n")
        if not keys:
            keys = ["# Нет рабочих ключей"]
        f.write("\n".join(k for k in keys if k and k.strip()))
    return path

def
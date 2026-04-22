"""
main.py — ДИАГНОСТИЧЕСКАЯ ВЕРСИЯ
- Сбор из 50+ источников (включая REALITY, XHTTP и XTLS Vision)
- ИСПРАВЛЕНО: В FAST/ByPass файлы попадают ТОЛЬКО конфиги, проверенные реальным трафиком Xray
- ДОБАВЛЕНО: Вывод ошибок Xray для понимания, почему отсеиваются конфиги (парсер или мертвый источник?)
- WHITE/BLACK сплит адаптирован под GitHub Actions
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
from urllib.parse import quote, unquote
from collections import defaultdict

# =============================================================================
# БЕЗОПАСНЫЙ ИМПОРТ
# =============================================================================
try:
    from github import Github, Auth, GithubException
    GITHUB_LIB_AVAILABLE = True
except ImportError:
    print("⚠️ Библиотека PyGithub не установлена. Загрузка на GitHub отключена.")
    GITHUB_LIB_AVAILABLE = False

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
    except:
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
except ImportError:
    print("⚠️ white_checker.py не найден, WHITE/BLACK сплит работать не будет")

# =============================================================================
# GitHub настройки
# =============================================================================

GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "MaxTre2/My-Config"

REPO = None
if GITHUB_LIB_AVAILABLE and GITHUB_TOKEN:
    try:
        g = Github(auth=Auth.Token(GITHUB_TOKEN))
        REPO = g.get_repo(REPO_NAME)
        REPO.get_contents("README.md")
        print("✅ GitHub токен работает!")
    except Exception as e:
        print(f"❌ Ошибка GitHub токена: {e}")
        REPO = None
elif GITHUB_LIB_AVAILABLE:
    print("❌ GitHub токен не найден в переменных окружения MY_TOKEN")

try:
    zone = zoneinfo.ZoneInfo("Europe/Moscow")
    thistime = datetime.now(zone)
except Exception:
    thistime = datetime.now()
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

for folder in [FOLDER_RU, FOLDER_EURO]:
    if os.path.exists(folder):
        try:
            shutil.rmtree(folder)
        except Exception:
            pass

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
# ФИЛЬТРЫ
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
# Приоритеты
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
# JSON-Кэш
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
    except Exception:
        pass

# =============================================================================
# ОПРЕДЕЛЕНИЕ СТРАНЫ
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
# ЗАГРУЗКА КЛЮЧЕЙ
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
# ИСПРАВЛЕННАЯ TCP ПРОВЕРКА (Пре-фильтр)
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

        start = time.time()
        with socket.create_connection((host, port), timeout=TIMEOUT):
            pass
        latency = int((time.time() - start) * 1000)
        
        return latency, country, host, key

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
    except:
        return 9999

# =============================================================================
# XRAY-ПРОВЕРКА С ДИАГНОСТИКОЙ ОШИБОК
# =============================================================================

def xray_fast_check(keys: list, limit: int = 300) -> list:
    if not XRAY_AVAILABLE:
        print("  ⚠️ Xray не доступен, пропускаем глубокую проверку")
        return keys
        
    try:
        from white_checker import _xray_binary, _build_outbound, _build_xray_config, _free_port, _wait_for_port
    except ImportError:
        return keys

    xray_bin = _xray_binary()
    if not xray_bin:
        return keys

    keys_to_test = keys[:limit]
    print(f"\n🛡️ Глубокая ПАРАЛЛЕЛЬНАЯ проверка XRAY для {len(keys_to_test)} конфигов (15 потоков)...")

    verified_keys = []
    debug_error_count = [0] # Счетчик для вывода ошибок (не больше 3-х)

    def test_single_xray(key):
        k_id = key.split("#")[0]
        outbound = _build_outbound(k_id)
        if not outbound:
            return None

        socks_port = _free_port()
        config = _build_xray_config(outbound, socks_port)
        proc = None
        tmp_cfg = None

        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as tf:
                json.dump(config, tf)
                tmp_cfg = tf.name

            # ИСПРАВЛЕНИЕ: Перехватываем stderr для диагностики
            proc = subprocess.Popen(
                [xray_bin, "run", "-config", tmp_cfg],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                start_new_session=True
            )

            if not _wait_for_port(socks_port, 4.0):
                raise Exception("Xray не поднялся")
            
            time.sleep(0.2) # Ждем стабильности инбаунда

            if proc.poll() is not None:
                raise Exception("Xray упал при старте")

            # ИСПРАВЛЕНИЕ: Используем изолированную сессию, чтобы не забивать пул основного клиента
            test_session = requests.Session()
            test_session.headers.update({"User-Agent": CHROME_UA})
            
            proxies = {"http": f"socks5h://127.0.0.1:{socks_port}", "https": f"socks5h://127.0.0.1:{socks_port}"}
            
            start_req = time.time()
            resp = test_session.get("http://cp.cloudflare.com/generate_204", proxies=proxies, timeout=8)
            real_latency = int((time.time() - start_req) * 1000)
            
            if resp.status_code in (204, 200):
                orig_tag = unquote(key.split("#")[-1]) if "#" in key else ""
                m = re.search(r'([A-Z]{2})\s+@', orig_tag)
                country = m.group(1) if m else "??"
                
                new_tag = f"[{real_latency}ms {country_to_flag(country)} {country} {MY_CHANNEL}]"
                return f"{k_id}#{quote(new_tag, safe='')}"
            return None
            
        except Exception as e:
            # ДИАГНОСТИКА: Выводим логи Xray для первых 3-х упавших конфигов
            if debug_error_count[0] < 3:
                err_msg = ""
                if proc and proc.stderr:
                    try:
                        err_msg = proc.stderr.read().decode(errors='ignore').strip()
                    except:
                        pass
                if err_msg:
                    print(f"\n🔍 ДИАГНОСТИКА XRAY (Ошибка #{debug_error_count[0]+1}):")
                    print(f"   {err_msg[:500]}\n")
                else:
                    print(f"\n🔍 ДИАГНОСТИКА XRAY: Трафик не прошел (Network Error: {str(e)[:100]})\n")
                debug_error_count[0] += 1
            return None
            
        finally:
            if proc:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    proc.wait(timeout=2)
                except Exception:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except Exception:
                        pass
            if tmp_cfg and os.path.exists(tmp_cfg):
                try: os.unlink(tmp_cfg)
                except: pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(test_single_xray, key): key for key in keys_to_test}
        for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
            result = future.result()
            if result:
                verified_keys.append(result)
            if i % 50 == 0:
                print(f"  Прогресс Xray: {i}/{len(keys_to_test)} | Рабочих: {len(verified_keys)}")

    dropped = len(keys_to_test) - len(verified_keys)
    print(f"✅ Xray-проверка завершена. Отсеяно мертвых: {dropped} | Осталось РЕАЛЬНО рабочих: {len(verified_keys)}")
    
    return verified_keys

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

def save_fixed_chunks_ru(keys_list: list, folder: str) -> list:
    valid = [k.strip() for k in keys_list if k and k.strip()]
    chunks = [valid[i:i + CHUNK_LIMIT] for i in range(0, min(len(valid), CHUNK_LIMIT * 4), CHUNK_LIMIT)]
    while len(chunks) < 4:
        chunks.append([])
    titles = ["MaxTre - VPN RUSSIA FAST ⚡ Part 1", "MaxTre - VPN RUSSIA FAST ⚡ Part 2", 
              "MaxTre - VPN RUSSIA FAST ⚡ Part 3", "MaxTre - VPN RUSSIA FAST ⚡ Part 4"]
    for i, fname in enumerate(RU_FILES):
        chunk = chunks[i] if i < len(chunks) else []
        save_exact(chunk, folder, fname, titles[i])
        print(f"  {fname}: {len(chunk)} ключей")
    return RU_FILES

def save_fixed_chunks_euro(keys_list: list, folder: str) -> list:
    valid = [k.strip() for k in keys_list if k and k.strip()]
    chunks = [valid[i:i + EURO_CHUNK_LIMIT] for i in range(0, min(len(valid), EURO_CHUNK_LIMIT * 3), EURO_CHUNK_LIMIT)]
    while len(chunks) < 3:
        chunks.append([])
    titles = ["MaxTre - VPN EUROPE FAST ⚡ Part 1", "MaxTre - VPN EUROPE FAST ⚡ Part 2", 
              "MaxTre - VPN EUROPE FAST ⚡ Part 3"]
    for i, fname in enumerate(EURO_FILES):
        chunk = chunks[i] if i < len(chunks) else []
        save_exact(chunk, folder, fname, titles[i])
        print(f"  {fname}: {len(chunk)} ключей")
    return EURO_FILES

def save_chunked(keys_list: list, folder: str, base_name: str, chunk_size: int = None) -> list:
    if chunk_size is None:
        chunk_size = CHUNK_LIMIT
    valid = [k.strip() for k in keys_list if k and k.strip()]
    chunks = [valid[i:i + chunk_size] for i in range(0, len(valid), chunk_size)]
    names = []
    category = "RUSSIA" if "ru" in base_name else "EUROPE"
    emoji = "🇷🇺" if "ru" in base_name else "🇪🇺"
    for idx, chunk in enumerate(chunks, start=1):
        fname = f"{base_name}_part{idx}.txt"
        title = f"MaxTre - VPN {category} ALL {emoji} Part {idx}"
        save_exact(chunk, folder, fname, title)
        names.append(fname)
        print(f"  {fname}: {len(chunk)} ключей")
    return names

# =============================================================================
# ЗАГРУЗКА В GITHUB
# =============================================================================

def upload_to_github(local_path, remote_path):
    if not REPO: return
    if not os.path.exists(local_path):
        return
    with open(local_path, "r", encoding="utf-8") as file:
        content = file.read()
    max_retries = 5
    for attempt in range(1, max_retries + 1):
        try:
            try:
                file_in_repo = REPO.get_contents(remote_path)
                current_sha = file_in_repo.sha
            except GithubException as e_get:
                if getattr(e_get, "status", None) == 404:
                    REPO.create_file(path=remote_path, message=f"🆕 Создан {remote_path} {offset}", content=content)
                    return
                else:
                    return
            try:
                remote_content = file_in_repo.decoded_content.decode("utf-8", errors="replace")
                if remote_content == content:
                    return
            except Exception:
                pass
            REPO.update_file(path=remote_path, message=f"🚀 Обновление {remote_path} {offset}", content=content, sha=current_sha)
            return
        except GithubException as e_upd:
            if getattr(e_upd, "status", None) == 409 and attempt < max_retries:
                time.sleep(0.5 * (2 ** (attempt - 1)))
                continue
            else:
                return

# =============================================================================
# ГЕНЕРАЦИЯ SUBSCRIPTIONS_LIST.TXT
# =============================================================================

def generate_subscriptions_list() -> str:
    BASE_RAW = f"https://raw.githubusercontent.com/{REPO_NAME}/main"
    lines = []
    lines += ["=== 🇷🇺 RUSSIA (FAST) ==="]
    lines += [f"{BASE_RAW}/githubmirror/RU_Best/{f}" for f in RU_FILES]
    lines += [""]
    lines += ["=== 🇪🇺 EUROPE (FAST) ==="]
    lines += [f"{BASE_RAW}/githubmirror/My_Euro/{f}" for f in EURO_FILES]
    lines += [""]
    lines += ["=== 🇷🇺 RUSSIA (ALL) ==="]
    ru_all = sorted(f for f in os.listdir(FOLDER_RU) if f.startswith("ru_white_all_part") and f.endswith(".txt"))
    lines += [f"{BASE_RAW}/githubmirror/RU_Best/{f}" for f in ru_all[:2]]
    lines += [""]
    lines += ["=== 🇪🇺 EUROPE (ALL) ==="]
    eu_all = sorted(f for f in os.listdir(FOLDER_EURO) if f.startswith("my_euro_all_part") and f.endswith(".txt"))
    lines += [f"{BASE_RAW}/githubmirror/My_Euro/{f}" for f in eu_all[:2]]
    lines += [""]
    lines += ["=== ✅ WHITE RUSSIA (ALL) ==="]
    lines += [f"{BASE_RAW}/githubmirror/RU_Best/ru_white_all_WHITE.txt", ""]
    lines += ["=== ✅ WHITE EUROPE (ALL) ==="]
    lines += [f"{BASE_RAW}/githubmirror/My_Euro/my_euro_all_WHITE.txt", ""]
    lines += ["=== ⚠️ BLACK RUSSIA (ALL) ==="]
    lines += [f"{BASE_RAW}/githubmirror/RU_Best/ru_white_all_BLACK.txt", ""]
    lines += ["=== ⚠️ BLACK EUROPE (ALL) ==="]
    lines += [f"{BASE_RAW}/githubmirror/My_Euro/my_euro_all_BLACK.txt"]
    lines += [""]
    lines += ["=== 🛡️ BYPASS (XRAY ПРОВЕРКА) ==="]
    lines += [f"{BASE_RAW}/githubmirror/ByPassVpnLera.txt"]
    path = os.path.join(BASE_DIR, "subscriptions_list.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path

# =============================================================================
# СОЗДАНИЕ БАЙПАС ФАЙЛА (ИСПРАВЛЕНО: ТОЖЕ ЧЕРЕЗ XRAY)
# =============================================================================

def create_bypass_file(ip_country_map: dict = None):
    bypass_path = os.path.join(BASE_DIR, "ByPassVpnLera.txt")
    print(f"\n🔍 Сбор конфигов для ByPassVpnLera.txt (XRAY проверка)...")
    
    all_configs = []
    
    def _load_extra_configs(url):
        try:
            data = fetch_data(url, timeout=8, max_attempts=2)
            data, _ = filter_insecure_configs(data, log_enabled=False)
            data = re.sub(r'(vmess|vless|trojan|ss|ssr)://', r'\n\1://', data)
            lines = [l.strip() for l in data.splitlines() if l.strip() and not l.startswith('#')]
            return lines
        except Exception:
            return []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(_load_extra_configs, url) for url in EXTRA_URLS_FOR_BYPASS]
        for future in concurrent.futures.as_completed(futures):
            all_configs.extend(future.result())
    
    unique_configs = {}
    for cfg in all_configs:
        k_id = cfg.split("#")[0]
        if k_id not in unique_configs or len(cfg) > len(unique_configs[k_id]):
            unique_configs[k_id] = cfg
    unique_list = list(unique_configs.values())
    
    # ИСПРАВЛЕНИЕ: Сортируем по TCP пингу перед XRAY
    tcp_checked = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        future_to_cfg = {executor.submit(check_single_key, cfg, ip_country_map): cfg for cfg in unique_list[:BYPASS_TEST_LIMIT]}
        for future in concurrent.futures.as_completed(future_to_cfg):
            cfg = future_to_cfg[future]
            try:
                latency, country, host, _ = future.result(timeout=TIMEOUT + 5)
                if latency is not None:
                    flag = country_to_flag(country)
                    k_id = cfg.split("#")[0]
                    final_cfg = f"{k_id}#[{latency}ms {flag} {country} {MY_CHANNEL}]"
                    tcp_checked.append(final_cfg)
            except Exception:
                pass
    
    tcp_checked.sort(key=extract_ping_from_uri)
    
    # ИСПРАВЛЕНИЕ: Прогоняем топ ByPass конфигов через XRAY (лимит 100, чтобы не убить таймаут)
    if XRAY_AVAILABLE:
        tcp_checked = xray_fast_check(tcp_checked, limit=100)
    
    top_configs = tcp_checked[:200]
    
    title = "MaxTre - VPN Bypass (XRAY ПРОВЕРКА)"
    title_base64 = base64.b64encode(title.encode('utf-8')).decode('utf-8')
    
    header = f"#profile-title: base64:{title_base64}\n"
    header += "#profile-update-interval: 3\n"
    header += f"# {title}\n"
    header += f"# Рабочих конфигов: {len(top_configs)}\n"
    header += f"# Обновлено: {offset}\n\n"
    
    with open(bypass_path, "w", encoding="utf-8") as file:
        file.write(header + "\n".join(top_configs))
    
    print(f"📁 Создан {bypass_path} с {len(top_configs)} РЕАЛЬНО проверенными Xray конфигами")
    return bypass_path

# =============================================================================
# ОСНОВНАЯ ФУНКЦИЯ
# =============================================================================

def main(dry_run=False):
    print("=" * 60)
    print("  🚀 MAIN.PY ДИАГНОСТИЧЕСКАЯ ВЕРСИЯ (REALITY + XHTTP + XTLS Vision)")
    print("=" * 60)
    start_time = time.time()
    
    all_keys = fetch_keys(URLS)
    
    unique_keys = {}
    for k in all_keys:
        k_id = k.split("#")[0]
        if k_id not in unique_keys or len(k) > len(unique_keys[k_id]):
            unique_keys[k_id] = k
            
    all_items = list(unique_keys.values())
    if len(all_items) > MAX_KEYS_TO_CHECK:
        all_items = all_items[:MAX_KEYS_TO_CHECK]
    print(f"\n📊 Уникальных ключей: {len(all_items)}")
    
    unknown_ips = set()
    for key in all_items:
        try:
            parsed = urllib.parse.urlparse(key)
            host = parsed.hostname or ""
            if host and get_country_fast(host, key) == "UNKNOWN":
                try:
                    ipaddress.ip_address(host)
                    unknown_ips.add(host)
                except ValueError:
                    pass
        except Exception:
            pass
            
    ip_country_map = resolve_ip_countries(unknown_ips)
    
    history = load_json(HISTORY_FILE)
    current_time = time.time()
    to_check = []
    res_ru = []
    res_euro = []
    
    for key in all_items:
        k_id = key.split("#")[0]
        try:
            host = urllib.parse.urlparse(key).hostname or ""
        except:
            host = ""
            
        country = get_country_fast(host, key)
        if country == "UNKNOWN" and host in ip_country_map:
            country = ip_country_map[host]
            
        cached = history.get(k_id)
        
        if cached and (current_time - cached["time"] < CACHE_HOURS * 3600) and cached.get("xray_verified"):
            cached_country = cached.get("country")
            if not cached_country or cached_country == "UNKNOWN":
                cached_country = country
                
            final = make_final_key(k_id, cached["latency"], cached_country)
            if cached_country == "RU" or is_russian_exit(key, cached.get("host", ""), cached_country):
                res_ru.append(final)
            elif cached_country in EURO_CODES:
                res_euro.append(final)
        else:
            to_check.append(key)
    
    print(f"✅ Из кеша (проверенных Xray): RU={len(res_ru)} EURO={len(res_euro)}")
    print(f"🔍 На TCP пре-фильтр: {len(to_check)}")
    
    if to_check:
        checked_count = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
            future_to_key = {executor.submit(check_single_key, key, ip_country_map): key for key in to_check}
            for future in concurrent.futures.as_completed(future_to_key):
                key = future_to_key[future]
                try:
                    latency, country, host, _ = future.result()
                except Exception:
                    continue
                    
                if latency is None:
                    continue
                k_id = key.split("#")[0]
                
                history[k_id] = {
                    "alive": True, 
                    "latency": latency, 
                    "time": time.time(), 
                    "country": country, 
                    "host": host,
                    "xray_verified": False
                }
                
                final = make_final_key(k_id, latency, country)
                if country == "RU" or is_russian_exit(key, host, country):
                    res_ru.append(final)
                elif country in EURO_CODES:
                    res_euro.append(final)
                checked_count += 1
                if checked_count % 100 == 0:
                    print(f"  TCP пре-фильтр: {checked_count}/{len(to_check)}")
        print(f"✅ Прошли TCP пре-фильтр: {checked_count}")
    
    now = time.time()
    save_json(HISTORY_FILE, {k: v for k, v in history.items() if now - v["time"] < MAX_HISTORY_AGE})
    
    res_ru_clean = [k for k in res_ru if extract_ping(k) is not None and extract_ping(k) <= MAX_PING_MS]
    res_euro_clean = [k for k in res_euro if extract_ping(k) is not None and extract_ping(k) <= MAX_PING_MS]
    
    def sort_key_with_priority(key_str):
        ping = extract_ping(key_str) or 9999
        return calculate_priority(key_str, ping)
    
    res_ru_clean.sort(key=sort_key_with_priority)
    res_euro_clean.sort(key=sort_key_with_priority)
    
    print(f"\n📈 После фильтрации (≤{MAX_PING_MS}ms): RU: {len(res_ru_clean)} EURO: {len(res_euro_clean)}")
    
    res_ru_fast = res_ru_clean[:FAST_LIMIT]
    res_euro_fast = res_euro_clean[:FAST_LIMIT]
    
    if not dry_run:
        res_ru_fast = xray_fast_check(res_ru_fast, limit=300)
        res_euro_fast = xray_fast_check(res_euro_fast, limit=300)
        
        for k in res_ru_fast + res_euro_fast:
            k_id = k.split("#")[0]
            real_ping = extract_ping_from_uri(k)
            if k_id in history and real_ping != 9999:
                history[k_id]["latency"] = real_ping
                history[k_id]["xray_verified"] = True

    res_ru_all = res_ru_clean
    res_euro_all = res_euro_clean
    
    print(f"\n🚀 FAST (после Xray): RU FAST: {len(res_ru_fast)} EURO FAST: {len(res_euro_fast)}")
    
    if not dry_run:
        print(f"\n💾 Сохранение файлов...")
        print(f"\n📁 {FOLDER_RU}:")
        save_fixed_chunks_ru(res_ru_fast, FOLDER_RU)
        print(f"\n📁 {FOLDER_EURO}:")
        save_fixed_chunks_euro(res_euro_fast, FOLDER_EURO)
        print(f"\n📁 ALL RU:")
        save_chunked(res_ru_all, FOLDER_RU, "ru_white_all")
        print(f"\n📁 ALL EURO:")
        save_chunked(res_euro_all, FOLDER_EURO, "my_euro_all", chunk_size=EURO_CHUNK_LIMIT)
        
        print(f"\n🔬 WHITE / BLACK сплит...")
        if WHITE_CHECK_AVAILABLE and XRAY_AVAILABLE:
            ru_to_test = res_ru_all[:MAX_WHITE_TEST]
            ru_untested = res_ru_all[MAX_WHITE_TEST:]
            euro_to_test = res_euro_all[:MAX_WHITE_TEST]
            euro_untested = res_euro_all[MAX_WHITE_TEST:]
            
            ru_white, ru_black = batch_white_check(ru_to_test, history, label="RU")
            euro_white, euro_black = batch_white_check(euro_to_test, history, label="EURO")
            
            ru_black.extend(ru_untested)
            euro_black.extend(euro_untested)
        else:
            print("  ⚠️ white_checker недоступен — все ключи → WHITE")
            ru_white, ru_black = list(res_ru_all), []
            euro_white, euro_black = list(res_euro_all), []
        
        print(f"\n💾 WHITE/BLACK:")
        save_exact(ru_white, FOLDER_RU, "ru_white_all_WHITE.txt", "MaxTre - VPN RUSSIA WHITE ✅")
        save_exact(ru_black, FOLDER_RU, "ru_white_all_BLACK.txt", "MaxTre - VPN RUSSIA BLACK ⚠️")
        save_exact(euro_white, FOLDER_EURO, "my_euro_all_WHITE.txt", "MaxTre - VPN EUROPE WHITE ✅")
        save_exact(euro_black, FOLDER_EURO, "my_euro_all_BLACK.txt", "MaxTre - VPN EUROPE BLACK ⚠️")
        
        bypass_path = create_bypass_file(ip_country_map)
        
        if REPO:
            print(f"\n📤 Загрузка в GitHub...")
            upload_futures = []
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                for f in os.listdir(FOLDER_RU):
                    if f.endswith('.txt'):
                        upload_futures.append(executor.submit(upload_to_github, os.path.join(FOLDER_RU, f), f"githubmirror/RU_Best/{f}"))
                for f in os.listdir(FOLDER_EURO):
                    if f.endswith('.txt'):
                        upload_futures.append(executor.submit(upload_to_github, os.path.join(FOLDER_EURO, f), f"githubmirror/My_Euro/{f}"))
                upload_futures.append(executor.submit(upload_to_github, bypass_path, "githubmirror/ByPassVpnLera.txt"))
                upload_futures.append(executor.submit(upload_to_github, HISTORY_FILE, "githubmirror/history.json"))
                upload_futures.append(executor.submit(upload_to_github, generate_subscriptions_list(), "githubmirror/subscriptions_list.txt"))
                
                for future in concurrent.futures.as_completed(upload_futures):
                    try:
                        future.result()
                        time.sleep(0.5)
                    except Exception as e:
                        print(f"❌ Критическая ошибка потока загрузки: {e}")
        else:
            print("\n⏭️ Пропуск загрузки на GitHub.")
        
        elapsed = time.time() - start_time
        bypass_count = 0
        try:
            with open(bypass_path, "r", encoding="utf-8") as bp_file:
                bypass_count = len([c for c in bp_file.readlines() if c.startswith(('vless://', 'vmess://', 'trojan://', 'ss://'))])
        except Exception:
            pass

        print("\n" + "=" * 60)
        print("  ✅  SUCCESS")
        print("=" * 60)
        print(f"  RU  FAST  : {len(res_ru_fast)}")
        print(f"  RU  ALL   : {len(res_ru_all)}")
        print(f"  RU  WHITE : {len(ru_white)}")
        print(f"  RU  BLACK : {len(ru_black)}")
        print(f"  EU  FAST  : {len(res_euro_fast)}")
        print(f"  EU  ALL   : {len(res_euro_all)}")
        print(f"  EU  WHITE : {len(euro_white)}")
        print(f"  EU  BLACK : {len(euro_black)}")
        print(f"  BYPASS    : {bypass_count}")
        print(f"  ⏱ Время: {elapsed:.2f} сек")
        print("=" * 60)
        
        save_json(HISTORY_FILE, {k: v for k, v in history.items() if now - v["time"] < MAX_HISTORY_AGE})

    else:
        print("\n🏁 Dry-run завершен.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="Только проверка без сохранения")
    args = parser.parse_args()
    main(dry_run=args.dry_run)
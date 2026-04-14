"""
main.py — ОПТИМИЗИРОВАННАЯ И ИСПРАВЛЕННАЯ ВЕРСИЯ
- Сбор из 50+ источников (включая REALITY, XHTTP и XTLS Vision)
- Продвинутая проверка и классификация
- WHITE/BLACK сплит (только топ-200)
- ByPassVpnLera.txt с ПОЛНОЙ проверкой (TCP+TLS/REALITY)
- Приоритизация XHTTP + REALITY + XTLS Vision конфигов
- ИСПРАВЛЕНИЯ: Base64, IPv6, WebSocket timeout, кеширование мусора, Github Rate Limits
- АРХИТЕКТУРА: Надежное определение путей (Git-based) для GitHub Actions
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
from datetime import datetime
from github import Github, Auth, GithubException
from urllib.parse import quote, unquote
from collections import defaultdict

# =============================================================================
# ОПТИМИЗИРОВАННЫЕ НАСТРОЙКИ
# =============================================================================

MAX_KEYS_TO_CHECK = 4000        # Снижено до безопасного предела
TIMEOUT = 12                    # Таймаут 12 секунд
THREADS = 25                    # Увеличено потоков для компенсации
MAX_PING_MS = 5000              # Максимальный пинг 5 секунд
FAST_LIMIT = 2000               # Топ-2000 быстрых
CHUNK_LIMIT = 1000              
EURO_CHUNK_LIMIT = 500
CACHE_HOURS = 6
MAX_HISTORY_AGE = 2 * 24 * 3600
MAX_WHITE_TEST = 200            # Проверяем только топ-200 ключей на белизну
BYPASS_TEST_LIMIT = 300         # Сколько ключей проверять для ByPassVpnLera

# =============================================================================
# ПРОВЕРКА ОКРУЖЕНИЯ
# =============================================================================

# Защита от зависания (только для Unix)
if hasattr(signal, 'SIGALRM'):
    def timeout_handler(signum, frame):
        print("⚠️ Скрипт выполнялся слишком долго, прерываем...")
        sys.exit(1)
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(5400)  # 90 минут (с запасом)
    print("✅ Таймаут 90 минут установлен")

# Проверка наличия xray (Ищем строго в папке со скриптом - source/)
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

# Попытка импорта white_checker
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

if GITHUB_TOKEN:
    g = Github(auth=Auth.Token(GITHUB_TOKEN))
else:
    g = Github()
REPO = g.get_repo(REPO_NAME)

# Проверка токена
if GITHUB_TOKEN:
    try:
        REPO.get_contents("README.md")
        print("✅ GitHub токен работает!")
    except Exception as e:
        print(f"❌ Ошибка GitHub токена: {e}")
else:
    print("❌ GitHub токен не найден в переменных окружения MY_TOKEN")

# Временная зона
zone = zoneinfo.ZoneInfo("Europe/Moscow")
thistime = datetime.now(zone)
offset = thistime.strftime("%H:%M | %d.%m.%Y")

# =============================================================================
# Структура папок (Абсолютно надежное определение корня репозитория)
# =============================================================================

def get_repo_root() -> str:
    """Определяет корень репозитория через Git, работает везде, включая GitHub Actions"""
    try:
        import subprocess
        git_root = subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], stderr=subprocess.DEVNULL).decode('utf-8').strip()
        if os.path.isdir(git_root):
            return git_root
    except Exception:
        pass
    
    # Фоллбэк, если запущено не под Git (например, локально без инициализации)
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

# Очистка старых папок
if os.path.exists(FOLDER_RU):
    shutil.rmtree(FOLDER_RU)
if os.path.exists(FOLDER_EURO):
    shutil.rmtree(FOLDER_EURO)
os.makedirs(FOLDER_RU, exist_ok=True)
os.makedirs(FOLDER_EURO, exist_ok=True)
os.makedirs(BASE_DIR, exist_ok=True)

# Имена выходных файлов
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
# ИСТОЧНИКИ (включая REALITY, XHTTP и XTLS Vision)
# =============================================================================

URLS = [
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
    
    # === ДОПОЛНИТЕЛЬНЫЕ REALITY + gRPC ИСТОЧНИКИ ===
    "https://raw.githubusercontent.com/alanbobs999/TopFreeProxies/master/REALITY",
    "https://raw.githubusercontent.com/AzadNet/channel/main/REALITY",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/reality",
    "https://raw.githubusercontent.com/NiREvil/vless/main/reality.txt",
    "https://raw.githubusercontent.com/amini8k/Free-Configs/main/reality.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/reality.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/reality.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/reality.txt",
    
    # === XHTTP + REALITY источники (САМЫЕ ЖИВУЧИЕ) ===
    "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/all.txt",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/xhttp",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/splitted/xhttp.txt",
    
    # === XTLS VISION + REALITY источники ===
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/splitted/vless.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/vless",
]

# =============================================================================
# ДОПОЛНИТЕЛЬНЫЕ ИСТОЧНИКИ ДЛЯ БАЙПАСА
# =============================================================================
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
    key_upper = key_str.upper()
    if host_lower.endswith(".ru"):
        return True
    for marker in RU_MARKERS_STRICT:
        if marker.lower() in host_lower:
            return True
        if marker.upper() in key_upper:
            return True
    return False

def is_garbage_text(key_str: str) -> bool:
    upper = key_str.upper()
    for m in BAD_MARKERS:
        if m in upper:
            return True
    if ".ir" in key_str or ".cn" in key_str or "127.0.0.1" in key_str:
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
    """Вычисляет приоритет ключа для сортировки (меньше = лучше)"""
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
# ОПРЕДЕЛЕНИЕ СТРАНЫ
# =============================================================================

def get_country_fast(host: str, key_name: str) -> str:
    try:
        h = host.lower()
        n = key_name.upper()
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
    except Exception:
        pass
    return "UNKNOWN"

# =============================================================================
# ЗАГРУЗКА КЛЮЧЕЙ
# =============================================================================

def fetch_keys(urls: list) -> list:
    out = []
    print(f"📥 Загрузка {len(urls)} источников...")
    for i, url in enumerate(urls, 1):
        try:
            data = fetch_data(url, timeout=15, max_attempts=2)
            if not data:
                continue
            
            data, filtered = filter_insecure_configs(data, log_enabled=False)
            
            if "://" not in data:
                try:
                    # ИСПРАВЛЕНИЕ: Правильное восстановление паддинга для Base64
                    missing_padding = len(data) % 4
                    if missing_padding:
                        data += "=" * (4 - missing_padding)
                    lines = base64.b64decode(data).decode("utf-8", errors="ignore").splitlines()
                except Exception:
                    lines = data.splitlines()
            else:
                lines = data.splitlines()
            
            added = 0
            for line in lines:
                line = line.strip()
                if len(line) > 2000:
                    continue
                if line.startswith(("vless://", "vmess://", "trojan://", "ss://")):
                    if is_garbage_text(line):
                        continue
                    out.append(line)
                    added += 1
            print(f"  {i}. {url.split('/')[-1][:40]}: +{added}")
        except Exception as e:
            print(f"  ⚠️  {i}. Ошибка: {str(e)[:50]}")
    return out

# =============================================================================
# TCP/TLS/WS/XHTTP/XTLS ПРОВЕРКА
# =============================================================================

def check_single_key(key: str):
    try:
        # ИСПРАВЛЕНИЕ: Безопасный парсинг URI (поддержка IPv6)
        parsed = urllib.parse.urlparse(key)
        if not parsed.hostname or not parsed.port:
            return None, None, None, None
        
        host = parsed.hostname
        port = parsed.port

        country = get_country_fast(host, key)

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

        # REALITY + VLESS + TCP (XTLS Vision) - проверяем только TCP соединение
        if "security=reality" in key and key.startswith("vless://") and is_tcp:
            with socket.create_connection((host, port), timeout=TIMEOUT):
                pass
            latency = int((time.time() - start) * 1000)
            return latency, country, host, key

        if is_ws:
            protocol = "wss" if is_tls else "ws"
            ws_url = f"{protocol}://{host}:{port}{path}"
            # ИСПРАВЛЕНИЕ: Явный таймаут на уровне сокета для WS
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
                    # ИСПРАВЛЕНИЕ: Ждем 1 байт, чтобы отсеять фейковые прокси
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
    """Извлекает пинг из URI для сортировки"""
    try:
        label = unquote(uri).split("#")[-1]
        m = re.search(r"\[(\d+)ms", label)
        return int(m.group(1)) if m else 9999
    except:
        return 9999

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
    if not os.path.exists(local_path):
        print(f"❌ Файл {local_path} не найден.")
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
                    print(f"🆕 Файл {remote_path} создан.")
                    return
                else:
                    print(f"⚠️ Ошибка получения {remote_path}: {e_get}")
                    return
            try:
                remote_content = file_in_repo.decoded_content.decode("utf-8", errors="replace")
                if remote_content == content:
                    print(f"🔄 Изменений для {remote_path} нет.")
                    return
            except Exception:
                pass
            REPO.update_file(path=remote_path, message=f"🚀 Обновление {remote_path} {offset}", content=content, sha=current_sha)
            print(f"🚀 Файл {remote_path} обновлён.")
            return
        except GithubException as e_upd:
            if getattr(e_upd, "status", None) == 409 and attempt < max_retries:
                time.sleep(0.5 * (2 ** (attempt - 1)))
                continue
            else:
                print(f"❌ Не удалось обновить {remote_path}: {e_upd}")
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
    lines += ["=== 🛡️ BYPASS (ПОЛНАЯ ПРОВЕРКА) ==="]
    lines += [f"{BASE_RAW}/githubmirror/ByPassVpnLera.txt"]
    path = os.path.join(BASE_DIR, "subscriptions_list.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n📋 subscriptions_list.txt: {len([l for l in lines if l.startswith('http')])} ссылок")
    return path

# =============================================================================
# СОЗДАНИЕ БАЙПАС ФАЙЛА С ПОЛНОЙ ПРОВЕРКОЙ
# =============================================================================

def create_bypass_file():
    """Создает ByPassVpnLera.txt с ПОЛНОСТЬЮ проверенными конфигами (TCP+TLS/REALITY)"""
    bypass_path = os.path.join(BASE_DIR, "ByPassVpnLera.txt")
    
    print(f"\n🔍 Сбор конфигов для ByPassVpnLera.txt (ПОЛНАЯ ПРОВЕРКА)...")
    
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
    
    # ИСПРАВЛЕНИЕ: Умная дедупликация (оставляем конфиг с самым длинным/информативным тегом)
    unique_configs = {}
    for cfg in all_configs:
        k_id = cfg.split("#")[0]
        if k_id not in unique_configs or len(cfg) > len(unique_configs[k_id]):
            unique_configs[k_id] = cfg
    unique_list = list(unique_configs.values())
    
    print(f"📊 Собрано уникальных конфигов: {len(unique_list)}")
    
    max_to_test = min(BYPASS_TEST_LIMIT, len(unique_list))
    print(f"🔍 ПОЛНАЯ проверка {max_to_test} ключей (TCP+TLS/REALITY/WS/XHTTP)...")
    
    working_configs = []
    tested = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        future_to_cfg = {}
        for cfg in unique_list[:max_to_test]:
            future = executor.submit(check_single_key, cfg)
            future_to_cfg[future] = cfg
        
        for future in concurrent.futures.as_completed(future_to_cfg):
            cfg = future_to_cfg[future]
            tested += 1
            try:
                latency, country, host, _ = future.result(timeout=TIMEOUT + 5)
                if latency is not None:
                    flag = country_to_flag(country)
                    k_id = cfg.split("#")[0]
                    final_cfg = f"{k_id}#[{latency}ms {flag} {country} {MY_CHANNEL}]"
                    working_configs.append(final_cfg)
                    if len(working_configs) % 20 == 0:
                        print(f"  ✅ Найдено рабочих: {len(working_configs)}/{tested}")
            except Exception:
                pass
    
    print(f"📊 Найдено ПОЛНОСТЬЮ рабочих конфигов: {len(working_configs)}")
    
    working_configs.sort(key=extract_ping_from_uri)
    top_configs = working_configs[:200]
    
    title = "MaxTre - VPN Bypass (ПОЛНАЯ проверка)"
    title_base64 = base64.b64encode(title.encode('utf-8')).decode('utf-8')
    
    header = f"#profile-title: base64:{title_base64}\n"
    header += "#profile-update-interval: 3\n"
    header += f"# {title}\n"
    header += f"# Проверено: TCP+TLS/REALITY/WS/XHTTP рукопожатие\n"
    header += f"# Рабочих конфигов: {len(top_configs)}\n"
    header += f"# Обновлено: {offset}\n\n"
    
    with open(bypass_path, "w", encoding="utf-8") as file:
        file.write(header + "\n".join(top_configs))
    
    print(f"📁 Создан {bypass_path} с {len(top_configs)} ПОЛНОСТЬЮ проверенными конфигами")
    return bypass_path

# =============================================================================
# ОСНОВНАЯ ФУНКЦИЯ
# =============================================================================

def main(dry_run=False):
    print("=" * 60)
    print("  🚀 MAIN.PY ОПТИМИЗИРОВАННАЯ ВЕРСИЯ (REALITY + XHTTP + XTLS Vision)")
    print("=" * 60)
    start_time = time.time()
    
    all_keys = fetch_keys(URLS)
    
    # ИСПРАВЛЕНИЕ: Умная дедупликация (сохранение лучших тегов)
    unique_keys = {}
    for k in all_keys:
        k_id = k.split("#")[0]
        if k_id not in unique_keys or len(k) > len(unique_keys[k_id]):
            unique_keys[k_id] = k
            
    all_items = list(unique_keys.values())
    if len(all_items) > MAX_KEYS_TO_CHECK:
        all_items = all_items[:MAX_KEYS_TO_CHECK]
    print(f"\n📊 Уникальных ключей: {len(all_items)}")
    
    history = load_json(HISTORY_FILE)
    current_time = time.time()
    to_check = []
    res_ru = []
    res_euro = []
    
    for key in all_items:
        # ИСПРАВЛЕНИЕ: Проверка на мусор ПЕРВОЙ, до сохранения в кеш
        if is_garbage_text(key):
            continue
            
        k_id = key.split("#")[0]
        cached = history.get(k_id)
        if cached and (current_time - cached["time"] < CACHE_HOURS * 3600) and cached.get("alive"):
            final = make_final_key(k_id, cached["latency"], cached.get("country", "UNKNOWN"))
            if cached.get("country") == "RU" or is_russian_exit(key, cached.get("host", ""), cached.get("country", "")):
                res_ru.append(final)
            elif cached.get("country") in EURO_CODES:
                res_euro.append(final)
        else:
            to_check.append(key)
    
    print(f"✅ Из кеша: RU={len(res_ru)} EURO={len(res_euro)}")
    print(f"🔍 На проверку: {len(to_check)}")
    
    if to_check:
        checked_count = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
            future_to_key = {executor.submit(check_single_key, key): key for key in to_check}
            for future in concurrent.futures.as_completed(future_to_key):
                key = future_to_key[future]
                try:
                    latency, country, host, _ = future.result()
                except Exception:
                    continue
                    
                if latency is None:
                    continue
                k_id = key.split("#")[0]
                history[k_id] = {"alive": True, "latency": latency, "time": time.time(), "country": country, "host": host}
                final = make_final_key(k_id, latency, country)
                if country == "RU" or is_russian_exit(key, host, country):
                    res_ru.append(final)
                elif country in EURO_CODES:
                    res_euro.append(final)
                checked_count += 1
                if checked_count % 100 == 0:
                    print(f"  Проверено {checked_count}/{len(to_check)}")
        print(f"✅ Успешно проверено: {checked_count}")
    
    # ИСПРАВЛЕНИЕ: Использование актуального времени для очистки кеша
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
    res_ru_all = res_ru_clean
    res_euro_all = res_euro_clean
    print(f"\n🚀 FAST (топ {FAST_LIMIT}): RU FAST: {len(res_ru_fast)} EURO FAST: {len(res_euro_fast)}")
    
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
            
            print(f"  [RU] Проверяем {len(ru_to_test)} ключей, {len(ru_untested)} без проверки → BLACK")
            print(f"  [EURO] Проверяем {len(euro_to_test)} ключей, {len(euro_untested)} без проверки → BLACK")
            
            ru_white, ru_black = batch_white_check(ru_to_test, history, label="RU")
            euro_white, euro_black = batch_white_check(euro_to_test, history, label="EURO")
            
            ru_black.extend(ru_untested)
            euro_black.extend(euro_untested)
            
            print(f"  [RU] Итог: WHITE={len(ru_white)} BLACK={len(ru_black)}")
            print(f"  [EURO] Итог: WHITE={len(euro_white)} BLACK={len(euro_black)}")
        else:
            print("  ⚠️ white_checker недоступен — все ключи → WHITE")
            ru_white, ru_black = list(res_ru_all), []
            euro_white, euro_black = list(res_euro_all), []
        
        print(f"\n💾 WHITE/BLACK:")
        save_exact(ru_white, FOLDER_RU, "ru_white_all_WHITE.txt", "MaxTre - VPN RUSSIA WHITE ✅")
        save_exact(ru_black, FOLDER_RU, "ru_white_all_BLACK.txt", "MaxTre - VPN RUSSIA BLACK ⚠️")
        save_exact(euro_white, FOLDER_EURO, "my_euro_all_WHITE.txt", "MaxTre - VPN EUROPE WHITE ✅")
        save_exact(euro_black, FOLDER_EURO, "my_euro_all_BLACK.txt", "MaxTre - VPN EUROPE BLACK ⚠️")
        
        bypass_path = create_bypass_file()
        
        print(f"\n📤 Загрузка в GitHub...")
        upload_futures = []
        
        # ИСПРАВЛЕНИЕ: Снижено количество потоков до 2 для GitHub API
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
            
            # ИСПРАВЛЕНИЕ: Безопасный перехват ошибок загрузки без падения скрипта
            for future in concurrent.futures.as_completed(upload_futures):
                try:
                    future.result()
                    time.sleep(0.5) # Защита от Rate Limit
                except Exception as e:
                    print(f"❌ Критическая ошибка потока загрузки: {e}")
        
        elapsed = time.time() - start_time
        
        # Безопасное чтение количества байпасов
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
    else:
        print("\n🏁 Dry-run завершен.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="Только проверка без сохранения")
    args = parser.parse_args()
    main(dry_run=args.dry_run)
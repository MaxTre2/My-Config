"""
main.py (НОВАЯ ВЕРСИЯ) - Построена на базе checker.py v5
Объединяет функциональность обоих скриптов:
- Сбор из 50+ источников (из main.py)
- Продвинутая проверка и классификация (из checker.py)
- Автоматическая загрузка в GitHub
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
from datetime import datetime
from github import Github, Auth, GithubException
from urllib.parse import quote, unquote
from collections import defaultdict

# =============================================================================
# НАСТРОЙКИ (из обоих скриптов)
# =============================================================================

# --- GitHub настройки (из main.py) ---
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "MaxTre2/My-Config"
if GITHUB_TOKEN:
    g = Github(auth=Auth.Token(GITHUB_TOKEN))
else:
    g = Github()
REPO = g.get_repo(REPO_NAME)

# --- Временная зона (из main.py) ---
zone = zoneinfo.ZoneInfo("Europe/Moscow")
thistime = datetime.now(zone)
offset = thistime.strftime("%H:%M | %d.%m.%Y")

# --- Структура папок (из checker.py) ---
BASE_DIR = "githubmirror"
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

# --- Параметры проверки (из checker.py) ---
TIMEOUT = 5
socket.setdefaulttimeout(TIMEOUT)
THREADS = 40
CACHE_HOURS = 6
CHUNK_LIMIT = 1000
EURO_CHUNK_LIMIT = 500
MAX_KEYS_TO_CHECK = 30000
MAX_PING_MS = 3000
FAST_LIMIT = 3000
MAX_HISTORY_AGE = 2 * 24 * 3600
MAX_WHITE_TEST = 200

# --- Имена выходных файлов (из checker.py) ---
RU_FILES = ["ru_white_part1.txt", "ru_white_part2.txt", "ru_white_part3.txt", "ru_white_part4.txt"]
EURO_FILES = ["my_euro_part1.txt", "my_euro_part2.txt", "my_euro_part3.txt"]

HISTORY_FILE = os.path.join(BASE_DIR, "history.json")
MY_CHANNEL = "@vlesstrojan"

# --- Флаги стран (из checker.py) ---
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
# РАСШИРЕННЫЕ ИСТОЧНИКИ (все 52 URL из main.py)
# =============================================================================

URLS = [
    # Оригинальные 25 источников
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
    
    # Дополнительные 27 источников
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
    "https://raw.githubusercontent.com/amini8k/Free-Configs/main/vless.txt",
    "https://raw.githubusercontent.com/amini8k/Free-Configs/main/vmess.txt",
    "https://raw.githubusercontent.com/amini8k/Free-Configs/main/trojan.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/vless.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/vmess.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/trojan.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/XHTTP_Reality.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/xhttp_reality.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/xhttp",
    "https://raw.githubusercontent.com/NiREvil/vless/main/xhttp.txt",
]

# =============================================================================
# ДОПОЛНИТЕЛЬНЫЕ ИСТОЧНИКИ ДЛЯ БАЙПАСА (из main.py)
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
    "https://wlrus.lol/confs/selected.txt"
]

# =============================================================================
# ЖЁСТКИЙ ФИЛЬТР (из checker.py)
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
# БЕЛЫЙ СПИСОК ДОМЕНОВ (из checker.py)
# =============================================================================
WHITELIST_DOMAINS = [
    "alfabank.ru", "vtb.ru", "psbank.ru", "mts-bank.ru",
    "sberbank.ru", "tinkoff.ru", "raiffeisen.ru", "gazprombank.ru",
    "gosuslugi.ru", "mos.ru", "nalog.ru", "pfr.gov.ru",
    "cbr.ru", "minfin.ru", "egov.ru",
    "wildberries.ru", "ozon.ru", "lamoda.ru", "mvideo.ru",
    "avito.ru", "youla.ru",
    "5ka.ru", "x5.ru", "perekrestok.ru",
    "vkusnoitochka.ru", "burgerking.ru", "kfc.ru",
    "mts.ru", "beeline.ru", "megafon.ru", "tele2.ru",
    "zdravcity.ru", "apteka.ru", "eapteka.ru",
]

# =============================================================================
# HTTP клиент с повторными попытками (из main.py)
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
# ФИЛЬТРЫ (из checker.py)
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
    """Фильтрует конфиги с allowInsecure параметрами"""
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
# JSON-КЕШ (из checker.py)
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
# ОПРЕДЕЛЕНИЕ СТРАНЫ (из checker.py)
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
# ЗАГРУЗКА КЛЮЧЕЙ (адаптированная из checker.py)
# =============================================================================

def fetch_keys(urls: list) -> list:
    out = []
    print(f"📥 Загрузка {len(urls)} источников...")
    for i, url in enumerate(urls, 1):
        try:
            data = fetch_data(url, timeout=15, max_attempts=2)
            if not data:
                continue
            
            # Фильтрация небезопасных
            data, filtered = filter_insecure_configs(data, log_enabled=False)
            
            # Парсинг
            if "://" not in data:
                try:
                    lines = base64.b64decode(data + "==").decode("utf-8", errors="ignore").splitlines()
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
# TCP/TLS/WS ПРОВЕРКА (из checker.py)
# =============================================================================

def check_single_key(key: str):
    try:
        if "@" not in key or ":" not in key:
            return None, None, None, None

        part = key.split("@")[1].split("?")[0].split("#")[0]
        host_port = part.rsplit(":", 1)
        if len(host_port) != 2:
            return None, None, None, None
        host, port = host_port[0].strip("[]"), int(host_port[1])

        country = get_country_fast(host, key)

        is_tls = (
            "security=tls" in key
            or "security=reality" in key
            or key.startswith("trojan://")
            or key.startswith("vmess://")
        )
        is_ws = "type=ws" in key or "net=ws" in key

        path = "/"
        m = re.search(r"path=([^&]+)", key)
        if m:
            path = unquote(m.group(1))

        start = time.time()

        if is_ws:
            protocol = "wss" if is_tls else "ws"
            ws_url = f"{protocol}://{host}:{port}{path}"
            ws = websocket.create_connection(
                ws_url,
                timeout=TIMEOUT,
                sslopt={"cert_reqs": ssl.CERT_NONE},
                sockopt=((socket.SOL_SOCKET, socket.SO_RCVTIMEO, TIMEOUT),),
            )
            ws.close()
        elif is_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    pass
        else:
            with socket.create_connection((host, port), timeout=TIMEOUT):
                pass

        latency = int((time.time() - start) * 1000)
        return latency, country, host, key

    except Exception:
        return None, None, None, None

# =============================================================================
# ФОРМИРОВАНИЕ ФИНАЛЬНОГО КЛЮЧА (из checker.py)
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

# =============================================================================
# СОХРАНЕНИЕ ФАЙЛОВ (из checker.py + main.py)
# =============================================================================

def save_exact(keys: list, folder: str, filename: str) -> str:
    if not keys:
        keys = ["# Нет рабочих ключей"]
    path = os.path.join(folder, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(k for k in keys if k and k.strip()))
    return path

def save_fixed_chunks_ru(keys_list: list, folder: str) -> list:
    valid = [k.strip() for k in keys_list if k and k.strip()]
    chunks = [valid[i:i + CHUNK_LIMIT] for i in range(0, min(len(valid), CHUNK_LIMIT * 4), CHUNK_LIMIT)]
    while len(chunks) < 4:
        chunks.append([])
    for i, fname in enumerate(RU_FILES):
        chunk = chunks[i] if i < len(chunks) else []
        save_exact(chunk, folder, fname)
        print(f"  {fname}: {len(chunk)} ключей")
    return RU_FILES

def save_fixed_chunks_euro(keys_list: list, folder: str) -> list:
    valid = [k.strip() for k in keys_list if k and k.strip()]
    chunks = [valid[i:i + EURO_CHUNK_LIMIT]
              for i in range(0, min(len(valid), EURO_CHUNK_LIMIT * 3), EURO_CHUNK_LIMIT)]
    while len(chunks) < 3:
        chunks.append([])
    for i, fname in enumerate(EURO_FILES):
        chunk = chunks[i] if i < len(chunks) else []
        save_exact(chunk, folder, fname)
        print(f"  {fname}: {len(chunk)} ключей")
    return EURO_FILES

def save_chunked(keys_list: list, folder: str, base_name: str, chunk_size: int = None) -> list:
    if chunk_size is None:
        chunk_size = CHUNK_LIMIT
    valid = [k.strip() for k in keys_list if k and k.strip()]
    chunks = [valid[i:i + chunk_size] for i in range(0, len(valid), chunk_size)]
    names = []
    for idx, chunk in enumerate(chunks, start=1):
        fname = f"{base_name}_part{idx}.txt"
        save_exact(chunk, folder, fname)
        names.append(fname)
        print(f"  {fname}: {len(chunk)} ключей")
    return names

# =============================================================================
# ЗАГРУЗКА В GITHUB (из main.py)
# =============================================================================

updated_files = set()
_UPDATED_FILES_LOCK = threading.Lock()

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
                    REPO.create_file(
                        path=remote_path,
                        message=f"🆕 Создан {remote_path} {offset}",
                        content=content,
                    )
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

            REPO.update_file(
                path=remote_path,
                message=f"🚀 Обновление {remote_path} {offset}",
                content=content,
                sha=current_sha,
            )
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
# ОБНОВЛЕНИЕ README.md (из main.py, адаптированное)
# =============================================================================

def update_readme_table():
    try:
        try:
            readme_file = REPO.get_contents("README.md")
            old_content = readme_file.decoded_content.decode("utf-8")
        except GithubException as e:
            if e.status == 404:
                print("❌ README.md не найден")
                return
            else:
                print(f"⚠️ Ошибка при получении README.md: {e}")
                return

        time_part, date_part = offset.split(" | ")

        # Собираем все сгенерированные файлы
        all_files = []
        # RU FAST
        for f in RU_FILES:
            all_files.append((f, FOLDER_RU))
        # EURO FAST
        for f in EURO_FILES:
            all_files.append((f, FOLDER_EURO))
        # ALL chunks
        for f in os.listdir(FOLDER_RU):
            if f.startswith("ru_white_all_part"):
                all_files.append((f, FOLDER_RU))
        for f in os.listdir(FOLDER_EURO):
            if f.startswith("my_euro_all_part"):
                all_files.append((f, FOLDER_EURO))
        # WHITE/BLACK
        all_files.append(("ru_white_all_WHITE.txt", FOLDER_RU))
        all_files.append(("ru_white_all_BLACK.txt", FOLDER_RU))
        all_files.append(("my_euro_all_WHITE.txt", FOLDER_EURO))
        all_files.append(("my_euro_all_BLACK.txt", FOLDER_EURO))

        table_header = "| Файл | Папка | Размер | Обновлено |\n|--|--|--|--|"
        table_rows = []

        for filename, folder in all_files:
            local_path = os.path.join(folder, filename)
            if os.path.exists(local_path):
                size = os.path.getsize(local_path)
                size_kb = size // 1024
                raw_url = f"https://github.com/{REPO_NAME}/raw/refs/heads/main/{folder}/{filename}"
                table_rows.append(
                    f"| [`{filename}`]({raw_url}) | {folder.split('/')[-1]} | {size_kb} KB | {time_part} {date_part} |"
                )

        new_table = table_header + "\n" + "\n".join(table_rows)

        # Заменяем таблицу в README
        table_pattern = r"\| Файл \| Папка \| Размер \| Обновлено \|[\s\S]*?(\n\n## |$)"
        new_content = re.sub(table_pattern, new_table + r"\1", old_content)

        if new_content != old_content:
            REPO.update_file(
                path="README.md",
                message=f"📝 Обновление таблицы {offset}",
                content=new_content,
                sha=readme_file.sha
            )
            print("📝 README.md обновлен")
        else:
            print("📝 README.md без изменений")

    except Exception as e:
        print(f"⚠️ Ошибка при обновлении README.md: {e}")

# =============================================================================
# ГЕНЕРАЦИЯ SUBCRIPTIONS_LIST.TXT (из checker.py, адаптированная)
# =============================================================================

def generate_subscriptions_list() -> str:
    GITHUB_USER_REPO = REPO_NAME
    BRANCH = "main"
    BASE_RAW = f"https://raw.githubusercontent.com/{GITHUB_USER_REPO}/{BRANCH}"

    lines = []

    # FAST слой
    lines += ["=== 🇷🇺 RUSSIA (FAST) ==="]
    lines += [f"{BASE_RAW}/githubmirror/RU_Best/{f}" for f in RU_FILES]
    lines += [""]

    lines += ["=== 🇪🇺 EUROPE (FAST) ==="]
    lines += [f"{BASE_RAW}/githubmirror/My_Euro/{f}" for f in EURO_FILES]
    lines += [""]

    # ALL слой
    lines += ["=== 🇷🇺 RUSSIA (ALL) ==="]
    ru_all = sorted(
        f for f in os.listdir(FOLDER_RU)
        if f.startswith("ru_white_all_part") and f.endswith(".txt")
    )
    lines += [f"{BASE_RAW}/githubmirror/RU_Best/{f}" for f in ru_all[:2]]
    lines += [""]

    lines += ["=== 🇪🇺 EUROPE (ALL) ==="]
    eu_all = sorted(
        f for f in os.listdir(FOLDER_EURO)
        if f.startswith("my_euro_all_part") and f.endswith(".txt")
    )
    lines += [f"{BASE_RAW}/githubmirror/My_Euro/{f}" for f in eu_all[:2]]
    lines += [""]

    # WHITE слой
    lines += ["=== ✅ WHITE RUSSIA (ALL) ==="]
    lines += [f"{BASE_RAW}/githubmirror/RU_Best/ru_white_all_WHITE.txt", ""]

    lines += ["=== ✅ WHITE EUROPE (ALL) ==="]
    lines += [f"{BASE_RAW}/githubmirror/My_Euro/my_euro_all_WHITE.txt", ""]

    # BLACK слой
    lines += ["=== ⚠️ BLACK RUSSIA (ALL) ==="]
    lines += [f"{BASE_RAW}/githubmirror/RU_Best/ru_white_all_BLACK.txt", ""]

    lines += ["=== ⚠️ BLACK EUROPE (ALL) ==="]
    lines += [f"{BASE_RAW}/githubmirror/My_Euro/my_euro_all_BLACK.txt"]

    path = os.path.join(BASE_DIR, "subscriptions_list.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    http_count = sum(1 for l in lines if l.startswith("http"))
    print(f"\n📋 subscriptions_list.txt: {http_count} ссылок")
    return path

# =============================================================================
# СОЗДАНИЕ БАЙПАС ФАЙЛА (из main.py, адаптированное)
# =============================================================================

def create_bypass_file():
    """Создает ByPassVpnLera.txt с конфигами для SNI/CIDR белых списков"""
    bypass_path = os.path.join(BASE_DIR, "ByPassVpnLera.txt")
    
    # Собираем конфиги из extra источников
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
    
    # Дедупликация
    unique_configs = list(set(all_configs))
    
    # Сохраняем
    title = "MaxTre - VPN Bypass"
    title_base64 = base64.b64encode(title.encode('utf-8')).decode('utf-8')
    
    header = f"#profile-title: base64:{title_base64}\n"
    header += "#profile-update-interval: 3\n"
    header += f"# {title}\n"
    header += f"# Конфигов: {len(unique_configs)}\n"
    header += f"# Обновлено: {offset}\n\n"
    
    with open(bypass_path, "w", encoding="utf-8") as file:
        file.write(header + "\n".join(unique_configs))
    
    print(f"📁 Создан {bypass_path} с {len(unique_configs)} конфигами")
    return bypass_path

# =============================================================================
# ОСНОВНАЯ ФУНКЦИЯ
# =============================================================================

def main(dry_run=False):
    print("=" * 60)
    print("  🚀 MAIN.PY НОВАЯ ВЕРСИЯ (на базе checker.py v5)")
    print("=" * 60)
    
    # --------------------------------------------------------------------------
    # 1. Загрузка ключей
    # --------------------------------------------------------------------------
    all_keys = fetch_keys(URLS)
    
    # Дедупликация
    unique_keys = {}
    for k in all_keys:
        k_id = k.split("#")[0]
        if k_id not in unique_keys:
            unique_keys[k_id] = k
    all_items = list(unique_keys.values())
    
    if len(all_items) > MAX_KEYS_TO_CHECK:
        all_items = all_items[:MAX_KEYS_TO_CHECK]
    
    print(f"\n📊 Уникальных ключей: {len(all_items)}")
    
    # --------------------------------------------------------------------------
    # 2. Кеш
    # --------------------------------------------------------------------------
    history = load_json(HISTORY_FILE)
    current_time = time.time()
    to_check = []
    res_ru = []
    res_euro = []
    
    for key in all_items:
        k_id = key.split("#")[0]
        cached = history.get(k_id)
        
        if cached and (current_time - cached["time"] < CACHE_HOURS * 3600) and cached.get("alive"):
            latency = cached["latency"]
            country = cached.get("country", "UNKNOWN")
            host = cached.get("host", "")
            final = make_final_key(k_id, latency, country)
            
            if country == "RU" or is_russian_exit(key, host, country):
                res_ru.append(final)
            elif country in EURO_CODES:
                res_euro.append(final)
        else:
            to_check.append(key)
    
    print(f"✅ Из кеша: RU={len(res_ru)} EURO={len(res_euro)}")
    print(f"🔍 На проверку: {len(to_check)}")
    
    # --------------------------------------------------------------------------
    # 3. Параллельная проверка
    # --------------------------------------------------------------------------
    if to_check:
        checked_count = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
            future_to_key = {executor.submit(check_single_key, key): key for key in to_check}
            
            for future in concurrent.futures.as_completed(future_to_key):
                key = future_to_key[future]
                latency, country, host, _ = future.result()
                
                if latency is None:
                    continue
                
                k_id = key.split("#")[0]
                history[k_id] = {
                    "alive": True,
                    "latency": latency,
                    "time": time.time(),
                    "country": country,
                    "host": host,
                }
                
                final = make_final_key(k_id, latency, country)
                
                if country == "RU" or is_russian_exit(key, host, country):
                    res_ru.append(final)
                elif country in EURO_CODES:
                    res_euro.append(final)
                
                checked_count += 1
        
        print(f"✅ Успешно проверено: {checked_count}")
    
    # --------------------------------------------------------------------------
    # 4. Очистка истории
    # --------------------------------------------------------------------------
    save_json(HISTORY_FILE, {
        k: v for k, v in history.items()
        if current_time - v["time"] < MAX_HISTORY_AGE
    })
    
    # --------------------------------------------------------------------------
    # 5. Фильтрация по пингу
    # --------------------------------------------------------------------------
    res_ru_clean = [k for k in res_ru if extract_ping(k) is not None and extract_ping(k) <= MAX_PING_MS]
    res_euro_clean = [k for k in res_euro if extract_ping(k) is not None and extract_ping(k) <= MAX_PING_MS]
    
    res_ru_clean.sort(key=extract_ping)
    res_euro_clean.sort(key=extract_ping)
    
    print(f"\n📈 После фильтрации (≤{MAX_PING_MS}ms):")
    print(f"  RU:   {len(res_ru_clean)}")
    print(f"  EURO: {len(res_euro_clean)}")
    
    # --------------------------------------------------------------------------
    # 6. FAST / ALL слои
    # --------------------------------------------------------------------------
    res_ru_fast = res_ru_clean[:FAST_LIMIT]
    res_euro_fast = res_euro_clean[:FAST_LIMIT]
    res_ru_all = res_ru_clean
    res_euro_all = res_euro_clean
    
    # --------------------------------------------------------------------------
    # 7. Сохранение файлов (если не dry-run)
    # --------------------------------------------------------------------------
    if not dry_run:
        print(f"\n💾 Сохранение файлов...")
        
        # RU FAST
        print(f"\n📁 {FOLDER_RU}:")
        save_fixed_chunks_ru(res_ru_fast, FOLDER_RU)
        
        # EURO FAST
        print(f"\n📁 {FOLDER_EURO}:")
        save_fixed_chunks_euro(res_euro_fast, FOLDER_EURO)
        
        # ALL chunks
        print(f"\n📁 ALL RU:")
        save_chunked(res_ru_all, FOLDER_RU, "ru_white_all")
        print(f"\n📁 ALL EURO:")
        save_chunked(res_euro_all, FOLDER_EURO, "my_euro_all", chunk_size=EURO_CHUNK_LIMIT)
        
        # WHITE/BLACK (пока без реальной проверки, все в WHITE)
        print(f"\n📁 WHITE/BLACK (все в WHITE):")
        save_exact(res_ru_all, FOLDER_RU, "ru_white_all_WHITE.txt")
        save_exact([], FOLDER_RU, "ru_white_all_BLACK.txt")
        save_exact(res_euro_all, FOLDER_EURO, "my_euro_all_WHITE.txt")
        save_exact([], FOLDER_EURO, "my_euro_all_BLACK.txt")
        
        # Bypass файл
        bypass_path = create_bypass_file()
        
        # ----------------------------------------------------------------------
        # 8. Загрузка в GitHub
        # ----------------------------------------------------------------------
        print(f"\n📤 Загрузка в GitHub...")
        
        upload_futures = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            # Загружаем все файлы из RU_Best
            for f in os.listdir(FOLDER_RU):
                if f.endswith('.txt'):
                    local = os.path.join(FOLDER_RU, f)
                    remote = f"githubmirror/RU_Best/{f}"
                    upload_futures.append(executor.submit(upload_to_github, local, remote))
            
            # Загружаем все файлы из My_Euro
            for f in os.listdir(FOLDER_EURO):
                if f.endswith('.txt'):
                    local = os.path.join(FOLDER_EURO, f)
                    remote = f"githubmirror/My_Euro/{f}"
                    upload_futures.append(executor.submit(upload_to_github, local, remote))
            
            # Загружаем bypass файл
            upload_futures.append(executor.submit(upload_to_github, bypass_path, "githubmirror/ByPassVpnLera.txt"))
            
            # Загружаем history.json
            upload_futures.append(executor.submit(upload_to_github, HISTORY_FILE, "githubmirror/history.json"))
            
            # Загружаем subscriptions_list.txt
            sub_path = generate_subscriptions_list()
            upload_futures.append(executor.submit(upload_to_github, sub_path, "githubmirror/subscriptions_list.txt"))
            
            for future in concurrent.futures.as_completed(upload_futures):
                future.result()
        
        # ----------------------------------------------------------------------
        # 9. Обновление README
        # ----------------------------------------------------------------------
        update_readme_table()
        
        print("\n" + "=" * 60)
        print("  ✅  SUCCESS")
        print("=" * 60)
        print(f"  RU  FAST  : {len(res_ru_fast)}")
        print(f"  RU  ALL   : {len(res_ru_all)}")
        print(f"  EU  FAST  : {len(res_euro_fast)}")
        print(f"  EU  ALL   : {len(res_euro_all)}")
        print("=" * 60)
    else:
        print("\n🏁 Dry-run завершен. Файлы не сохранены и не загружены.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="Только проверка без сохранения")
    args = parser.parse_args()
    main(dry_run=args.dry_run)
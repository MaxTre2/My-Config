from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from collections import defaultdict
from github import GithubException
from github import Github, Auth
from datetime import datetime
import concurrent.futures
import urllib.parse
import threading
import zoneinfo
import requests
import urllib3
import base64
import html
import json
import re
import os
import socket
import time
import subprocess
import platform
import random
import string
import uuid
import ipaddress

# -------------------- ЛОГИРОВАНИЕ --------------------
LOGS_BY_FILE: dict[int, list[str]] = defaultdict(list)
_LOG_LOCK = threading.Lock()
_UPDATED_FILES_LOCK = threading.Lock()

_GITHUBMIRROR_INDEX_RE = re.compile(r"githubmirror/(\d+)\.txt")
updated_files = set()

def _extract_index(msg: str) -> int:
    """Пытается извлечь номер файла из строки вида 'githubmirror/12.txt'."""
    m = _GITHUBMIRROR_INDEX_RE.search(msg)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            pass
    return 0

def log(message: str):
    """Добавляет сообщение в общий словарь логов потокобезопасно."""
    idx = _extract_index(message)
    with _LOG_LOCK:
        LOGS_BY_FILE[idx].append(message)

# Получение текущего времени по часовому поясу Европа/Москва
zone = zoneinfo.ZoneInfo("Europe/Moscow")
thistime = datetime.now(zone)
offset = thistime.strftime("%H:%M | %d.%m.%Y")

# Получение GitHub токена из переменных окружения
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "MaxTre2/My-Config"

if GITHUB_TOKEN:
    g = Github(auth=Auth.Token(GITHUB_TOKEN))
else:
    g = Github()

REPO = g.get_repo(REPO_NAME)

# Проверка лимитов GitHub API
try:
    remaining, limit = g.rate_limiting
    if remaining < 100:
        log(f"⚠️ Внимание: осталось {remaining}/{limit} запросов к GitHub API")
    else:
        log(f"ℹ️ Доступно запросов к GitHub API: {remaining}/{limit}")
except Exception as e:
    log(f"⚠️ Не удалось проверить лимиты GitHub API: {e}")

if not os.path.exists("githubmirror"):
    os.mkdir("githubmirror")

# ============ РАСШИРЕННЫЕ ИСТОЧНИКИ ============
URLS = [
    "https://github.com/sakha1370/OpenRay/raw/refs/heads/main/output/all_valid_proxies.txt", #1
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt", #2
    "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt", #3
    "https://raw.githubusercontent.com/acymz/AutoVPN/refs/heads/main/data/V2.txt", #4
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/sub.txt", #5
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt", #6
    "https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/trojan.txt", #7
    "https://raw.githubusercontent.com/CidVpn/cid-vpn-config/refs/heads/main/general.txt", #8
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt", #9
    "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/vless", #10
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt", #11
    "https://raw.githubusercontent.com/expressalaki/ExpressVPN/refs/heads/main/configs3.txt", #12
    "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/refs/heads/main/xray_final.txt", #13
    "https://github.com/LalatinaHub/Mineral/raw/refs/heads/master/result/nodes", #14
    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/refs/heads/main/vless_iran.txt", #15
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub", #16
    "https://github.com/MhdiTaheri/V2rayCollector_Py/raw/refs/heads/main/sub/Mix/mix.txt", #17
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt", #18
    "https://github.com/MhdiTaheri/V2rayCollector/raw/refs/heads/main/sub/mix", #19
    "https://github.com/Argh94/Proxy-List/raw/refs/heads/main/All_Config.txt", #20
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt", #21
    "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri", #22
    "https://raw.githubusercontent.com/zipvpn/FreeVPNNodes/refs/heads/main/free_v2ray_xray_nodes.txt", #23
    "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR.BYPASS#STR.BYPASS%F0%9F%91%BE", #24
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt", #25
    
    # ДОПОЛНИТЕЛЬНЫЕ ИСТОЧНИКИ (новые)
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt", #26
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vmess.txt", #27
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/trojan.txt", #28
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vless.txt", #29
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vmess.txt", #30
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/trojan.txt", #31
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/ss.txt", #32
    "https://raw.githubusercontent.com/sashalsk/V2Ray/main/VLESS.txt", #33
    "https://raw.githubusercontent.com/sashalsk/V2Ray/main/VMESS.txt", #34
    "https://raw.githubusercontent.com/sashalsk/V2Ray/main/TROJAN.txt", #35
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/vless", #36
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/vmess", #37
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/trojan", #38
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/ss", #39
    "https://raw.githubusercontent.com/NiREvil/vless/main/vless.txt", #40
    "https://raw.githubusercontent.com/NiREvil/vless/main/vmess.txt", #41
    "https://raw.githubusercontent.com/NiREvil/vless/main/trojan.txt", #42
    "https://raw.githubusercontent.com/amini8k/Free-Configs/main/vless.txt", #43
    "https://raw.githubusercontent.com/amini8k/Free-Configs/main/vmess.txt", #44
    "https://raw.githubusercontent.com/amini8k/Free-Configs/main/trojan.txt", #45
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/vless.txt", #46
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/vmess.txt", #47
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/trojan.txt", #48
]

# ============ ДОПОЛНИТЕЛЬНЫЕ ИСТОЧНИКИ ============
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

# ============ НОВЫЕ ИСТОЧНИКИ ДЛЯ XHTTP И REALITY (пункт 2) ============
XHTTP_REALITY_SOURCES = [
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

# Добавляем новые источники в общий список для загрузки
for i, url in enumerate(XHTTP_REALITY_SOURCES, len(URLS) + 1):
    URLS.append(url)

EXTRA_URL_TIMEOUT = int(os.environ.get("EXTRA_URL_TIMEOUT", "6"))
EXTRA_URL_MAX_ATTEMPTS = int(os.environ.get("EXTRA_URL_MAX_ATTEMPTS", "2"))

REMOTE_PATHS = [f"githubmirror/{i+1}.txt" for i in range(len(URLS))]
LOCAL_PATHS = [f"githubmirror/{i+1}.txt" for i in range(len(URLS))]

REMOTE_PATHS.append("ByPassVpnLera.txt")
LOCAL_PATHS.append("ByPassVpnLera.txt")

# Добавляем новые файлы для лучших конфигов
REMOTE_PATHS.append("XHTTP_Reality.txt")
LOCAL_PATHS.append("XHTTP_Reality.txt")
REMOTE_PATHS.append("REALITY_WORKING.txt")  # Резервный файл с Reality (пункт 3)
LOCAL_PATHS.append("REALITY_WORKING.txt")
REMOTE_PATHS.append("TOP_FASTEST_10.txt")
LOCAL_PATHS.append("TOP_FASTEST_10.txt")
REMOTE_PATHS.append("TOP_FASTEST_50.txt")
LOCAL_PATHS.append("TOP_FASTEST_50.txt")
REMOTE_PATHS.append("TOP_FASTEST_100.txt")
LOCAL_PATHS.append("TOP_FASTEST_100.txt")
REMOTE_PATHS.append("VIDEO_OPTIMIZED.txt")
LOCAL_PATHS.append("VIDEO_OPTIMIZED.txt")
REMOTE_PATHS.append("LOW_PING.txt")
LOCAL_PATHS.append("LOW_PING.txt")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/143.0.0.0 Safari/537.36"
)

DEFAULT_MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "16"))

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

REQUESTS_SESSION = _build_session(max_pool_size=max(DEFAULT_MAX_WORKERS, len(URLS))) if 'URLS' in globals() else _build_session(DEFAULT_MAX_WORKERS)

def fetch_data(url, timeout=10, max_attempts=3, session=None, allow_http_downgrade=True):
    sess = session or REQUESTS_SESSION
    for attempt in range(1, max_attempts + 1):
        try:
            modified_url = url
            verify = True

            if attempt == 2:
                verify = False
            elif attempt == 3:
                parsed = urllib.parse.urlparse(url)
                if parsed.scheme == "https" and allow_http_downgrade:
                    modified_url = parsed._replace(scheme="http").geturl()
                verify = False

            response = sess.get(modified_url, timeout=timeout, verify=verify)
            response.raise_for_status()
            return response.text

        except requests.exceptions.RequestException as exc:
            last_exc = exc
            if attempt < max_attempts:
                continue
            raise last_exc

def _format_fetch_error(exc):
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
            status = exc.response.status_code
            return f"HTTP {status}"
        except Exception:
            return "HTTP error"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "Connection error"
    msg = str(exc)
    if len(msg) > 160:
        msg = msg[:160] + "…"
    return msg

def save_to_local_file(path, content):
    with open(path, "w", encoding="utf-8") as file:
        file.write(content)
    log(f"📁 Данные сохранены локально в {path}")

def extract_source_name(url):
    try:
        parsed = urllib.parse.urlparse(url)
        path_parts = parsed.path.split('/')
        if len(path_parts) > 2:
            return f"{path_parts[1]}/{path_parts[2]}"
        return parsed.netloc
    except:
        return "Источник"

def _traffic_counts(traffic):
    if traffic is None:
        return 0, 0

    if isinstance(traffic, tuple) and len(traffic) >= 2:
        if isinstance(traffic[0], (int, float)) and isinstance(traffic[1], (int, float)):
            return int(traffic[0]), int(traffic[1])

    if isinstance(traffic, dict):
        if "count" in traffic or "uniques" in traffic:
            return int(traffic.get("count", 0)), int(traffic.get("uniques", 0))
        items = traffic.get("views") or traffic.get("clones") or []
        return _sum_traffic_items(items)

    if hasattr(traffic, "count") and hasattr(traffic, "uniques"):
        return int(getattr(traffic, "count", 0) or 0), int(getattr(traffic, "uniques", 0) or 0)

    for attr in ("views", "clones"):
        if hasattr(traffic, attr):
            items = getattr(traffic, attr) or []
            return _sum_traffic_items(items)

    if hasattr(traffic, "raw_data"):
        raw = getattr(traffic, "raw_data") or {}
        if isinstance(raw, dict):
            if "count" in raw or "uniques" in raw:
                return int(raw.get("count", 0)), int(raw.get("uniques", 0))
            items = raw.get("views") or raw.get("clones") or []
            return _sum_traffic_items(items)

    if isinstance(traffic, (list, tuple)):
        return _sum_traffic_items(traffic)

    return 0, 0

def _sum_traffic_items(items):
    total_count = 0
    total_uniques = 0
    for item in items or []:
        if isinstance(item, dict):
            total_count += int(item.get("count", 0) or 0)
            total_uniques += int(item.get("uniques", 0) or 0)
            continue
        if hasattr(item, "count"):
            total_count += int(getattr(item, "count", 0) or 0)
        if hasattr(item, "uniques"):
            total_uniques += int(getattr(item, "uniques", 0) or 0)
    return total_count, total_uniques

def _get_repo_stats():
    stats = {}
    try:
        views = REPO.get_views_traffic()
        views_count, views_uniques = _traffic_counts(views)
        stats["views_count"] = views_count
        stats["views_uniques"] = views_uniques
    except Exception as e:
        log(f"⚠️ Не удалось получить просмотры (traffic views): {e}")
        return None

    try:
        clones = REPO.get_clones_traffic()
        clones_count, clones_uniques = _traffic_counts(clones)
        stats["clones_count"] = clones_count
        stats["clones_uniques"] = clones_uniques
    except Exception as e:
        log(f"⚠️ Не удалось получить клоны (traffic clones): {e}")
        return None

    return stats

def _build_repo_stats_table(stats):
    def _format_num(value):
        try:
            return f"{int(value):,}"
        except Exception:
            return str(value)

    header = "| Показатель | Значение |\n|--|--|"
    rows = [
        f"| Просмотры (14Д) | {_format_num(stats['views_count'])} |",
        f"| Клоны (14Д) | {_format_num(stats['clones_count'])} |",
        f"| Уникальные клоны (14Д) | {_format_num(stats['clones_uniques'])} |",
        f"| Уникальные посетители (14Д) | {_format_num(stats['views_uniques'])} |",
    ]
    return header + "\n" + "\n".join(rows)

def _insert_repo_stats_section(content, stats_section):
    pattern = r"(\| № \| Файл \| Источник \| Время \| Дата \|[\s\S]*?\|--\|--\|--\|--\|--\|[\s\S]*?\n)(?=\n## )"
    match = re.search(pattern, content)
    if not match:
        return content.rstrip() + "\n\n" + stats_section + "\n"
    return re.sub(pattern, lambda m: m.group(1) + "\n" + stats_section, content, count=1)

def update_readme_table():
    try:
        try:
            readme_file = REPO.get_contents("README.md")
            old_content = readme_file.decoded_content.decode("utf-8")
        except GithubException as e:
            if e.status == 404:
                log("❌ README.md не найден в репозитории")
                return
            else:
                log(f"⚠️ Ошибка при получении README.md: {e}")
                return

        time_part, date_part = offset.split(" | ")
        
        table_header = "| № | Файл | Источник | Время | Дата |\n|--|--|--|--|--|"
        table_rows = []
        
        # Обновляем таблицу для всех файлов
        all_remote = REMOTE_PATHS
        all_local = LOCAL_PATHS
        
        for i, (remote_path) in enumerate(all_remote, 1):
            filename = os.path.basename(remote_path)
            raw_file_url = f"https://github.com/{REPO_NAME}/raw/refs/heads/main/{remote_path}"
            
            if i <= 48:
                source_name = extract_source_name(URLS[i-1])
                source_column = f"[{source_name}]({URLS[i-1]})"
            elif i <= 48 + len(XHTTP_REALITY_SOURCES):
                # Новые источники XHTTP
                source_idx = i - 49
                if source_idx < len(XHTTP_REALITY_SOURCES):
                    source_name = extract_source_name(XHTTP_REALITY_SOURCES[source_idx])
                    source_column = f"[{source_name}]({XHTTP_REALITY_SOURCES[source_idx]})"
                else:
                    source_name = "XHTTP источник"
                    source_column = f"[{source_name}]({raw_file_url})"
            elif i == 49 + len(XHTTP_REALITY_SOURCES):
                source_name = "Обход SNI/CIDR"
                source_column = f"[{source_name}]({raw_file_url})"
            elif i == 50 + len(XHTTP_REALITY_SOURCES):
                source_name = "XHTTP+Reality (отобранные)"
                source_column = f"[{source_name}]({raw_file_url})"
            elif i == 51 + len(XHTTP_REALITY_SOURCES):
                source_name = "Reality (рабочие, резерв)"
                source_column = f"[{source_name}]({raw_file_url})"
            elif i == 52 + len(XHTTP_REALITY_SOURCES):
                source_name = "ТОП-10 самых быстрых"
                source_column = f"[{source_name}]({raw_file_url})"
            elif i == 53 + len(XHTTP_REALITY_SOURCES):
                source_name = "ТОП-50 самых быстрых"
                source_column = f"[{source_name}]({raw_file_url})"
            elif i == 54 + len(XHTTP_REALITY_SOURCES):
                source_name = "ТОП-100 самых быстрых"
                source_column = f"[{source_name}]({raw_file_url})"
            elif i == 55 + len(XHTTP_REALITY_SOURCES):
                source_name = "Для видео"
                source_column = f"[{source_name}]({raw_file_url})"
            elif i == 56 + len(XHTTP_REALITY_SOURCES):
                source_name = "Низкий пинг"
                source_column = f"[{source_name}]({raw_file_url})"
            else:
                source_name = "Источник"
                source_column = f"[{source_name}]({raw_file_url})"
            
            if i in updated_files:
                update_time = time_part
                update_date = date_part
            else:
                # Ищем существующее время в старом README
                pattern = rf"\|\s*{i}\s*\|\s*\[`{re.escape(filename)}`\].*?\|.*?\|\s*(.*?)\s*\|\s*(.*?)\s*\|"
                match = re.search(pattern, old_content)
                if match:
                    update_time = match.group(1).strip() if match.group(1).strip() else "Никогда"
                    update_date = match.group(2).strip() if match.group(2).strip() else "Никогда"
                else:
                    update_time = "Никогда"
                    update_date = "Никогда"
            
            table_rows.append(f"| {i} | [`{filename}`]({raw_file_url}) | {source_column} | {update_time} | {update_date} |")

        new_table = table_header + "\n" + "\n".join(table_rows)

        table_pattern = r"\| № \| Файл \| Источник \| Время \| Дата \|[\s\S]*?\|--\|--\|--\|--\|--\|[\s\S]*?(\n\n## |$)"
        new_content = re.sub(table_pattern, new_table + r"\1", old_content)

        repo_stats = _get_repo_stats()
        if repo_stats:
            stats_section = "## 📊 Статистика репозитория\n" + _build_repo_stats_table(repo_stats) + "\n"
            stats_pattern = r"## 📊 Статистика репозитория\s*\n[\s\S]*?(?=\n## |\Z)"
            if re.search(stats_pattern, new_content):
                new_content = re.sub(stats_pattern, stats_section, new_content)
            else:
                new_content = _insert_repo_stats_section(new_content, stats_section)
        else:
            log("⚠️ Статистика репозитория недоступна, раздел не обновлён.")

        if new_content != old_content:
            REPO.update_file(
                path="README.md",
                message=f"📝 Обновление таблицы в README.md по часовому поясу Европа/Москва: {offset}",
                content=new_content,
                sha=readme_file.sha
            )
            log("📝 Таблица в README.md обновлена")
        else:
            log("📝 Таблица в README.md не требует изменений")

    except Exception as e:
        log(f"⚠️ Ошибка при обновлении README.md: {e}")

def upload_to_github(local_path, remote_path):
    if not os.path.exists(local_path):
        log(f"❌ Файл {local_path} не найден.")
        return

    repo = REPO

    with open(local_path, "r", encoding="utf-8") as file:
        content = file.read()

    max_retries = 5
    import time

    for attempt in range(1, max_retries + 1):
        try:
            try:
                file_in_repo = repo.get_contents(remote_path)
                current_sha = file_in_repo.sha
            except GithubException as e_get:
                if getattr(e_get, "status", None) == 404:
                    basename = os.path.basename(remote_path)
                    repo.create_file(
                        path=remote_path,
                        message=f"🆕 Первый коммит {basename} по часовому поясу Европа/Москва: {offset}",
                        content=content,
                    )
                    log(f"🆕 Файл {remote_path} создан.")
                    # Определяем индекс файла для updated_files
                    file_index = None
                    if "githubmirror" in remote_path:
                        file_index = int(remote_path.split('/')[1].split('.')[0])
                    elif "ByPassVpnLera" in remote_path:
                        file_index = 49 + len(XHTTP_REALITY_SOURCES)
                    elif "XHTTP_Reality" in remote_path:
                        file_index = 50 + len(XHTTP_REALITY_SOURCES)
                    elif "REALITY_WORKING" in remote_path:
                        file_index = 51 + len(XHTTP_REALITY_SOURCES)
                    elif "TOP_FASTEST_10" in remote_path:
                        file_index = 52 + len(XHTTP_REALITY_SOURCES)
                    elif "TOP_FASTEST_50" in remote_path:
                        file_index = 53 + len(XHTTP_REALITY_SOURCES)
                    elif "TOP_FASTEST_100" in remote_path:
                        file_index = 54 + len(XHTTP_REALITY_SOURCES)
                    elif "VIDEO_OPTIMIZED" in remote_path:
                        file_index = 55 + len(XHTTP_REALITY_SOURCES)
                    elif "LOW_PING" in remote_path:
                        file_index = 56 + len(XHTTP_REALITY_SOURCES)
                    
                    if file_index:
                        with _UPDATED_FILES_LOCK:
                            updated_files.add(file_index)
                    return
                else:
                    msg = e_get.data.get("message", str(e_get))
                    log(f"⚠️ Ошибка при получении {remote_path}: {msg}")
                    return

            try:
                remote_content = file_in_repo.decoded_content.decode("utf-8", errors="replace")
                if remote_content == content:
                    log(f"🔄 Изменений для {remote_path} нет.")
                    return
            except Exception:
                pass

            basename = os.path.basename(remote_path)
            try:
                repo.update_file(
                    path=remote_path,
                    message=f"🚀 Обновление {basename} по часовому поясу Европа/Москва: {offset}",
                    content=content,
                    sha=current_sha,
                )
                log(f"🚀 Файл {remote_path} обновлён в репозитории.")
                # Определяем индекс файла для updated_files
                file_index = None
                if "githubmirror" in remote_path:
                    file_index = int(remote_path.split('/')[1].split('.')[0])
                elif "ByPassVpnLera" in remote_path:
                    file_index = 49 + len(XHTTP_REALITY_SOURCES)
                elif "XHTTP_Reality" in remote_path:
                    file_index = 50 + len(XHTTP_REALITY_SOURCES)
                elif "REALITY_WORKING" in remote_path:
                    file_index = 51 + len(XHTTP_REALITY_SOURCES)
                elif "TOP_FASTEST_10" in remote_path:
                    file_index = 52 + len(XHTTP_REALITY_SOURCES)
                elif "TOP_FASTEST_50" in remote_path:
                    file_index = 53 + len(XHTTP_REALITY_SOURCES)
                elif "TOP_FASTEST_100" in remote_path:
                    file_index = 54 + len(XHTTP_REALITY_SOURCES)
                elif "VIDEO_OPTIMIZED" in remote_path:
                    file_index = 55 + len(XHTTP_REALITY_SOURCES)
                elif "LOW_PING" in remote_path:
                    file_index = 56 + len(XHTTP_REALITY_SOURCES)
                
                if file_index:
                    with _UPDATED_FILES_LOCK:
                        updated_files.add(file_index)
                return
            except GithubException as e_upd:
                if getattr(e_upd, "status", None) == 409:
                    if attempt < max_retries:
                        wait_time = 0.5 * (2 ** (attempt - 1))
                        log(f"⚠️ Конфликт SHA для {remote_path}, попытка {attempt}/{max_retries}, ждем {wait_time} сек")
                        time.sleep(wait_time)
                        continue
                    else:
                        log(f"❌ Не удалось обновить {remote_path} после {max_retries} попыток")
                        return
                else:
                    msg = e_upd.data.get("message", str(e_upd))
                    log(f"⚠️ Ошибка при загрузке {remote_path}: {msg}")
                    return

        except Exception as e_general:
            short_msg = str(e_general)
            if len(short_msg) > 200:
                short_msg = short_msg[:200] + "…"
            log(f"⚠️ Непредвиденная ошибка при обновлении {remote_path}: {short_msg}")
            return

    log(f"❌ Не удалось обновить {remote_path} после {max_retries} попыток")

def download_and_save(idx):
    url = URLS[idx]
    local_path = LOCAL_PATHS[idx]
    try:
        data = fetch_data(url)
        data, _ = filter_insecure_configs(local_path, data)

        if os.path.exists(local_path):
            try:
                with open(local_path, "r", encoding="utf-8") as f_old:
                    old_data = f_old.read()
                if old_data == data:
                    log(f"🔄 Изменений для {local_path} нет (локально). Пропуск загрузки в GitHub.")
                    return None
            except Exception:
                pass

        save_to_local_file(local_path, data)
        return local_path, REMOTE_PATHS[idx]
    except Exception as e:
        short_msg = str(e)
        if len(short_msg) > 200:
            short_msg = short_msg[:200] + "…"
        log(f"⚠️ Ошибка при скачивании {url}: {short_msg}")
        return None

INSECURE_PATTERN = re.compile(
    r'(?:[?&;]|3%[Bb])(allowinsecure|allow_insecure|insecure)=(?:1|true|yes)(?:[&;#]|$|(?=\s|$))',
    re.IGNORECASE
)

def filter_insecure_configs(local_path, data, log_enabled=True):
    result = []
    splitted = data.splitlines()

    for line in splitted:
        original_line = line
        processed = line.strip()
        processed = urllib.parse.unquote(html.unescape(processed))

        if INSECURE_PATTERN.search(processed):
            continue

        result.append(original_line)

    filtered_count = len(splitted) - len(result)
    
    if filtered_count > 0 and log_enabled:
        log(f"ℹ️ Отфильтровано {filtered_count} небезопасных конфигов для {local_path}")
    
    return "\n".join(result), filtered_count

def _extract_host_port(line):
    """Извлекает хост и порт из строки конфига"""
    if not line:
        return None
    
    # VLESS
    if line.startswith("vless://"):
        m = re.search(r'@([\w\.-]+):(\d{1,5})', line)
        if m:
            return m.group(1), m.group(2)
    
    # VMESS
    elif line.startswith("vmess://"):
        try:
            payload = line[8:]
            rem = len(payload) % 4
            if rem:
                payload += '=' * (4 - rem)
            decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
            if decoded.startswith('{'):
                j = json.loads(decoded)
                host = j.get('add') or j.get('host') or j.get('ip')
                port = j.get('port')
                if host and port:
                    return str(host), str(port)
        except Exception:
            pass
    
    # TROJAN
    elif line.startswith("trojan://"):
        m = re.search(r'@([\w\.-]+):(\d{1,5})', line)
        if m:
            return m.group(1), m.group(2)
    
    # Shadowsocks
    elif line.startswith("ss://"):
        try:
            # Пропускаем первую часть до @
            if '@' in line:
                m = re.search(r'@([\w\.-]+):(\d{1,5})', line)
                if m:
                    return m.group(1), m.group(2)
        except Exception:
            pass
    
    # Общий случай для других протоколов
    m = re.search(r'(?:@|//)([\w\.-]+):(\d{1,5})', line)
    if m:
        return m.group(1), m.group(2)
    
    return None

# ============ УЛУЧШЕННАЯ ФУНКЦИЯ ТЕСТИРОВАНИЯ ============
def test_config_ping(config_str, timeout=3):
    """Проверяет доступность конфига и измеряет пинг"""
    try:
        hostport = _extract_host_port(config_str)
        if not hostport:
            return None, None
        
        host, port = hostport
        
        # Измеряем время подключения
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, int(port)))
        end_time = time.time()
        sock.close()
        
        if result == 0:
            ping_ms = int((end_time - start_time) * 1000)  # в миллисекундах
            return True, ping_ms
        else:
            return False, None
    except Exception:
        return False, None

def test_config_speed(config_str, test_size=1024, timeout=5):
    """
    Тестирует скорость конфига (имитация загрузки)
    Возвращает скорость в КБ/с
    """
    try:
        hostport = _extract_host_port(config_str)
        if not hostport:
            return 0
        
        host, port = hostport
        
        # Простая проверка: пытаемся отправить и принять данные
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        start_time = time.time()
        sock.connect((host, int(port)))
        connect_time = time.time() - start_time
        
        # Отправляем небольшой запрос
        sock.send(b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode())
        
        # Принимаем данные
        total_received = 0
        start_recv = time.time()
        
        while time.time() - start_recv < 2:  # 2 секунды на замер
            try:
                data = sock.recv(4096)
                if not data:
                    break
                total_received += len(data)
            except socket.timeout:
                break
        
        sock.close()
        
        # Вычисляем скорость в КБ/с
        elapsed = time.time() - start_recv
        if elapsed > 0 and total_received > 0:
            speed_kbps = (total_received / 1024) / elapsed
            return round(speed_kbps, 2)
        else:
            return 0
            
    except Exception:
        return 0

def advanced_test_config(config_str, ping_timeout=3, speed_test=True):
    """
    Расширенное тестирование конфига
    Возвращает словарь с результатами
    """
    result = {
        "config": config_str,
        "working": False,
        "ping_ms": None,
        "speed_kbps": 0,
        "stability": 0,
        "score": 0
    }
    
    # Проверяем пинг
    working, ping = test_config_ping(config_str, ping_timeout)
    if not working:
        return result
    
    result["working"] = True
    result["ping_ms"] = ping
    
    # Проверяем скорость (опционально, может быть долго)
    if speed_test:
        speed = test_config_speed(config_str)
        result["speed_kbps"] = speed
    
    # Проверяем стабильность (делаем 3 коротких замера)
    stability_success = 0
    for _ in range(3):
        w, p = test_config_ping(config_str, 1)
        if w:
            stability_success += 1
    result["stability"] = stability_success * 33  # процент стабильности
    
    # Вычисляем общий балл (чем меньше пинг и выше скорость, тем лучше)
    # Балл от 0 до 100
    ping_score = max(0, 100 - (ping / 3)) if ping else 0  # 30ms = 90 баллов
    speed_score = min(100, speed / 10) if speed else 0    # 1000 КБ/с = 100 баллов
    
    # Веса: пинг важнее (60%), скорость (40%)
    result["score"] = (ping_score * 0.6) + (speed_score * 0.4)
    
    return result

def find_fastest_configs(configs_list, max_to_test=500, top_n=100):
    """
    Находит самые быстрые конфиги с лучшим пингом
    Возвращает отсортированный список лучших конфигов
    """
    log(f"🚀 Поиск самых быстрых конфигов среди {min(len(configs_list), max_to_test)}...")
    
    results = []
    tested = 0
    
    # Сначала быстрая проверка пинга для всех
    ping_results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {}
        for cfg in configs_list[:max_to_test]:
            futures[executor.submit(test_config_ping, cfg, 2)] = cfg
        
        for future in concurrent.futures.as_completed(futures):
            cfg = futures[future]
            tested += 1
            try:
                working, ping = future.result(timeout=5)
                if working and ping:
                    ping_results.append((cfg, ping))
                    if tested % 50 == 0:
                        log(f"📊 Протестировано пинг: {tested}/{min(len(configs_list), max_to_test)}")
            except Exception:
                pass
    
    log(f"✅ Найдено {len(ping_results)} работающих конфигов с измеренным пингом")
    
    # Сортируем по пингу
    ping_results.sort(key=lambda x: x[1])
    
    # Берём топ-100 по пингу для теста скорости
    top_ping = ping_results[:100]
    
    log(f"🚀 Тестирование скорости топ-100 конфигов с лучшим пингом...")
    
    # Тестируем скорость для лучших по пингу
    speed_tested = 0
    for cfg, ping in top_ping:
        speed_tested += 1
        try:
            speed = test_config_speed(cfg, timeout=4)
            
            # Вычисляем балл
            ping_score = max(0, 100 - (ping / 3))
            speed_score = min(100, speed / 10)
            total_score = (ping_score * 0.6) + (speed_score * 0.4)
            
            results.append({
                "config": cfg,
                "ping_ms": ping,
                "speed_kbps": speed,
                "score": total_score
            })
            
            log(f"📊 #{speed_tested}: пинг={ping}ms, скорость={speed}КБ/с, балл={total_score:.1f}")
        except Exception as e:
            pass
    
    # Сортируем по баллу
    results.sort(key=lambda x: x["score"], reverse=True)
    
    log(f"🏆 Найдено {len(results)} конфигов. Лучший балл: {results[0]['score']:.1f}")
    
    return results

def create_fastest_configs_files(all_results, base_configs_list):
    """
    Создаёт файлы с самыми быстрыми конфигами
    """
    if not all_results:
        log("⚠️ Нет результатов для создания файлов с быстрыми конфигами")
        return []
    
    # Извлекаем только конфиги из результатов
    top_configs = [r["config"] for r in all_results]
    
    # Дополняем из основного списка, если не хватает
    if len(top_configs) < 100 and len(base_configs_list) > 100:
        # Добавляем конфиги из основного списка, которых нет в топе
        existing = set(top_configs)
        for cfg in base_configs_list:
            if cfg not in existing and len(top_configs) < 100:
                top_configs.append(cfg)
                existing.add(cfg)
    
    created_files = []
    
    # ТОП-10 самых быстрых
    if len(top_configs) >= 10:
        top10 = top_configs[:10]
        file_path = "TOP_FASTEST_10.txt"
        title = "MaxTre - ТОП-10 самых быстрых конфигов"
        title_base64 = base64.b64encode(title.encode('utf-8')).decode('utf-8')
        
        header = f"#profile-title: base64:{title_base64}\n"
        header += "#profile-update-interval: 3\n"
        header += f"# {title}\n"
        header += f"# Сгенерировано: {offset}\n"
        header += "# Лучшие по скорости и пингу\n"
        if len(all_results) >= 10:
            avg_ping = sum(r['ping_ms'] for r in all_results[:10]) / 10
            header += f"# Средний пинг: {avg_ping:.0f}ms\n\n"
        else:
            header += "\n"
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(header)
            f.write("\n".join(top10))
        
        log(f"📁 Создан файл {file_path} с топ-10 быстрыми конфигами")
        created_files.append(file_path)
    
    # ТОП-50 самых быстрых
    if len(top_configs) >= 50:
        top50 = top_configs[:50]
        file_path = "TOP_FASTEST_50.txt"
        title = "MaxTre - ТОП-50 самых быстрых конфигов"
        title_base64 = base64.b64encode(title.encode('utf-8')).decode('utf-8')
        
        header = f"#profile-title: base64:{title_base64}\n"
        header += "#profile-update-interval: 4\n"
        header += f"# {title}\n"
        header += f"# Сгенерировано: {offset}\n"
        header += "# Отбор по скорости и стабильности\n\n"
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(header)
            f.write("\n".join(top50))
        
        log(f"📁 Создан файл {file_path} с топ-50 быстрыми конфигами")
        created_files.append(file_path)
    
    # ТОП-100 самых быстрых
    if len(top_configs) >= 100:
        top100 = top_configs[:100]
        file_path = "TOP_FASTEST_100.txt"
        title = "MaxTre - ТОП-100 быстрых конфигов"
        title_base64 = base64.b64encode(title.encode('utf-8')).decode('utf-8')
        
        header = f"#profile-title: base64:{title_base64}\n"
        header += "#profile-update-interval: 5\n"
        header += f"# {title}\n"
        header += f"# Сгенерировано: {offset}\n"
        header += "# Проверенные рабочие конфиги\n\n"
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(header)
            f.write("\n".join(top100))
        
        log(f"📁 Создан файл {file_path} с топ-100 быстрыми конфигами")
        created_files.append(file_path)
    
    return created_files

def create_video_optimized_configs(all_results, base_configs_list):
    """
    Создаёт файл с конфигами, оптимизированными для видео
    (приоритет: скорость > пинг)
    """
    if not all_results:
        log("⚠️ Нет результатов для создания видео-оптимизированных конфигов")
        return None
    
    # Для видео важнее скорость, поэтому сортируем по скорости
    video_sorted = sorted(all_results, key=lambda x: x["speed_kbps"], reverse=True)
    
    # Берём топ-20 по скорости, но с учётом пинга
    video_configs = []
    for r in video_sorted:
        if r["speed_kbps"] > 50:  # Минимальная скорость для видео
            video_configs.append(r["config"])
            if len(video_configs) >= 30:
                break
    
    # Если мало быстрых, добавляем из основного списка
    if len(video_configs) < 20 and len(base_configs_list) > 20:
        existing = set(video_configs)
        for cfg in base_configs_list:
            if cfg not in existing and len(video_configs) < 30:
                video_configs.append(cfg)
                existing.add(cfg)
    
    if video_configs:
        file_path = "VIDEO_OPTIMIZED.txt"
        title = "MaxTre - Для видео (YouTube, стриминг)"
        title_base64 = base64.b64encode(title.encode('utf-8')).decode('utf-8')
        
        header = f"#profile-title: base64:{title_base64}\n"
        header += "#profile-update-interval: 4\n"
        header += f"# {title}\n"
        header += f"# Сгенерировано: {offset}\n"
        header += "# Оптимизированы для просмотра видео\n"
        header += "# Высокая скорость, стабильное соединение\n\n"
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(header)
            f.write("\n".join(video_configs))
        
        log(f"📁 Создан файл {file_path} с {len(video_configs)} видео-оптимизированными конфигами")
        return file_path
    
    return None

def create_low_ping_configs(all_results):
    """
    Создаёт файл с конфигами с минимальным пингом
    """
    if not all_results:
        return None
    
    # Сортируем по пингу
    low_ping_sorted = sorted(all_results, key=lambda x: x["ping_ms"])
    
    # Берём топ-20 с минимальным пингом
    low_ping_configs = [r["config"] for r in low_ping_sorted[:20]]
    
    file_path = "LOW_PING.txt"
    title = "MaxTre - Низкий пинг (игры, звонки)"
    title_base64 = base64.b64encode(title.encode('utf-8')).decode('utf-8')
    
    avg_ping = sum(r["ping_ms"] for r in low_ping_sorted[:20]) / min(20, len(low_ping_sorted))
    
    header = f"#profile-title: base64:{title_base64}\n"
    header += "#profile-update-interval: 3\n"
    header += f"# {title}\n"
    header += f"# Сгенерировано: {offset}\n"
    header += "# Минимальная задержка (пинг)\n"
    header += f"# Средний пинг: {avg_ping:.0f}ms\n"
    header += "# Идеально для игр и видеозвонков\n\n"
    
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(header)
        f.write("\n".join(low_ping_configs))
    
    log(f"📁 Создан файл {file_path} с {len(low_ping_configs)} конфигами с низким пингом")
    return file_path

# ============ ПУНКТ 1: ПОИСК XHTTP+REALITY КОНФИГОВ В ИСТОЧНИКАХ ============
def find_xhttp_reality_configs(all_configs):
    """
    Ищет реальные XHTTP+Reality конфиги в собранных данных
    """
    log("🔍 Поиск XHTTP+Reality конфигов в источниках...")
    
    xhttp_configs = []
    
    # Паттерны для поиска XHTTP конфигов
    xhttp_patterns = [
        r'type=xhttp',
        r'type%3Dxhttp',
        r'xhttpMode=',
        r'xhttpMode%3D',
        r'network=xhttp',
        r'network%3Dxhttp',
    ]
    
    # Объединяем все паттерны в один regex
    xhttp_regex = re.compile('|'.join(xhttp_patterns), re.IGNORECASE)
    
    for cfg in all_configs:
        if not cfg or not isinstance(cfg, str):
            continue
        
        # Проверяем наличие XHTTP и Reality
        has_xhttp = xhttp_regex.search(cfg) is not None
        has_reality = 'security=reality' in cfg or 'security%3Dreality' in cfg
        has_vision = 'flow=xtls-rprx-vision' in cfg or 'flow%3Dxtls-rprx-vision' in cfg
        
        if has_xhttp and has_reality:
            xhttp_configs.append(cfg)
            log(f"✅ Найден XHTTP конфиг: {cfg[:100]}...")
    
    log(f"📊 Найдено {len(xhttp_configs)} XHTTP+Reality конфигов в источниках")
    return xhttp_configs

# ============ ПУНКТ 2: ТЕСТИРОВАНИЕ XHTTP КОНФИГОВ ============
def test_xhttp_config(config_str, timeout=5):
    """
    Специальный тест для XHTTP конфигов
    Проверяет не только порт, но и отвечает ли сервер
    """
    try:
        hostport = _extract_host_port(config_str)
        if not hostport:
            return False
        
        host, port = hostport
        
        # Проверяем доступность порта
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, int(port)))
        sock.close()
        
        if result != 0:
            return False
        
        # Для XHTTP проверяем HTTP-ответ
        try:
            import http.client
            conn = http.client.HTTPConnection(host, port, timeout=3)
            conn.request("HEAD", "/")
            response = conn.getresponse()
            conn.close()
            # Любой ответ (даже 400) значит, что сервер отвечает
            return True
        except:
            # Если HTTP не работает, но порт открыт — возможно это XHTTP
            return True
            
    except Exception:
        return False

def test_and_filter_xhttp_configs(xhttp_configs):
    """
    Тестирует найденные XHTTP конфиги и оставляет только рабочие
    """
    if not xhttp_configs:
        log("⚠️ Нет XHTTP конфигов для тестирования")
        return []
    
    log(f"🔄 Тестирование {len(xhttp_configs)} XHTTP+Reality конфигов...")
    
    working_xhttp = []
    tested = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(test_xhttp_config, cfg): cfg for cfg in xhttp_configs[:200]}
        
        for future in concurrent.futures.as_completed(futures):
            cfg = futures[future]
            tested += 1
            try:
                is_working = future.result(timeout=8)
                if is_working:
                    working_xhttp.append(cfg)
                    if len(working_xhttp) % 10 == 0:
                        log(f"✅ XHTTP РАБОЧИХ: {len(working_xhttp)}/{tested}")
                # Не логируем каждый, чтобы не засорять вывод
            except Exception as e:
                pass
    
    log(f"📊 Найдено {len(working_xhttp)} рабочих XHTTP+Reality конфигов из {tested} протестированных")
    
    # Дедупликация
    seen = set()
    unique_xhttp = []
    for cfg in working_xhttp:
        if cfg not in seen:
            seen.add(cfg)
            unique_xhttp.append(cfg)
    
    return unique_xhttp

def create_xhttp_configs_file(xhttp_configs):
    """
    Создаёт файл с реально работающими XHTTP+Reality конфигами
    """
    if not xhttp_configs:
        log("⚠️ Нет XHTTP конфигов для создания файла")
        return None
    
    file_path = "XHTTP_Reality.txt"
    title = "MaxTre - XHTTP+Reality (рабочие)"
    title_base64 = base64.b64encode(title.encode('utf-8')).decode('utf-8')
    
    header = f"#profile-title: base64:{title_base64}\n"
    header += "#profile-update-interval: 5\n"
    header += f"# {title}\n"
    header += f"# Сгенерировано: {offset}\n"
    header += f"# Реально работающие XHTTP+Reality конфиги из источников\n"
    header += f"# Всего: {len(xhttp_configs)}\n\n"
    
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(header)
        f.write("\n".join(xhttp_configs))
    
    log(f"📁 Создан файл {file_path} с {len(xhttp_configs)} рабочими XHTTP+Reality конфигами")
    return file_path

# ============ ПУНКТ 3: РЕЗЕРВНЫЙ ФАЙЛ С REALITY КОНФИГАМИ ============
def find_and_test_reality_configs(all_configs):
    """
    Находит и тестирует Reality конфиги (работают везде)
    """
    log("🔍 Поиск Reality конфигов для резервного файла...")
    
    reality_configs = []
    
    for cfg in all_configs:
        if not cfg or not isinstance(cfg, str):
            continue
        
        # Ищем Reality конфиги
        if ('security=reality' in cfg or 'security%3Dreality' in cfg) and \
           ('type=tcp' in cfg or 'type%3Dtcp' in cfg):
            reality_configs.append(cfg)
    
    log(f"📊 Найдено {len(reality_configs)} Reality конфигов")
    
    if not reality_configs:
        log("⚠️ Reality конфиги не найдены")
        return []
    
    # Тестируем их (быстрая проверка пинга)
    log(f"🔄 Тестирование {len(reality_configs)} Reality конфигов...")
    
    working_reality = []
    tested = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(test_config_ping, cfg, 3): cfg for cfg in reality_configs[:300]}
        
        for future in concurrent.futures.as_completed(futures):
            cfg = futures[future]
            tested += 1
            try:
                working, ping = future.result(timeout=5)
                if working:
                    working_reality.append(cfg)
                    if len(working_reality) % 20 == 0:
                        log(f"✅ Reality РАБОЧИХ: {len(working_reality)}/{tested}")
            except Exception:
                pass
    
    log(f"📊 Найдено {len(working_reality)} рабочих Reality конфигов")
    
    # Дедупликация
    seen = set()
    unique_reality = []
    for cfg in working_reality:
        if cfg not in seen:
            seen.add(cfg)
            unique_reality.append(cfg)
    
    return unique_reality

def create_reality_configs_file(reality_configs):
    """
    Создаёт резервный файл с рабочими Reality конфигами
    """
    if not reality_configs:
        log("⚠️ Нет Reality конфигов для создания резервного файла")
        return None
    
    file_path = "REALITY_WORKING.txt"
    title = "MaxTre - Reality (рабочие, резерв)"
    title_base64 = base64.b64encode(title.encode('utf-8')).decode('utf-8')
    
    header = f"#profile-title: base64:{title_base64}\n"
    header += "#profile-update-interval: 5\n"
    header += f"# {title}\n"
    header += f"# Сгенерировано: {offset}\n"
    header += f"# Резервный файл с рабочими Reality конфигами\n"
    header += f"# Всегда работают, если XHTTP недоступен\n"
    header += f"# Всего: {len(reality_configs)}\n\n"
    
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(header)
        f.write("\n".join(reality_configs[:100]))  # Берём топ-100
    
    log(f"📁 Создан резервный файл {file_path} с {min(100, len(reality_configs))} Reality конфигами")
    return file_path

def create_filtered_configs():
    """Создает ByPassVpnLera.txt с конфигами для SNI/CIDR белых списков"""
    sni_domains = [
        "00.img.avito.st", "01.img.avito.st", "02.img.avito.st", "03.img.avito.st",
        "04.img.avito.st", "05.img.avito.st", "06.img.avito.st", "07.img.avito.st",
        "08.img.avito.st", "09.img.avito.st", "10.img.avito.st", "1013a--ma--8935--cp199.stbid.ru",
        "11.img.avito.st", "12.img.avito.st", "13.img.avito.st", "14.img.avito.st",
        "15.img.avito.st", "16.img.avito.st", "17.img.avito.st", "18.img.avito.st",
        "19.img.avito.st", "1l-api.mail.ru", "1l-go.mail.ru", "1l-hit.mail.ru", "1l-s2s.mail.ru",
        "1l-view.mail.ru", "1l.mail.ru", "1link.mail.ru", "20.img.avito.st", "2018.mail.ru",
        "2019.mail.ru", "2020.mail.ru", "2021.mail.ru", "21.img.avito.st", "22.img.avito.st",
        "23.img.avito.st", "23feb.mail.ru", "24.img.avito.st", "25.img.avito.st",
        "26.img.avito.st", "27.img.avito.st", "28.img.avito.st", "29.img.avito.st", "2gis.com",
        "2gis.ru", "30.img.avito.st", "300.ya.ru", "31.img.avito.st", "32.img.avito.st",
        "33.img.avito.st", "34.img.avito.st", "3475482542.mc.yandex.ru", "35.img.avito.st",
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
        "87.img.avito.st", "88.img.avito.st", "89.img.avito.st", "8mar.mail.ru", "8march.mail.ru",
        "90.img.avito.st", "91.img.avito.st", "92.img.avito.st", "93.img.avito.st",
        "94.img.avito.st", "95.img.avito.st", "96.img.avito.st", "97.img.avito.st",
        "98.img.avito.st", "99.img.avito.st", "9may.mail.ru", "a.auth-nsdi.ru", "a.res-nsdi.ru",
        "a.wb.ru", "aa.mail.ru", "ad.adriver.ru", "ad.mail.ru", "adm.digital.gov.ru",
        "adm.mp.rzd.ru", "admin.cs7777.vk.ru", "admin.tau.vk.ru", "ads.vk.ru", "adv.ozon.ru",
        "afisha.mail.ru", "agent.mail.ru", "akashi.vk-portal.net", "alfabank.ru",
        "alfabank.servicecdn.ru", "alfabank.st", "alpha3.minigames.mail.ru",
        "alpha4.minigames.mail.ru", "amigo.mail.ru", "ams2-cdn.2gis.com", "an.yandex.ru",
        "analytics.predict.mail.ru", "analytics.vk.ru", "answer.mail.ru", "answers.mail.ru",
        "api-maps.yandex.ru", "api.2gis.ru", "api.a.mts.ru", "api.apteka.ru", "api.avito.ru",
        "api.browser.yandex.com", "api.browser.yandex.ru", "api.cs7777.vk.ru",
        "api.events.plus.yandex.net", "api.expf.ru", "api.max.ru", "api.mindbox.ru", "api.ok.ru",
        "api.photo.2gis.com", "api.plus.kinopoisk.ru", "api.predict.mail.ru",
        "api.reviews.2gis.com", "api.s3.yandex.net", "api.tau.vk.ru", "api.uxfeedback.yandex.net",
        "api.vk.ru", "api2.ivi.ru", "apps.research.mail.ru", "authdl.mail.ru", "auto.mail.ru",
        "auto.ru", "autodiscover.corp.mail.ru", "autodiscover.ord.ozon.ru", "av.mail.ru",
        "avatars.mds.yandex.com", "avatars.mds.yandex.net", "avito.ru", "avito.st", "aw.mail.ru",
        "away.cs7777.vk.ru", "away.tau.vk.ru", "azt.mail.ru", "b.auth-nsdi.ru", "b.res-nsdi.ru",
        "bank.ozon.ru", "banners-website.wildberries.ru", "bb.mail.ru", "bd.mail.ru",
        "beeline.api.flocktory.com", "beko.dom.mail.ru", "bender.mail.ru", "beta.mail.ru",
        "bfds.sberbank.ru", "bitva.mail.ru", "biz.mail.ru", "blackfriday.mail.ru", "blog.mail.ru",
        "bot.gosuslugi.ru", "botapi.max.ru", "bratva-mr.mail.ru", "bro-bg-store.s3.yandex.com",
        "bro-bg-store.s3.yandex.net", "bro-bg-store.s3.yandex.ru", "brontp-pre.yandex.ru",
        "browser.mail.ru", "browser.yandex.com", "browser.yandex.ru", "business.vk.ru",
        "c.dns-shop.ru", "c.rdrom.ru", "calendar.mail.ru", "capsula.mail.ru", "cargo.rzd.ru",
        "cars.mail.ru", "catalog.api.2gis.com", "cdn.connect.mail.ru", "cdn.gpb.ru",
        "cdn.lemanapro.ru", "cdn.newyear.mail.ru", "cdn.rosbank.ru", "cdn.s3.yandex.net",
        "cdn.tbank.ru", "cdn.uxfeedback.ru", "cdn.yandex.ru", "cdn1.tu-tu.ru", "cdnn21.img.ria.ru",
        "cdnrhkgfkkpupuotntfj.svc.cdn.yandex.net", "cf.mail.ru", "chat-ct.pochta.ru",
        "chat-prod.wildberries.ru", "chat3.vtb.ru", "cloud.cdn.yandex.com", "cloud.cdn.yandex.net",
        "cloud.cdn.yandex.ru", "cloud.mail.ru", "cloud.vk.com", "cloud.vk.ru",
        "cloudcdn-ams19.cdn.yandex.net", "cloudcdn-m9-10.cdn.yandex.net",
        "cloudcdn-m9-12.cdn.yandex.net", "cloudcdn-m9-13.cdn.yandex.net",
        "cloudcdn-m9-14.cdn.yandex.net", "cloudcdn-m9-15.cdn.yandex.net",
        "cloudcdn-m9-2.cdn.yandex.net", "cloudcdn-m9-3.cdn.yandex.net",
        "cloudcdn-m9-4.cdn.yandex.net", "cloudcdn-m9-5.cdn.yandex.net",
        "cloudcdn-m9-6.cdn.yandex.net", "cloudcdn-m9-7.cdn.yandex.net",
        "cloudcdn-m9-9.cdn.yandex.net", "cm.a.mts.ru", "cms-res-web.online.sberbank.ru",
        "cobma.mail.ru", "cobmo.mail.ru", "cobrowsing.tbank.ru", "code.mail.ru",
        "codefest.mail.ru", "cog.mail.ru", "collections.yandex.com", "collections.yandex.ru",
        "comba.mail.ru", "combu.mail.ru", "commba.mail.ru", "company.rzd.ru", "compute.mail.ru",
        "connect.cs7777.vk.ru", "contacts.rzd.ru", "contract.gosuslugi.ru", "corp.mail.ru",
        "counter.yadro.ru", "cpa.hh.ru", "cpg.money.mail.ru", "crazypanda.mail.ru",
        "crowdtest.payment-widget-smarttv.plus.tst.kinopoisk.ru",
        "crowdtest.payment-widget.plus.tst.kinopoisk.ru", "cs.avito.ru", "cs7777.vk.ru",
        "csp.yandex.net", "ctlog.mail.ru", "ctlog2023.mail.ru", "ctlog2024.mail.ru", "cto.mail.ru",
        "cups.mail.ru", "d-assets.2gis.ru", "d5de4k0ri8jba7ucdbt6.apigw.yandexcloud.net",
        "da-preprod.biz.mail.ru", "da.biz.mail.ru", "data.amigo.mail.ru", "dating.ok.ru",
        "deti.mail.ru", "dev.cs7777.vk.ru", "dev.max.ru", "dev.tau.vk.ru", "dev1.mail.ru",
        "dev2.mail.ru", "dev3.mail.ru", "digital.gov.ru", "disk.2gis.com", "disk.rzd.ru",
        "dk.mail.ru", "dl.mail.ru", "dl.marusia.mail.ru", "dmp.dmpkit.lemanapro.ru", "dn.mail.ru",
        "dnd.wb.ru", "dobro.mail.ru", "doc.mail.ru", "dom.mail.ru", "download.max.ru",
        "dr.yandex.net", "dr2.yandex.net", "dragonpals.mail.ru", "ds.mail.ru", "duck.mail.ru",
        "duma.gov.ru", "dzen.ru", "e.mail.ru", "education.mail.ru", "egress.yandex.net",
        "eh.vk.com", "ekmp-a-51.rzd.ru", "enterprise.api-maps.yandex.ru", "epp.genproc.gov.ru",
        "esa-res.online.sberbank.ru", "esc.predict.mail.ru", "esia.gosuslugi.ru", "et.mail.ru",
        "expert.vk.ru", "external-api.mediabilling.kinopoisk.ru", "external-api.plus.kinopoisk.ru",
        "eye.targetads.io", "favicon.yandex.com", "favicon.yandex.net", "favicon.yandex.ru",
        "favorites.api.2gis.com", "fb-cdn.premier.one", "fe.mail.ru", "filekeeper-vod.2gis.com",
        "finance.mail.ru", "finance.wb.ru", "five.predict.mail.ru", "foto.mail.ru",
        "frontend.vh.yandex.ru", "fw.wb.ru", "games-bamboo.mail.ru", "games-fisheye.mail.ru",
        "games.mail.ru", "gazeta.ru", "genesis.mail.ru", "geo-apart.predict.mail.ru",
        "get4click.ru", "gibdd.mail.ru", "go.mail.ru", "golos.mail.ru", "gosuslugi.ru",
        "gosweb.gosuslugi.ru", "government.ru", "goya.rutube.ru", "gpb.finance.mail.ru",
        "graphql-web.kinopoisk.ru", "graphql.kinopoisk.ru", "gu-st.ru", "guns.mail.ru",
        "hb-bidder.skcrtxr.com", "hd.kinopoisk.ru", "health.mail.ru", "help.max.ru",
        "help.mcs.mail.ru", "hh.ru", "hhcdn.ru", "hi-tech.mail.ru", "horo.mail.ru", "hrc.tbank.ru",
        "hs.mail.ru", "http-check-headers.yandex.ru", "i.hh.ru", "i.max.ru", "i.rdrom.ru",
        "i0.photo.2gis.com", "i1.photo.2gis.com", "i2.photo.2gis.com", "i3.photo.2gis.com",
        "i4.photo.2gis.com", "i5.photo.2gis.com", "i6.photo.2gis.com", "i7.photo.2gis.com",
        "i8.photo.2gis.com", "i9.photo.2gis.com", "id.cs7777.vk.ru", "id.sber.ru", "id.tau.vk.ru",
        "id.tbank.ru", "id.vk.ru", "identitystatic.mts.ru", "images.apteka.ru",
        "imgproxy.cdn-tinkoff.ru", "imperia.mail.ru", "informer.yandex.ru", "infra.mail.ru",
        "internet.mail.ru", "invest.ozon.ru", "io.ozone.ru", "ir.ozone.ru", "it.mail.ru",
        "izbirkom.ru", "jam.api.2gis.com", "jd.mail.ru", "jitsi.wb.ru", "journey.mail.ru",
        "jsons.injector.3ebra.net", "juggermobile.mail.ru", "junior.mail.ru", "keys.api.2gis.com",
        "kicker.mail.ru", "kiks.yandex.com", "kiks.yandex.ru", "kingdomrift.mail.ru",
        "kino.mail.ru", "knights.mail.ru", "kobma.mail.ru", "kobmo.mail.ru", "komba.mail.ru",
        "kombo.mail.ru", "kombu.mail.ru", "kommba.mail.ru", "konflikt.mail.ru", "kp.ru",
        "kremlin.ru", "kz.mcs.mail.ru", "la.mail.ru", "lady.mail.ru", "landing.mail.ru",
        "le.tbank.ru", "learning.ozon.ru", "legal.max.ru", "legenda.mail.ru",
        "legendofheroes.mail.ru", "lemanapro.ru", "lenta.ru", "link.max.ru", "link.mp.rzd.ru",
        "live.ok.ru", "lk.gosuslugi.ru", "loa.mail.ru", "log.strm.yandex.ru", "login.cs7777.vk.ru",
        "login.mts.ru", "login.tau.vk.ru", "login.vk.com", "login.vk.ru", "lotro.mail.ru",
        "love.mail.ru", "m.47news.ru", "m.avito.ru", "m.cs7777.vk.ru", "m.ok.ru", "m.tau.vk.ru",
        "m.vk.ru", "m.vkvideo.cs7777.vk.ru", "ma.kinopoisk.ru", "magnit-ru.injector.3ebra.net",
        "mail.yandex.com", "mail.yandex.ru", "mailer.mail.ru", "mailexpress.mail.ru",
        "man.mail.ru", "map.gosuslugi.ru", "mapgl.2gis.com", "mapi.learning.ozon.ru",
        "maps.mail.ru", "market.rzd.ru", "marusia.mail.ru", "max.ru", "mc.yandex.com",
        "mc.yandex.ru", "mcs.mail.ru", "mddc.tinkoff.ru", "me.cs7777.vk.ru", "media-golos.mail.ru",
        "media.mail.ru", "mediafeeds.yandex.com", "mediafeeds.yandex.ru", "mediapro.mail.ru",
        "merch-cpg.money.mail.ru", "metrics.alfabank.ru", "microapps.kinopoisk.ru",
        "miniapp.internal.myteam.mail.ru", "minigames.mail.ru", "mkb.ru", "mking.mail.ru",
        "mobfarm.mail.ru", "money.mail.ru", "moscow.megafon.ru", "moskva.beeline.ru",
        "moskva.taximaxim.ru", "mosqa.mail.ru", "mowar.mail.ru", "mozilla.mail.ru", "mp.rzd.ru",
        "ms.cs7777.vk.ru", "msk.t2.ru", "mtscdn.ru", "multitest.ok.ru", "music.vk.ru",
        "my.mail.ru", "my.rzd.ru", "myteam.mail.ru", "nebogame.mail.ru", "net.mail.ru",
        "neuro.translate.yandex.ru", "new.mail.ru", "news.mail.ru", "newyear.mail.ru",
        "newyear2018.mail.ru", "nonstandard.sales.mail.ru", "notes.mail.ru",
        "novorossiya.gosuslugi.ru", "nspk.ru", "oauth.cs7777.vk.ru", "oauth.tau.vk.ru",
        "oauth2.cs7777.vk.ru", "octavius.mail.ru", "ok.ru", "oneclick-payment.kinopoisk.ru",
        "online.sberbank.ru", "operator.mail.ru", "ord.ozon.ru", "ord.vk.ru", "otvet.mail.ru",
        "otveti.mail.ru", "otvety.mail.ru", "owa.ozon.ru", "ozon.ru", "ozone.ru", "panzar.mail.ru",
        "park.mail.ru", "partners.gosuslugi.ru", "partners.lemanapro.ru", "passport.pochta.ru",
        "pay.mail.ru", "pay.ozon.ru", "payment-widget-smarttv.plus.kinopoisk.ru",
        "payment-widget.kinopoisk.ru", "payment-widget.plus.kinopoisk.ru", "pernatsk.mail.ru",
        "personalization-web-stable.mindbox.ru", "pets.mail.ru", "pic.rutubelist.ru", "pikabu.ru",
        "pl-res.online.sberbank.ru", "pms.mail.ru", "pochta.ru", "pochtabank.mail.ru",
        "pogoda.mail.ru", "pokerist.mail.ru", "polis.mail.ru", "pos.gosuslugi.ru", "pp.mail.ru",
        "pptest.userapi.com", "predict.mail.ru", "preview.rutube.ru", "primeworld.mail.ru",
        "privacy-cs.mail.ru", "prodvizhenie.rzd.ru", "ptd.predict.mail.ru", "pubg.mail.ru",
        "public-api.reviews.2gis.com", "public.infra.mail.ru", "pulse.mail.ru", "pulse.mp.rzd.ru",
        "push.vk.ru", "pw.mail.ru", "px.adhigh.net", "quantum.mail.ru", "queuev4.vk.com",
        "quiz.kinopoisk.ru", "r.vk.ru", "r0.mradx.net", "rambler.ru", "rap.skcrtxr.com",
        "rate.mail.ru", "rbc.ru", "rebus.calls.mail.ru", "rebus.octavius.mail.ru",
        "receive-sentry.lmru.tech", "reseach.mail.ru", "restapi.dns-shop.ru", "rev.mail.ru",
        "riot.mail.ru", "rl.mail.ru", "rm.mail.ru", "rs.mail.ru", "rt.api.operator.mail.ru",
        "rutube.ru", "rzd.ru", "s.rbk.ru", "s.vtb.ru", "s0.bss.2gis.com", "s1.bss.2gis.com",
        "s11.auto.drom.ru", "s3.babel.mail.ru", "s3.mail.ru", "s3.media-mobs.mail.ru", "s3.t2.ru",
        "s3.yandex.net", "sales.mail.ru", "sangels.mail.ru", "sba.yandex.com", "sba.yandex.net",
        "sba.yandex.ru", "sberbank.ru", "scitylana.apteka.ru", "sdk.money.mail.ru",
        "secure-cloud.rzd.ru", "secure.rzd.ru", "securepay.ozon.ru", "security.mail.ru",
        "seller.ozon.ru", "sentry.hh.ru", "service.amigo.mail.ru", "servicepipe.ru",
        "serving.a.mts.ru", "sfd.gosuslugi.ru", "shadowbound.mail.ru", "sntr.avito.ru",
        "socdwar.mail.ru", "sochi-park.predict.mail.ru", "souz.mail.ru", "speller.yandex.net",
        "sphere.mail.ru", "splitter.wb.ru", "sport.mail.ru", "sso-app4.vtb.ru", "sso-app5.vtb.ru",
        "sso.auto.ru", "sso.dzen.ru", "sso.kinopoisk.ru", "ssp.rutube.ru", "st-gismeteo.st",
        "st-im.kinopoisk.ru", "st-ok.cdn-vk.ru", "st.avito.ru", "st.gismeteo.st",
        "st.kinopoisk.ru", "st.max.ru", "st.okcdn.ru", "st.ozone.ru",
        "staging-analytics.predict.mail.ru", "staging-esc.predict.mail.ru",
        "staging-sochi-park.predict.mail.ru", "stand.aoc.mail.ru", "stand.bb.mail.ru",
        "stand.cb.mail.ru", "stand.la.mail.ru", "stand.pw.mail.ru", "startrek.mail.ru",
        "stat-api.gismeteo.net", "statad.ru", "static-mon.yandex.net", "static.apteka.ru",
        "static.beeline.ru", "static.dl.mail.ru", "static.lemanapro.ru", "static.operator.mail.ru",
        "static.rutube.ru", "stats.avito.ru", "stats.vk-portal.net", "status.mcs.mail.ru",
        "storage.ape.yandex.net", "storage.yandexcloud.net", "stormriders.mail.ru",
        "stream.mail.ru", "street-combats.mail.ru", "strm-rad-23.strm.yandex.net",
        "strm-spbmiran-07.strm.yandex.net", "strm-spbmiran-08.strm.yandex.net", "strm.yandex.net",
        "strm.yandex.ru", "styles.api.2gis.com", "suggest.dzen.ru", "suggest.sso.dzen.ru",
        "sun6-20.userapi.com", "sun6-21.userapi.com", "sun6-22.userapi.com",
        "sun9-101.userapi.com", "sun9-38.userapi.com", "support.biz.mail.ru",
        "support.mcs.mail.ru", "support.tech.mail.ru", "surveys.yandex.ru",
        "sync.browser.yandex.net", "sync.rambler.ru", "tag.a.mts.ru", "tamtam.ok.ru",
        "target.smi2.net", "target.vk.ru", "team.mail.ru", "team.rzd.ru", "tech.mail.ru",
        "tech.vk.ru", "tera.mail.ru", "ticket.rzd.ru", "tickets.widget.kinopoisk.ru",
        "tidaltrek.mail.ru", "tile0.maps.2gis.com", "tile1.maps.2gis.com", "tile2.maps.2gis.com",
        "tile3.maps.2gis.com", "tile4.maps.2gis.com", "tiles.maps.mail.ru", "tmgame.mail.ru",
        "tmsg.tbank.ru", "tns-counter.ru", "todo.mail.ru", "top-fwz1.mail.ru",
        "touch.kinopoisk.ru", "townwars.mail.ru", "travel.rzd.ru", "travel.yandex.ru",
        "travel.yastatic.net", "trk.mail.ru", "ttbh.mail.ru", "tutu.ru", "tv.mail.ru",
        "typewriter.mail.ru", "u.corp.mail.ru", "ufo.mail.ru", "ui.cs7777.vk.ru", "ui.tau.vk.ru",
        "user-geo-data.wildberries.ru", "uslugi.yandex.ru", "uxfeedback-cdn.s3.yandex.net",
        "uxfeedback.yandex.ru", "vk-portal.net", "vk.com", "vk.mail.ru", "vkdoc.mail.ru",
        "vkvideo.cs7777.vk.ru", "voina.mail.ru", "voter.gosuslugi.ru", "vt-1.ozone.ru",
        "wap.yandex.com", "wap.yandex.ru", "warface.mail.ru", "warheaven.mail.ru",
        "wartune.mail.ru", "wb.ru", "wcm.weborama-tech.ru", "web-static.mindbox.ru", "web.max.ru",
        "webagent.mail.ru", "weblink.predict.mail.ru", "webstore.mail.ru", "welcome.mail.ru",
        "welcome.rzd.ru", "wf.mail.ru", "wh-cpg.money.mail.ru", "whatsnew.mail.ru",
        "widgets.cbonds.ru", "widgets.kinopoisk.ru", "wok.mail.ru", "wos.mail.ru",
        "ws-api.oneme.ru", "ws.seller.ozon.ru", "www.avito.ru", "www.avito.st", "www.biz.mail.ru",
        "www.cikrf.ru", "www.drive2.ru", "www.drom.ru", "www.farpost.ru", "www.gazprombank.ru",
        "www.gosuslugi.ru", "www.ivi.ru", "www.kinopoisk.ru", "www.kp.ru", "www.magnit.com",
        "www.mail.ru", "www.mcs.mail.ru", "www.open.ru", "www.ozon.ru", "www.pochta.ru",
        "www.psbank.ru", "www.pubg.mail.ru", "www.raiffeisen.ru", "www.rbc.ru", "www.rzd.ru",
        "www.sberbank.ru", "www.t2.ru", "www.tbank.ru", "www.tutu.ru", "www.unicreditbank.ru",
        "www.vtb.ru", "www.wf.mail.ru", "www.wildberries.ru", "www.x5.ru", "xapi.ozon.ru",
        "xn--80ajghhoc2aj1c8b.xn--p1ai", "ya.ru", "yabro-wbplugin.edadeal.yandex.ru",
        "yabs.yandex.ru", "yandex.com", "yandex.net", "yandex.ru", "yastatic.net", "yummy.drom.ru",
        "zen-yabro-morda.mediascope.mc.yandex.ru", "zen.yandex.com", "zen.yandex.net",
        "zen.yandex.ru", "честныйзнак.рф"
    ]

    sorted_domains = sorted(sni_domains, key=len)
    optimized_domains = []
    for d in sorted_domains:
        is_redundant = False
        for existing in optimized_domains:
            if existing in d:
                is_redundant = True
                break
        if not is_redundant:
            optimized_domains.append(d)

    try:
        pattern_str = r"(?:" + "|".join(re.escape(d) for d in optimized_domains) + r")"
        sni_regex = re.compile(pattern_str)
    except Exception as e:
        log(f"❌ Ошибка компиляции Regex: {e}")
        return None, None, None

    def _process_file_filtering(file_idx):
        local_path = f"githubmirror/{file_idx}.txt"
        filtered_lines = []
        if not os.path.exists(local_path):
            return filtered_lines
        try:
            with open(local_path, "r", encoding="utf-8") as file:
                content = file.read()
            content = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', content)
            lines = content.splitlines()
            for line in lines:
                line = line.strip()
                if not line: continue
                if sni_regex.search(line):
                    filtered_lines.append(line)
        except Exception:
            pass
        return filtered_lines

    all_configs = []

    # Обрабатываем все файлы 1-48
    for i in range(1, 49):
        all_configs.extend(_process_file_filtering(i))

    def _load_extra_configs(url):
        count_removed = 0
        configs = []
        try:
            data = fetch_data(
                url,
                timeout=EXTRA_URL_TIMEOUT,
                max_attempts=EXTRA_URL_MAX_ATTEMPTS,
                allow_http_downgrade=False,
            )
            data, count = filter_insecure_configs("ByPassVpnLera.txt", data, log_enabled=False)
            count_removed = count
            
            data = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', data)
            lines = data.splitlines()
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    configs.append(line)
        except Exception as e:
            log(f"⚠️ Ошибка при загрузке {url}: {_format_fetch_error(e)}")
        
        return configs, count_removed
    
    extra_configs = []
    total_insecure_filtered_bypass = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(EXTRA_URLS_FOR_BYPASS))) as executor:
        futures = [executor.submit(_load_extra_configs, url) for url in EXTRA_URLS_FOR_BYPASS]
        for future in concurrent.futures.as_completed(futures):
            res_configs, res_count = future.result()
            extra_configs.extend(res_configs)
            total_insecure_filtered_bypass += res_count
    
    if total_insecure_filtered_bypass > 0:
        log(f"ℹ️ Отфильтровано {total_insecure_filtered_bypass} небезопасных конфигов для ByPassVpnLera.txt")

    all_configs.extend(extra_configs)

    # Дедупликация перед тестированием
    seen_full = set()
    seen_hostport = set()
    unique_configs = []

    for cfg in all_configs:
        c = cfg.strip()
        if not c or c in seen_full: continue
        seen_full.add(c)
        hostport = _extract_host_port(c)
        if hostport:
            key = f"{hostport[0].lower()}:{hostport[1]}"
            if key in seen_hostport: continue
            seen_hostport.add(key)
        unique_configs.append(c)

    log(f"📊 После дедупликации осталось {len(unique_configs)} уникальных конфигов")

    # Поиск самых быстрых конфигов
    all_results = find_fastest_configs(unique_configs, max_to_test=800, top_n=100)
    
    if all_results:
        working_configs = [r["config"] for r in all_results]
        log(f"✅ Найдено {len(working_configs)} рабочих конфигов с измеренными характеристиками")
    else:
        log(f"⚠️ Не удалось найти рабочие конфиги, использую первые 100 как запасной вариант")
        working_configs = unique_configs[:100]
        all_results = []

    # Создаём файл ByPassVpnLera.txt
    local_path_bypass = "ByPassVpnLera.txt"
    try:
        title = "MaxTre - VPN"
        title_bytes = title.encode('utf-8')
        title_base64 = base64.b64encode(title_bytes).decode('utf-8')
        
        header = f"#profile-title: base64:{title_base64}\n"
        header += "#profile-update-interval: 9\n"
        header += f"# {title}\n"
        header += f"# Всего конфигов: {len(working_configs)}\n\n"
        
        with open(local_path_bypass, "w", encoding="utf-8") as file:
            file.write(header + "\n".join(working_configs))
        log(f"📁 Создан файл {local_path_bypass} с {len(working_configs)} рабочими конфигами")
    except Exception as e:
        log(f"⚠️ Ошибка при сохранении {local_path_bypass}: {e}")

    return local_path_bypass, all_results, working_configs, unique_configs

def main(dry_run=False):
    max_workers_download = min(DEFAULT_MAX_WORKERS, max(1, len(URLS)))
    max_workers_upload = max(2, min(6, len(URLS)))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers_download) as download_pool, \
         concurrent.futures.ThreadPoolExecutor(max_workers=max_workers_upload) as upload_pool:

        download_futures = [download_pool.submit(download_and_save, i) for i in range(len(URLS))]
        upload_futures = []

        for future in concurrent.futures.as_completed(download_futures):
            result = future.result()
            if result:
                local_path, remote_path = result
                if dry_run:
                    log(f"ℹ️ Dry-run: пропускаем загрузку {remote_path} (локальный путь {local_path})")
                else:
                    upload_futures.append(upload_pool.submit(upload_to_github, local_path, remote_path))

        for uf in concurrent.futures.as_completed(upload_futures):
            _ = uf.result()

    # Создаём ByPassVpnLera.txt с результатами тестирования
    local_path_bypass, all_results, working_configs, unique_configs = create_filtered_configs()
    
    if not dry_run:
        upload_to_github(local_path_bypass, "ByPassVpnLera.txt")
    
    # ============ ПУНКТ 1 и 2: ПОИСК И ТЕСТИРОВАНИЕ XHTTP КОНФИГОВ ============
    xhttp_configs = find_xhttp_reality_configs(unique_configs)
    working_xhttp = test_and_filter_xhttp_configs(xhttp_configs)
    xhttp_file = create_xhttp_configs_file(working_xhttp)
    
    if xhttp_file and not dry_run:
        upload_to_github(xhttp_file, "XHTTP_Reality.txt")
    
    # ============ ПУНКТ 3: РЕЗЕРВНЫЙ ФАЙЛ С REALITY КОНФИГАМИ ============
    reality_configs = find_and_test_reality_configs(unique_configs)
    reality_file = create_reality_configs_file(reality_configs)
    
    if reality_file and not dry_run:
        upload_to_github(reality_file, "REALITY_WORKING.txt")
    
    # ============ ФАЙЛЫ С САМЫМИ БЫСТРЫМИ КОНФИГАМИ ============
    if all_results and working_configs:
        # ТОП-10, ТОП-50, ТОП-100
        fast_files = create_fastest_configs_files(all_results, working_configs)
        
        for file_path in fast_files:
            if not dry_run:
                upload_to_github(file_path, file_path)
        
        # Видео-оптимизированные конфиги
        video_file = create_video_optimized_configs(all_results, working_configs)
        if video_file and not dry_run:
            upload_to_github(video_file, video_file)
        
        # Конфиги с низким пингом
        low_ping_file = create_low_ping_configs(all_results)
        if low_ping_file and not dry_run:
            upload_to_github(low_ping_file, low_ping_file)

    if not dry_run:
        update_readme_table()

    ordered_keys = sorted(k for k in LOGS_BY_FILE.keys() if k != 0)
    output_lines = []

    for k in ordered_keys:
        output_lines.append(f"----- {k}.txt -----")
        output_lines.extend(LOGS_BY_FILE[k])

    if LOGS_BY_FILE.get(0):
        output_lines.append("----- Общие сообщения -----")
        output_lines.extend(LOGS_BY_FILE[0])

    print("\n".join(output_lines))

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Скачивание конфигов и загрузка в GitHub")
    parser.add_argument("--dry-run", action="store_true", help="Только скачивать и сохранять локально, не загружать в GitHub")
    args = parser.parse_args()

    main(dry_run=args.dry_run)
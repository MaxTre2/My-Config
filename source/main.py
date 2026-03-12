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

# -------------------- ЛОГИРОВАНИЕ --------------------
LOGS_BY_FILE: dict[int, list[str]] = defaultdict(list)
_LOG_LOCK = threading.Lock()
_UPDATED_FILES_LOCK = threading.Lock()

updated_files = set()

def log(message: str):
    """Добавляет сообщение в общий словарь логов."""
    with _LOG_LOCK:
        if message.startswith("-----"):
            # Извлекаем номер файла из заголовка
            match = re.search(r'----- (\d+)\.txt -----', message)
            if match:
                idx = int(match.group(1))
                LOGS_BY_FILE[idx].append(message)
            else:
                LOGS_BY_FILE[0].append(message)
        else:
            LOGS_BY_FILE[0].append(message)

# Получение текущего времени
zone = zoneinfo.ZoneInfo("Europe/Moscow")
thistime = datetime.now(zone)
offset = thistime.strftime("%H:%M | %d.%m.%Y")

# GitHub токен
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "MaxTre2/My-Config"

if GITHUB_TOKEN:
    g = Github(auth=Auth.Token(GITHUB_TOKEN))
else:
    g = Github()

REPO = g.get_repo(REPO_NAME)

if not os.path.exists("githubmirror"):
    os.mkdir("githubmirror")

# ============ ИСТОЧНИКИ ============
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
    "https://raw.githubusercontent.com/amini8k/Free-Configs/main/vless.txt",
    "https://raw.githubusercontent.com/amini8k/Free-Configs/main/vmess.txt",
    "https://raw.githubusercontent.com/amini8k/Free-Configs/main/trojan.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/vless.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/vmess.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/trojan.txt",
]

# Источники для XHTTP
XHTTP_SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/XHTTP_Reality.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/xhttp_reality.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/xhttp",
    "https://raw.githubusercontent.com/NiREvil/vless/main/xhttp.txt",
]

# Добавляем XHTTP источники
for src in XHTTP_SOURCES:
    URLS.append(src)

# Дополнительные источники
EXTRA_URLS = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless.txt",
    "https://whiteprime.github.io/xraycheck/configs/white-list_available",
]

REMOTE_PATHS = [f"githubmirror/{i+1}.txt" for i in range(len(URLS))]
LOCAL_PATHS = [f"githubmirror/{i+1}.txt" for i in range(len(URLS))]

# Добавляем дополнительные файлы
REMOTE_PATHS.extend(["ByPassVpnLera.txt", "XHTTP_Reality.txt", "REALITY_WORKING.txt", 
                     "TOP_FASTEST_10.txt", "TOP_FASTEST_50.txt", "TOP_FASTEST_100.txt",
                     "VIDEO_OPTIMIZED.txt", "LOW_PING.txt"])
LOCAL_PATHS.extend(["ByPassVpnLera.txt", "XHTTP_Reality.txt", "REALITY_WORKING.txt",
                    "TOP_FASTEST_10.txt", "TOP_FASTEST_50.txt", "TOP_FASTEST_100.txt",
                    "VIDEO_OPTIMIZED.txt", "LOW_PING.txt"])

urllib3.disable_warnings()

CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# ============ ФУНКЦИИ ЗАГРУЗКИ ============
def fetch_data(url, timeout=10):
    """Скачивает данные по URL"""
    try:
        headers = {"User-Agent": CHROME_UA}
        response = requests.get(url, timeout=timeout, headers=headers, verify=False)
        response.raise_for_status()
        return response.text
    except Exception as e:
        log(f"⚠️ Ошибка загрузки {url}: {str(e)[:50]}")
        return None

def save_to_local_file(path, content):
    """Сохраняет данные в файл"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    log(f"📁 Сохранено в {path}")

def download_and_save(idx):
    """Скачивает и сохраняет один файл"""
    if idx >= len(URLS):
        return None
    
    url = URLS[idx]
    local_path = LOCAL_PATHS[idx]
    
    log(f"----- {idx+1}.txt -----")
    log(f"⬇️ Загрузка: {url}")
    
    try:
        data = fetch_data(url)
        if data:
            # Фильтруем небезопасные конфиги
            data = filter_insecure_configs(data)
            save_to_local_file(local_path, data)
            return local_path, REMOTE_PATHS[idx]
        else:
            log(f"❌ Не удалось загрузить {url}")
            return None
    except Exception as e:
        log(f"❌ Ошибка: {str(e)[:100]}")
        return None

def filter_insecure_configs(data):
    """Удаляет небезопасные конфиги"""
    lines = data.splitlines()
    filtered = []
    for line in lines:
        if 'insecure=1' not in line and 'allowInsecure=1' not in line:
            filtered.append(line)
    return "\n".join(filtered)

# ============ ИЗВЛЕЧЕНИЕ ХОСТА И ПОРТА ============
def extract_host_port(line):
    """Извлекает хост и порт из строки конфига"""
    if not line or not isinstance(line, str):
        return None
    
    # VLESS, TROJAN, SS
    match = re.search(r'@([\w\.-]+):(\d{1,5})', line)
    if match:
        return match.group(1), match.group(2)
    
    # VMESS
    if line.startswith("vmess://"):
        try:
            payload = line[8:]
            # Добавляем padding если нужно
            rem = len(payload) % 4
            if rem:
                payload += '=' * (4 - rem)
            decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
            if decoded.startswith('{'):
                data = json.loads(decoded)
                host = data.get('add') or data.get('host')
                port = data.get('port')
                if host and port:
                    return str(host), str(port)
        except:
            pass
    
    return None

# ============ ТЕСТИРОВАНИЕ КОНФИГОВ ============
def test_config_ping(config_str, timeout=2):
    """Проверяет доступность конфига и возвращает пинг"""
    try:
        hostport = extract_host_port(config_str)
        if not hostport:
            return False, None
        
        host, port = hostport
        
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, int(port)))
        sock.close()
        
        if result == 0:
            ping_ms = int((time.time() - start) * 1000)
            return True, ping_ms
        return False, None
    except:
        return False, None

def test_config_speed(config_str, timeout=3):
    """Тестирует скорость конфига (КБ/с)"""
    try:
        hostport = extract_host_port(config_str)
        if not hostport:
            return 0
        
        host, port = hostport
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        
        # Отправляем простой HTTP запрос
        request = f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n"
        sock.send(request.encode())
        
        # Принимаем данные
        total = 0
        start = time.time()
        sock.settimeout(1)
        
        while time.time() - start < 2:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                total += len(data)
            except:
                break
        
        sock.close()
        
        elapsed = time.time() - start
        if elapsed > 0 and total > 0:
            return round((total / 1024) / elapsed, 2)
        return 0
    except:
        return 0

# ============ ПОИСК КОНФИГОВ ПО ТИПУ ============
def find_xhttp_configs(all_configs):
    """Находит XHTTP конфиги"""
    xhttp_list = []
    for cfg in all_configs:
        if not cfg or not isinstance(cfg, str):
            continue
        cfg_lower = cfg.lower()
        if ('type=xhttp' in cfg_lower or 'type%3dxhttp' in cfg_lower) and \
           ('security=reality' in cfg_lower or 'security%3dreality' in cfg_lower):
            xhttp_list.append(cfg)
    return xhttp_list

def find_reality_configs(all_configs):
    """Находит Reality конфиги"""
    reality_list = []
    for cfg in all_configs:
        if not cfg or not isinstance(cfg, str):
            continue
        cfg_lower = cfg.lower()
        if ('security=reality' in cfg_lower or 'security%3dreality' in cfg_lower) and \
           'type=xhttp' not in cfg_lower:
            reality_list.append(cfg)
    return reality_list

# ============ СБОР ВСЕХ КОНФИГОВ ============
def collect_all_configs():
    """Собирает все конфиги из скачанных файлов"""
    all_configs = []
    
    # Собираем из основных файлов
    for i in range(1, len(URLS) + 1):
        path = f"githubmirror/{i}.txt"
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Разделяем по протоколам
                    content = re.sub(r'(vmess|vless|trojan|ss)://', r'\n\1://', content)
                    lines = content.splitlines()
                    for line in lines:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            all_configs.append(line)
            except:
                pass
    
    # Собираем из extra источников
    for url in EXTRA_URLS:
        try:
            data = fetch_data(url, timeout=5)
            if data:
                data = re.sub(r'(vmess|vless|trojan|ss)://', r'\n\1://', data)
                lines = data.splitlines()
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        all_configs.append(line)
        except:
            pass
    
    log(f"📊 Собрано {len(all_configs)} конфигов")
    return all_configs

# ============ ТЕСТИРОВАНИЕ И СОРТИРОВКА ============
def test_and_sort_configs(configs, max_to_test=300):
    """Тестирует конфиги и возвращает отсортированные по качеству"""
    if not configs:
        return []
    
    log(f"🔄 Тестирование {min(len(configs), max_to_test)} конфигов...")
    
    results = []
    tested = 0
    
    # Сначала проверяем пинг
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = {}
        for cfg in configs[:max_to_test]:
            futures[executor.submit(test_config_ping, cfg, 2)] = cfg
        
        for future in concurrent.futures.as_completed(futures):
            cfg = futures[future]
            tested += 1
            try:
                working, ping = future.result(timeout=3)
                if working:
                    results.append({
                        "config": cfg,
                        "ping": ping,
                        "speed": 0
                    })
                if tested % 50 == 0:
                    log(f"📊 Протестировано: {tested}/{min(len(configs), max_to_test)}")
            except:
                pass
    
    log(f"✅ Найдено {len(results)} рабочих конфигов")
    
    if not results:
        return []
    
    # Тестируем скорость у лучших по пингу
    results.sort(key=lambda x: x["ping"])
    top_results = results[:50]  # Берём 50 лучших по пингу
    
    speed_tested = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {}
        for item in top_results:
            futures[executor.submit(test_config_speed, item["config"], 3)] = item
        
        for future in concurrent.futures.as_completed(futures):
            item = futures[future]
            speed_tested += 1
            try:
                speed = future.result(timeout=4)
                item["speed"] = speed
                log(f"⚡ #{speed_tested}: пинг={item['ping']}ms, скорость={speed}КБ/с")
            except:
                pass
    
    # Вычисляем общий балл
    for item in results:
        ping_score = max(0, 100 - (item["ping"] / 2))
        speed_score = min(100, item["speed"] / 10) if item["speed"] > 0 else 0
        item["score"] = (ping_score * 0.5) + (speed_score * 0.5)
    
    results.sort(key=lambda x: x["score"], reverse=True)
    return results

# ============ СОЗДАНИЕ ФАЙЛОВ ============
def create_file_with_header(filename, title, configs, description=""):
    """Создаёт файл с base64 заголовком"""
    if not configs:
        log(f"⚠️ Нет конфигов для {filename}")
        return None
    
    title_b64 = base64.b64encode(title.encode()).decode()
    
    header = f"#profile-title: base64:{title_b64}\n"
    header += "#profile-update-interval: 6\n"
    header += f"# {title}\n"
    header += f"# Сгенерировано: {offset}\n"
    if description:
        header += f"# {description}\n"
    header += f"# Конфигов: {len(configs)}\n\n"
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(header)
        f.write("\n".join(configs))
    
    log(f"📁 Создан {filename} с {len(configs)} конфигами")
    return filename

# ============ ЗАГРУЗКА В GITHUB ============
def upload_to_github(local_path, remote_path):
    """Загружает файл в GitHub"""
    if not os.path.exists(local_path):
        log(f"❌ Файл {local_path} не найден")
        return
    
    with open(local_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    try:
        # Пытаемся получить существующий файл
        try:
            file = REPO.get_contents(remote_path)
            # Если файл существует, обновляем
            if file.decoded_content.decode() != content:
                REPO.update_file(
                    path=remote_path,
                    message=f"🔄 Обновление {os.path.basename(remote_path)}",
                    content=content,
                    sha=file.sha
                )
                log(f"🚀 Обновлён {remote_path}")
                # Добавляем в обновлённые для README
                file_index = None
                if "githubmirror" in remote_path:
                    file_index = int(remote_path.split('/')[1].split('.')[0])
                elif "ByPassVpnLera" in remote_path:
                    file_index = len(URLS) + 1
                elif "XHTTP_Reality" in remote_path:
                    file_index = len(URLS) + 2
                elif "REALITY_WORKING" in remote_path:
                    file_index = len(URLS) + 3
                
                if file_index:
                    with _UPDATED_FILES_LOCK:
                        updated_files.add(file_index)
            else:
                log(f"🔄 {remote_path} без изменений")
        except:
            # Если файла нет, создаём
            REPO.create_file(
                path=remote_path,
                message=f"🆕 Создание {os.path.basename(remote_path)}",
                content=content
            )
            log(f"🆕 Создан {remote_path}")
    except Exception as e:
        log(f"⚠️ Ошибка загрузки {remote_path}: {str(e)[:100]}")

# ============ ОБНОВЛЕНИЕ README ============
def update_readme():
    """Обновляет README.md"""
    try:
        readme = REPO.get_contents("README.md")
        content = readme.decoded_content.decode()
        
        # Создаём новую таблицу
        table = "| № | Файл | Источник | Время | Дата |\n|--|--|--|--|--|\n"
        
        for i in range(1, len(URLS) + 1):
            status = "🟢" if i in updated_files else "⚪"
            table += f"| {i} | [`{i}.txt`](https://github.com/{REPO_NAME}/raw/refs/heads/main/githubmirror/{i}.txt) | {URLS[i-1][:30]}... | {offset} | {thistime.strftime('%d.%m.%Y')} |\n"
        
        # Дополнительные файлы
        extra_files = [
            ("ByPassVpnLera.txt", "Обход SNI"),
            ("XHTTP_Reality.txt", "XHTTP+Reality"),
            ("REALITY_WORKING.txt", "Reality (резерв)"),
            ("TOP_FASTEST_10.txt", "ТОП-10 быстрых"),
            ("TOP_FASTEST_50.txt", "ТОП-50 быстрых"),
            ("TOP_FASTEST_100.txt", "ТОП-100 быстрых"),
            ("VIDEO_OPTIMIZED.txt", "Для видео"),
            ("LOW_PING.txt", "Низкий пинг"),
        ]
        
        for i, (fname, desc) in enumerate(extra_files, len(URLS) + 1):
            status = "🟢" if i in updated_files else "⚪"
            table += f"| {i} | [`{fname}`](https://github.com/{REPO_NAME}/raw/refs/heads/main/{fname}) | {desc} | {offset} | {thistime.strftime('%d.%m.%Y')} |\n"
        
        # Заменяем старую таблицу
        pattern = r'\| № \| Файл \| Источник \| Время \| Дата \|[\s\S]*?(?=\n## |\Z)'
        new_content = re.sub(pattern, table, content)
        
        if new_content != content:
            REPO.update_file(
                path="README.md",
                message=f"📝 Обновление README",
                content=new_content,
                sha=readme.sha
            )
            log("📝 README обновлён")
    except Exception as e:
        log(f"⚠️ Ошибка обновления README: {e}")

# ============ ОСНОВНАЯ ФУНКЦИЯ ============
def main(dry_run=False):
    log("🚀 Запуск скрипта")
    
    # 1. Скачиваем все источники
    download_futures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        for i in range(len(URLS)):
            download_futures.append(executor.submit(download_and_save, i))
        
        for future in concurrent.futures.as_completed(download_futures):
            result = future.result()
            if result and not dry_run:
                local_path, remote_path = result
                upload_to_github(local_path, remote_path)
    
    # 2. Собираем все конфиги
    all_configs = collect_all_configs()
    
    if not all_configs:
        log("❌ Нет конфигов для обработки")
        return
    
    # 3. Находим XHTTP и Reality конфиги
    xhttp_configs = find_xhttp_configs(all_configs)
    reality_configs = find_reality_configs(all_configs)
    
    log(f"📊 Найдено XHTTP: {len(xhttp_configs)}, Reality: {len(reality_configs)}")
    
    # 4. Тестируем и сортируем
    tested_results = test_and_sort_configs(all_configs, 400)
    
    if not tested_results:
        log("❌ Нет рабочих конфигов")
        return
    
    # 5. Извлекаем конфиги из результатов
    working_configs = [r["config"] for r in tested_results]
    
    # 6. Создаём файлы
    
    # ByPassVpnLera.txt (все рабочие)
    create_file_with_header("ByPassVpnLera.txt", "MaxTre - VPN", working_configs[:200])
    
    # XHTTP_Reality.txt (только XHTTP)
    if xhttp_configs:
        # Тестируем XHTTP
        xhttp_tested = []
        for cfg in xhttp_configs[:100]:
            working, ping = test_config_ping(cfg, 2)
            if working:
                xhttp_tested.append(cfg)
        if xhttp_tested:
            create_file_with_header("XHTTP_Reality.txt", "MaxTre - XHTTP+Reality", xhttp_tested[:50])
    
    # REALITY_WORKING.txt (резерв)
    if reality_configs:
        reality_tested = []
        for cfg in reality_configs[:150]:
            working, ping = test_config_ping(cfg, 2)
            if working:
                reality_tested.append(cfg)
        if reality_tested:
            create_file_with_header("REALITY_WORKING.txt", "MaxTre - Reality (резерв)", reality_tested[:100])
    
    # ТОП файлы
    if len(working_configs) >= 10:
        create_file_with_header("TOP_FASTEST_10.txt", "MaxTre - ТОП-10 быстрых", 
                               working_configs[:10], "Самые быстрые конфиги")
    
    if len(working_configs) >= 50:
        create_file_with_header("TOP_FASTEST_50.txt", "MaxTre - ТОП-50 быстрых", 
                               working_configs[:50], "Отбор по скорости и пингу")
    
    if len(working_configs) >= 100:
        create_file_with_header("TOP_FASTEST_100.txt", "MaxTre - ТОП-100 быстрых", 
                               working_configs[:100], "Проверенные рабочие")
    
    # Видео-оптимизированные (по скорости)
    video_configs = [r["config"] for r in sorted(tested_results, key=lambda x: x["speed"], reverse=True)[:30]]
    if video_configs:
        create_file_with_header("VIDEO_OPTIMIZED.txt", "MaxTre - Для видео", 
                               video_configs, "Высокая скорость для стриминга")
    
    # Низкий пинг
    low_ping_configs = [r["config"] for r in sorted(tested_results, key=lambda x: x["ping"])[:20]]
    if low_ping_configs:
        avg_ping = sum(r["ping"] for r in sorted(tested_results, key=lambda x: x["ping"])[:20]) / 20
        create_file_with_header("LOW_PING.txt", "MaxTre - Низкий пинг", 
                               low_ping_configs, f"Средний пинг: {avg_ping:.0f}ms")
    
    # 7. Загружаем всё в GitHub
    if not dry_run:
        files_to_upload = [
            "ByPassVpnLera.txt",
            "XHTTP_Reality.txt",
            "REALITY_WORKING.txt",
            "TOP_FASTEST_10.txt",
            "TOP_FASTEST_50.txt", 
            "TOP_FASTEST_100.txt",
            "VIDEO_OPTIMIZED.txt",
            "LOW_PING.txt"
        ]
        
        for fname in files_to_upload:
            if os.path.exists(fname):
                upload_to_github(fname, fname)
        
        update_readme()
    
    # 8. Выводим логи
    for k in sorted(LOGS_BY_FILE.keys()):
        if k == 0:
            print("\n".join(LOGS_BY_FILE[k]))
        else:
            print(f"----- {k}.txt -----")
            for msg in LOGS_BY_FILE[k][1:]:  # Пропускаем заголовок
                print(msg)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    main(dry_run=args.dry_run)
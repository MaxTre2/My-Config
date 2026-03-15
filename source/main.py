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
import yaml
import os
import socket
try:
    import geoip2.database as _geoip2_db
    _GEOIP2_AVAILABLE = True
except ImportError:
    _geoip2_db = None
    _GEOIP2_AVAILABLE = False
import time
import subprocess
import platform

# -------------------- КОНВЕРТЕР ПОДПИСОК (из sub_convert.py) --------------------
class sub_convert:
    """
    Конвертер VPN-подписок.
    Поддерживает форматы: Base64, plain URL-список, Clash YAML.
    Протоколы: VMess, VLESS, Shadowsocks, ShadowsocksR, Trojan.
    """

    def main(raw_input, input_type='url', output_type='url',
             custom_set=None):
        if custom_set is None:
            custom_set = {'dup_rm_enabled': False, 'format_name_enabled': False}

        if input_type == 'url':
            sub_content = ''
            if isinstance(raw_input, list):
                a_content = []
                for url in raw_input:
                    s = requests.Session()
                    s.mount('http://', HTTPAdapter(max_retries=5))
                    s.mount('https://', HTTPAdapter(max_retries=5))
                    try:
                        resp = s.get(url, timeout=5)
                        s_content = sub_convert.yaml_decode(
                            sub_convert.format(resp.content.decode('utf-8')))
                        a_content.append(s_content)
                    except Exception as err:
                        return 'Url 解析错误'
                sub_content = sub_convert.format(''.join(a_content))
            else:
                s = requests.Session()
                s.mount('http://', HTTPAdapter(max_retries=5))
                s.mount('https://', HTTPAdapter(max_retries=5))
                try:
                    resp = s.get(raw_input, timeout=5)
                    sub_content = sub_convert.format(resp.content.decode('utf-8'))
                except Exception:
                    return 'Url 解析错误'
        elif input_type == 'content':
            sub_content = sub_convert.format(raw_input)
        else:
            return '订阅内容解析错误'

        if sub_content != '订阅内容解析错误' and sub_content is not None:
            final_content = sub_content  # makeup без geoip2 пропускаем
            if output_type == 'YAML':
                return yaml.dump(final_content, default_flow_style=False,
                                 sort_keys=False, allow_unicode=True, width=750, indent=2)
            elif output_type == 'Base64':
                return sub_convert.base64_encode(sub_convert.yaml_decode(final_content))
            elif output_type in ('url', 'content'):
                return sub_convert.yaml_decode(final_content)
            else:
                return '订阅内容解析错误'
        else:
            return '订阅内容解析错误'

    def format(sub_content, output=False):
        if not sub_content or '</b>' in sub_content:
            return '订阅内容解析错误'
        if 'proxies:' not in sub_content:
            url_list = []
            try:
                if '://' not in sub_content:
                    sub_content = sub_convert.base64_decode(sub_content)
                raw_url_list = re.split(r'\r?\n+', sub_content)
                for url in raw_url_list:
                    while len(re.split('ss://|ssr://|vmess://|trojan://|vless://', url)) > 2:
                        try:
                            url_to_split = url[8:]
                            if 'ss://' in url_to_split and 'vmess://' not in url_to_split and 'vless://' not in url_to_split:
                                url_splited = url_to_split.replace('ss://', '\nss://', 1)
                            elif 'ssr://' in url_to_split:
                                url_splited = url_to_split.replace('ssr://', '\nssr://', 1)
                            elif 'vmess://' in url_to_split:
                                url_splited = url_to_split.replace('vmess://', '\nvmess://', 1)
                            elif 'trojan://' in url_to_split:
                                url_splited = url_to_split.replace('trojan://', '\ntrojan://', 1)
                            elif 'vless://' in url_to_split:
                                url_splited = url_to_split.replace('vless://', '\nvless://', 1)
                            else:
                                break
                            url_split = url_splited.split('\n')
                            front_url = url[:8] + url_split[0]
                            url_list.append(front_url)
                            url = url_split[1]
                        except Exception:
                            break
                    url_list.append(url)
                url_content = '\n'.join(url_list)
                return sub_convert.yaml_encode(url_content, output=False)
            except Exception:
                return '订阅内容解析错误'
        else:
            try:
                if '!<str> ' in sub_content:
                    sub_content = sub_content.replace('!<str> ', '').replace('!<str>', '')
                try_load = yaml.safe_load(sub_content)
                if output:
                    raise ValueError
                return try_load
            except Exception:
                try:
                    sub_content = sub_content.replace("'", '').replace('"', '')
                    il_chars = ['|', '?', '[', ']', '@', '!', '%', ':']
                    lines = re.split(r'\n+', sub_content)
                    line_fix_list = []
                    for line in lines:
                        value_list = re.split(r': |, ', line)
                        if len(value_list) > 1:
                            value_list_fix = []
                            for value in value_list:
                                value_il = any(c in value for c in il_chars)
                                if value_il and '{' not in value and '}' not in value:
                                    value = '"' + value + '"'
                                value_list_fix.append(value)
                            line_fix = line
                            for idx_v in range(len(value_list_fix)):
                                line_fix = line_fix.replace(value_list[idx_v], value_list_fix[idx_v], 1)
                            line_fix_list.append(line_fix)
                        else:
                            line_fix_list.append(line)
                    sub_content = '\n'.join(line_fix_list).replace('False', 'false').replace('True', 'true')
                    if output:
                        return sub_content
                    return yaml.safe_load(sub_content)
                except Exception:
                    return '订阅内容解析错误'

    def yaml_encode(url_content, output=True):
        try:
            url_list = []
            lines = re.split(r'\n+', url_content)
            for line in lines:
                try:
                    yaml_url = {}
                    if 'vmess://' in line:
                        try:
                            vmess_json_config = json.loads(
                                sub_convert.base64_decode(line.replace('vmess://', '')))
                            defaults = {'v': 'Vmess Node', 'ps': 'Vmess Node', 'add': '0.0.0.0',
                                        'port': 0, 'id': '', 'aid': 0, 'scy': 'auto',
                                        'net': '', 'type': '', 'host': '', 'path': '/', 'tls': ''}
                            defaults.update(vmess_json_config)
                            cfg = defaults
                            if cfg['id']:
                                yaml_url.setdefault('name', urllib.parse.unquote(str(cfg['ps'])))
                                yaml_url.setdefault('server', cfg['add'])
                                yaml_url.setdefault('port', int(cfg['port']))
                                yaml_url.setdefault('type', 'vmess')
                                yaml_url.setdefault('uuid', cfg['id'])
                                yaml_url.setdefault('alterId', int(cfg['aid']))
                                yaml_url.setdefault('cipher', cfg['scy'])
                                yaml_url.setdefault('skip-cert-verify', True)
                                yaml_url.setdefault('network', cfg['net'] or 'tcp')
                                if cfg['tls'] in ('tls',) or cfg['net'] in ('h2', 'grpc'):
                                    yaml_url.setdefault('tls', True)
                                yaml_url.setdefault('ws-opts', {})
                                if cfg['path']:
                                    yaml_url['ws-opts'].setdefault('path', cfg['path'])
                                if cfg['host']:
                                    yaml_url['ws-opts'].setdefault('headers', {'Host': cfg['host']})
                                url_list.append(yaml_url)
                        except Exception:
                            pass

                    if 'ss://' in line and 'vless://' not in line and 'vmess://' not in line:
                        if '#' not in line:
                            line = line + '#SS%20Node'
                        try:
                            ss_content = line.replace('ss://', '')
                            part_list = ss_content.split('#', 1)
                            yaml_url.setdefault('name', urllib.parse.unquote(part_list[1]))
                            if '@' in part_list[0]:
                                mix_part = part_list[0].split('@', 1)
                                method_part = sub_convert.base64_decode(mix_part[0])
                                server_part = f'{method_part}@{mix_part[1]}'
                            else:
                                server_part = sub_convert.base64_decode(part_list[0])
                            server_part_list = server_part.split(':', 1)
                            method_part = server_part_list[0]
                            server_part_list = server_part_list[1].rsplit('@', 1)
                            password_part = server_part_list[0]
                            server_part_list = server_part_list[1].split(':', 1)
                            yaml_url.setdefault('server', server_part_list[0])
                            yaml_url.setdefault('port', server_part_list[1])
                            yaml_url.setdefault('type', 'ss')
                            yaml_url.setdefault('cipher', method_part)
                            yaml_url.setdefault('password', password_part)
                            url_list.append(yaml_url)
                        except Exception:
                            pass

                    if 'ssr://' in line:
                        try:
                            ssr_content = sub_convert.base64_decode(line.replace('ssr://', ''))
                            parts = re.split(':', ssr_content)
                            if len(parts) == 6:
                                pw_params = re.split(r'/\?', parts[5])
                                password_encode_str = pw_params[0]
                                params = pw_params[1]
                                param_dic = {'remarks': 'U1NSIE5vZGU=', 'obfsparam': '', 'protoparam': '', 'group': ''}
                                for part in re.split(r'&', params):
                                    kv = re.split(r'=', part)
                                    if len(kv) == 2:
                                        param_dic[kv[0]] = kv[1]
                                yaml_url.setdefault('name', sub_convert.base64_decode(param_dic['remarks']))
                                yaml_url.setdefault('server', parts[0])
                                yaml_url.setdefault('port', parts[1])
                                yaml_url.setdefault('type', 'ssr')
                                yaml_url.setdefault('cipher', parts[3])
                                yaml_url.setdefault('password', sub_convert.base64_decode(password_encode_str))
                                yaml_url.setdefault('obfs', parts[4])
                                yaml_url.setdefault('protocol', parts[2])
                                yaml_url.setdefault('obfsparam', sub_convert.base64_decode(param_dic['obfsparam']))
                                yaml_url.setdefault('protoparam', sub_convert.base64_decode(param_dic['protoparam']))
                                url_list.append(yaml_url)
                        except Exception:
                            pass

                    if 'trojan://' in line:
                        try:
                            url_content_t = line.replace('trojan://', '')
                            part_list = re.split('#', url_content_t, maxsplit=1)
                            yaml_url.setdefault('name', urllib.parse.unquote(part_list[1]))
                            server_part = part_list[0]
                            server_part_list = re.split(r':|@|\?|&', server_part)
                            yaml_url.setdefault('server', server_part_list[1])
                            yaml_url.setdefault('port', server_part_list[2])
                            yaml_url.setdefault('type', 'trojan')
                            yaml_url.setdefault('password', server_part_list[0])
                            yaml_url.setdefault('skip-cert-verify', True)
                            url_list.append(yaml_url)
                        except Exception:
                            pass

                except Exception:
                    pass

            yaml_content_dic = {'proxies': url_list}
            if output:
                return yaml.dump(yaml_content_dic, default_flow_style=False,
                                 sort_keys=False, allow_unicode=True, width=750, indent=2)
            return yaml_content_dic
        except Exception:
            return '订阅内容解析错误'

    def yaml_decode(url_content):
        try:
            if isinstance(url_content, dict):
                sub_content = url_content
            else:
                sub_content = sub_convert.format(url_content)
            if not sub_content or sub_content == '订阅内容解析错误':
                return ''
            proxies_list = sub_content.get('proxies', [])
            protocol_url = []

            for proxy in proxies_list:
                try:
                    if proxy.get('type') == 'vmess':
                        defaults = {'name': 'Vmess Node', 'server': '0.0.0.0', 'port': 0,
                                    'uuid': '', 'alterId': 0, 'cipher': 'auto', 'network': 'ws',
                                    'ws-opts': {'path': '', 'headers': {'Host': ''}}, 'tls': '', 'sni': ''}
                        defaults.update(proxy)
                        pc = defaults
                        vmess_val = {
                            'v': 2, 'ps': pc['name'], 'add': pc['server'], 'port': pc['port'],
                            'id': pc['uuid'], 'aid': pc['alterId'], 'scy': pc['cipher'],
                            'net': pc['network'], 'type': None, 'sni': pc['sni']
                        }
                        if proxy.get('tls') in (True, 'true', 'tls'):
                            vmess_val['tls'] = 'tls'
                        ws_opts = proxy.get('ws-opts')
                        if ws_opts:
                            h = ws_opts.get('headers', {})
                            if h.get('Host'):
                                vmess_val['host'] = h['Host']
                            if ws_opts.get('path'):
                                vmess_val['path'] = ws_opts['path']
                        vmess_raw = json.dumps(vmess_val, sort_keys=False, indent=2, ensure_ascii=False)
                        protocol_url.append('\nvmess://' + sub_convert.base64_encode(vmess_raw) + '\n')

                    elif proxy.get('type') == 'vless':
                        params = f"encryption={proxy.get('servername', 'none')}"
                        params += f"&type={proxy.get('network', 'tcp')}"
                        if proxy.get('tls'):
                            params += f"&security={proxy.get('tls', 'tls')}"
                        if proxy.get('sni'):
                            params += f"&sni={proxy['sni']}"
                        if proxy.get('ws-opts', {}).get('path'):
                            params += f"&path={urllib.parse.quote(proxy['ws-opts']['path'], safe='')}"
                        vless_proxy = f"\nvless://{proxy.get('uuid', '')}@{proxy['server']}:{proxy['port']}?{params}#{urllib.parse.quote(proxy['name'])}\n"
                        protocol_url.append(vless_proxy)

                    elif proxy.get('type') == 'ss':
                        ss_b64 = sub_convert.base64_encode(
                            f"{proxy['cipher']}:{proxy['password']}@{proxy['server']}:{proxy['port']}")
                        protocol_url.append(f"\nss://{ss_b64}#{urllib.parse.quote(proxy['name'])}\n")

                    elif proxy.get('type') == 'trojan':
                        trojan_go = '?allowInsecure=1'
                        if proxy.get('sni'):
                            trojan_go += f"&sni={proxy['sni']}"
                        protocol_url.append(
                            f"\ntrojan://{proxy['password']}@{proxy['server']}:{proxy['port']}{trojan_go}#{urllib.parse.quote(proxy['name'])}\n")

                    elif proxy.get('type') == 'ssr':
                        remarks = sub_convert.base64_encode(proxy['name']).replace('+', '-')
                        password = sub_convert.base64_encode(proxy.get('password', ''))
                        obfsparam = sub_convert.base64_encode(proxy.get('obfsparam', ''))
                        protoparam = sub_convert.base64_encode(proxy.get('protoparam', ''))
                        group = sub_convert.base64_encode(proxy.get('group', 'SSRProvider'))
                        ssr_str = (f"{proxy['server']}:{proxy['port']}:{proxy.get('protocol', 'origin')}:"
                                   f"{proxy['cipher']}:{proxy.get('obfs', 'plain')}:{password}"
                                   f"/?group={group}&remarks={remarks}&obfsparam={obfsparam}&protoparam={protoparam}")
                        protocol_url.append('\nssr://' + sub_convert.base64_encode(ssr_str) + '\n')

                except Exception:
                    pass

            result = ''.join(protocol_url)
            result = "\n".join(filter(lambda x: x != '', result.split("\n")))
            return result
        except Exception:
            return '订阅内容解析错误'

    def makeup(input_data, format_name_enabled=True,
               mmdb_path='./utils/Country.mmdb'):
        """
        Геолоцирует каждый прокси и переименовывает его в формат:
        🇩🇪DE-1.2.3.4-042
        Cloudflare и приватные адреса → 🏁RELAY.
        Требует файл Country.mmdb (MaxMind GeoLite2).
        """
        EMOJI = {
            'AD':'🇦🇩','AE':'🇦🇪','AF':'🇦🇫','AG':'🇦🇬','AI':'🇦🇮','AL':'🇦🇱','AM':'🇦🇲','AO':'🇦🇴',
            'AQ':'🇦🇶','AR':'🇦🇷','AS':'🇦🇸','AT':'🇦🇹','AU':'🇦🇺','AW':'🇦🇼','AX':'🇦🇽','AZ':'🇦🇿',
            'BA':'🇧🇦','BB':'🇧🇧','BD':'🇧🇩','BE':'🇧🇪','BF':'🇧🇫','BG':'🇧🇬','BH':'🇧🇭','BI':'🇧🇮',
            'BJ':'🇧🇯','BL':'🇧🇱','BM':'🇧🇲','BN':'🇧🇳','BO':'🇧🇴','BQ':'🇧🇶','BR':'🇧🇷','BS':'🇧🇸',
            'BT':'🇧🇹','BV':'🇧🇻','BW':'🇧🇼','BY':'🇧🇾','BZ':'🇧🇿','CA':'🇨🇦','CC':'🇨🇨','CD':'🇨🇩',
            'CF':'🇨🇫','CG':'🇨🇬','CH':'🇨🇭','CI':'🇨🇮','CK':'🇨🇰','CL':'🇨🇱','CM':'🇨🇲','CN':'🇨🇳',
            'CO':'🇨🇴','CR':'🇨🇷','CU':'🇨🇺','CV':'🇨🇻','CW':'🇨🇼','CX':'🇨🇽','CY':'🇨🇾','CZ':'🇨🇿',
            'DE':'🇩🇪','DJ':'🇩🇯','DK':'🇩🇰','DM':'🇩🇲','DO':'🇩🇴','DZ':'🇩🇿','EC':'🇪🇨','EE':'🇪🇪',
            'EG':'🇪🇬','EH':'🇪🇭','ER':'🇪🇷','ES':'🇪🇸','ET':'🇪🇹','EU':'🇪🇺','FI':'🇫🇮','FJ':'🇫🇯',
            'FK':'🇫🇰','FM':'🇫🇲','FO':'🇫🇴','FR':'🇫🇷','GA':'🇬🇦','GB':'🇬🇧','GD':'🇬🇩','GE':'🇬🇪',
            'GF':'🇬🇫','GG':'🇬🇬','GH':'🇬🇭','GI':'🇬🇮','GL':'🇬🇱','GM':'🇬🇲','GN':'🇬🇳','GP':'🇬🇵',
            'GQ':'🇬🇶','GR':'🇬🇷','GS':'🇬🇸','GT':'🇬🇹','GU':'🇬🇺','GW':'🇬🇼','GY':'🇬🇾','HK':'🇭🇰',
            'HM':'🇭🇲','HN':'🇭🇳','HR':'🇭🇷','HT':'🇭🇹','HU':'🇭🇺','ID':'🇮🇩','IE':'🇮🇪','IL':'🇮🇱',
            'IM':'🇮🇲','IN':'🇮🇳','IO':'🇮🇴','IQ':'🇮🇶','IR':'🇮🇷','IS':'🇮🇸','IT':'🇮🇹','JE':'🇯🇪',
            'JM':'🇯🇲','JO':'🇯🇴','JP':'🇯🇵','KE':'🇰🇪','KG':'🇰🇬','KH':'🇰🇭','KI':'🇰🇮','KM':'🇰🇲',
            'KN':'🇰🇳','KP':'🇰🇵','KR':'🇰🇷','KW':'🇰🇼','KY':'🇰🇾','KZ':'🇰🇿','LA':'🇱🇦','LB':'🇱🇧',
            'LC':'🇱🇨','LI':'🇱🇮','LK':'🇱🇰','LR':'🇱🇷','LS':'🇱🇸','LT':'🇱🇹','LU':'🇱🇺','LV':'🇱🇻',
            'LY':'🇱🇾','MA':'🇲🇦','MC':'🇲🇨','MD':'🇲🇩','ME':'🇲🇪','MF':'🇲🇫','MG':'🇲🇬','MH':'🇲🇭',
            'MK':'🇲🇰','ML':'🇲🇱','MM':'🇲🇲','MN':'🇲🇳','MO':'🇲🇴','MP':'🇲🇵','MQ':'🇲🇶','MR':'🇲🇷',
            'MS':'🇲🇸','MT':'🇲🇹','MU':'🇲🇺','MV':'🇲🇻','MW':'🇲🇼','MX':'🇲🇽','MY':'🇲🇾','MZ':'🇲🇿',
            'NA':'🇳🇦','NC':'🇳🇨','NE':'🇳🇪','NF':'🇳🇫','NG':'🇳🇬','NI':'🇳🇮','NL':'🇳🇱','NO':'🇳🇴',
            'NP':'🇳🇵','NR':'🇳🇷','NU':'🇳🇺','NZ':'🇳🇿','OM':'🇴🇲','PA':'🇵🇦','PE':'🇵🇪','PF':'🇵🇫',
            'PG':'🇵🇬','PH':'🇵🇭','PK':'🇵🇰','PL':'🇵🇱','PM':'🇵🇲','PN':'🇵🇳','PR':'🇵🇷','PS':'🇵🇸',
            'PT':'🇵🇹','PW':'🇵🇼','PY':'🇵🇾','QA':'🇶🇦','RE':'🇷🇪','RO':'🇷🇴','RS':'🇷🇸','RU':'🇷🇺',
            'RW':'🇷🇼','SA':'🇸🇦','SB':'🇸🇧','SC':'🇸🇨','SD':'🇸🇩','SE':'🇸🇪','SG':'🇸🇬','SH':'🇸🇭',
            'SI':'🇸🇮','SJ':'🇸🇯','SK':'🇸🇰','SL':'🇸🇱','SM':'🇸🇲','SN':'🇸🇳','SO':'🇸🇴','SR':'🇸🇷',
            'SS':'🇸🇸','ST':'🇸🇹','SV':'🇸🇻','SX':'🇸🇽','SY':'🇸🇾','SZ':'🇸🇿','TC':'🇹🇨','TD':'🇹🇩',
            'TF':'🇹🇫','TG':'🇹🇬','TH':'🇹🇭','TJ':'🇹🇯','TK':'🇹🇰','TL':'🇹🇱','TM':'🇹🇲','TN':'🇹🇳',
            'TO':'🇹🇴','TR':'🇹🇷','TT':'🇹🇹','TV':'🇹🇻','TW':'🇹🇼','TZ':'🇹🇿','UA':'🇺🇦','UG':'🇺🇬',
            'UM':'🇺🇲','US':'🇺🇸','UY':'🇺🇾','UZ':'🇺🇿','VA':'🇻🇦','VC':'🇻🇨','VE':'🇻🇪','VG':'🇻🇬',
            'VI':'🇻🇮','VN':'🇻🇳','VU':'🇻🇺','WF':'🇼🇫','WS':'🇼🇸','XK':'🇽🇰','YE':'🇾🇪','YT':'🇾🇹',
            'ZA':'🇿🇦','ZM':'🇿🇲','ZW':'🇿🇼',
            'RELAY':'🏁','NOWHERE':'🇦🇶',
        }

        if not _GEOIP2_AVAILABLE or not os.path.exists(mmdb_path):
            return input_data  # geoip2 недоступен — возвращаем как есть

        if isinstance(input_data, dict):
            sub_content = input_data
        else:
            sub_content = sub_convert.format(input_data)

        if not sub_content or sub_content == '订阅内容解析错误':
            return input_data

        proxies_list = sub_content.get('proxies', [])
        if not proxies_list:
            return input_data

        total = len(proxies_list)
        width = 4 if total >= 1000 else (3 if total >= 100 else 2)

        with _geoip2_db.Reader(mmdb_path) as reader:
            for idx_p, proxy in enumerate(proxies_list):
                try:
                    server = proxy.get('server', '')
                    if not server or server == '127.0.0.1':
                        continue
                    # Резолвим хост в IP
                    ip = server if server.replace('.', '').isdigit() else socket.gethostbyname(server)
                    # Определяем страну
                    try:
                        resp = reader.country(ip)
                        cc = resp.country.iso_code or 'NOWHERE'
                    except Exception:
                        cc = 'NOWHERE'
                    if cc in ('CLOUDFLARE', 'PRIVATE'):
                        cc = 'RELAY'
                    flag = EMOJI.get(cc, EMOJI['NOWHERE'])
                    proxy['name'] = f"{flag}{cc}-{ip}-{idx_p:0>{width}d}"
                except Exception:
                    pass

        return sub_content

    def base64_decode(url_content):
        if not url_content:
            return ''
        url_content = url_content.replace('-', '+').replace('_', '/')
        missing_padding = len(url_content) % 4
        if missing_padding:
            url_content += '=' * (4 - missing_padding)
        try:
            return base64.b64decode(url_content.encode('utf-8')).decode('utf-8', 'ignore')
        except Exception:
            return str(base64.b64decode(url_content))

    def base64_encode(url_content):
        if url_content is None:
            url_content = ''
        return base64.b64encode(url_content.encode('utf-8')).decode('ascii')


def _normalize_sub_content(data, local_path):
    """
    Нормализует контент подписки через sub_convert.
    Если контент в формате Base64 или Clash YAML — конвертирует в plain URL-строки.
    При ошибке возвращает исходный контент.
    """
    stripped = data.strip()
    is_base64 = stripped and '://' not in stripped and '\n' not in stripped[:200]
    is_clash_yaml = 'proxies:' in stripped

    if not (is_base64 or is_clash_yaml):
        return data  # уже plain-текст, конвертация не нужна

    try:
        result = sub_convert.main(data, input_type='content', output_type='url')
        if result and result not in ('订阅内容解析错误', 'Url 解析错误') and len(result.strip()) > 0:
            log(f"🔄 [{local_path}] Контент нормализован через sub_convert ({'Base64' if is_base64 else 'Clash YAML'} → URL)")
            return result
    except Exception as e:
        log(f"⚠️ [{local_path}] Ошибка нормализации sub_convert: {e}")
    return data


def _geo_rename_configs(configs: list, label: str,
                        mmdb_path: str = './utils/Country.mmdb') -> list:
    """
    Принимает список plain-URL конфигов, проставляет каждому имя
    с флагом страны (🇩🇪DE-1.2.3.4-042) через sub_convert.makeup().
    Возвращает обновлённый список URL-строк (или оригинальный при ошибке).
    """
    if not _GEOIP2_AVAILABLE or not os.path.exists(mmdb_path):
        if not _GEOIP2_AVAILABLE:
            log(f"⚠️ [{label}] geoip2 не установлен — пропуск геолокации")
        else:
            log(f"⚠️ [{label}] {mmdb_path} не найден — пропуск геолокации")
        return configs

    try:
        # plain URL → Clash dict
        joined = '\n'.join(configs)
        yaml_dict = sub_convert.yaml_encode(joined, output=False)
        if not yaml_dict or not yaml_dict.get('proxies'):
            return configs

        # Применяем геолокацию и переименование
        renamed_dict = sub_convert.makeup(yaml_dict, format_name_enabled=True, mmdb_path=mmdb_path)
        if not isinstance(renamed_dict, dict):
            return configs

        # Clash dict → plain URL
        result_text = sub_convert.yaml_decode(renamed_dict)
        if not result_text or result_text == '订阅内容解析错误':
            return configs

        result_list = [l.strip() for l in result_text.splitlines() if l.strip()]
        log(f"🌍 [{label}] Геолокация применена к {len(result_list)} конфигам")
        return result_list
    except Exception as e:
        log(f"⚠️ [{label}] Ошибка геолокации: {e}")
        return configs


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
    
    # ДОПОЛНИТЕЛЬНЫЕ ИСТОЧНИКИ
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
    
    # XHTTP ИСТОЧНИКИ
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/XHTTP_Reality.txt", #49
    "https://raw.githubusercontent.com/zieng2/wl/main/xhttp_reality.txt", #50
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/xhttp", #51
    "https://raw.githubusercontent.com/NiREvil/vless/main/xhttp.txt", #52

    # SUB_CONVERT ИСТОЧНИКИ (Base64/Clash YAML — автоматически конвертируются)
    "https://cdn.jsdelivr.net/gh/mahdibland/ShadowsocksAggregator@master/sub/sub_merge.txt", #53
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

EXTRA_URL_TIMEOUT = int(os.environ.get("EXTRA_URL_TIMEOUT", "6"))
EXTRA_URL_MAX_ATTEMPTS = int(os.environ.get("EXTRA_URL_MAX_ATTEMPTS", "2"))

REMOTE_PATHS = [f"githubmirror/{i+1}.txt" for i in range(len(URLS))]
LOCAL_PATHS = [f"githubmirror/{i+1}.txt" for i in range(len(URLS))]

REMOTE_PATHS.append("ByPassVpnLera.txt")
LOCAL_PATHS.append("ByPassVpnLera.txt")

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
        
        for i, (remote_path, url) in enumerate(zip(REMOTE_PATHS, URLS + [""]), 1):
            if i <= len(URLS):
                filename = f"{i}.txt"
                raw_file_url = f"https://github.com/{REPO_NAME}/raw/refs/heads/main/githubmirror/{i}.txt"
                source_name = extract_source_name(url)
                source_column = f"[{source_name}]({url})"
            else:
                filename = "ByPassVpnLera.txt"
                raw_file_url = f"https://github.com/{REPO_NAME}/raw/refs/heads/main/ByPassVpnLera.txt"
                source_name = "Обход SNI/CIDR белых списков"
                source_column = f"[{source_name}]({raw_file_url})"
            
            if i in updated_files:
                update_time = time_part
                update_date = date_part
            else:
                if i <= len(URLS):
                    pattern = rf"\|\s*{i}\s*\|\s*\[`{i}\.txt`\].*?\|.*?\|\s*(.*?)\s*\|\s*(.*?)\s*\|"
                else:
                    pattern = rf"\|\s*{len(URLS)+1}\s*\|\s*\[`ByPassVpnLera\.txt`\].*?\|.*?\|\s*(.*?)\s*\|\s*(.*?)\s*\|"
                match = re.search(pattern, old_content)
                if match:
                    update_time = match.group(1).strip() if match.group(1).strip() else "Никогда"
                    update_date = match.group(2).strip() if match.group(2).strip() else "Никогда"
                else:
                    update_time = "Никогда"
                    update_date = "Никогда"
            
            if i <= len(URLS):
                table_rows.append(f"| {i} | [`{i}.txt`]({raw_file_url}) | {source_column} | {update_time} | {update_date} |")
            else:
                table_rows.append(f"| {len(URLS)+1} | [`ByPassVpnLera.txt`]({raw_file_url}) | {source_column} | {update_time} | {update_date} |")

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
                    if "githubmirror" in remote_path:
                        file_index = int(remote_path.split('/')[1].split('.')[0])
                    else:
                        file_index = len(URLS) + 1
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
                if "githubmirror" in remote_path:
                    file_index = int(remote_path.split('/')[1].split('.')[0])
                else:
                    file_index = len(URLS) + 1
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
        data = _normalize_sub_content(data, local_path)  # Base64/Clash YAML → plain URL
        data, _ = filter_insecure_configs(local_path, data)

        # Проставляем флаги стран в именах конфигов
        lines = [l.strip() for l in data.splitlines() if l.strip()]
        lines = _geo_rename_configs(lines, local_path)
        data = '\n'.join(lines)

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
            if '@' in line:
                m = re.search(r'@([\w\.-]+):(\d{1,5})', line)
                if m:
                    return m.group(1), m.group(2)
        except Exception:
            pass
    
    # Общий случай
    m = re.search(r'(?:@|//)([\w\.-]+):(\d{1,5})', line)
    if m:
        return m.group(1), m.group(2)
    
    return None

# ============ ФУНКЦИЯ ТЕСТИРОВАНИЯ ============
def test_config(config_str, timeout=5):
    """Проверяет, работает ли конфиг (TCP connect)"""
    try:
        hostport = _extract_host_port(config_str)
        if not hostport:
            return False
        
        host, port = hostport
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, int(port)))
        sock.close()
        
        return result == 0
    except Exception:
        return False

# ============ ФИЛЬТРАЦИЯ XHTTP И REALITY ============
def filter_xhttp_configs(configs):
    """Оставляет только XHTTP+Reality конфиги"""
    result = []
    for cfg in configs:
        if ('type=xhttp' in cfg or 'type%3Dxhttp' in cfg) and \
           ('security=reality' in cfg or 'security%3Dreality' in cfg):
            result.append(cfg)
    return result

def filter_reality_configs(configs):
    """Оставляет только Reality конфиги (без XHTTP)"""
    result = []
    for cfg in configs:
        if ('security=reality' in cfg or 'security%3Dreality' in cfg) and \
           'type=xhttp' not in cfg and 'type%3Dxhttp' not in cfg:
            result.append(cfg)
    return result

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
        return None

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

    # ============ ШАГ 1: ДЕДУПЛИКАЦИЯ ============
    log(f"🔄 Дедупликация {len(all_configs)} конфигов...")
    
    seen_full = set()
    seen_hostport = set()
    unique_configs = []

    for cfg in all_configs:
        c = cfg.strip()
        if not c or c in seen_full: 
            continue
        seen_full.add(c)
        
        # Проверяем на дубликаты по хосту:порту
        hostport = _extract_host_port(c)
        if hostport:
            key = f"{hostport[0].lower()}:{hostport[1]}"
            if key in seen_hostport: 
                continue
            seen_hostport.add(key)
        
        unique_configs.append(c)

    log(f"📊 После дедупликации осталось {len(unique_configs)} уникальных конфигов")

    # ============ ШАГ 2: ТЕСТИРОВАНИЕ ============
    log(f"🔄 Тестирование {min(500, len(unique_configs))} уникальных конфигов...")
    
    working_configs = []
    tested = 0
    max_to_test = min(500, len(unique_configs))
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(test_config, cfg): cfg for cfg in unique_configs[:max_to_test]}
        
        for future in concurrent.futures.as_completed(futures):
            cfg = futures[future]
            tested += 1
            try:
                is_working = future.result(timeout=10)
                if is_working:
                    working_configs.append(cfg)
                    if len(working_configs) % 10 == 0:
                        log(f"✅ Найдено рабочих: {len(working_configs)}/{tested}")
            except Exception as e:
                pass
    
    log(f"📊 Найдено {len(working_configs)} рабочих конфигов из {tested} протестированных")
    
    if len(working_configs) == 0:
        log(f"⚠️ Нет рабочих конфигов! Использую уникальные как запасной вариант")
        final_configs = unique_configs[:100]
    else:
        final_configs = working_configs

    # Проставляем флаги стран для ByPassVpnLera.txt
    log(f"🌍 Геолокация {len(final_configs)} конфигов для ByPassVpnLera.txt...")
    final_configs = _geo_rename_configs(final_configs, "ByPassVpnLera.txt")

    # ============ СОХРАНЕНИЕ С ИНТЕРВАЛОМ 3 ЧАСА ============
    local_path_bypass = "ByPassVpnLera.txt"
    try:
        title = "MaxTre - VPN"
        title_base64 = base64.b64encode(title.encode('utf-8')).decode('utf-8')
        
        header = f"#profile-title: base64:{title_base64}\n"
        header += "#profile-update-interval: 3\n"  # ИНТЕРВАЛ 3 ЧАСА
        header += f"# {title}\n"
        header += f"# Рабочих конфигов: {len(final_configs)}\n"
        header += f"# Обновлено: {offset}\n\n"
        
        with open(local_path_bypass, "w", encoding="utf-8") as file:
            file.write(header + "\n".join(final_configs))
        log(f"📁 Создан файл {local_path_bypass} с интервалом обновления 3 часа и {len(final_configs)} конфигами")
    except Exception as e:
        log(f"⚠️ Ошибка при сохранении {local_path_bypass}: {e}")

    return local_path_bypass

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

    local_path_bypass = create_filtered_configs()
    
    if not dry_run:
        upload_to_github(local_path_bypass, "ByPassVpnLera.txt")

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

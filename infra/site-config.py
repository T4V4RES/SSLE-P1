#!/usr/bin/env python3
"""Lê a configuração dos sites e gera manifestos e ficheiros de serviço."""

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
KUBERNETES = ROOT / 'kubernetes'
NODES = ('k3s-master.incus', 'k3s-node1.incus')
FIELDS = ('ingestion_replicas', 'sensor_port', 'api_port', 'metrics_port', 'gateway_port')


def load_sites(path):
    sites = json.loads(Path(path).read_text())
    if not isinstance(sites, dict) or not sites:
        raise ValueError('é necessário configurar pelo menos um site')
    ports = set()
    for name, config in sites.items():
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,30}(?<!-)', name):
            raise ValueError(f'nome de site inválido: {name}')
        if not isinstance(config, dict) or set(config) != set(FIELDS):
            raise ValueError(f'configuração incompleta ou desconhecida no site {name}')
        for field in FIELDS:
            value = config[field]
            lower, upper = {'ingestion_replicas': (1, 12), 'gateway_port': (80, 29999)}.get(field, (30000, 32767))
            if type(value) is not int or not lower <= value <= upper:
                raise ValueError(f'{name}.{field} deve estar entre {lower} e {upper}')
            if field.endswith('_port'):
                if value in ports:
                    raise ValueError(f'porta repetida: {value}')
                ports.add(value)
    return sites


def manifest(site, config, tag, gateway_ip, monitor_ip):
    if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,63}', tag):
        raise ValueError('tag de imagem inválida')
    params = {field.upper(): value for field, value in config.items()}
    monitoring = (KUBERNETES / 'site-prometheus.yml').read_text().replace('@SITE@', site)
    rules = (KUBERNETES / 'site-rules.yml').read_text()
    params.update(SITE=site, IMAGE_TAG=tag, FEDERATION_NODE=NODES[0].split('.')[0],
                  GATEWAY_CIDR=f'{ipaddress.IPv4Address(gateway_ip)}/32',
                  MONITOR_CIDR=f'{ipaddress.IPv4Address(monitor_ip)}/32',
                  MONITOR_HASH=hashlib.sha256((monitoring + '\n' + rules).encode()).hexdigest())
    return re.sub(r'@([A-Z_]+)@', lambda match: str(params[match[1]]),
                  (KUBERNETES / 'site.yaml').read_text())


def gateway(sites, limits=True):
    """Configuração do nginx. limits=False só serve o ensaio comparativo sem proteção."""
    print('''limit_req_zone "$server_port:$binary_remote_addr" zone=api:10m rate=5r/s;
limit_conn_zone "$server_port:$binary_remote_addr" zone=perip:10m;
limit_conn_zone $server_port zone=per_site:1m;
limit_req_status 429;
# Pressão de ligações não deve alimentar a deteção Wazuh baseada em 429.
limit_conn_status 503;
''')
    protection = '''        limit_req zone=api burst=10 nodelay;
        limit_conn perip 20;
        limit_conn per_site 120;
''' if limits else '        # ensaio sem proteção: sem limites de pedidos nem de ligações\n'
    for name, config in sites.items():
        print(f'upstream ssle_{name} {{')
        for node in NODES:
            print(f'    server {node}:{config["api_port"]};')
        print(f'''}}
server {{
    listen {config['gateway_port']} default_server;
    server_name _;
    server_tokens off;
    client_max_body_size 64k;
    client_header_timeout 5s;
    client_body_timeout 5s;
    proxy_connect_timeout 2s;
    proxy_read_timeout 5s;
    proxy_next_upstream error timeout http_502 http_503;
    access_log /var/log/nginx/ssle-{name}-access.log;
    error_log /var/log/nginx/ssle-{name}-error.log warn;
    add_header X-Content-Type-Options nosniff always;

    location = /health {{ return 200 "ok\\n"; }}
    location = /nginx_status {{
        stub_status;
        access_log off;
        allow 127.0.0.1;
        deny all;
    }}
    location /api/ {{
{protection}        location = /api/average {{ proxy_pass http://ssle_{name}/average; }}
        location = /api/temperatures {{ proxy_pass http://ssle_{name}/temperatures; }}
        return 404;
    }}
    location / {{ return 404; }}
}}''')


def global_prometheus(sites):
    federation_targets = [{'targets': [f'{NODES[0]}:{config["metrics_port"]}'],
                           'labels': {'site': name}} for name, config in sites.items()]
    return {'global': {'scrape_interval': '15s', 'evaluation_interval': '15s'},
            'alerting': {'alertmanagers': [{'static_configs': [{'targets': ['localhost:9093']}]}]},
            'rule_files': ['/etc/prometheus/rules/global.yml', '/etc/prometheus/rules/shared-gateway.yml'],
            'scrape_configs': [
                {'job_name': 'prometheus', 'static_configs': [{'targets': ['localhost:9090']}]},
                {'job_name': 'gateway', 'static_configs': [{'targets': ['ssle-gateway.incus:9113']}]},
                {'job_name': 'federate-k3s', 'honor_labels': True, 'metrics_path': '/federate',
                 'params': {'match[]': ['{__name__=~"site:.*"}']}, 'static_configs': federation_targets},
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sites', default=KUBERNETES / 'sites.json')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('names')
    output = sub.add_parser('gateway')
    output.add_argument('--sem-limites', action='store_true', help='só para o ensaio comparativo')
    sub.add_parser('global-prometheus')
    output = sub.add_parser('setting')
    output.add_argument('site')
    output.add_argument('field', choices=FIELDS)
    output = sub.add_parser('manifest')
    output.add_argument('site')
    output.add_argument('tag')
    output.add_argument('gateway_ip')
    output.add_argument('monitor_ip')
    args = parser.parse_args()
    try:
        sites = load_sites(args.sites)
        if args.command == 'names':
            print('\n'.join(sites))
        elif args.command == 'gateway':
            gateway(sites, limits=not args.sem_limites)
        elif args.command == 'global-prometheus':
            print(json.dumps(global_prometheus(sites), indent=2))
        elif args.command == 'setting':
            print(sites[args.site][args.field])
        elif args.command == 'manifest':
            print(manifest(args.site, sites[args.site], args.tag, args.gateway_ip, args.monitor_ip), end='')
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(2, f'{exc}\n')


if __name__ == '__main__':
    main()

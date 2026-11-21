#!/usr/bin/env python3
"""Observa as defesas da instalação K3s a partir da VM Kali."""

import argparse
import json
import re
import subprocess
import time
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidencias" / "k3s-defesas-20261120T105202Z"

VOLUME = 'ssle:shared_gateway_requests:increase1m'
GATEWAY = 'nginx_up{job="gateway"}'
AUTH = 'site:ssle_ingestion_auth_rejections:increase5m'
INGEST = 'site:ssle_instances_up:sum{service="ingestion-service"}'
ALERT_AUTH = 'ALERTS{alertname="SsleIngestionAuthRejections",alertstate="firing"}'
ALERT_GATEWAY = 'ALERTS{alertname="SharedGatewayRequestSurge",alertstate="firing"}'

# Os IDs são os do ruleset SSLE. O contexto explica os casos sem alerta próprio.
SCENARIOS = {
    "rajada-http": (
        "nginx limita a taxa → HTTP 429 → Wazuh 100204/100206 → firewall do gateway; o pico global correlaciona (100232).",
        (VOLUME, GATEWAY, ALERT_GATEWAY), ("100204", "100206", "100232"), "ssle-gateway",
    ),
    "spam": (
        "SpamAssassin marca a mensagem → quarentena (hold) → Wazuh 100221/100222 → firewall do correio.",
        (), ("100221", "100222"), "lis-mail",
    ),
    "publicacao": (
        "Ingestão devolve 401/403 antes do SQLite → Prometheus → Alertmanager → Wazuh 100245.",
        (AUTH, INGEST), ("100245",), None,
    ),
    "shellshock": (
        "Assinatura no Wazuh 100210. A prevenção depende do Bash corrigido e da ausência de CGI.",
        (GATEWAY,), ("100210",), "ssle-gateway",
    ),
    "mitm": (
        "O sensor verifica o certificado do servidor. Uma falha de TLS termina antes de HTTP.",
        (INGEST,), (), None,
    ),
    "ddos": (
        "Várias origens: 100205 por origem, 100207 (botnet), 100206 bloqueia quem excede o limite; pico global → 100232.",
        (VOLUME, GATEWAY, ALERT_GATEWAY), ("100205", "100207", "100206", "100232"), "ssle-gateway",
    ),
    "sensores": (
        "A ingestão associa o token ou certificado ao ID e rejeita a publicação após revogação.",
        (AUTH, INGEST), ("100245",), None,
    ),
    "replicas": (
        "Cada site mantém réplicas de ingestão. O global mostra quantas estão disponíveis.",
        (INGEST,), (), None,
    ),
}


def incus(container, *command):
    try:
        result = subprocess.run(
            ["incus", "exec", container, "--", *command],
            capture_output=True, text=True, timeout=8, check=True,
        )
    except FileNotFoundError:
        raise RuntimeError("Executa este guião no terminal da Kali, com Incus.") from None
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{container}: a leitura excedeu o tempo limite.") from None
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip().splitlines()
        raise RuntimeError(f"{container}: {detail[-1] if detail else 'leitura sem sucesso'}") from None
    return result.stdout


def prometheus(queries, endpoint="http://127.0.0.1:9090"):
    """Lê as séries instantâneas no Prometheus indicado."""
    for query in queries:
        payload = incus(
            "prom-global", "curl", "-fsS", "--max-time", "5", "--get",
            "--data-urlencode", f"query={query}", f"{endpoint}/api/v1/query",
        )
        response = json.loads(payload)
        values = response["data"]["result"]
        display = ", ".join(
            f"{item['metric'].get('site') or item['metric'].get('job') or 'global'}={float(item['value'][1]):.3g}"
            for item in values
        )
        print(f"  {query}: {display or 'sem série nesta consulta'}")


def local_auth_alerts():
    settings = ROOT / "kubernetes" / "sites.json"
    for site, config in json.loads(settings.read_text()).items():
        print(f"  Prometheus local de {site} — só alertas ativos:")
        prometheus((ALERT_AUTH,), f"http://k3s-master.incus:{config['metrics_port']}")


def wazuh(rules):
    print("\nWazuh")
    if not rules:
        print("  Sem regra específica do projeto neste cenário.")
        return
    print("  Filtro: " + " OR ".join(f'rule.id:"{rule}"' for rule in rules))
    events = deque(maxlen=6)
    raw = incus("wazuh-container", "tail", "-n", "1500", "/var/ossec/logs/alerts/alerts.json")
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        rule = str(event.get("rule", {}).get("id", ""))
        if rule in rules:
            data = event.get("data", {})
            source = data.get("pm_site") or event.get("agent", {}).get("name", "?")
            label = "  [registo sintético]" if "SSLE-VALIDACAO-" in event.get("full_log", "") else ""
            events.append(f"{event.get('timestamp', '?')}  regra={rule}  origem={source}{label}")
    if not events:
        print("  Sem eventos destas regras nos últimos 1500 registos do gestor.")
    for event in events:
        print("  " + event)


def nginx_statuses():
    print("\nGateway nginx — últimos 80 registos de cada site")
    for site in ("lisboa", "porto"):
        raw = incus("ssle-gateway", "tail", "-n", "80", f"/var/log/nginx/ssle-{site}-access.log")
        counts = Counter(re.findall(r'"[^"]*" (\d{3}) \d+', raw))
        print(f"  {site}: HTTP 200={counts['200']}  HTTP 429={counts['429']}  HTTP 503={counts['503']}")


def spam_status():
    print("\nSpamAssassin e Postfix")
    state = incus("lis-mail", "systemctl", "is-active", "postfix", "spamd").split()
    print(f"  Postfix={state[0]}  SpamAssassin={state[1]}")
    raw = incus("lis-mail", "journalctl", "-t", "spamfilter", "-n", "8", "--no-pager", "-o", "short-iso")
    decisions = re.finditer(r"^(\S+).*?\bresult=(Yes|No) score=([\d.-]+)(.*)$", raw, re.MULTILINE)
    displayed = False
    for decision in decisions:
        stamp, result, score, details = decision.groups()
        label = "  [registo sintético]" if "SSLE-VALIDACAO-" in details else ""
        print(f"  {stamp}  spam={result}  pontuação={score}{label}")
        displayed = True
    if not displayed:
        print("  Sem classificações recentes no journal.")


def firewall(container):
    print(f"\nFirewall de {container} — estado atual")
    rules = incus(container, "iptables", "-S", "INPUT").splitlines()
    drops = [rule for rule in rules if rule.startswith("-A INPUT ") and re.search(r"(?:^| )-j DROP(?: |$)", rule)]
    print(f"  Regras DROP em INPUT: {len(drops)}")
    validation_ip = {"ssle-gateway": "192.0.2.42", "lis-mail": "192.0.2.43"}[container]
    for label, address in (("manual", "192.0.2.1"), ("integrado", validation_ip)):
        active = f"-A INPUT -s {address}/32 -j DROP" in drops
        print(f"  Teste {label} ({address}): {'ativo' if active else 'inativo'}")
    print("  Últimas operações registadas pelo agente:")
    raw = incus(container, "tail", "-n", "120", "/var/ossec/logs/active-responses.log")
    actions = []
    for line in raw.splitlines():
        if "firewall-drop" not in line or "{" not in line:
            continue
        try:
            message = json.loads(line[line.index("{"):])
        except json.JSONDecodeError:
            continue
        command = message.get("command")
        if command in ("add", "delete"):
            alert = message.get("parameters", {}).get("alert", {})
            rule = alert.get("rule", {}).get("id", "")
            suffix = f"  regra={rule}" if rule else ""
            actions.append(f"{line[:19]}  {'adicionar' if command == 'add' else 'retirar'} bloqueio{suffix}")
    for action in actions[-6:]:
        print("  " + action)
    if not actions:
        print("  Sem operações recentes no ficheiro de respostas ativas.")
    print("  Estas operações podem pertencer a uma validação anterior ou a outra regra.")


def evidence(scenario):
    if not EVIDENCE.is_dir():
        print("As evidências históricas estão na pasta do projeto no computador anfitrião.")
        return
    summary_filters = {
        "rajada-http": ("429", "classificação Wazuh", "firewalls"),
        "spam": ("Postfix", "classificação Wazuh", "firewalls"),
        "publicacao": ("gravação", "100245"),
        "shellshock": ("Shellshock",),
        "mitm": ("CA correta",),
        "ddos": ("503",),
        "sensores": ("token", "gravação"),
        "replicas": ("uma réplica",),
    }
    print("Evidência guardada em 20/11/2026 — instalação K3s", flush=True)
    for line in (EVIDENCE / "resumo.md").read_text().splitlines():
        if line.startswith("- ") and any(term in line for term in summary_filters[scenario]):
            print(line)
    log_filters = {
        "publicacao": ("Wazuh 100245",),
        "replicas": ("réplicas de ingestão visíveis",),
    }
    for line in (EVIDENCE / "retoma.log").read_text().splitlines():
        if any(term in line for term in log_filters.get(scenario, ())):
            print("  " + line)
    if scenario in ("rajada-http", "spam"):
        print("  Classificação e resposta ativa verificadas em etapas separadas.")
    print(f"  Fonte: {EVIDENCE.relative_to(ROOT)}/")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cenario", choices=SCENARIOS)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--acompanhar", action="store_true", help="Atualiza de 10 em 10 segundos até Ctrl+C.")
    mode.add_argument("--evidencia", action="store_true", help="Mostra a evidência guardada deste cenário.")
    options = parser.parse_args()
    route, queries, rules, firewall_container = SCENARIOS[options.cenario]

    try:
        if options.evidencia:
            evidence(options.cenario)
            return 0
        while True:
            stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
            print(f"\n{stamp}  {options.cenario}\n{route}", flush=True)
            print("\nPrometheus global")
            if queries:
                prometheus(queries)
            else:
                print("  O projeto atual não recolhe métricas de spam no Prometheus.")
            if options.cenario == "publicacao":
                local_auth_alerts()
            wazuh(rules)
            if options.cenario in ("rajada-http", "ddos"):
                nginx_statuses()
            if options.cenario == "spam":
                spam_status()
            if firewall_container:
                firewall(firewall_container)
            print("  Para executar os testes da Kali, consulta o README.md.", flush=True)
            if not options.acompanhar:
                return 0
            time.sleep(10)
    except KeyboardInterrupt:
        return 0
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        parser.exit(1, f"Erro: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env bash
# Funções comuns dos ensaios de ataque. Correm na VM Kali, na raiz do projeto.
# Os alvos e as origens são sempre contentores da bridge do laboratório.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../infra/k3s-lib.sh"

LAB_CIDR=$(incus network get "$SSLE_BRIDGE" ipv4.address)
STARTED=()

now() { date -u +%H:%M:%S.%3N; }
epoch() { date +%s.%N; }

# IPv4 de um contentor, recusando qualquer endereço fora da bridge.
lab_ip() {
    local ip
    ip=$(container_ipv4 "$1")
    python3 -c 'import ipaddress, sys; sys.exit(ipaddress.ip_address(sys.argv[1]) not in ipaddress.ip_network(sys.argv[2], strict=False))' \
        "${ip:-0.0.0.0}" "$LAB_CIDR" || { echo "$1 sem IPv4 na rede $LAB_CIDR" >&2; exit 1; }
    printf '%s\n' "$ip"
}

# Liga os clientes de ensaio que estiverem parados e volta a pará-los no fim.
start_clients() {
    local client
    for client in "$@"; do
        if [[ $(incus list "^$client$" -c s -f csv) != RUNNING ]]; then
            incus start "$client"
            STARTED+=("$client")
        fi
    done
    for client in "$@"; do
        for _ in $(seq 30); do [[ -n $(container_ipv4 "$client") ]] && break; sleep 1; done
        lab_ip "$client" >/dev/null
    done
}
stop_clients() {
    local client
    for client in "${STARTED[@]}"; do incus stop "$client" || true; done
}
trap stop_clients EXIT

evidence_dir() {
    OUT=${SSLE_EVIDENCE:-$ROOT/evidencias}/$1-$(date -u +%Y%m%dT%H%M%SZ)
    mkdir -p "$OUT"
    printf 'Evidência em %s\n' "$OUT"
}

# Regista as mudanças de estado do bloqueio de uma origem na firewall de um agente.
watch_drop() {
    local container=$1 ip=$2 seconds=$3 state last=none end
    end=$(( $(date +%s) + seconds ))
    while (( $(date +%s) < end )); do
        if incus exec "$container" -- iptables -S INPUT </dev/null | grep -q -- "-s $ip/32 -j DROP"; then state=DROP; else state=none; fi
        [[ $state != "$last" ]] && printf '%s %s\n' "$(now)" "$state" && last=$state
        sleep 0.5
    done
}

# Alertas do Wazuh desde um instante (epoch) para as regras indicadas.
wazuh_alerts() {
    local since=$1; shift
    incus exec wazuh-container -- python3 - "$since" "$@" </dev/null <<'PY'
import datetime, json, re, sys
since, rules = float(sys.argv[1]), set(sys.argv[2:])
for line in open('/var/ossec/logs/alerts/alerts.json', errors='replace'):
    try:
        alert = json.loads(line)
    except ValueError:
        continue
    rule = alert.get('rule', {})
    if rule.get('id') not in rules:
        continue
    stamp = re.sub(r'([+-]\d{2})(\d{2})$', r'\1:\2', alert['timestamp'])
    if datetime.datetime.fromisoformat(stamp).timestamp() < since:
        continue
    data = alert.get('data', {})
    print(json.dumps({'timestamp': alert['timestamp'], 'rule': rule['id'], 'level': rule.get('level'),
                      'description': rule.get('description'), 'agent': alert.get('agent', {}).get('name'),
                      'srcip': data.get('srcip'), 'location': alert.get('location'),
                      'correlation': {k: data[k] for k in ('site', 'scope', 'attack_rule', 'source', 'performance_alert', 'delta_seconds') if k in data} or None},
                     ensure_ascii=False))
PY
}

# Resumo dos alertas: contagem e primeiro instante de cada regra.
summarize_alerts() {
    python3 - "$1" <<'PY'
import collections, json, sys
first, count = {}, collections.Counter()
for line in open(sys.argv[1]):
    alert = json.loads(line)
    count[alert['rule']] += 1
    first.setdefault(alert['rule'], (alert['timestamp'][11:23], alert['description']))
for rule in sorted(count):
    print(f"regra {rule}: {count[rule]}x, primeira às {first[rule][0]} UTC - {first[rule][1]}")
PY
}

# Agentes com resposta ativa (firewall-drop).
AR_AGENTS=(ssle-gateway lis-mail k3s-master k3s-node1)

# Espera que não haja bloqueios ativos (exceto os endereços TEST-NET dos testes).
wait_unblocked_lab() {
    local c busy
    for _ in $(seq 90); do
        busy=0
        for c in "${AR_AGENTS[@]}"; do
            incus exec "$c" -- iptables -S INPUT </dev/null | grep -- '-j DROP' | grep -vq -- '-s 192.0.2.' && busy=1
        done
        ((busy)) || return 0
        sleep 10
    done
    echo "aviso: ainda há bloqueios ativos" >&2
}

# Limpa o historial de reincidentes, que o correlacionador guarda em memória.
# Usado entre repetições, para serem independentes, e antes da demonstração.
reset_reputation() {
    incus exec wazuh-container -- systemctl restart ssle-correlator </dev/null
    sleep 2
}

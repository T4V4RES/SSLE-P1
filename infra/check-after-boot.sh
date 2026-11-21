#!/usr/bin/env bash
# Verificação depois de arrancar a VM ou antes da demonstração.
set -euo pipefail
source "$(dirname "$0")/k3s-lib.sh"
fail=0
problem() { printf 'PROBLEMA: %s\n' "$*" >&2; fail=1; }

echo '== Nomes .incus (host-record, independentes do DHCP)'
for container in "${CORE_CONTAINERS[@]}"; do
    expected=$(container_ipv4 "$container")
    for client in ssle-gateway prom-global; do
        got=$(incus exec "$client" -- getent ahostsv4 "$container.incus" | awk 'NR==1 {print $1}')
        [[ $got == "$expected" ]] || problem "$client resolve $container.incus para '${got:-nada}' (esperado $expected)"
    done
done
incus network get "$SSLE_BRIDGE" raw.dnsmasq | grep -q host-record || problem "sem host-record no $SSLE_BRIDGE (correr pin_dns)"

echo '== K3s'
kube get nodes
for site in $(config names); do
    kube -n "$site" get deployment,pvc
    for service in storage ingestion analytics sensor prometheus; do
        kube -n "$site" rollout status "deployment/$service" --timeout=45s
    done
    port=$(config setting "$site" gateway_port)
    incus exec ssle-gateway -- curl -fsS --max-time 8 "http://127.0.0.1:$port/api/average?limit=1" || problem "API de $site"
    printf '\n'
done

echo '== Gateway, correio e SIEM'
incus exec ssle-gateway -- nginx -t 2>&1 | tail -1 || problem 'nginx -t'
incus exec prom-global -- systemctl is-active prometheus prometheus-alertmanager ssle-alert-webhook || problem 'serviços do prom-global'
incus exec lis-mail -- systemctl is-active postfix spamd || problem 'correio'
incus exec wazuh-container -- systemctl is-active wazuh-manager ssle-correlator || problem 'Wazuh'
agents=$(incus exec wazuh-container -- /var/ossec/bin/agent_control -l)
for agent in ssle-gateway lis-mail prom-global; do
    grep -q "Name: $agent,.*Active" <<<"$agents" || problem "agente Wazuh $agent inativo"
done
for container in ssle-gateway lis-mail; do
    left=$(incus exec "$container" -- iptables -S INPUT | grep -c -- '-j DROP' || true)
    [[ $left == 0 ]] || echo "Aviso: $container tem $left bloqueio(s) ativo(s) da resposta ativa."
done

echo '== Prometheus global'
incus exec prom-global -- python3 - <<'PY' || problem 'alvos do Prometheus em baixo'
import json, sys, urllib.request
get = lambda path: json.load(urllib.request.urlopen('http://127.0.0.1:9090/api/v1/' + path, timeout=5))['data']
down = [t['labels'].get('job') + '/' + t['labels'].get('site', '-') for t in get('targets')['activeTargets'] if t['health'] != 'up']
firing = sorted({a['labels']['alertname'] + '/' + a['labels'].get('site', '-') for a in get('alerts')['alerts'] if a['state'] == 'firing'})
print('alvos em baixo:', down or 'nenhum')
print('alertas ativos:', firing or 'nenhum')
sys.exit(1 if down else 0)
PY
exit "$fail"

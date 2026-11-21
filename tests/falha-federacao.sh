#!/usr/bin/env bash
# Falha controlada: o Prometheus global deixa de federar um site enquanto um
# atacante tenta publicar sem credencial. Verifica que SiteMonitoringUnreachable
# dispara e que o alerta de segurança do site não fica suprimido pela inibição.
# Uso: tests/falha-federacao.sh [site]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/infra/k3s-lib.sh"
site=${1:-lisboa}
mkdir -p "${SSLE_EVIDENCE:-$root/evidencias}"
exec > >(tee "${SSLE_EVIDENCE:-$root/evidencias}/falha-federacao-$site-$(date -u +%Y%m%dT%H%M%SZ).log") 2>&1
port=$(config setting "$site" metrics_port)
monitor=$(container_ipv4 prom-global)
rule=(PREROUTING -s "$monitor/32" -p tcp --dport "$port" -m comment --comment ssle-falha-federacao -j DROP)
# O nó K3s usa o iptables que vem com o K3s.
iptables_k3s() { incus exec k3s-master -- /var/lib/rancher/k3s/data/current/bin/aux/iptables "$@" </dev/null; }
restore() { iptables_k3s -t raw -D "${rule[@]}" 2>/dev/null || true; }
trap restore EXIT

firing() {
    incus exec prom-global -- curl -s http://127.0.0.1:9090/api/v1/alerts </dev/null | python3 -c '
import json, sys
site = sys.argv[1]
names = {a["labels"]["alertname"] for a in json.load(sys.stdin)["data"]["alerts"] if a["state"] == "firing" and a["labels"].get("site") == site}
sys.exit(0 if "SiteMonitoringUnreachable" in names else 1)' "$site"
}

printf '%s corte da federação de %s (prom-global -> k3s-master:%s)\n' "$(date -u +%T)" "$site" "$port"
iptables_k3s -t raw -I "${rule[@]}"
for _ in $(seq 36); do firing && break; sleep 5; done
firing || { echo 'SiteMonitoringUnreachable não disparou' >&2; exit 1; }
printf '%s SiteMonitoringUnreachable ativo para %s\n' "$(date -u +%T)" "$site"

SSLE_EVIDENCE=${SSLE_EVIDENCE:-$root/evidencias} "$root/ataques/publicacao.sh" "$site"

restore
printf '%s federação reposta\n' "$(date -u +%T)"
for _ in $(seq 36); do firing || break; sleep 5; done
if firing; then echo 'a federação não recuperou' >&2; exit 1; fi
printf '%s SiteMonitoringUnreachable resolvido\n' "$(date -u +%T)"

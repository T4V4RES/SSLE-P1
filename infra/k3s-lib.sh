#!/usr/bin/env bash
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

export SSLE_SITES=${SSLE_SITES:-$ROOT/kubernetes/sites.json}
config() { python3 "$ROOT/infra/site-config.py" --sites "$SSLE_SITES" "$@"; }
kube() { incus exec k3s-master --mode=non-interactive -- k3s kubectl "$@"; }

container_ipv4() {
    incus list "^$1$" -f json | python3 -c '
import json, sys
rows = json.load(sys.stdin)
if rows:
    network = (rows[0].get("state") or {}).get("network") or {}
    for address in network.get("eth0", {}).get("addresses", []):
        if address["family"] == "inet" and address["scope"] == "global":
            print(address["address"])
            break
'
}

reserve_address() {
    local container=$1 ip
    ip=$(container_ipv4 "$container")
    [[ -n $ip ]] || { echo "Sem IPv4: $container" >&2; return 1; }
    if [[ $(incus config device get "$container" eth0 ipv4.address 2>/dev/null) != "$ip" ]]; then
        incus config device override "$container" eth0 "ipv4.address=$ip" >/dev/null 2>&1 ||
            incus config device set "$container" eth0 ipv4.address "$ip" >/dev/null
    fi
    printf '%s\n' "$ip"
}

# Nomes .incus fixos. O dnsmasq do Incus só publica o nome de um contentor
# enquanto existe a concessão DHCP; se a VM for suspensa ou a renovação
# falhar, o nome desaparece e o nginx, a federação e o Alertmanager deixam de
# encontrar os destinos (falha observada a 21/11). Cada contentor principal
# fica com o IP reservado e com um host-record que não depende da concessão.
CORE_CONTAINERS=(k3s-master k3s-node1 ssle-gateway lis-mail prom-global wazuh-container)
SSLE_BRIDGE=${SSLE_BRIDGE:-incusbr0}
pin_dns() {
    local records='' container ip
    for container in "${CORE_CONTAINERS[@]}"; do
        ip=$(reserve_address "$container") || return 1
        records+="host-record=$container.incus,$container,$ip"$'\n'
    done
    if [[ $(incus network get "$SSLE_BRIDGE" raw.dnsmasq) != "${records%$'\n'}" ]]; then
        incus network set "$SSLE_BRIDGE" "raw.dnsmasq=${records%$'\n'}"
    fi
}

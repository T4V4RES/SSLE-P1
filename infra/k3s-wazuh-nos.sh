#!/usr/bin/env bash
# Agente Wazuh nos nós K3s (grupo k3s). Lê as recusas da ingestão, que ficam
# no log do contentor com o IP real do sensor, e aplica a resposta ativa à
# origem que insiste (regra 100247). O K3s traz o seu próprio iptables; o
# firewall-drop procura "iptables" no PATH, por isso fica um atalho para ele.
set -euo pipefail
source "$(dirname "$0")/k3s-lib.sh"
manager=wazuh-container

incus exec "$manager" -- /var/ossec/bin/agent_groups -a -g k3s -q 2>/dev/null || true
incus exec "$manager" -- mkdir -p /var/ossec/etc/shared/k3s
push "$ROOT/wazuh/groups/k3s.conf" "$manager/var/ossec/etc/shared/k3s/agent.conf"
incus exec "$manager" -- chown wazuh:wazuh /var/ossec/etc/shared/k3s/agent.conf

for node in k3s-master k3s-node1; do
    log "Agente Wazuh em $node"
    incus exec "$node" -- sh -ec '
        bundled=/var/lib/rancher/k3s/data/current/bin/aux/iptables
        test -x "$bundled"
        if ! command -v iptables >/dev/null; then
            printf "#!/bin/sh\nexec %s \"\$@\"\n" "$bundled" > /usr/local/sbin/iptables
            chmod 755 /usr/local/sbin/iptables
        fi'
    if [[ -z $(wazuh_agent_id "$node") ]] || ! incus exec "$node" -- systemctl is-active --quiet wazuh-agent; then
        install_wazuh_agent "$node" k3s
    fi
done

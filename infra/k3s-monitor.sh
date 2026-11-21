#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/k3s-lib.sh"
container=prom-global
mode=${1:-activate}
[[ $mode == prepare || $mode == activate ]] || exit 2

launch "$container"
if ! incus exec "$container" -- sh -c 'command -v promtool >/dev/null && command -v amtool >/dev/null'; then
    apt_install "$container" 'prometheus prometheus-alertmanager python3'
fi
if [[ $mode == prepare ]]; then exit 0; fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
config global-prometheus > "$work/prometheus.yml"
incus exec "$container" -- install -d -m 0755 /etc/prometheus/rules /var/log/ssle
push "$ROOT/monitorizacao/rules-global.yml" "$container/etc/prometheus/rules/global.yml"
push "$ROOT/monitorizacao/shared-gateway.yml" "$container/etc/prometheus/rules/shared-gateway.yml"
push "$work/prometheus.yml" "$container/etc/prometheus/prometheus-k3s.yml"
push "$ROOT/monitorizacao/alertmanager-k3s.yml" "$container/etc/prometheus/alertmanager-k3s.yml"
push "$ROOT/monitorizacao/alert_webhook.py" "$container/usr/local/bin/alert_webhook.py"
push "$ROOT/monitorizacao/ssle-alert-webhook.service" "$container/etc/systemd/system/ssle-alert-webhook.service"
incus exec "$container" -- sh -ec '
    cd /etc/prometheus
    promtool check config prometheus-k3s.yml
    amtool check-config alertmanager-k3s.yml
    if test -f prometheus.yml && ! test -e prometheus-before-k3s.yml; then cp -p prometheus.yml prometheus-before-k3s.yml; fi
    if test -f alertmanager.yml && ! test -e alertmanager-before-k3s.yml; then cp -p alertmanager.yml alertmanager-before-k3s.yml; fi
    install -m 0644 prometheus-k3s.yml prometheus.yml
    install -m 0644 alertmanager-k3s.yml alertmanager.yml
    touch /var/log/ssle/prometheus-alerts.json
    systemctl daemon-reload
    systemctl enable --now ssle-alert-webhook prometheus prometheus-alertmanager
    systemctl restart ssle-alert-webhook prometheus prometheus-alertmanager
'
if [[ -z $(wazuh_agent_id "$container") ]] || ! incus exec "$container" -- systemctl is-active --quiet wazuh-agent; then
    incus exec wazuh-container -- /var/ossec/bin/agent_groups -a -g monitoring -q 2>/dev/null || true
    incus exec wazuh-container -- mkdir -p /var/ossec/etc/shared/monitoring
    push "$ROOT/wazuh/groups/monitoring.conf" wazuh-container/var/ossec/etc/shared/monitoring/agent.conf
    incus exec wazuh-container -- chown wazuh:wazuh /var/ossec/etc/shared/monitoring/agent.conf
    install_wazuh_agent "$container" monitoring
fi

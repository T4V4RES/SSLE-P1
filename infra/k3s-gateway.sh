#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/k3s-lib.sh"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
gateway=ssle-gateway
config gateway > "$work/site.conf"
log 'Gateway partilhado'
launch "$gateway"
apt_install "$gateway" 'nginx prometheus-nginx-exporter iptables curl'
reserve_address "$gateway" >/dev/null
port=$(config setting "$(config names | sed -n '1p')" gateway_port)

while IFS= read -r site; do
    incus exec "$gateway" -- touch "/var/log/nginx/ssle-$site-access.log" "/var/log/nginx/ssle-$site-error.log"
done < <(config names)
push "$work/site.conf" "$gateway/etc/nginx/sites-available/ssle-k3s"
incus exec "$gateway" -- sh -ec '
    ln -sf /etc/nginx/sites-available/ssle-k3s /etc/nginx/sites-enabled/ssle-k3s
    unlink /etc/nginx/sites-enabled/default 2>/dev/null || test ! -L /etc/nginx/sites-enabled/default
    printf "ARGS=\"--nginx.scrape-uri=http://127.0.0.1:%s/nginx_status\"\n" "$1" > /etc/default/prometheus-nginx-exporter
    mkdir -p /etc/systemd/system/nginx.service.d
    printf "[Unit]\nStartLimitIntervalSec=0\n[Service]\nRestart=on-failure\nRestartSec=3s\n" > /etc/systemd/system/nginx.service.d/ssle-retry.conf
    nginx -t
    systemctl daemon-reload
    systemctl enable --now nginx prometheus-nginx-exporter
    systemctl reload nginx
    systemctl restart prometheus-nginx-exporter
' sh "$port"

manager=wazuh-container
incus exec "$manager" -- /var/ossec/bin/agent_groups -a -g gateway -q 2>/dev/null || true
incus exec "$manager" -- mkdir -p /var/ossec/etc/shared/gateway
push "$ROOT/wazuh/groups/gateway.conf" "$manager/var/ossec/etc/shared/gateway/agent.conf"
incus exec "$manager" -- chown wazuh:wazuh /var/ossec/etc/shared/gateway/agent.conf
incus exec "$manager" -- /var/ossec/bin/wazuh-logcollector -t
if [[ -z $(wazuh_agent_id "$gateway") ]] || ! incus exec "$gateway" -- systemctl is-active --quiet wazuh-agent; then
    install_wazuh_agent "$gateway" gateway
fi
push "$ROOT/monitorizacao/correlate.py" "$manager/usr/local/bin/ssle-correlate.py"
incus exec "$manager" -- systemctl restart ssle-correlator

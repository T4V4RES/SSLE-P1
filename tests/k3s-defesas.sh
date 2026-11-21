#!/usr/bin/env bash
# Aceitação defensiva da instalação atual, na VM Kali.
set -euo pipefail
source "$(dirname "$0")/../infra/k3s-lib.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
umask 077

wazuh_rules() {
    incus exec wazuh-container --mode=non-interactive -- /var/ossec/bin/wazuh-logtest 2>&1 |
        awk '/^\*\*Phase 3/ {phase=1; next}
             phase && /id:/ {gsub(/[^0-9]/, ""); print; phase=0}'
}

spam_lines() {
    local count=$1 result=$2 stamp
    stamp=$(date -u '+%b %e %T')
    for ((i = 0; i < count; i++)); do
        printf '%s lis-mail spamfilter: result=%s score=7.5 client=192.0.2.27 from=<probe@example.test> to=<probe@example.test> tests=SSLE\n' "$stamp" "$result"
    done
}

check_rule() {
    local expected=$1 result
    result=$(wazuh_rules)
    grep -Fxq "$expected" <<< "$result" || {
        printf 'Regra %s não encontrada. Regras: %s\n' "$expected" "$result" >&2
        return 1
    }
}

wait_for_alert() {
    local site=$1 port active_at
    port=$(config setting "$site" metrics_port)
    for ((attempt = 1; attempt <= 30; attempt++)); do
        active_at=$(incus exec prom-global -- curl -fsS --max-time 4 "http://k3s-master.incus:$port/api/v1/alerts" 2>/dev/null |
            python3 -c 'import json, sys; print(next((a["activeAt"] for a in json.load(sys.stdin)["data"]["alerts"] if a["labels"].get("alertname") == "SsleIngestionAuthRejections" and a["state"] == "firing"), ""))' 2>/dev/null) || active_at=""
        if incus exec wazuh-container -- python3 -c '
import datetime
import json
import re
import sys
from pathlib import Path

def parse_time(value):
    value = re.sub(r"([+-]\d{2})(\d{2})$", lambda match: match[1] + ":" + match[2], value.replace("Z", "+00:00"))
    value = re.sub(r"\.(\d+)", lambda match: "." + match[1][:6].ljust(6, "0"), value)
    return datetime.datetime.fromisoformat(value)

site, since, active_at = sys.argv[1:]
start = parse_time(since)
active = parse_time(active_at) if active_at else None
events = []
for line in Path("/var/ossec/logs/alerts/alerts.json").open():
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue
    if event.get("rule", {}).get("id") != "100245":
        continue
    data = event.get("data", {})
    timestamp = parse_time(event["timestamp"])
    if data.get("pm_site") != site:
        continue
    episode = data.get("pm_starts_at")
    same_episode = active and episode and abs((parse_time(episode) - active).total_seconds()) <= 15
    if timestamp >= start or same_episode:
        events.append((timestamp, timestamp >= start))
if not events:
    sys.exit(1)
timestamp, new = max(events)
origin = "novo" if new else "mesmo episódio ainda ativo"
print(f"{site}: alerta Wazuh 100245 às {timestamp.isoformat()} ({origin}).")
' "$site" "$started_at" "$active_at"; then return; fi
        sleep 5
    done
    printf 'Alerta de ingestão por confirmar no Wazuh: %s\n' "$site" >&2
    return 1
}

wait_for_metrics() {
    for ((attempt = 1; attempt <= 24; attempt++)); do
        if incus exec prom-global -- curl -fsS --max-time 5 -G http://127.0.0.1:9090/api/v1/query \
            --data-urlencode 'query=site:ssle_ingestion_auth_rejections:increase5m' |
            python3 -c 'import json, sys; rows=json.load(sys.stdin)["data"]["result"]; sys.exit(not set(sys.argv[1:]).issubset({row["metric"].get("site") for row in rows}))' "$@"; then return; fi
        sleep 5
    done
    echo 'Métrica de rejeições por confirmar no Prometheus global.' >&2
    return 1
}

if [[ ${1:-} == --publicacao ]]; then
    mapfile -t sites < <(config names)
    wait_for_metrics "${sites[@]}"
    started_at=$(date -u --iso-8601=seconds)
    bash "$ROOT/tests/k3s-core.sh"
    for site in "${sites[@]}"; do wait_for_alert "$site"; done
    exit 0
fi

bash "$ROOT/infra/check-after-boot.sh"
incus exec ssle-gateway --mode=non-interactive -- bash -s < "$ROOT/tests/gateway-limits.sh"
bash "$ROOT/tests/prometheus-rules.sh"
bash "$ROOT/tests/wazuh-logtest-dos.sh"
[[ $(spam_lines 1 Yes | wazuh_rules) == 100221 ]]
[[ $(spam_lines 1 No | wazuh_rules) != *100221* ]]
mail_rules=$(spam_lines 4 Yes | wazuh_rules)
[[ $mail_rules != *100222* ]]
spam_lines 5 Yes | check_rule 100222
echo 'Correio: classificação individual e regra de volume verificadas no Wazuh com registos sintéticos.'
incus exec lis-mail --mode=non-interactive -- bash -s <<'MAIL_CHECK'
set -euo pipefail
systemctl is-active --quiet postfix
systemctl is-active --quiet spamd
work=$(mktemp)
trap 'rm -f "$work"' EXIT
id="ssle-check-$(date +%s)-$$@lis-mail.incus"
printf 'From: Verificação SSLE <ssle-check@lis-mail.incus>\r\nTo: alice@lis-mail.incus\r\nMessage-ID: <%s>\r\nSubject: Verificacao de entrega SSLE\r\n\r\nMensagem de teste da entrega local.\r\n' "$id" > "$work"
curl --noproxy '*' -fsS --max-time 8 --url smtp://127.0.0.1 \
    --mail-from ssle-check@lis-mail.incus --mail-rcpt alice@lis-mail.incus --upload-file "$work" >/dev/null
for ((attempt = 1; attempt <= 20; attempt++)); do
    if test -r /var/mail/alice && awk -v id="$id" 'BEGIN{RS="\nFrom "} index($0,id) && /X-Spam-Status: No/ {ok=1} END{exit !ok}' /var/mail/alice; then
        echo 'Correio: uma mensagem legítima foi filtrada e entregue à caixa local de teste.'
        exit 0
    fi
    sleep 1
done
echo 'Entrega da mensagem de teste por confirmar.' >&2
exit 1
MAIL_CHECK
incus exec ssle-gateway -- dpkg-query -W bash
nginx_config=$(incus exec ssle-gateway -- nginx -T 2>&1)
if grep -Eiq '^[[:space:]]*fastcgi_pass|cgi-bin' <<< "$nginx_config"; then
    echo 'Rever o encaminhamento CGI no gateway.' >&2; exit 1
fi
echo 'Gateway: regras Shellshock verificadas no logtest e configuração sem encaminhamento CGI.'

master_ip=$(container_ipv4 k3s-master)
mkdir "$work/empty-ca"
mapfile -t sites < <(config names)
[[ ${#sites[@]} -ge 2 ]]
for site in "${sites[@]}"; do
    kube -n "$site" get configmap ingestion-ca -o 'jsonpath={.data.ca\.crt}' > "$work/$site.crt"
done
for site in "${sites[@]}"; do
    other=${sites[0]}
    if [[ $other == "$site" ]]; then other=${sites[1]}; fi
    port=$(config setting "$site" sensor_port)
    tls=(--noproxy '*' --max-time 5 --resolve "k3s-master.incus:$port:$master_ip" --capath "$work/empty-ca"
        "https://k3s-master.incus:$port/health")
    curl -fsS --cacert "$work/$site.crt" "${tls[@]}" >/dev/null
    rc=0
    curl -fsS --cacert "$work/$other.crt" "${tls[@]}" >/dev/null 2>&1 || rc=$?
    [[ $rc == 60 ]] || { printf '%s: código TLS inesperado %s\n' "$site" "$rc" >&2; exit 1; }
    printf '%s: HTTPS aceita a CA do site e rejeita a CA de outro site.\n' "$site"
done

wait_for_metrics "${sites[@]}"
started_at=$(date -u --iso-8601=seconds)
bash "$ROOT/tests/k3s-core.sh" --wazuh
for site in "${sites[@]}"; do wait_for_alert "$site"; done

if [[ ${1:-} == --replica ]]; then
    bash "$ROOT/tests/k3s-scale-verify.sh" lisboa 1
fi

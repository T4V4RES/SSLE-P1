#!/usr/bin/env bash
# Extra 1: publicação não autorizada de leituras (sequestro de sinais).
# bot-3 tenta gravar 99,9 °C na ingestão HTTPS do site, sem credencial, com um
# token forjado, com um ID inválido ou inexistente e por HTTP simples. Depois
# tenta voltar a ligar-se a cada 5 s: a regra 100247 bloqueia-o no nó K3s.
# Uso: ataques/publicacao.sh [site]   (lisboa por omissão)
source "$(dirname "$0")/lib.sh"
site=${1:-lisboa}
port=$(config setting "$site" sensor_port)
gw_port=$(config setting "$site" gateway_port)
start_clients bot-3
node=$(lab_ip k3s-master)
device="pt.$site.dc1.rack1.lab.sensor.temperature.01"
evidence_dir "publicacao-$site"
fake=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
t0=$(epoch)
printf 'inicio %s alvo=https://%s:%s/ingest\n' "$(now)" "$node" "$port" | tee "$OUT/meta"
bot=$(lab_ip bot-3)
watch_drop k3s-master "$bot" 200 > "$OUT/firewall.log" &
before=$(incus exec ssle-gateway -- curl -s "http://127.0.0.1:$gw_port/api/temperatures?limit=50" </dev/null | grep -o '99\.9' | wc -l || true)

incus exec bot-3 -- sh -c "
    url=https://$node:$port/ingest
    body='{\"device_id\":\"$device\",\"temperature\":99.9}'
    try() { printf '%s %-18s ' \$(date -u +%T) \"\$1\"; shift; curl -sk -m 4 -o /dev/null -w '%{http_code}\n' -H 'Content-Type: application/json' \"\$@\"; }
    try 'sem credencial' -d \"\$body\" \$url
    try 'sem credencial' -d \"\$body\" \$url
    for i in 1 2 3; do try 'token forjado' -H 'Authorization: Bearer $fake' -d \"\$body\" \$url; done
    try 'ID com ../' -H 'Authorization: Bearer $fake' -d '{\"device_id\":\"../../etc/passwd\",\"temperature\":1}' \$url
    try 'ID inexistente' -H 'Authorization: Bearer $fake' -d '{\"device_id\":\"pt.$site.dc1.rack9.x\",\"temperature\":1}' \$url
    printf '%s %-18s ' \$(date -u +%T) 'HTTP simples'; curl -s -m 4 -o /dev/null -w '%{http_code}\n' -d \"\$body\" http://$node:$port/ingest
" </dev/null | tee "$OUT/pedidos.log" || true
# O atacante insiste a cada 5 s com o mesmo token forjado e para na primeira
# resposta depois do bloqueio, para não reincidir (a reincidência alarga o bloqueio).
incus exec bot-3 -- sh -c "seen=0; end=\$((\$(date +%s)+${SSLE_SONDA:-170})); while [ \$(date +%s) -lt \$end ]; do
    code=\$(curl -sk -m 2 -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer $fake' -H 'Content-Type: application/json' -d '{\"device_id\":\"$device\",\"temperature\":99.9}' https://$node:$port/ingest)
    printf '%s %s\\n' \$(date -u +%T) \$code
    if [ \$code = 000 ]; then seen=1; elif [ \$seen = 1 ]; then break; fi
    sleep 5; done" \
    </dev/null > "$OUT/sonda-atacante.log" 2>&1 &

# Alerta: Prometheus local -> Alertmanager -> webhook -> Wazuh (até 4 min).
for _ in $(seq 48); do
    wazuh_alerts "$t0" 100231 100245 100246 100247 651 652 > "$OUT/alertas-wazuh.jsonl"
    grep -q '"rule": "100245"' "$OUT/alertas-wazuh.jsonl" && break
    sleep 5
done
wait
wazuh_alerts "$t0" 100231 100245 100246 100247 651 652 > "$OUT/alertas-wazuh.jsonl"
after=$(incus exec ssle-gateway -- curl -s "http://127.0.0.1:$gw_port/api/temperatures?limit=50" </dev/null | grep -o '99\.9' | wc -l || true)
incus exec prom-global -- curl -s http://127.0.0.1:9093/api/v2/alerts </dev/null | python3 -c '
import json, sys
for a in json.load(sys.stdin):
    if a["labels"].get("alertname") == "SsleIngestionAuthRejections":
        print("Alertmanager:", a["labels"].get("site"), a["status"]["state"], "inibido por", a["status"]["inhibitedBy"] or "nada")' > "$OUT/alertmanager.txt" || true

{
    awk '{print $NF}' "$OUT/pedidos.log" | sort | uniq -c | sed 's/^/respostas: /'
    printf 'leituras 99.9 nas últimas 50 de %s: antes %s, depois %s\n' "$site" "$before" "$after"
    cat "$OUT/alertmanager.txt"
    sed 's/^/firewall k3s-master /' "$OUT/firewall.log"
    awk 'NR==1 || $2!=s {print "sonda " $0} {s=$2}' "$OUT/sonda-atacante.log"
    summarize_alerts "$OUT/alertas-wazuh.jsonl"
} | tee "$OUT/resumo.txt"

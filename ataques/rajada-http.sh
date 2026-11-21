#!/usr/bin/env bash
# Cenário 1a: rajada HTTP de uma origem contra o gateway partilhado (guião de DDoS).
# bot-1 envia 40 pedidos com concorrência 2 (a carga do guião de DoS);
# client-user consulta a API uma vez por segundo durante todo o ensaio.
# Uso: ataques/rajada-http.sh [porta]   (80 = Lisboa, 8080 = Porto)
source "$(dirname "$0")/lib.sh"
port=${1:-80}
start_clients bot-1 client-user
gw=$(lab_ip ssle-gateway); bot=$(lab_ip bot-1)
evidence_dir rajada-http
t0=$(epoch)
printf 'inicio %s bot-1=%s porta=%s\n' "$(now)" "$bot" "$port" | tee "$OUT/meta"

watch_drop ssle-gateway "$bot" 170 > "$OUT/firewall.log" &
incus exec client-user -- sh -c "end=\$((\$(date +%s)+170)); while [ \$(date +%s) -lt \$end ]; do
    printf '%s ' \$(date -u +%T); curl -s -m 3 -o /dev/null -w '%{http_code} %{time_total}\n' http://$gw:$port/api/average?limit=10; sleep 1; done" \
    </dev/null > "$OUT/legitimo.log" 2>&1 &
sleep 5
printf 'ataque %s\n' "$(now)" | tee -a "$OUT/meta"
incus exec bot-1 -- ab -n 40 -c 2 -s 5 "http://$gw:$port/api/average?limit=100" </dev/null > "$OUT/ab.log" 2>&1 || true
# A origem bloqueada tenta voltar a cada 5 s nas duas portas do gateway.
incus exec bot-1 -- sh -c "end=\$((\$(date +%s)+${SSLE_SONDA:-150})); while [ \$(date +%s) -lt \$end ]; do
    printf '%s 80=%s 8080=%s\n' \$(date -u +%T) \$(curl -s -m 2 -o /dev/null -w '%{http_code}' http://$gw/health) \$(curl -s -m 2 -o /dev/null -w '%{http_code}' http://$gw:8080/health); sleep 5; done" \
    </dev/null > "$OUT/sonda-atacante.log" 2>&1
wait
wazuh_alerts "$t0" 100204 100206 100232 651 652 > "$OUT/alertas-wazuh.jsonl"

{
    grep -E 'Complete requests|Non-2xx|Failed requests' "$OUT/ab.log"
    awk '{c[$2]++; s+=$3; if ($3>m) m=$3} END {for (k in c) printf "legítimo %s: %d\n", k, c[k]; printf "legítimo: média %.1f ms, máximo %.1f ms\n", s/NR*1000, m*1000}' "$OUT/legitimo.log"
    sed 's/^/firewall /' "$OUT/firewall.log"
    awk 'NR==1 || $2!=s {print "sonda " $0} {s=$2}' "$OUT/sonda-atacante.log"
    summarize_alerts "$OUT/alertas-wazuh.jsonl"
} | tee "$OUT/resumo.txt"

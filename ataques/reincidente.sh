#!/usr/bin/env bash
# Reputação por reincidência: bot-1 faz a rajada HTTP, espera que o bloqueio
# expire e repete-a. O correlacionador reconhece a reincidência (regra 100208)
# e a origem fica bloqueada 10 min em todos os serviços: gateway, correio e
# nós K3s. Depois o historial é limpo e uma terceira rajada volta a ter só o
# bloqueio local de 120 s. Demora cerca de 16 minutos.
source "$(dirname "$0")/lib.sh"
start_clients bot-1
gw=$(lab_ip ssle-gateway); bot=$(lab_ip bot-1)
evidence_dir reincidente
t0=$(epoch)
printf 'inicio %s bot-1=%s\n' "$(now)" "$bot" | tee "$OUT/meta"

blocked_on() { incus exec "$1" -- iptables -S INPUT </dev/null | grep -q -- "-s $bot/32 -j DROP"; }
burst_and_measure() {
    local label=$1 tag=$2 start end where c
    incus exec bot-1 -- ab -n 40 -c 2 -s 5 "http://$gw/api/average?limit=100" </dev/null > "$OUT/ab-$tag.log" 2>&1 || true
    for _ in $(seq 40); do blocked_on ssle-gateway && break; sleep 0.5; done
    blocked_on ssle-gateway || { echo "$label: sem bloqueio" | tee -a "$OUT/resumo.txt"; return 1; }
    start=$(date +%s)
    sleep 8
    where=""
    for c in "${AR_AGENTS[@]}"; do blocked_on "$c" && where+="$c "; done
    while blocked_on ssle-gateway; do sleep 2; done
    end=$(date +%s)
    printf '%s: %s × 429, bloqueio de %d s no gateway (%s a %s UTC); bloqueado em: %s\n' "$label" \
        "$(awk '/Non-2xx/ {print $3}' "$OUT/ab-$tag.log")" $((end - start)) \
        "$(date -u -d "@$start" +%T)" "$(date -u -d "@$end" +%T)" "$where" | tee -a "$OUT/resumo.txt"
}

reset_reputation
burst_and_measure "1.ª rajada" 1
wait_unblocked_lab
burst_and_measure "2.ª rajada (reincidente)" 2-reincidente
wait_unblocked_lab
reset_reputation
burst_and_measure "3.ª rajada (historial limpo)" 3-historial-limpo
wazuh_alerts "$t0" 100206 100208 100209 651 652 > "$OUT/alertas-wazuh.jsonl"
summarize_alerts "$OUT/alertas-wazuh.jsonl" | tee -a "$OUT/resumo.txt"

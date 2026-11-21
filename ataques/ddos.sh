#!/usr/bin/env bash
# Cenário 1b: tráfego distribuído de três origens (botnet emulada) contra Lisboa.
#   ataques/ddos.sh          cada bot a ~10 pedidos/s durante 20 s (acima do limite por IP)
#   ataques/ddos.sh --lento  cada bot a ~4 pedidos/s durante 40 s (abaixo do limite por IP)
# client-user mede o serviço a 1 pedido/s. No fim, o ensaio espera pelo alerta do
# Prometheus e pela correlação 100232 no Wazuh.
source "$(dirname "$0")/lib.sh"
mode=${1:-rapido}
case $mode in
    rapido) pause=0.1; seconds=20 ;;
    --lento) pause=0.25; seconds=40 ;;
    *) echo "uso: $0 [--lento]" >&2; exit 2 ;;
esac
bots=(bot-1 bot-2 bot-3)
start_clients "${bots[@]}" client-user
gw=$(lab_ip ssle-gateway)
evidence_dir "ddos-${mode#--}"
t0=$(epoch)
printf 'inicio %s modo=%s pausa=%ss duracao=%ss\n' "$(now)" "$mode" "$pause" "$seconds" | tee "$OUT/meta"
for bot in "${bots[@]}"; do printf '%s=%s\n' "$bot" "$(lab_ip "$bot")"; done | tee -a "$OUT/meta"

incus exec client-user -- sh -c "end=\$((\$(date +%s)+$((seconds + 40)))); while [ \$(date +%s) -lt \$end ]; do
    printf '%s ' \$(date -u +%T); curl -s -m 3 -o /dev/null -w '%{http_code} %{time_total}\n' http://$gw/api/average?limit=10; sleep 1; done" \
    </dev/null > "$OUT/legitimo.log" 2>&1 &
sleep 5
for bot in "${bots[@]}"; do
    incus exec "$bot" -- sh -c "end=\$((\$(date +%s)+$seconds)); while [ \$(date +%s) -lt \$end ]; do
        printf '%s ' \$(date -u +%T); curl -s -m 1 -o /dev/null -w '%{http_code}\n' http://$gw/api/average?limit=100; sleep $pause; done" \
        </dev/null > "$OUT/$bot.log" 2>&1 &
done
wait
incus exec ssle-gateway -- iptables -S INPUT </dev/null | grep DROP > "$OUT/firewall-fim.txt" || true
# O pico chega ao Wazuh pelo Prometheus e pelo Alertmanager (recolha de 15 s,
# group_wait de 20 s). A correlação só existe dentro da janela de 120 s.
for _ in $(seq 18); do
    wazuh_alerts "$t0" 100205 100206 100207 100231 100232 651 652 > "$OUT/alertas-wazuh.jsonl"
    grep -q '"rule": "100232"' "$OUT/alertas-wazuh.jsonl" && break
    sleep 5
done

{
    for bot in "${bots[@]}"; do
        printf '%s: %s\n' "$bot" "$(awk '{print $2}' "$OUT/$bot.log" | sort | uniq -c | awk '{printf "%s×%s ", $1, $2}')"
        awk '$2=="000" && !t {t=$1} END {if (t) print "  primeiro 000 (bloqueado) às " t}' "$OUT/$bot.log"
    done
    awk '{c[$2]++; s+=$3; if ($3>m) m=$3} END {for (k in c) printf "legítimo %s: %d\n", k, c[k]; printf "legítimo: média %.1f ms, máximo %.1f ms\n", s/NR*1000, m*1000}' "$OUT/legitimo.log"
    sed 's/^/bloqueio ativo no fim: /' "$OUT/firewall-fim.txt"
    summarize_alerts "$OUT/alertas-wazuh.jsonl"
    grep '"rule": "100232"' "$OUT/alertas-wazuh.jsonl" | python3 -c 'import json, sys
for line in sys.stdin: print("correlação:", json.loads(line)["correlation"])' || echo 'sem correlação 100232'
} | tee "$OUT/resumo.txt"

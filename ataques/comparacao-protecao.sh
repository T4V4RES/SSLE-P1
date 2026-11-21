#!/usr/bin/env bash
# Cenário 1, efeito da mitigação no serviço: a mesma carga de três bots contra
# Lisboa, primeiro sem os limites do nginx e depois com a proteção normal.
# Cada bot corre 10 clientes HTTP em paralelo durante 30 s; client-user mede a
# API a 1 pedido/s. A análise tem 0,2 CPU por réplica, o recurso que satura.
# O nginx é sempre reposto com a configuração normal, mesmo em caso de erro.
source "$(dirname "$0")/lib.sh"
bots=(bot-1 bot-2 bot-3)
start_clients "${bots[@]}" client-user
gw=$(lab_ip ssle-gateway)
evidence_dir comparacao-protecao
work=$(mktemp -d)
config gateway > "$work/normal.conf"
config gateway --sem-limites > "$work/aberto.conf"
nginx_config() {
    incus file push "$1" ssle-gateway/etc/nginx/sites-available/ssle-k3s </dev/null >/dev/null
    incus exec ssle-gateway -- sh -c 'nginx -t 2>/dev/null && systemctl reload nginx' </dev/null
}
restore() { nginx_config "$work/normal.conf"; rm -rf "$work"; stop_clients; }
trap restore EXIT

prom() {  # valor máximo de uma expressão nos últimos 2 min, no Prometheus global
    incus exec prom-global -- curl -s http://127.0.0.1:9090/api/v1/query --data-urlencode "query=max_over_time(($1)[2m:15s])" </dev/null |
        python3 -c 'import json, sys; r = json.load(sys.stdin)["data"]["result"]; print("%.3f" % float(r[0]["value"][1]) if r else "-")'
}

run() {
    local mode=$1 dir="$OUT/$1"
    mkdir -p "$dir"
    printf '%s modo=%s\n' "$(now)" "$mode" | tee -a "$OUT/meta"
    incus exec client-user -- sh -c "end=\$((\$(date +%s)+70)); while [ \$(date +%s) -lt \$end ]; do
        printf '%s ' \$(date -u +%T); curl -s -m 5 -o /dev/null -w '%{http_code} %{time_total}\n' http://$gw/api/average?limit=10; sleep 1; done" \
        </dev/null > "$dir/legitimo.log" 2>&1 &
    sleep 10
    for bot in "${bots[@]}"; do
        incus exec "$bot" -- sh -c "end=\$((\$(date +%s)+30)); for w in 1 2 3 4 5 6 7 8 9 10; do
            (while [ \$(date +%s) -lt \$end ]; do curl -s -m 2 -o /dev/null -w '%{http_code}\n' http://$gw/api/temperatures?limit=1000; done) & done; wait" \
            </dev/null > "$dir/$bot.log" 2>&1 &
    done
    wait
    {
        printf 'modo %s\n' "$mode"
        for bot in "${bots[@]}"; do sort "$dir/$bot.log" | uniq -c | awk -v b="$bot" '{printf "%s %s×%s ", b, $1, $2} END {print ""}'; done
        python3 - "$dir/legitimo.log" <<'PY'
import statistics, sys
rows = [line.split() for line in open(sys.argv[1]) if len(line.split()) == 3]
ok = [float(t) * 1000 for _, code, t in rows if code == '200']
bad = len(rows) - len(ok)
q = statistics.quantiles(ok, n=20) if len(ok) > 1 else [0] * 19
print(f"legítimo: {len(ok)}/{len(rows)} 200, falhas {bad}, mediana {statistics.median(ok):.1f} ms, p95 {q[18]:.1f} ms, máximo {max(ok):.1f} ms" if ok else f"legítimo: 0/{len(rows)} 200")
PY
        printf 'p95 da análise no Prometheus (máx. em 2 min): %s s\n' "$(prom 'site:ssle_http_latency_p95:1m{site="lisboa",service="analytics-service"}')"
        printf 'pedidos no gateway (máx. por minuto): %s\n' "$(prom 'ssle:shared_gateway_requests:increase1m')"
    } | tee "$dir/resumo.txt"
}

nginx_config "$work/aberto.conf"
run sem-protecao
nginx_config "$work/normal.conf"
# Espera que a latência e o volume voltem ao normal antes do segundo modo.
sleep 90
reset_reputation
run com-protecao
wazuh_alerts "$(python3 -c 'import time; print(time.time() - 600)')" 100205 100206 100207 100231 100232 651 > "$OUT/alertas-wazuh.jsonl"
summarize_alerts "$OUT/alertas-wazuh.jsonl" | tee "$OUT/alertas.txt"
cat "$OUT"/*/resumo.txt > "$OUT/resumo.txt"

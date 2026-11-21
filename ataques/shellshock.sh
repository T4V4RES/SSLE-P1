#!/usr/bin/env bash
# Cenário 3: tentativa Shellshock (CVE-2014-6271) contra o gateway, a partir de bot-3,
# como no guião do Wazuh.
# O nginx não executa CGI; o objetivo é observar a deteção por assinatura no
# log de acesso e o bloqueio da origem nas duas portas do gateway.
source "$(dirname "$0")/lib.sh"
start_clients bot-3
gw=$(lab_ip ssle-gateway); bot=$(lab_ip bot-3)
evidence_dir shellshock
t0=$(epoch)
printf 'inicio %s bot-3=%s\n' "$(now)" "$bot" | tee "$OUT/meta"
watch_drop ssle-gateway "$bot" 160 > "$OUT/firewall.log" &
incus exec bot-3 -- curl -s -m 3 -o /dev/null -w "%{http_code}\n" \
    -A '() { :; }; /bin/cat /etc/passwd' "http://$gw/cgi-bin/status" </dev/null | sed "s/^/$(now) resposta /" | tee "$OUT/pedido.log"
incus exec bot-3 -- sh -c "end=\$((\$(date +%s)+${SSLE_SONDA:-150})); while [ \$(date +%s) -lt \$end ]; do
    printf '%s 80=%s 8080=%s\n' \$(date -u +%T) \$(curl -s -m 2 -o /dev/null -w '%{http_code}' http://$gw/health) \$(curl -s -m 2 -o /dev/null -w '%{http_code}' http://$gw:8080/health); sleep 5; done" \
    </dev/null > "$OUT/sonda-atacante.log" 2>&1
wait
wazuh_alerts "$t0" 31166 31168 100210 651 652 > "$OUT/alertas-wazuh.jsonl"
{
    cat "$OUT/pedido.log"
    sed 's/^/firewall /' "$OUT/firewall.log"
    awk 'NR==1 || $2!=s {print "sonda " $0} {s=$2}' "$OUT/sonda-atacante.log"
    summarize_alerts "$OUT/alertas-wazuh.jsonl"
} | tee "$OUT/resumo.txt"

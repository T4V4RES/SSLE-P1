#!/usr/bin/env bash
# Cenário 2: campanha de spam e fraude (guião de spam) a partir de bot-2 contra lis-mail.
# bot-2 envia 40 mensagens com 0,1 s de intervalo; client-user envia correio
# legítimo antes do ataque e durante o bloqueio. O ensaio mede o que chega à
# caixa, o que fica em quarentena (fila hold) e quando a firewall corta a origem.
source "$(dirname "$0")/lib.sh"
start_clients bot-2 client-user
mail=$(lab_ip lis-mail); bot=$(lab_ip bot-2)
evidence_dir spam
for client in bot-2 client-user; do incus file push "$ROOT/ataques/smtp_send.py" "$client/tmp/smtp_send.py" </dev/null >/dev/null; done
counts() {
    incus exec lis-mail -- sh -c 'printf "caixa=%s quarentena=%s\n" "$(grep -c "^From " /var/mail/alice 2>/dev/null || echo 0)" "$(find /var/spool/postfix/hold -type f | wc -l)"' </dev/null
}
t0=$(epoch)
printf 'inicio %s bot-2=%s\nantes: %s\n' "$(now)" "$bot" "$(counts)" | tee "$OUT/meta"

watch_drop lis-mail "$bot" 200 > "$OUT/firewall.log" &
incus exec client-user -- python3 /tmp/smtp_send.py "$mail" legitimo 1 0 </dev/null > "$OUT/legitimo-antes.log" 2>&1
printf 'ataque %s\n' "$(now)" | tee -a "$OUT/meta"
incus exec bot-2 -- python3 /tmp/smtp_send.py "$mail" campanha 40 0.1 "${SSLE_SPAM_DESISTE:-0}" </dev/null > "$OUT/spam.log" 2>&1
printf 'fim-ataque %s\n' "$(now)" | tee -a "$OUT/meta"
incus exec client-user -- python3 /tmp/smtp_send.py "$mail" legitimo 1 0 </dev/null > "$OUT/legitimo-durante.log" 2>&1
# O spammer tenta voltar a ligar a cada 10 s até a regra expirar.
incus exec bot-2 -- python3 - "$mail" "${SSLE_SONDA:-150}" </dev/null > "$OUT/sonda-atacante.log" 2>&1 <<'PY'
import socket, sys, time
from datetime import datetime, timezone
end = time.time() + int(sys.argv[2])
while time.time() < end:
    stamp = datetime.now(timezone.utc).strftime('%H:%M:%S')
    try:
        with socket.create_connection((sys.argv[1], 25), timeout=3) as s:
            print(stamp, 'ligou:', s.recv(64).decode(errors='replace').strip(), flush=True)
    except OSError as e:
        print(stamp, 'sem ligação:', type(e).__name__, flush=True)
    time.sleep(10)
PY
wait
sleep 5
printf 'depois: %s\n' "$(counts)" | tee -a "$OUT/meta"
incus exec lis-mail -- journalctl -t spamfilter -t postfix/smtpd -t postfix/cleanup --since "@${t0%.*}" --no-pager -o short-iso </dev/null > "$OUT/correio.log"
wazuh_alerts "$t0" 100221 100222 651 652 > "$OUT/alertas-wazuh.jsonl"

{
    printf 'spam aceite pelo SMTP: %s de 40\n' "$(grep -c ' OK$' "$OUT/spam.log")"
    grep FALHOU "$OUT/spam.log" | sed 's/.*FALHOU //' | sort | uniq -c | sed 's/^/recusado: /'
    printf 'legítimo antes: %s | durante o bloqueio: %s\n' "$(cut -d' ' -f4- "$OUT/legitimo-antes.log")" "$(cut -d' ' -f4- "$OUT/legitimo-durante.log")"
    grep -o 'result=[A-Za-z]* score=[-0-9.]* client=[0-9.]*' "$OUT/correio.log" | sort | uniq -c | sed 's/^/filtro: /'
    printf 'quarentena (hold): %s\n' "$(grep -c ': hold: header X-Spam-Flag' "$OUT/correio.log" || true)"
    printf 'limite anvil: %s\n' "$(grep -c 'rate limit exceeded' "$OUT/correio.log" || true)"
    sed 's/^/firewall /' "$OUT/firewall.log"
    awk 'NR==1 || $2!=s {print "sonda " $0} {s=$2}' "$OUT/sonda-atacante.log"
    sed -n 's/^antes/caixa e fila antes/p; s/^depois/caixa e fila depois/p' "$OUT/meta"
    summarize_alerts "$OUT/alertas-wazuh.jsonl"
} | tee "$OUT/resumo.txt"

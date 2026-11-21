#!/usr/bin/env python3
"""Envio SMTP de ensaio para lis-mail. Corre num cliente do laboratório.
Uso: smtp_send.py IP modo N intervalo [desiste]   (modo: volume, fraude, campanha ou legitimo)
A campanha alterna as mensagens de volume e de fraude. Com desiste > 0, o envio
para depois desse número de falhas seguidas (útil na demonstração)."""
import ipaddress, smtplib, socket, sys, time
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

ip, mode, n, gap = sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
give_up = int(sys.argv[5]) if len(sys.argv) > 5 else 0
failures = 0
assert ipaddress.ip_address(ip).is_private and 1 <= n <= 40, "só alvos do laboratório, no máximo 40 mensagens"
me = socket.gethostname()
SAMPLES = {
    "volume": ("BUY CHEAP VIAGRA NOW FREE PILLS AND CIALIS", "buy viagra cheap free shipping now cialis generic pills"),
    "fraude": ("URGENT: you have won the lottery", "Dear friend, you have won 1,000,000 EUR in our lottery winner draw. To claim your prize send your bank details today."),
    "legitimo": ("Relatorio semanal de temperaturas", "Ola Alice, segue o resumo das temperaturas desta semana. Abraco, Bob"),
}
assert mode in SAMPLES or mode == "campanha", "modo desconhecido"
for i in range(n):
    subject, body = SAMPLES[("volume", "fraude")[i % 2] if mode == "campanha" else mode]
    msg = EmailMessage()
    msg["From"] = f"{'bob' if mode == 'legitimo' else 'promo%d' % i}@{me}.incus"
    msg["To"] = "alice@lis-mail.incus"
    msg["Subject"] = f"{subject} #{i}" if mode != "legitimo" else subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=f"{me}.incus")
    msg.set_content(body)
    t = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
    try:
        with smtplib.SMTP(ip, 25, timeout=4, local_hostname=f"{me}.incus") as s:
            s.send_message(msg)
        print(f"{t} {mode} #{i} OK", flush=True)
        failures = 0
    except (smtplib.SMTPException, OSError) as e:
        print(f"{t} {mode} #{i} FALHOU {type(e).__name__}: {e}", flush=True)
        failures += 1
        if give_up and failures >= give_up:
            print(f"{t} {mode} desiste após {failures} falhas seguidas", flush=True)
            break
    time.sleep(gap)

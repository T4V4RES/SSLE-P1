#!/usr/bin/env python3
"""Resume as repetições guardadas por ataques/repeticoes.sh.

Para cada métrica mostra a mediana, o mínimo, o máximo e o número de ensaios.
Os instantes contam a partir do primeiro pedido do ataque.
Uso: resumo-repeticoes.py PASTA
"""
import datetime as dt
import json
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path


def day_of(folder):
    return re.search(r"(\d{8})T", folder.name)[1]


def clock(folder, hms):
    """Instante de uma hora HH:MM:SS[.mmm] no dia do ensaio (UTC)."""
    stamp = dt.datetime.strptime(day_of(folder) + hms[:12].ljust(12, "0") if "." in hms else day_of(folder) + hms + ".000",
                                 "%Y%m%d%H:%M:%S.%f")
    return stamp.replace(tzinfo=dt.timezone.utc).timestamp()


def wazuh(folder):
    alerts = defaultdict(list)
    path = folder / "alertas-wazuh.jsonl"
    if path.exists():
        for line in path.read_text().splitlines():
            alert = json.loads(line)
            stamp = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", alert["timestamp"])
            alerts[alert["rule"]].append(dt.datetime.fromisoformat(stamp).timestamp())
    return alerts


def meta_time(folder, key):
    for line in (folder / "meta").read_text().splitlines():
        if line.startswith(key + " "):
            return clock(folder, line.split()[1])
    return None


def firewall_lines(folder):
    path = folder / "firewall.log"
    return path.read_text().splitlines() if path.exists() else []


def first_drop(folder):
    for line in firewall_lines(folder):
        if line.endswith("DROP"):
            return clock(folder, line.split()[0])
    return None


def block_seconds(folder):
    times = [(clock(folder, line.split()[0]), line.split()[1]) for line in firewall_lines(folder)]
    for (t1, s1), (t2, s2) in zip(times, times[1:]):
        if s1 == "DROP" and s2 == "none":
            return t2 - t1
    return None


def legit(folder, name="legitimo.log"):
    rows = [line.split() for line in (folder / name).read_text().splitlines() if len(line.split()) == 3]
    ok = [float(t) * 1000 for _, code, t in rows if code == "200"]
    return len(ok), len(rows), max(ok) if ok else None


metrics = defaultdict(list)


def add(name, value):
    if value is not None:
        metrics[name].append(value)


root = Path(sys.argv[1])
for folder in sorted(p for p in root.iterdir() if p.is_dir()):
    alerts = wazuh(folder)
    if folder.name.startswith("rajada-http"):
        start = meta_time(folder, "ataque")
        ab = (folder / "ab.log").read_text()
        add("rajada: respostas 429 (de 40)", int(re.search(r"Non-2xx responses:\s+(\d+)", ab)[1]) if "Non-2xx" in ab else 0)
        add("rajada: 100206 (s)", min(alerts["100206"]) - start if alerts["100206"] else None)
        add("rajada: bloqueio no gateway (s)", first_drop(folder) - start if first_drop(folder) else None)
        add("rajada: duração do bloqueio (s)", block_seconds(folder))
        ok, total, worst = legit(folder)
        add("rajada: cliente legítimo com 200 (%)", 100 * ok / total)
        add("rajada: latência máxima do legítimo (ms)", worst)
    elif folder.name.startswith("ddos-rapido"):
        firsts, blocked = [], []
        for bot in ("bot-1", "bot-2", "bot-3"):
            lines = (folder / f"{bot}.log").read_text().splitlines()
            firsts.append(clock(folder, lines[0].split()[0]))
            zero = next((clock(folder, l.split()[0]) for l in lines if l.split()[1] == "000"), None)
            if zero:
                blocked.append(zero)
        start = min(firsts)
        add("DDoS: bots bloqueados (de 3)", len(blocked))
        add("DDoS: último bot bloqueado (s)", max(blocked) - start if blocked else None)
        add("DDoS: 100207 (s)", min(alerts["100207"]) - start if alerts["100207"] else None)
        add("DDoS: correlações 100232", len(alerts["100232"]))
        add("DDoS: primeira 100232 (s)", min(alerts["100232"]) - start if alerts["100232"] else None)
        ok, total, worst = legit(folder)
        add("DDoS: cliente legítimo com 200 (%)", 100 * ok / total)
        add("DDoS: latência máxima do legítimo (ms)", worst)
    elif folder.name.startswith("spam"):
        start = meta_time(folder, "ataque")
        sent = (folder / "spam.log").read_text()
        mail = (folder / "correio.log").read_text()
        meta = (folder / "meta").read_text()
        before = re.search(r"antes: caixa=(\d+) quarentena=(\d+)", meta)
        after = re.search(r"depois: caixa=(\d+) quarentena=(\d+)", meta)
        add("spam: aceites pelo SMTP (de 40)", sent.count(" OK"))
        add("spam: em quarentena", mail.count(": hold: header X-Spam-Flag"))
        add("spam: mensagens novas na caixa (2 legítimas)", int(after[1]) - int(before[1]))
        add("spam: bloqueio no correio (s)", first_drop(folder) - start if first_drop(folder) else None)
        legit_ok = sum((folder / n).read_text().count(" OK") for n in ("legitimo-antes.log", "legitimo-durante.log"))
        add("spam: legítimas entregues (de 2)", legit_ok)
    elif folder.name.startswith("publicacao"):
        start = meta_time(folder, "inicio")
        codes = [line.split()[-1] for line in (folder / "pedidos.log").read_text().splitlines()]
        add("publicação: recusas 401/403/400 (de 7)", sum(c in ("400", "401", "403") for c in codes))
        summary = (folder / "resumo.txt").read_text()
        add("publicação: leituras forjadas gravadas", int(re.search(r"depois (\d+)", summary)[1]))
        add("publicação: 100247 (s)", min(alerts["100247"]) - start if alerts["100247"] else None)
        add("publicação: bloqueio no nó K3s (s)", first_drop(folder) - start if first_drop(folder) else None)
        add("publicação: 100245 (s)", min(alerts["100245"]) - start if alerts["100245"] else None)
    elif folder.name.startswith("shellshock"):
        start = clock(folder, (folder / "pedido.log").read_text().split()[0])
        add("Shellshock: 100210 (s)", min(alerts["100210"]) - start if alerts["100210"] else None)
        add("Shellshock: bloqueio no gateway (s)", first_drop(folder) - start if first_drop(folder) else None)

print(f"{'métrica':48} {'mediana':>9} {'mín.':>8} {'máx.':>8} {'n':>3}")
for name, values in metrics.items():
    print(f"{name:48} {statistics.median(values):9.1f} {min(values):8.1f} {max(values):8.1f} {len(values):3d}")

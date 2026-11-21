#!/usr/bin/env python3
"""Correlaciona alertas de agentes distintos por site e janela temporal e mantém a
reputação das origens bloqueadas (reincidência partilhada entre serviços)."""
import datetime
import json
from pathlib import Path
import re
import time

# Sinais de ataque vistos pelo Wazuh nos logs do nginx partilhado.
SECURITY_RULES = {"100206", "100207"}
# Sintomas vistos pelo Prometheus. O alerta da entrada partilhada tem site=gateway
# e vale para qualquer site servido pelo nginx.
PERFORMANCE_ALERTS = {"SsleHighLatency", "SsleErrorRate", "MultiSiteDegradation", "SharedGatewayRequestSurge"}
SHARED_SITE = "gateway"
SITE_LOG = re.compile(r"/var/log/nginx/ssle-([a-z][a-z0-9-]*)-access\.log")


def parse_time(stamp):
    """Instante de um alerta Wazuh. O Wazuh escreve +0000 e o fromisoformat
    do Python 3.10 (o do manager) so aceita +00:00."""
    stamp = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", stamp.replace("Z", "+00:00"))
    return datetime.datetime.fromisoformat(stamp).timestamp()


def incident(rule, alert, site):
    """Identidade do incidente que o alerta representa. Um bloqueio repetido da
    mesma origem e um alerta do Prometheus reenviado pelo Alertmanager (mesmo
    inicio) sao o mesmo incidente; sem estes campos, cada alerta conta por si."""
    data = alert.get("data", {})
    if rule == "100206" and data.get("srcip"):
        return ("block", data["srcip"])
    if rule == "100207":
        return ("botnet", site)
    if rule == "100231" and data.get("pm_starts_at"):
        return ("performance", data.get("pm_alertname"), data["pm_starts_at"])
    return ("alert", alert["id"])


def site_of(rule, alert):
    """Site do alerta: o log do nginx identifica o site nos alertas do Wazuh e
    a etiqueta site identifica-o nos alertas do Prometheus."""
    if rule in SECURITY_RULES:
        if alert.get("agent", {}).get("name") != "ssle-gateway":
            return None
        match = SITE_LOG.fullmatch(alert.get("location", ""))
        return match[1] if match else None
    data = alert.get("data", {})
    if rule == "100231" and data.get("pm_alertname") in PERFORMANCE_ALERTS:
        return data.get("pm_site")
    return None


def same_scope(site, other):
    return site == other or SHARED_SITE in (site, other)


class Correlator:
    def __init__(self, window=120):
        self.window = window
        self.pending = []      # (instante, site, regra, incidente, alerta)
        self.emitted = set()   # pares de incidentes ja correlacionados
        self.latest = float("-inf")

    def feed(self, alert):
        rule = str(alert.get("rule", {}).get("id", ""))
        site = site_of(rule, alert)
        if not site or not alert.get("id"):
            return []
        try:
            stamp = parse_time(alert["timestamp"])
        except (ValueError, KeyError, TypeError):
            return []
        self.latest = max(self.latest, stamp)
        self.pending = [e for e in self.pending if e[0] >= self.latest - self.window]
        if stamp < self.latest - self.window:
            return []
        security = rule in SECURITY_RULES
        key = (site, incident(rule, alert, site))
        output = []
        for other_time, other_site, other_rule, other_key, other_alert in self.pending:
            pair = tuple(sorted((key, other_key)))
            if security != (other_rule in SECURITY_RULES) and same_scope(site, other_site) \
                    and abs(stamp - other_time) <= self.window and pair not in self.emitted:
                self.emitted.add(pair)
                attack, performance = (alert, other_alert) if security else (other_alert, alert)
                attack_site, performance_site = (site, other_site) if security else (other_site, site)
                output.append({"ssle_correlation": "dos_performance", "site": attack_site,
                               "scope": "gateway" if performance_site == SHARED_SITE else "site",
                               "first_alert": min(alert["id"], other_alert["id"]),
                               "second_alert": max(alert["id"], other_alert["id"]),
                               "attack_rule": attack["rule"]["id"],
                               "source": attack.get("data", {}).get("srcip"),
                               "performance_alert": performance.get("data", {}).get("pm_alertname"),
                               "delta_seconds": abs(stamp - other_time)})
        if key not in {e[3] for e in self.pending}:    # a primeira notificacao do incidente marca o instante
            self.pending.append((stamp, site, rule, key, alert))
        active = {e[3] for e in self.pending}
        self.emitted = {pair for pair in self.emitted if set(pair) <= active}
        return output


# Regras que bloqueiam uma origem (resposta ativa de 120 s no agente local).
BLOCK_RULES = {"100206", "100210", "100222", "100247"}
# Duração do bloqueio por número de incidentes na última hora: o 1.º é o
# bloqueio local da regra; a partir do 2.º, a origem é bloqueada em todos os
# serviços (regras 100208 e 100209).
BLOCK_SECONDS = {1: 120, 2: 600}
LONG_BLOCK = 3600


class Reputation:
    """Historial de bloqueios por IP. Um alerta só conta como novo incidente
    depois de o bloqueio anterior expirar: os vários disparos da mesma rajada
    (100206 à 10.a e à 20.a recusa) são o mesmo incidente."""

    def __init__(self, memory=3600):
        self.memory = memory
        self.incidents = {}    # ip -> instantes de início dos incidentes
        self.until = {}        # ip -> fim do bloqueio atual

    def feed(self, alert):
        rule = str(alert.get("rule", {}).get("id", ""))
        ip = alert.get("data", {}).get("srcip")
        if rule not in BLOCK_RULES or not ip:
            return []
        try:
            stamp = parse_time(alert["timestamp"])
        except (ValueError, KeyError, TypeError):
            return []
        if stamp < self.until.get(ip, float("-inf")):
            return []
        starts = [t for t in self.incidents.get(ip, []) if stamp - t <= self.memory] + [stamp]
        self.incidents[ip] = starts
        self.until[ip] = stamp + BLOCK_SECONDS.get(len(starts), LONG_BLOCK)
        if len(starts) < 2:
            return []
        return [{"ssle_reputation": "reincidente", "srcip": ip, "bloqueios": len(starts),
                 "attack_rule": rule, "agent": alert.get("agent", {}).get("name"),
                 "block_seconds": BLOCK_SECONDS.get(len(starts), LONG_BLOCK)}]


def main():
    source = Path("/var/ossec/logs/alerts/alerts.json")
    target = Path("/var/log/ssle/correlations.jsonl")
    target.parent.mkdir(parents=True, exist_ok=True)
    correlator = Correlator()
    reputation = Reputation()
    stream = None
    inode = None
    while True:
        try:
            stat = source.stat()
            if stream is None or stat.st_ino != inode or stat.st_size < stream.tell():
                first = stream is None
                if stream:
                    stream.close()
                stream = source.open()
                inode = stat.st_ino
                if first:
                    stream.seek(0, 2)
            offset = stream.tell()
            line = stream.readline()
            if not line or not line.endswith("\n"):
                stream.seek(offset)
                time.sleep(0.2)
                continue
            try:
                alert = json.loads(line)
                events = correlator.feed(alert) + reputation.feed(alert)
            except (ValueError, TypeError, AttributeError):
                continue
            if events:
                with target.open("a") as output:
                    for event in events:
                        output.write(json.dumps(event) + "\n")
        except FileNotFoundError:
            time.sleep(1)


if __name__ == "__main__":
    main()

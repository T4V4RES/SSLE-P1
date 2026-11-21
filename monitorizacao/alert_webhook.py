#!/usr/bin/env python3
"""Recetor de webhooks do Alertmanager.

Cada alerta e escrito como uma linha JSON em LOG_FILE. O agente Wazuh deste
container le esse ficheiro, e assim os alertas de desempenho/disponibilidade
do Prometheus chegam ao SIEM e podem ser correlacionados com eventos de
seguranca (ex.: flood bloqueado no gateway + latencia alta no mesmo site).
"""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

LOG_FILE = os.environ.get("LOG_FILE", "/var/log/ssle/prometheus-alerts.json")
PORT = int(os.environ.get("PORT", "9095"))
LABELS = ("alertname", "severity", "site", "service", "instance_id", "node", "rack", "name")


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length))
        except ValueError:
            self.send_response(400)
            self.end_headers()
            return
        with open(LOG_FILE, "a") as f:
            for alert in payload.get("alerts", []):
                labels = alert.get("labels", {})
                # Prefixo pm_ para nao chocar com campos reservados do Wazuh (status, name, ...)
                event = {"pm_source": "prometheus", "pm_status": alert.get("status", "")}
                event.update({"pm_" + k: labels[k] for k in LABELS if k in labels})
                event["pm_summary"] = alert.get("annotations", {}).get("summary", "")
                event["pm_starts_at"] = alert.get("startsAt", "")
                f.write(json.dumps(event) + "\n")
        self.send_response(200)
        self.end_headers()

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()

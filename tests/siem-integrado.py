#!/usr/bin/env python3
"""Validação integrada da resposta automática a registos sintéticos na Kali."""

import argparse
import fcntl
import json
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

HTTP_LOG = "/var/log/nginx/ssle-validacao-access.log"
CASES = {
    "http": ("ssle-gateway", "192.0.2.42", "100206", 10),
    "spam": ("lis-mail", "192.0.2.43", "100222", 5),
}


def incus(container, *args, data=None):
    try:
        return subprocess.run(
            ["incus", "exec", container, "--mode=non-interactive", "--", *args],
            input=data, check=True, text=True, capture_output=True, timeout=10,
        ).stdout
    except subprocess.CalledProcessError as error:
        raise RuntimeError(f"{container}: {error.stderr.strip() or 'comando sem sucesso'}") from None


def utc():
    return datetime.now(timezone.utc)


def emit(name, container, address, count, marker):
    if name == "http":
        stamp = utc().strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines = [
            f'{address} - - [{stamp}] "GET /api/average HTTP/1.1" 429 0 "-" "{marker}-{index}"'
            for index in range(count)
        ]
        incus(container, "tee", "-a", HTTP_LOG, data="\n".join(lines) + "\n")
    else:
        lines = [
            f"result=Yes score=7.5 client={address} from=<teste@example.test> "
            f"to=<teste@example.test> tests={marker}-{index}"
            for index in range(count)
        ]
        incus(container, "logger", "-t", "spamfilter", data="\n".join(lines) + "\n")
    print(f"{utc():%H:%M:%S} UTC  {name}: {count} registos sintéticos, marcador {marker}", flush=True)


def alerts():
    raw = incus("wazuh-container", "tail", "-n", "1500", "/var/ossec/logs/alerts/alerts.json")
    for line in raw.splitlines():
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def blocked(container, address):
    rules = incus(container, "iptables", "-S", "INPUT").splitlines()
    return f"-A INPUT -s {address}/32 -j DROP" in rules


def validate(names, marker, results):
    for name in names:
        container, address, rule, count = CASES[name]
        if blocked(container, address):
            raise RuntimeError(f"{name}: já existe uma regra de teste ativa. Aguarda a expiração.")
        results[name] = {"agent": container, "source": address, "rule_id": rule, "records": count}
    if "http" in names:
        incus("ssle-gateway", "touch", HTTP_LOG)

    for name in names:
        container, address, _, count = CASES[name]
        emit(name, container, address, count, marker)
        results[name]["injected_at"] = utc().isoformat()

    started = time.monotonic()
    while time.monotonic() - started < 155:
        if any("alert_at" not in details for details in results.values()):
            for event in alerts():
                full_log = event.get("full_log", "")
                if marker not in full_log:
                    continue
                for name, details in results.items():
                    if ("alert_at" not in details
                        and str(event.get("rule", {}).get("id")) == details["rule_id"]
                        and event.get("agent", {}).get("name") == details["agent"]
                        and event.get("data", {}).get("srcip") == details["source"]):
                        details["alert_at"] = event["timestamp"]
                        print(f"{utc():%H:%M:%S} UTC  {name}: alerta real do Wazuh {details['rule_id']} em {details['agent']}", flush=True)
        for name, details in results.items():
            if "alert_at" not in details or "unblocked_at" in details:
                continue
            active = blocked(details["agent"], details["source"])
            if active and "blocked_at" not in details:
                details["blocked_at"] = utc().isoformat()
                print(f"{utc():%H:%M:%S} UTC  {name}: bloqueio automático DROP confirmado na firewall", flush=True)
            if not active and "blocked_at" in details:
                details["unblocked_at"] = utc().isoformat()
                print(f"{utc():%H:%M:%S} UTC  {name}: regra DROP removida por expiração", flush=True)
        if all("unblocked_at" in details for details in results.values()):
            return
        if time.monotonic() - started > 32:
            incomplete = [name for name, details in results.items() if "blocked_at" not in details]
            if incomplete:
                raise RuntimeError("Alerta ou resposta automática por confirmar: " + ", ".join(incomplete))
        time.sleep(2)
    raise RuntimeError("Expiração da resposta por confirmar.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cenario", choices=("http", "spam", "todos"), default="todos", nargs="?")
    options = parser.parse_args()
    names = tuple(CASES) if options.cenario == "todos" else (options.cenario,)
    start = utc()
    marker = f"SSLE-VALIDACAO-{start:%Y%m%dT%H%M%S%fZ}"
    results = {}
    try:
        with Path(__file__).open() as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            validate(names, marker, results)
    except BlockingIOError:
        parser.exit(1, "Já está em curso uma validação.\n")
    except (RuntimeError, subprocess.TimeoutExpired, FileNotFoundError) as error:
        parser.exit(1, f"Validação incompleta. {error}\n")
    finally:
        if results:
            folder = Path(tempfile.mkdtemp(prefix=f"ssle-siem-{start:%Y%m%dT%H%M%SZ}-"))
            proof = {"marker": marker, "input": "registos sintéticos", "results": results}
            (folder / "resultado.json").write_text(json.dumps(proof, indent=2, ensure_ascii=False) + "\n")
            print(f"Evidência: {folder}/resultado.json", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

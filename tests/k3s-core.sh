#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/../infra/k3s-lib.sh"

master_ip=$(container_ipv4 k3s-master)
work=$(mktemp -d)
site=""
device=""
cleanup() {
    if [[ -n $device ]]; then python3 "$ROOT/infra/sensor-credentials.py" "$site" revoke "$device" >/dev/null 2>&1 || true; fi
    rm -rf "$work"
}
trap cleanup EXIT
umask 077

prom_query() {
    incus exec prom-global -- curl -fsS --max-time 4 -G http://127.0.0.1:9090/api/v1/query --data-urlencode "query=$1"
}

sensor_status() {
    local id=$1
    shift
    curl -sS --max-time 4 --cacert "$work/ca.crt" --resolve "k3s-master.incus:$sensor_port:$master_ip" \
        -w '%{http_code}' -o /dev/null "$@" -H 'Content-Type: application/json' \
        --data "{\"device_id\":\"$id\",\"temperature\":22.5}" \
        "https://k3s-master.incus:$sensor_port/ingest"
}

wait_for_status() {
    local expected=$1
    shift
    local actual
    for attempt in {1..48}; do
        actual=$(sensor_status "$@")
        if [[ $actual == "$expected" ]]; then return; fi
        sleep 2
    done
    printf 'Site %s: esperado HTTP %s, obtido %s\n' "$site" "$expected" "$actual" >&2
    return 1
}

wait_for_mount() {
    local expected=$1 pod actual ready
    for attempt in {1..48}; do
        ready=1
        for pod in $(kube -n "$site" get pods -l app=ingestion -o name); do
            actual=absent
            if kube -n "$site" exec "$pod" -- test -r "/run/ssle/devices/$device" 2>/dev/null; then actual=present; fi
            if [[ $actual != "$expected" ]]; then ready=0; break; fi
        done
        if ((ready)); then return; fi
        sleep 2
    done
    echo "A credencial não ficou no estado $expected em todas as réplicas de $site" >&2
    return 1
}

verify_storage() {
    incus exec ssle-gateway -- curl -fsS --max-time 8 "http://127.0.0.1:$port/api/temperatures?limit=100" |
        python3 -c 'import json, sys; ids=[row["device_id"] for row in json.load(sys.stdin)]; sys.exit(not (ids.count(sys.argv[1]) == 1 and sys.argv[1] + ".other" not in ids))' "$device"
}

for site in $(config names); do
    port=$(config setting "$site" gateway_port)
    sensor_port=$(config setting "$site" sensor_port)
    average=$(incus exec ssle-gateway -- curl -fsS --max-time 8 "http://127.0.0.1:$port/api/average?limit=3")
    python3 -c 'import json, sys; assert json.load(sys.stdin)["sample_count"] == 3' <<< "$average"
    incus exec ssle-gateway -- curl -fsS --max-time 8 "http://127.0.0.1:$port/api/temperatures?limit=1" |
        python3 -c 'import json, sys; assert len(json.load(sys.stdin)) == 1'
    for component in storage ingestion analytics sensor prometheus; do
        kube -n "$site" rollout status "deployment/$component" --timeout=30s
    done
    kube -n "$site" get configmap ingestion-ca -o 'jsonpath={.data.ca\.crt}' > "$work/ca.crt"
    device="pt.$site.smoke.$(date +%s)"
    [[ $(sensor_status "$device") == 401 ]]
    python3 "$ROOT/infra/sensor-credentials.py" "$site" enroll "$device" "$work/token"
    printf 'Authorization: Bearer %s\n' "$(<"$work/token")" > "$work/header"
    wait_for_mount present
    wait_for_status 202 "$device" -H "@$work/header"
    [[ $(sensor_status "$device.other" -H "@$work/header") == 403 ]]
    python3 "$ROOT/infra/sensor-credentials.py" "$site" revoke "$device"
    wait_for_mount absent
    wait_for_status 403 "$device" -H "@$work/header"
    verify_storage
    device=""
    rm -f "$work/token" "$work/header"

    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -subj /CN=smoke-test -keyout "$work/sensor.key" -out "$work/sensor.csr" 2>/dev/null
    device=$(python3 "$ROOT/infra/sensor-credentials.py" "$site" issue "$work/sensor.csr" "$work/sensor.crt")
    client_auth=(--cert "$work/sensor.crt" --key "$work/sensor.key")
    wait_for_mount present
    [[ $(sensor_status "$device") == 401 ]]
    wait_for_status 202 "$device" "${client_auth[@]}"
    [[ $(sensor_status "$device.other" "${client_auth[@]}") == 403 ]]
    python3 "$ROOT/infra/sensor-credentials.py" "$site" revoke "$device"
    wait_for_mount absent
    wait_for_status 403 "$device" "${client_auth[@]}"
    verify_storage
    device=""
    rm -f "$work/sensor.key" "$work/sensor.csr" "$work/sensor.crt"

    replicas=$(config setting "$site" ingestion_replicas)
    query="site:ssle_instances_up:sum{site=\"$site\",service=\"ingestion-service\"}"
    healthy=0
    for attempt in {1..25}; do
        if prom_query "$query" | python3 -c 'import json,sys; rows=json.load(sys.stdin)["data"]["result"]; assert len(rows)==1 and float(rows[0]["value"][1])==int(sys.argv[1])' "$replicas" 2>/dev/null; then
            healthy=1
            break
        fi
        sleep 3
    done
    [[ $healthy == 1 ]] || { echo "Federação ou alvos HTTPS em falta: $site" >&2; exit 1; }
    printf '%s: API, credenciais por token e certificado, persistência autorizada e métricas federadas confirmadas.\n' "$site"
done
incus exec lis-mail -- systemctl is-active --quiet postfix
incus exec wazuh-container -- systemctl is-active --quiet wazuh-manager
incus exec wazuh-container -- /var/ossec/bin/agent_control -lc | grep 'Name: ssle-gateway,'
if [[ ${1:-} == --wazuh ]]; then
    for target in ssle-gateway lis-mail; do
        wazuh_ensure_active_response "$target"
        printf '%s: resposta ativa verificada para um endereço reservado.\n' "$target"
    done
fi

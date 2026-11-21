#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/../infra/k3s-lib.sh"

site=${1:?usage: k3s-scale-verify.sh SITE REPLICAS}
target=${2:?usage: k3s-scale-verify.sh SITE REPLICAS}
config setting "$site" ingestion_replicas >/dev/null
[[ $target =~ ^([1-9]|1[0-2])$ ]]
original=$(kube -n "$site" get deployment/ingestion -o 'jsonpath={.spec.replicas}')
[[ $original != "$target" ]] || { echo 'Escolher um número de réplicas diferente do atual.' >&2; exit 2; }
restore() { kube -n "$site" scale deployment/ingestion --replicas="$original"; }
trap restore EXIT

verify() {
    local count=$1
    kube -n "$site" rollout status deployment/ingestion --timeout=90s
    for attempt in {1..24}; do
        if incus exec prom-global -- curl -fsS --max-time 5 -G http://127.0.0.1:9090/api/v1/query \
            --data-urlencode "query=site:ssle_instances_up:sum{site=\"$site\",service=\"ingestion-service\"}" |
            python3 -c 'import json,sys; rows=json.load(sys.stdin)["data"]["result"]; assert len(rows)==1 and float(rows[0]["value"][1])==int(sys.argv[1])' "$count" 2>/dev/null; then
            printf '%s: %s réplicas de ingestão visíveis no Prometheus global.\n' "$site" "$count"
            return
        fi
        sleep 3
    done
    echo "Réplicas não observadas: $site, $count" >&2
    return 1
}

kube -n "$site" scale deployment/ingestion --replicas="$target"
verify "$target"
kube -n "$site" exec deployment/sensor -- temperature_sensor --count 1 --interval-ms 0
restore
verify "$original"
trap - EXIT

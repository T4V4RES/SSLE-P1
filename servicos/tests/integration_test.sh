#!/usr/bin/env bash
set -euo pipefail

registry=$1
storage=$2
ingestion=$3
analytics=$4
sensor=$5
test_dir=$(mktemp -d /tmp/ssle-c-test.XXXXXX)

cleanup() {
  kill "${registry_pid:-}" "${storage_pid:-}" "${ingestion_pid:-}" "${analytics_pid:-}" 2>/dev/null || true
  wait "${registry_pid:-}" "${storage_pid:-}" "${ingestion_pid:-}" "${analytics_pid:-}" 2>/dev/null || true
  rm -rf "$test_dir"
}
trap cleanup EXIT

"$registry" >"$test_dir/registry.log" 2>&1 & registry_pid=$!
TEMP_DB="$test_dir/temperatures.db" "$storage" >"$test_dir/storage.log" 2>&1 & storage_pid=$!
"$ingestion" >"$test_dir/ingestion.log" 2>&1 & ingestion_pid=$!
"$analytics" >"$test_dir/analytics.log" 2>&1 & analytics_pid=$!

sleep 1
"$sensor" --count 5 --interval-ms 10
services=$(curl -fsS http://127.0.0.1:5050/services)
readings=$(curl -fsS 'http://127.0.0.1:5002/temperatures?limit=5')
average=$(curl -fsS 'http://127.0.0.1:5003/average?limit=5')
metrics=$(curl -fsS http://127.0.0.1:5001/metrics)

[[ "$services" == *'ingestion-service'* ]]
[[ "$services" == *'storage-service'* ]]
[[ "$services" == *'analytics-service'* ]]
[[ "$readings" == *'temperature'* ]]
[[ "$average" == *'"sample_count":5'* ]]
[[ "$metrics" == *'ssle_http_requests_total{code="2xx"} 5'* ]]

echo "$average"

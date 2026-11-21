#!/usr/bin/env bash
set -euo pipefail
work=$(mktemp -d)
pids=()
cleanup() {
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait || true
    rm -rf "$work"
}
trap cleanup EXIT
trap 'cat "$work"/*.log >&2' ERR

umask 077
mkdir "$work/devices"
openssl rand -hex 32 > "$work/token"
token=$(<"$work/token")
printf '%s' "$token" | openssl dgst -sha256 -r | cut -d' ' -f1 > "$work/devices/lab.sensor.01"
openssl req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
    -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1 \
    -keyout "$work/server.key" -out "$work/server.crt" 2>/dev/null
openssl req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
    -subj /CN=SensorCA -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -keyout "$work/ca.key" -out "$work/ca.crt" 2>/dev/null
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -subj /CN=lab.cert.01 -keyout "$work/client.key" -out "$work/client.csr" 2>/dev/null
printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' \
    'extendedKeyUsage=critical,clientAuth' > "$work/client.ext"
openssl x509 -req -in "$work/client.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" \
    -days 1 -set_serial 1 -extfile "$work/client.ext" -out "$work/client.crt" 2>/dev/null

export SSLE_DIRECT=1 STORAGE_URL=http://127.0.0.1:15002 INGESTION_URL=https://127.0.0.1:15001
export DEVICE_ID=lab.sensor.01 SENSOR_TOKEN_FILE="$work/token" INGESTION_CA="$work/server.crt"
PORT=15002 TEMP_DB="$work/db" "$1" >"$work/storage.log" 2>&1 & pids+=("$!")
PORT=15001 DEVICE_KEYS_DIR="$work/devices" INGESTION_TLS_CERT="$work/server.crt" \
    INGESTION_CLIENT_CA="$work/ca.crt" \
    INGESTION_TLS_KEY="$work/server.key" "$2" >"$work/ingestion.log" 2>&1 & pids+=("$!")
PORT=15003 "$3" >"$work/analytics.log" 2>&1 & pids+=("$!")
curl -fsS --retry 6 --retry-delay 1 --retry-connrefused --cacert "$INGESTION_CA" "$INGESTION_URL/health" >/dev/null
curl -fsS --retry 6 --retry-delay 1 --retry-connrefused "$STORAGE_URL/health" >/dev/null

post_status() {
    local device=$1
    shift
    curl -sS --cacert "$INGESTION_CA" -o /dev/null -w '%{http_code}' "$@" \
        -H 'Content-Type: application/json' --data "{\"device_id\":\"$device\",\"temperature\":23}" \
        "$INGESTION_URL/ingest"
}
auth_rejections() {
    curl -fsS --cacert "$INGESTION_CA" "$INGESTION_URL/metrics" |
        awk '$1 == "ssle_http_auth_rejections_total" {print $2}'
}

[[ $(auth_rejections) == 0 ]]
[[ $(post_status "$DEVICE_ID") == 401 ]]
[[ $(post_status lab.other.01 -H "Authorization: Bearer $token") == 403 ]]
[[ $(auth_rejections) == 2 ]]
if curl -fsS "$INGESTION_URL/health" >/dev/null 2>&1; then exit 1; fi
"$4" --count 2 --interval-ms 5
[[ $(auth_rejections) == 2 ]]
[[ $(curl -fsS http://127.0.0.1:15003/average) == *'"sample_count":2'* ]]
[[ $(curl -fsS 'http://127.0.0.1:15003/temperatures?limit=1') == *'lab.sensor.01'* ]]
digest_applied="$work/devices/lab.new.01"
cp "$work/devices/lab.sensor.01" "$digest_applied"
[[ $(post_status lab.new.01 -H "Authorization: Bearer $token") == 202 ]]
rm "$digest_applied"
[[ $(post_status lab.new.01 -H "Authorization: Bearer $token") == 403 ]]

client_args=(--cert "$work/client.crt" --key "$work/client.key")
[[ $(post_status lab.cert.01 "${client_args[@]}") == 403 ]]

# Even a registered fingerprint must chain to the site's client CA.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
    -subj /CN=lab.foreign.01 -addext 'extendedKeyUsage=clientAuth' \
    -keyout "$work/foreign.key" -out "$work/foreign.crt" 2>/dev/null
digest=$(openssl x509 -in "$work/foreign.crt" -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1)
printf 'x509:%s\n' "$digest" > "$work/devices/lab.foreign.01"
[[ $(post_status lab.foreign.01 --cert "$work/foreign.crt" --key "$work/foreign.key") == 403 ]]
digest=$(openssl x509 -in "$work/client.crt" -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1)
printf 'x509:%s\n' "$digest" > "$work/devices/lab.cert.01"
[[ $(post_status lab.cert.01) == 401 ]]
[[ $(post_status lab.cert.01 -H "Authorization: Bearer $token") == 403 ]]
[[ $(post_status "$DEVICE_ID" "${client_args[@]}") == 403 ]]
[[ $(post_status lab.cert.01 "${client_args[@]}") == 202 ]]
env -u SENSOR_TOKEN_FILE SENSOR_TLS_CERT="$work/client.crt" SENSOR_TLS_KEY="$work/client.key" \
    "$4" --device-id lab.cert.01 --count 1
[[ $(curl -fsS 'http://127.0.0.1:15003/temperatures?limit=1') == *'lab.cert.01'* ]]
rm "$work/devices/lab.cert.01"
[[ $(post_status lab.cert.01 "${client_args[@]}") == 403 ]]

#!/usr/bin/env bash
# Teste dos dois estados de rejeição numa instância nginx só em loopback.
set -euo pipefail
work=$(mktemp -d)
nginx_pid=""
client_pid=""
cleanup() {
    if [[ -n $client_pid ]]; then kill "$client_pid" 2>/dev/null || true; wait "$client_pid" 2>/dev/null || true; fi
    if [[ -n $nginx_pid ]]; then kill "$nginx_pid" 2>/dev/null || true; wait "$nginx_pid" 2>/dev/null || true; fi
    rm -rf "$work"
}
trap cleanup EXIT

config=/etc/nginx/sites-enabled/ssle-k3s
grep -Fq 'limit_conn per_site 120;' "$config"
grep -Fq 'limit_req_status 429;' "$config"
grep -Fq 'limit_conn_status 503;' "$config"
rules=$(grep -E '^(limit_req_zone|limit_conn_zone|limit_req_status|limit_conn_status) ' "$config" |
    sed -E 's/rate=[0-9]+r\/s/rate=1r\/m/')
port=$((20000 + RANDOM % 20000))
chmod 755 "$work"
printf 'consulta legítima\n' > "$work/read"
head -c 1024 /dev/zero > "$work/hold"
cat > "$work/nginx.conf" <<EOF
daemon off;
pid $work/pid;
error_log $work/error.log;
events {}
http {
    access_log off;
    $rules
    server {
        listen 127.0.0.1:$port;
        root $work;
        location = /health { return 200; }
        location = /read { limit_req zone=api; }
        location = /hold { limit_conn perip 20; limit_conn per_site 1; limit_rate 32; }
    }
}
EOF
nginx -p "$work" -c "$work/nginx.conf" &
nginx_pid=$!
url="http://127.0.0.1:$port"
status() { curl --noproxy '*' --max-time 4 -sS -o /dev/null -w '%{http_code}' "$@"; }
for ((attempt = 1; attempt <= 30; attempt++)); do
    kill -0 "$nginx_pid" 2>/dev/null || { cat "$work/error.log" >&2; exit 1; }
    if [[ $(status "$url/health" 2>/dev/null) == 200 ]]; then break; fi
    sleep 0.1
done
[[ $(status "$url/read") == 200 ]]
[[ $(status "$url/read") == 429 ]]

curl --noproxy '*' --max-time 12 -s -D "$work/first.headers" -o /dev/null "$url/hold" &
client_pid=$!
for ((attempt = 1; attempt <= 30; attempt++)); do
    if grep -q ' 200 ' "$work/first.headers" 2>/dev/null; then break; fi
    sleep 0.1
done
grep -q ' 200 ' "$work/first.headers"
[[ $(status --head "$url/hold") == 503 ]]
kill "$client_pid" 2>/dev/null || true
wait "$client_pid" 2>/dev/null || true
client_pid=""
for ((attempt = 1; attempt <= 30; attempt++)); do
    if [[ $(status --head "$url/hold" 2>/dev/null) == 200 ]]; then
        echo 'nginx em loopback: 429 por taxa, 503 por ocupação e recuperação para 200.'
        exit 0
    fi
    sleep 0.1
done
echo 'A ocupação da ligação de teste não recuperou.' >&2
exit 1

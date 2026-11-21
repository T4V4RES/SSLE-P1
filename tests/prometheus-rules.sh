#!/usr/bin/env bash
# Testes unitarios das regras do Prometheus (promtool test rules) com series
# sinteticas. Usa o promtool local, se existir; senao, o do contentor prom-global.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
tests=(tests/prometheus/global.test.yml tests/prometheus/k3s-auth.test.yml tests/prometheus/gateway.test.yml)
cd "$root"
if command -v promtool >/dev/null; then
    promtool test rules "${tests[@]}"
else
    incus exec prom-global -- rm -rf /tmp/ssle-promtool
    incus exec prom-global -- mkdir -p /tmp/ssle-promtool
    tar cf - monitorizacao/rules-global.yml monitorizacao/shared-gateway.yml kubernetes/site-rules.yml "${tests[@]}" |
        incus exec prom-global -- tar xf - -C /tmp/ssle-promtool
    incus exec prom-global -- sh -c "cd /tmp/ssle-promtool && promtool test rules ${tests[*]}"
fi

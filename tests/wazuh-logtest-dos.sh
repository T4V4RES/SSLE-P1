#!/usr/bin/env bash
# Valida no wazuh-logtest os limiares DoS (regras 100204, 100205 e 100206).
# Corre na VM; cada caso usa uma sessao nova do logtest e origens proprias.
set -euo pipefail

stamp=$(date -u '+%d/%b/%Y:%H:%M:%S +0000')

# lines <n> <codigo> <ip> [ip...]: n linhas nginx "combined", alternando as origens
lines() {
    local n=$1 code=$2 i
    shift 2
    local ips=("$@")
    for ((i = 0; i < n; i++)); do
        printf '%s - - [%s] "GET %s HTTP/1.0" %s 162 "-" "%s"\n' \
            "${ips[i % ${#ips[@]}]}" "$stamp" "${URL:-/api/average?limit=100}" "$code" "${AGENT:-ApacheBench/2.3}"
    done
}
SHELLSHOCK='() { :; }; /usr/bin/printf SSLE-LAB'

# Por evento: numero do evento e ID da regra escolhida na fase 3
rules_of() {
    incus exec wazuh-container -- /var/ossec/bin/wazuh-logtest 2>&1 |
        awk '/^\*\*Phase 1/ {n++} /^\*\*Phase 3/ {p = 1; next}
             p && /id:/ {gsub(/[^0-9]/, ""); print n, $0; p = 0}'
}

# first_at <regra>: evento em que a regra disparou pela primeira vez (vazio se nunca)
first_at() { awk -v r="$1" '$2 == r {print $1; exit}'; }

fail=0
check() {
    if [[ $2 == "$3" ]]; then
        echo "OK    $1"
    else
        echo "FALHA $1: obtido '${2:-nunca}', esperado '${3:-nunca}'"
        fail=1
    fi
}

check "um 429 gera 100204"                        "$(lines 1 429 10.9.9.1 | rules_of | first_at 100204)" "1"
check "9 x 429 da mesma origem nao bloqueiam"     "$(lines 9 429 10.9.9.2 | rules_of | first_at 100206)" ""
check "10 x 429 da mesma origem: 100206 no 10.o"  "$(lines 10 429 10.9.9.3 | rules_of | first_at 100206)" "10"
check "10 x 429 de duas origens nao bloqueiam"    "$(lines 10 429 10.9.9.4 10.9.9.5 | rules_of | first_at 100206)" ""
check "503 de sobrecarga nao aciona 100206"       "$(lines 10 503 192.0.2.9 | rules_of | first_at 100206)" ""
check "29 x 200 da mesma origem sem 100205"       "$(lines 29 200 10.9.9.6 | rules_of | first_at 100205)" ""
check "30 x 200 da mesma origem: 100205 no 30.o"  "$(lines 30 200 10.9.9.7 | rules_of | first_at 100205)" "30"
# As regras DoS nao podem tirar eventos as do Shellshock (31166 e 31168 -> 100210)
check "Shellshock com resposta 200 gera 100210"   "$(URL=/ AGENT=$SHELLSHOCK lines 1 200 10.9.9.8 | rules_of | first_at 100210)" "1"
check "Shellshock com resposta 429 gera 100210"   "$(URL=/ AGENT=$SHELLSHOCK lines 1 429 10.9.9.9 | rules_of | first_at 100210)" "1"
exit $fail

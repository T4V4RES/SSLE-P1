#!/usr/bin/env bash
# Repete os ensaios dos cenários principais e do Shellshock N vezes (5 por
# omissão), um de cada vez. Antes de cada ensaio repõe o historial de
# reincidentes e espera que não haja bloqueios ativos, para que as repetições
# sejam independentes. A publicação alterna entre Lisboa e Porto: o alerta de
# recusas de um site precisa de cerca de 5 min para resolver.
# No fim, ataques/resumo-repeticoes.py calcula mediana e intervalo.
# Duração: cerca de 14 min por repetição.
source "$(dirname "$0")/lib.sh"
trap - EXIT
reps=${1:-5}
SSLE_EVIDENCE=${SSLE_EVIDENCE:-$ROOT/evidencias/repeticoes-$(date -u +%Y%m%dT%H%M%SZ)}
export SSLE_EVIDENCE
# A sonda cobre o bloqueio de 120 s; o spammer desiste após 5 falhas seguidas.
export SSLE_SONDA=${SSLE_SONDA:-130} SSLE_SPAM_DESISTE=${SSLE_SPAM_DESISTE:-5}
mkdir -p "$SSLE_EVIDENCE"
log_file="$SSLE_EVIDENCE/execucao.log"

auth_alert_active() {
    incus exec prom-global -- curl -s http://127.0.0.1:9093/api/v2/alerts </dev/null | python3 -c '
import json, sys
sys.exit(0 if any(a["labels"].get("alertname") == "SsleIngestionAuthRejections" and a["labels"].get("site") == sys.argv[1]
                  and a["status"]["state"] == "active" for a in json.load(sys.stdin)) else 1)' "$1"
}

prepare() {
    wait_unblocked_lab
    reset_reputation
}

for ((i = 1; i <= reps; i++)); do
    site=$([[ $((i % 2)) == 1 ]] && echo lisboa || echo porto)
    printf '%s repetição %d/%d\n' "$(now)" "$i" "$reps" | tee -a "$log_file"
    prepare; bash "$ROOT/ataques/rajada-http.sh" >> "$log_file" 2>&1
    prepare; bash "$ROOT/ataques/ddos.sh" >> "$log_file" 2>&1
    prepare; bash "$ROOT/ataques/spam.sh" >> "$log_file" 2>&1
    for _ in $(seq 60); do auth_alert_active "$site" || break; sleep 10; done
    prepare; bash "$ROOT/ataques/publicacao.sh" "$site" >> "$log_file" 2>&1
    prepare; bash "$ROOT/ataques/shellshock.sh" >> "$log_file" 2>&1
done
python3 "$ROOT/ataques/resumo-repeticoes.py" "$SSLE_EVIDENCE" | tee "$SSLE_EVIDENCE/resumo.txt"

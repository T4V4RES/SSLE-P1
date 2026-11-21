#!/usr/bin/env bash
# Limpa o historial de reincidentes do correlacionador, por exemplo antes de
# uma demonstração. Os bloqueios em curso expiram normalmente.
source "$(dirname "$0")/lib.sh"
reset_reputation
echo "Historial de reincidentes limpo (ssle-correlator reiniciado)."

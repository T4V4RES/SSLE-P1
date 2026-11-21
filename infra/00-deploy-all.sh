#!/usr/bin/env bash
# Instalação normal do Projeto 1. Executar na VM Kali que aloja o Incus.
set -euo pipefail
source "$(dirname "$0")/k3s-lib.sh"

incus info wazuh-container >/dev/null || { echo 'Falta o gestor Wazuh dos guiões.' >&2; exit 1; }
for node in k3s-master k3s-node1; do
    incus info "$node" >/dev/null || { echo "Falta o nó $node." >&2; exit 1; }
done
kube wait --for=condition=Ready nodes/k3s-master nodes/k3s-node1 --timeout=90s
config names >/dev/null

fingerprint=$(cd "$ROOT" && find servicos -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -c1-12)
dockerfile=$(sha256sum "$ROOT/docker/Dockerfile" | cut -c1-12)
tag=${SSLE_IMAGE_TAG:-k3s-$fingerprint-$dockerfile}
"$ROOT/docker/build-k3s-images.sh" "$tag"
"$ROOT/infra/k3s-monitor.sh" prepare
if ! incus exec lis-mail -- systemctl is-active --quiet postfix 2>/dev/null; then
    "$ROOT/infra/05-deploy-mail.sh"
fi
"$ROOT/infra/k3s-gateway.sh"
"$ROOT/infra/k3s-sites.sh" "$tag" "${SSLE_BACKUP_DIR:-}"
"$ROOT/infra/k3s-monitor.sh" activate
"$ROOT/infra/k3s-wazuh-nos.sh"
SSLE_WAZUH_LAYOUT=k3s "$ROOT/infra/07-configure-wazuh.sh"
for container in "${CORE_CONTAINERS[@]}"; do
    incus config set "$container" boot.autostart=true
done
pin_dns
"$ROOT/infra/check-after-boot.sh"

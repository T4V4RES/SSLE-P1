#!/usr/bin/env bash
# Docker corre dentro do contentor Incus preparado no guia 2.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
incus exec docker -- docker info >/dev/null
tar -C "$root" --exclude=build --exclude=__pycache__ -czf "$work/src.tgz" servicos docker/Dockerfile
incus exec docker -- mkdir -p /root/ssle-project
incus file push "$work/src.tgz" docker/root/ssle-project/src.tgz
incus exec docker -- tar -xzf /root/ssle-project/src.tgz -C /root/ssle-project
refs=()
for image in registry storage ingestion analytics sensor; do
    ref="ssle/$image:project1"
    incus exec docker -- docker build -f /root/ssle-project/docker/Dockerfile \
        --target "$image" -t "$ref" /root/ssle-project/servicos
    refs+=("$ref")
done
incus exec docker -- docker save -o /root/ssle-project/images.tar "${refs[@]}"
incus file pull docker/root/ssle-project/images.tar "$work/images.tar"
# As imagens nao vem de nenhum registo (imagePullPolicy: Never). Com o disco acima
# de 85 %, o kubelet apaga as imagens que nenhum pod do no esta a usar, e um pod
# reagendado para esse no fica em ErrImageNeverPull. Marcadas como fixas, o
# kubelet nao as apaga.
for node in k3s-master k3s-node1; do
    incus file push "$work/images.tar" "$node/root/ssle-project-images.tar"
    incus exec "$node" -- k3s ctr images import /root/ssle-project-images.tar
    incus exec "$node" -- rm /root/ssle-project-images.tar
    for ref in "${refs[@]}"; do
        incus exec "$node" -- k3s ctr images label "docker.io/$ref" io.cri-containerd.pinned=pinned >/dev/null
    done
done

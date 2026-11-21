#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
tag=${1:?usage: build-k3s-images.sh TAG}
[[ $tag =~ ^[a-z0-9][a-z0-9.-]{0,63}$ ]] || exit 2
nodes=(k3s-master k3s-node1)
refs=()
for image in storage ingestion analytics sensor; do refs+=("ssle/$image:$tag"); done

ready=1
for node in "${nodes[@]}"; do
    images=$(incus exec "$node" -- k3s ctr images ls -q)
    for ref in "${refs[@]}"; do
        if ! grep -Fxq "docker.io/$ref" <<< "$images"; then ready=0; fi
    done
done
if ((ready)); then exit 0; fi

started=0
if [[ $(incus list '^docker$' -c s -f csv) == STOPPED ]]; then
    incus start docker
    started=1
fi
cleanup() {
    incus exec docker -- rm -rf /root/ssle-k3s-build
    if ((started)); then incus stop docker; fi
}
trap cleanup EXIT
for attempt in {1..30}; do
    if incus exec docker -- docker info >/dev/null 2>&1; then break; fi
    if ((attempt == 30)); then echo 'Docker builder indisponível' >&2; exit 1; fi
    sleep 1
done
incus exec docker -- mkdir -p /root/ssle-k3s-build
tar -C "$root" -cf - servicos docker/Dockerfile |
    incus exec docker --mode=non-interactive -- tar -xf - -C /root/ssle-k3s-build
for ref in "${refs[@]}"; do
    image=${ref#ssle/}
    incus exec docker -- docker build -f /root/ssle-k3s-build/docker/Dockerfile \
        --target "${image%:*}" -t "$ref" /root/ssle-k3s-build/servicos
done
for node in "${nodes[@]}"; do
    incus exec docker --mode=non-interactive -- docker save "${refs[@]}" |
        incus exec "$node" --mode=non-interactive -- k3s ctr images import -
    for ref in "${refs[@]}"; do
        incus exec "$node" -- k3s ctr images label "docker.io/$ref" io.cri-containerd.pinned=pinned >/dev/null
    done
done

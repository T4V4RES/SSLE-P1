#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/k3s-lib.sh"

tag=${1:?usage: k3s-sites.sh IMAGE_TAG [BACKUP_DIRECTORY]}
backup=${2:-}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
umask 077

sites=$(config names)
gateway_ip=$(reserve_address ssle-gateway)
monitor_ip=$(reserve_address prom-global)

provision_tls() (
    local site=$1
    local found
    found=$(kube -n "$site" get secret ingestion-tls --ignore-not-found -o name)
    if [[ -z $found ]]; then
        mkdir -p "$work/$site"
        cd "$work/$site"
        openssl req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
            -subj "/CN=SSLE $site Ingestion CA" -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
            -addext 'keyUsage=critical,keyCertSign,cRLSign' -keyout ca.key -out ca.crt 2>/dev/null
        openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
            -subj /CN=ingestion -keyout tls.key -out server.csr 2>/dev/null
        cat > extensions <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:ingestion,DNS:k3s-master.incus,DNS:k3s-node1.incus
EOF
        openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 \
            -extfile extensions -out tls.crt 2>/dev/null
        python3 - "$site" <<'PY' | kube -n "$site" create -f -
import base64, json, pathlib, sys
print(json.dumps({'apiVersion': 'v1', 'kind': 'Secret', 'type': 'kubernetes.io/tls',
                  'metadata': {'name': 'ingestion-tls', 'namespace': sys.argv[1]},
                  'data': {name: base64.b64encode(pathlib.Path(name).read_bytes()).decode()
                           for name in ('ca.crt', 'tls.crt', 'tls.key')}}))
PY
    fi
    kube -n "$site" get secret ingestion-tls -o 'jsonpath={.data.ca\.crt}' | base64 -d > "$work/$site.ca"
    openssl x509 -in "$work/$site.ca" -checkend 604800 -noout >/dev/null
)

restore_data() (
    local site=$1 source=$2
    python3 - "$source" <<'PY'
import sqlite3, sys
from pathlib import Path
path = Path(sys.argv[1]).resolve()
with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as db:
    if db.execute('PRAGMA quick_check').fetchone() != ('ok',):
        raise SystemExit('cópia SQLite inválida')
    print(f"{path.name}: {db.execute('SELECT count(*) FROM temperatures').fetchone()[0]} leituras")
PY
    [[ -z $(kube -n "$site" get deployment storage --ignore-not-found -o name) ]] || {
        echo "O armazenamento do site $site já existe. A recuperação inicial exige um volume novo." >&2; exit 1;
    }
    printf '%s\n' '{"apiVersion":"v1","kind":"PersistentVolumeClaim","metadata":{"name":"storage-data"},"spec":{"accessModes":["ReadWriteOnce"],"storageClassName":"local-path","resources":{"requests":{"storage":"1Gi"}}}}' |
        kube -n "$site" apply -f -
    cat <<EOF | kube -n "$site" apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: sqlite-import
spec:
  automountServiceAccountToken: false
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    fsGroup: 10001
    seccompProfile: {type: RuntimeDefault}
  containers:
  - name: import
    image: ssle/storage:$tag
    imagePullPolicy: Never
    command: [sleep, '600']
    resources:
      requests: {cpu: 5m, memory: 8Mi}
      limits: {cpu: 100m, memory: 32Mi}
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities: {drop: [ALL]}
    volumeMounts:
    - {name: data, mountPath: /data}
  volumes:
  - name: data
    persistentVolumeClaim: {claimName: storage-data}
EOF
    trap 'kube -n "$site" delete pod sqlite-import --ignore-not-found --wait=true' EXIT
    kube -n "$site" wait --for=condition=Ready pod/sqlite-import --timeout=100s
    expected=$(sha256sum "$source" | cut -d' ' -f1)
    kube -n "$site" exec -i sqlite-import -- sh -ec '
        umask 077
        test ! -e /data/temp_data.db
        cat > /data/.incoming.db
        printf "%s  /data/.incoming.db\n" "$1" | sha256sum -c -
        mv -n /data/.incoming.db /data/temp_data.db
    ' sh "$expected" < "$source"
)

for site in $sites; do
    kube create namespace "$site" --dry-run=client -o yaml | kube apply -f -
    kube label namespace "$site" pod-security.kubernetes.io/enforce=restricted --overwrite
    provision_tls "$site"
    kube -n "$site" create configmap ingestion-ca --from-literal="ca.crt=$(<"$work/$site.ca")" --dry-run=client -o json | kube apply -f -
    python3 "$ROOT/infra/sensor-credentials.py" "$site" bootstrap-ca > "$work/$site.sensor-ca"
    kube -n "$site" create configmap sensor-client-ca --from-literal="ca.crt=$(<"$work/$site.sensor-ca")" \
        --dry-run=client -o json | kube apply -f -
    if [[ -z $(kube -n "$site" get secret sensor-digests --ignore-not-found -o name) ]]; then
        kube -n "$site" create secret generic sensor-digests
    fi
    python3 "$ROOT/infra/sensor-credentials.py" "$site" bootstrap
    sed "s/@SITE@/$site/g" "$ROOT/kubernetes/site-prometheus.yml" > "$work/$site.prometheus.yml"
    python3 - "$site" "$work/$site.prometheus.yml" "$ROOT/kubernetes/site-rules.yml" <<'PY' | kube -n "$site" apply -f -
import json, pathlib, sys
site, config, rules = sys.argv[1:]
print(json.dumps({'apiVersion': 'v1', 'kind': 'ConfigMap',
                  'metadata': {'name': 'prometheus', 'namespace': site},
                  'data': {'prometheus.yml': pathlib.Path(config).read_text(),
                           'rules.yml': pathlib.Path(rules).read_text()}}))
PY
    if [[ -n $backup ]]; then restore_data "$site" "$backup/$site.db"; fi
    config manifest "$site" "$tag" "$gateway_ip" "$monitor_ip" | kube apply -f -
    for component in storage ingestion analytics sensor prometheus; do
        kube -n "$site" rollout status "deployment/$component" --timeout=140s
    done
done

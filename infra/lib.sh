# Funcoes comuns aos scripts de deploy.
# Uso: source "$(dirname "$0")/lib.sh"
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BASE_IMAGE=${BASE_IMAGE:-images:debian/trixie}
WAZUH_MANAGER=${WAZUH_MANAGER:-wazuh-container.incus}

# Sites do projeto: prefixo cidade rack replicas-de-ingestion
SITES=(
    "lis lisbon rack1 2"
    "opo porto rack1 1"
)

log() { printf '\n==> %s\n' "$*"; }

wait_network() {
    local c=$1
    for _ in $(seq 90); do
        incus exec "$c" -- getent hosts deb.debian.org >/dev/null 2>&1 && return 0
        sleep 1
    done
    echo "erro: $c sem rede" >&2
    return 1
}

apt_install() {
    local c=$1; shift
    incus exec "$c" -- env DEBIAN_FRONTEND=noninteractive sh -c \
        "apt-get update -q >/dev/null && apt-get install -y -q --no-install-recommends $*"
}

# Espera o systemd do container ficar operacional antes de usar systemctl
wait_systemd() {
    local c=$1
    for _ in $(seq 60); do
        case $(incus exec "$c" -- systemctl is-system-running 2>/dev/null) in
            running|degraded) return 0 ;;
        esac
        sleep 1
    done
    echo "erro: $c sem systemd operacional" >&2
    return 1
}

# launch <nome> [imagem]: reutiliza instancias existentes, preservando os dados.
launch() {
    local name=$1 image=${2:-$BASE_IMAGE}
    if incus info "$name" >/dev/null 2>&1; then
        incus start "$name" 2>/dev/null || true
    else
        incus launch "$image" "$name"
    fi
    wait_network "$name"
    wait_systemd "$name"
}

# push <ficheiro local> <container>/<caminho>
push() { incus file push -p "$1" "$2"; }

# wait_unblocked <cliente> <ip> [porta]: espera que o cliente volte a abrir
# ligacao ao destino (fim de um firewall-drop de 120 s). Ate WAIT_TRIES tentativas.
wait_unblocked() {
    local c=$1 ip=$2 port=${3:-80}
    for _ in $(seq "${WAIT_TRIES:-75}"); do
        incus exec "$c" -- timeout 2 bash -c "exec 3<>/dev/tcp/$ip/$port" 2>/dev/null && return 0
        sleep "${WAIT_SLEEP:-2}"
    done
    echo "erro: $c continua sem acesso a $ip:$port" >&2
    return 1
}

# render <template> <var=valor>...: substitui @VAR@ e escreve para stdout
render() {
    local file=$1; shift
    local args=()
    for pair in "$@"; do args+=(-e "s|@${pair%%=*}@|${pair#*=}|g"); done
    sed "${args[@]}" "$file"
}

# ---------- Wazuh ----------

wazuh_version() {
    incus exec wazuh-container -- /var/ossec/bin/wazuh-control info -v | tr -d 'v'
}

# ID do agente com este nome no manager (vazio se nao existir)
wazuh_agent_id() {
    incus exec wazuh-container -- /var/ossec/bin/manage_agents -l |
        awk -v n="$1," '$3 == "Name:" && $4 == n {gsub(",", "", $2); print $2}'
}

# Remove do manager um agente antigo com o mesmo nome (redeploy)
wazuh_forget_agent() {
    local id
    id=$(wazuh_agent_id "$1")
    [[ -n $id ]] && incus exec wazuh-container -- /var/ossec/bin/manage_agents -r "$id" >/dev/null
    return 0
}

# Confirma que a resposta ativa chega ao agente: pede um firewall-drop de
# 120 s para 192.0.2.1 (TEST-NET-1, nunca usado no laboratorio) e espera a
# regra no iptables do contentor. Depois de um "reload" por mudanca da
# configuracao partilhada, o agentd pode deixar de entregar respostas ao execd.
wazuh_check_active_response() {
    local c=$1 id
    id=$(wazuh_agent_id "$c")
    [[ -n $id ]] || { echo "erro: $c sem agente no manager" >&2; return 1; }
    incus exec wazuh-container -- /var/ossec/bin/agent_control -b 192.0.2.1 -f firewall-drop120 -u "$id" >/dev/null
    for _ in $(seq 20); do
        incus exec "$c" -- iptables -S INPUT 2>/dev/null | grep -q '192.0.2.1/32' && return 0
        sleep 1
    done
    echo "erro: resposta ativa nao chegou a $c" >&2
    return 1
}

# Se a resposta ativa nao chegar, reinicia o agente uma vez e volta a verificar.
wazuh_ensure_active_response() {
    local c=$1
    wazuh_check_active_response "$c" 2>/dev/null && return 0
    echo "aviso: resposta ativa sem efeito em $c; a reiniciar o agente" >&2
    incus exec "$c" -- systemctl restart wazuh-agent
    sleep 15
    wazuh_check_active_response "$c"
}

# IPv4 do manager: o servico de inscricao (authd) so escuta em IPv4 e o DNS
# do Incus devolve tambem IPv6, que o agente tentaria primeiro.
wazuh_manager_ip() {
    incus list wazuh-container -c4 -f csv | grep -oE '[0-9.]+ \(eth0\)' | cut -d' ' -f1
}

# install_wazuh_agent <container> <grupo>
# A configuracao (ficheiros a ler) vem do grupo, gerido no manager.
# Os agentes guardam o IP do gestor na inscricao. A bridge do Incus atribui
# enderecos por DHCP e, depois de um reinicio da VM, pode dar este a outro
# contentor: o gestor passa a ter o endereco atual reservado na bridge.
wazuh_pin_manager_ip() {
    local ip
    ip=$(wazuh_manager_ip)
    [[ -n $ip ]] || { echo "erro: wazuh-container sem IPv4" >&2; return 1; }
    [[ $(incus config device get wazuh-container eth0 ipv4.address 2>/dev/null) == "$ip" ]] && return 0
    incus config device override wazuh-container eth0 "ipv4.address=$ip" 2>/dev/null ||
        incus config device set wazuh-container eth0 ipv4.address "$ip"
}

install_wazuh_agent() {
    local c=$1 group=$2 version manager
    version=$(wazuh_version)
    wazuh_pin_manager_ip
    manager=$(wazuh_manager_ip)
    # O grupo tem de existir no manager antes da inscricao
    incus exec wazuh-container -- /var/ossec/bin/agent_groups -a -g "$group" -q 2>/dev/null || true
    wazuh_forget_agent "$c"
    apt_install "$c" "gnupg curl ca-certificates"
    incus exec "$c" -- sh -c '
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH |
            gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import &&
        chmod 644 /usr/share/keyrings/wazuh.gpg &&
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
            > /etc/apt/sources.list.d/wazuh.list'
    incus exec "$c" -- env DEBIAN_FRONTEND=noninteractive \
        WAZUH_MANAGER="$manager" WAZUH_AGENT_NAME="$c" WAZUH_AGENT_GROUP="$group" \
        sh -c "apt-get update -q >/dev/null && apt-get install -y -q wazuh-agent=$version-1"
    # Inscricao explicita (apontada ao IPv4) para funcionar tambem em redeploy
    incus exec "$c" -- sh -c "
        sed -i 's#<address>[^<]*</address>#<address>$manager</address>#' /var/ossec/etc/ossec.conf &&
        /var/ossec/bin/agent-auth -m '$manager' -A '$c' -G '$group' &&
        systemctl daemon-reload && systemctl enable wazuh-agent && systemctl restart wazuh-agent"
}

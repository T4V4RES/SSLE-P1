#!/usr/bin/env bash
# Separa a reputacao do guiao SIEM do cenario do projeto, sem a apagar.
#
# O guiao SIEM deixou no gestor a regra 100100 (endereco na lista
# blacklist-alienvault) e uma resposta ativa firewall-drop de 60 s. A lista do
# guiao so tem o endereco do anfitriao na bridge, usado como atacante no
# exercicio. No projeto, isso faz com que um pedido HTTP da propria VM a um
# gateway bloqueie a VM. A regra e a resposta ficam como o guiao as deixou; so
# muda o conteudo da lista ativa, e a lista original fica guardada ao lado.
#
# Uso: infra/siem-guiao.sh projeto|guiao|estado
#   projeto  guarda a lista do guiao em blacklist-alienvault.guiao e deixa ativa
#            uma lista so com 192.0.2.255 (TEST-NET-1, nunca usado no laboratorio)
#   guiao    repoe a lista original do guiao
#   estado   mostra a lista ativa e se a copia do guiao existe
source "$(dirname "$0")/lib.sh"

W=wazuh-container
LIST=/var/ossec/etc/lists/blacklist-alienvault
SAVED=$LIST.guiao
PLACEHOLDER="192.0.2.255:ssle-projeto"

wexec() { incus exec "$W" -- sh -c "$1"; }
active_agents() { incus exec "$W" -- /var/ossec/bin/agent_control -l | grep -c 'Active$' || true; }

restart_manager() {
    local before
    before=$(active_agents)
    incus exec "$W" -- systemctl restart wazuh-manager
    # Os agentes voltam a ligar-se sozinhos; espera que voltem todos.
    for _ in $(seq 60); do
        [[ $(active_agents) -ge $before ]] && return 0
        sleep 2
    done
    echo "aviso: so $(active_agents) de $before agentes ligados depois de reiniciar o gestor" >&2
}

case ${1:-estado} in
    projeto)
        if ! wexec "test -f $LIST"; then echo "sem lista do guiao SIEM no gestor; nada a fazer"; exit 0; fi
        if wexec "grep -qx '$PLACEHOLDER' $LIST"; then echo "ja em modo projeto"; exit 0; fi
        wexec "test -f $SAVED || cp -p $LIST $SAVED"
        wexec "printf '%s\n' '$PLACEHOLDER' > $LIST && chown wazuh:wazuh $LIST"
        restart_manager
        echo "modo projeto: lista do guiao guardada em $SAVED"
        ;;
    guiao)
        wexec "test -f $SAVED" || { echo "erro: nao existe $SAVED" >&2; exit 1; }
        wexec "cp -p $SAVED $LIST"
        restart_manager
        echo "modo guiao: lista original reposta"
        ;;
    estado)
        echo "lista ativa:"; wexec "cat $LIST 2>/dev/null || echo '(nao existe)'"
        wexec "test -f $SAVED" && echo "copia do guiao: $SAVED" || echo "copia do guiao: (nenhuma)"
        ;;
    *)
        echo "uso: $0 projeto|guiao|estado" >&2; exit 2 ;;
esac

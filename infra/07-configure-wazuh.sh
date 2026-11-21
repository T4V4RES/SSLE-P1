#!/usr/bin/env bash
# Configura o manager Wazuh: grupos de agentes, decoders, regras e a resposta
# ativa (firewall-drop) para as tres ameacas.
source "$(dirname "$0")/lib.sh"

W=wazuh-container
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

log "Grupos de agentes"
for g in gateway mail monitoring k3s; do
    incus exec "$W" -- /var/ossec/bin/agent_groups -a -g "$g" -q 2>/dev/null || true
    incus exec "$W" -- sh -c "mkdir -p /var/ossec/etc/shared/$g"
    push "$ROOT/wazuh/groups/$g.conf" "$W/var/ossec/etc/shared/$g/agent.conf"
done

log "Decoders e regras"
push "$ROOT/wazuh/decoders/ssle_decoders.xml" "$W/var/ossec/etc/decoders/ssle_decoders.xml"
push "$ROOT/wazuh/rules/ssle_rules.xml" "$W/var/ossec/etc/rules/ssle_rules.xml"
push "$ROOT/monitorizacao/correlate.py" "$W/usr/local/bin/ssle-correlate.py"
push "$ROOT/monitorizacao/ssle-correlator.service" "$W/etc/systemd/system/ssle-correlator.service"
incus exec "$W" -- sh -c 'mkdir -p /var/log/ssle && touch /var/log/ssle/correlations.jsonl &&
    systemctl daemon-reload && systemctl enable ssle-correlator && systemctl restart ssle-correlator'
incus exec "$W" -- sh -c 'grep -q "SSLE correlations" /var/ossec/etc/ossec.conf || cat >> /var/ossec/etc/ossec.conf <<XML
<!-- SSLE correlations -->
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/ssle/correlations.jsonl</location>
  </localfile>
</ossec_config>
XML'

log "Resposta ativa (firewall-drop) para as regras das ameacas"
# Idempotente: so adiciona o bloco se ainda nao existir
incus exec "$W" -- sh -c 'grep -q "SSLE active response" /var/ossec/etc/ossec.conf || cat >> /var/ossec/etc/ossec.conf <<XML

<!-- SSLE active response -->
<ossec_config>
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>100206,100210,100222,100247</rules_id>
    <timeout>120</timeout>
  </active-response>
</ossec_config>
XML'
# Instalações anteriores: acrescenta as regras novas ao bloco existente.
incus exec "$W" -- sed -i '/<!-- SSLE active response -->/,/<\/ossec_config>/ s#<rules_id>[^<]*</rules_id>#<rules_id>100206,100210,100222,100247</rules_id>#' /var/ossec/etc/ossec.conf

log "Permissoes e validacao"
incus exec "$W" -- sh -c 'chown wazuh:wazuh /var/ossec/etc/decoders/ssle_decoders.xml \
    /var/ossec/etc/rules/ssle_rules.xml /var/ossec/etc/shared/*/agent.conf &&
    /var/ossec/bin/wazuh-analysisd -t'

log "Reiniciar o manager"
incus exec "$W" -- systemctl restart wazuh-manager
sleep 5
incus exec "$W" -- /var/ossec/bin/agent_control -l

log "Verificar a resposta ativa nos agentes com firewall-drop"
# Os agentes voltam a ligar-se e podem recarregar a configuracao partilhada.
sleep 20
if [[ ${SSLE_WAZUH_LAYOUT:-legacy} == k3s ]]; then
    agents=(ssle-gateway lis-mail)
    for node in k3s-master k3s-node1; do
        [[ -n $(wazuh_agent_id "$node") ]] && agents+=("$node")
    done
else
    agents=(lis-gw opo-gw lis-mail)
fi
for c in "${agents[@]}"; do
    wazuh_ensure_active_response "$c"
    echo "$c: resposta ativa OK"
done

log "Reputacao: reincidentes bloqueados em todos os agentes com firewall"
# O correlacionador emite a reincidencia (regras 100208/100209). O execd so
# aceita um bloqueio ativo por executavel e IP: com o mesmo firewall-drop, o
# bloqueio de reputacao seria abortado no agente que ja tem o bloqueio local de
# 120 s. Uma copia com nome proprio deixa os dois bloqueios coexistir.
for c in "${agents[@]}"; do
    incus exec "$c" -- cp -p /var/ossec/active-response/bin/firewall-drop /var/ossec/active-response/bin/ssle-reputacao
done
block=$'<!-- SSLE reputation begin -->\n<ossec_config>\n  <command>\n    <name>ssle-reputacao</name>\n    <executable>ssle-reputacao</executable>\n    <timeout_allowed>yes</timeout_allowed>\n  </command>\n'
for c in "${agents[@]}"; do
    id=$(wazuh_agent_id "$c")
    for pair in 100208:600 100209:3600; do
        block+="  <active-response><command>ssle-reputacao</command><location>defined-agent</location><agent_id>$id</agent_id><rules_id>${pair%%:*}</rules_id><timeout>${pair##*:}</timeout></active-response>"$'\n'
    done
done
block+=$'</ossec_config>\n<!-- SSLE reputation end -->\n'
incus exec "$W" -- sed -i '/<!-- SSLE reputation begin -->/,/<!-- SSLE reputation end -->/d' /var/ossec/etc/ossec.conf
printf '%s' "$block" | incus exec "$W" -- sh -c 'cat >> /var/ossec/etc/ossec.conf'

log "Lista branca: a resposta ativa nunca bloqueia a bridge nem os contentores de servico"
# Os testes de aceitacao publicam a partir do anfitriao (IP da bridge); bloquear
# esse IP num no K3s cortaria o DNS e o acesso ao no.
bridge=$(incus network get "${SSLE_BRIDGE:-incusbr0}" ipv4.address)
whitelist=$'<!-- SSLE white_list begin -->\n<ossec_config>\n  <global>\n'
for ip in "${bridge%/*}" $(for c in k3s-master k3s-node1 ssle-gateway lis-mail prom-global wazuh-container; do
        incus list "^$c$" -c4 -f csv | grep -oE '[0-9.]+ \(eth0\)' | cut -d' ' -f1; done); do
    whitelist+="    <white_list>$ip</white_list>"$'\n'
done
whitelist+=$'  </global>\n</ossec_config>\n<!-- SSLE white_list end -->\n'
incus exec "$W" -- sed -i '/<!-- SSLE white_list begin -->/,/<!-- SSLE white_list end -->/d' /var/ossec/etc/ossec.conf
printf '%s' "$whitelist" | incus exec "$W" -- sh -c 'cat >> /var/ossec/etc/ossec.conf'
incus exec "$W" -- /var/ossec/bin/wazuh-analysisd -t
incus exec "$W" -- systemctl restart wazuh-manager ssle-correlator

log "Separar a reputacao do guiao SIEM do cenario do projeto"
# A lista do guiao tem o endereco do anfitriao: um pedido da VM a um gateway
# bloquearia a propria VM. A lista original fica guardada (siem-guiao.sh guiao repoe-a).
if [[ ${SSLE_WAZUH_LAYOUT:-legacy} == legacy ]]; then
    "$ROOT/infra/siem-guiao.sh" projeto
fi

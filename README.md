# SSLE — Projeto 1: deteção, monitorização e prevenção

A VM Kali aloja dois sites no mesmo cluster K3s, Lisboa e Porto. O Incus aloja os dois nós Kubernetes, o gateway nginx, o servidor de correio, o Prometheus global e o Wazuh. Cada site tem um sensor, ingestão, análise, armazenamento SQLite e Prometheus local. O relatório está em `relatorio/relatorio.pdf`.

| Pasta | Conteúdo |
|---|---|
| `servicos/`, `docker/` | serviços em C e imagens |
| `kubernetes/` | manifestos dos sites, regras do Prometheus local e `sites.json` |
| `infra/` | instalação, configuração do nginx (gerada por `site-config.py`), verificação e observação |
| `mail/` | Postfix, SpamAssassin, quarentena e filtro |
| `monitorizacao/` | Prometheus global, Alertmanager, webhook e correlacionador |
| `wazuh/` | regras, descodificadores e grupos de agentes |
| `ataques/` | ensaios com tráfego real |
| `tests/` | testes unitários, `promtool`, aceitação e falha controlada |
| `evidencias/` | resultados dos ensaios de 21/11/2026 |
| `relatorio/` | artigo em LaTeX e PDF |
| `demo/` | vídeos das demonstrações, um por ataque |

## Vídeos das demonstrações

Cada vídeo mostra o ataque a correr na VM, a firewall do serviço atacado e os eventos no Wazuh. Em alguns, mostra também o Prometheus global.

| Vídeo | Cenário | O que se vê |
|---|---|---|
| [`demo/demo-rajada.mp4`](demo/demo-rajada.mp4) | 1. Rajada HTTP (`bot-1`) | `429` no nginx, regras 100204/100206, DROP no gateway durante 120 s, cliente legítimo sem erros |
| [`demo/demo-ddos.mp4`](demo/demo-ddos.mp4) | 1. Botnet com 3 bots | DROP dos 3 bots aos 6 s, botnet (100207), pico no Prometheus (100231) e correlação no site de Lisboa (100232) |
| [`demo/demo-spam.mp4`](demo/demo-spam.mp4) | 2. Spam e fraude (`bot-2`) | quarentena no Postfix, regras 100221/100222, DROP no correio, cabeçalhos `X-Spam`, correio legítimo entregue |
| [`demo/demo-shellshock.mp4`](demo/demo-shellshock.mp4) | 3. Shellshock (`bot-3`) | pedido `() { :; };` com resposta `404`, regra 100210 de nível 12, DROP no gateway |
| [`demo/demo-publicacao.mp4`](demo/demo-publicacao.mp4) | Extra: publicação não autorizada | `401`/`403`/`400`, regras 100246/100247, DROP no nó K3s, alerta 100245 vindo do Prometheus, nenhuma leitura gravada |
| [`demo/demo-mitm.mp4`](demo/demo-mitm.mp4) | Extra: interceção do sensor | certificado falso recusado (`TLSV1_ALERT_UNKNOWN_CA`); só com `-k` o intercetor capta o pedido |
| [`demo/demo-reincidencia.mp4`](demo/demo-reincidencia.mp4) | Reputação (reincidência) | 1.º Shellshock bloqueado só no gateway; o 2.º, depois de o bloqueio expirar, gera a 100208 e bloqueia o `bot-3` durante 10 min no gateway, no correio e nos dois nós K3s |

## Confirmar o estado

```bash
cd ~/Projects/ssle
bash infra/check-after-boot.sh
```

O script verifica os nomes `.incus`, os deployments, a API dos dois sites, `nginx -t`, os serviços, os agentes Wazuh, os bloqueios ativos, os alvos do Prometheus e os alertas ativos. Termina com código diferente de zero se encontrar um problema.

No Firefox da Kali, abre o [Prometheus global](http://10.225.218.15:9090) e o [Wazuh](https://127.0.0.1:18443). As portas do nginx são `80` (Lisboa) e `8080` (Porto). Os sensores externos ao K3s usam os NodePorts HTTPS `30441` e `30442`.

## Ensaios de ataque

Os três cenários principais seguem os guiões práticos: DDoS (1), spam (2) e Shellshock com o Wazuh (3). A publicação não autorizada e a interceção do sensor são extras.

Cada script corre na VM e arranca os clientes de ensaio de que precisa. Mede o cliente legítimo, regista o bloqueio na firewall e os alertas do Wazuh e, no fim, volta a parar os clientes. O resultado fica em `evidencias/<ensaio>-<data>/resumo.txt`. Corre um ensaio de cada vez e espera que o bloqueio anterior expire (120 s).

| Script | Cenário | O que se observa |
|---|---|---|
| `bash ataques/rajada-http.sh` | 1. Rajada HTTP (`bot-1`, 40 pedidos) | `429`, regra 100206, DROP nas portas 80 e 8080 durante 120 s, cliente legítimo sem erros |
| `bash ataques/ddos.sh` | 1. Botnet acima do limite (3 bots) | 100207, 100206 ×3, pico no Prometheus, correlação 100232 |
| `bash ataques/ddos.sh --lento` | 1. Botnet abaixo do limite | sem bloqueio; 100205, 100207 e correlação 100232 |
| `bash ataques/comparacao-protecao.sh` | 1. Mesma carga sem e com proteção | latência e erros do cliente legítimo e p95 da análise nos dois modos |
| `bash ataques/publicacao.sh [site]` | Extra: publicação não autorizada (`bot-3`) | `401`/`403`/`400` com o IP real (100246), bloqueio no nó K3s (100247), nenhuma leitura gravada, alerta 100245 |
| `bash ataques/spam.sh` | 2. Spam e fraude (`bot-2`, 40 mensagens) | quarentena (`postqueue -p` em `lis-mail`), regra 100222, DROP |
| `bash ataques/shellshock.sh` | 3. Shellshock (`bot-3`) | `404`, regra 100210 e DROP nas duas portas |
| `bash ataques/mitm.sh` | Extra: interceção do sensor | certificado falso recusado; com `-k`, o intercetor capta o pedido |
| `bash ataques/reincidente.sh` | Reputação | 2.ª rajada da mesma origem: 100208 e bloqueio de 10 min em todos os serviços |
| `bash ataques/repeticoes.sh [N]` | Todos | repete os ensaios N vezes (5 por omissão) e calcula mediana e intervalo |
| `bash tests/falha-federacao.sh` | Falha: federação de Lisboa cortada | `SiteMonitoringUnreachable` e alerta de credenciais não inibido |

Para a demonstração, `SSLE_SONDA=30` encurta o tempo em que o atacante insiste depois do bloqueio e `SSLE_SPAM_DESISTE=3` faz o spammer desistir após 3 falhas seguidas. `bash ataques/repor-reputacao.sh` limpa o historial de reincidentes.

A quarentena do correio é a fila `hold` do Postfix. `postsuper -H <id>` liberta uma mensagem e `postsuper -d ALL hold` apaga todas as retidas.

Para acompanhar um cenário a cada dez segundos, noutro terminal:

```bash
python3 infra/observar-defesas.py rajada-http --acompanhar   # ou ddos, spam, publicacao, shellshock, mitm
```

No Wazuh, filtra por `rule.id` (100206, 100207, 100208, 100210, 100222, 100232, 100245, 100247). No Prometheus, `ssle:shared_gateway_requests:increase1m` mostra o volume no gateway e `site:ssle_ingestion_auth_rejections:increase5m` as recusas de publicação por site.

## Testes

```bash
python3 -m pytest -q tests/              # correlacionador, configuração dos sites, credenciais
bash tests/prometheus-rules.sh           # promtool: alertas globais, de recusas e de pico
bash tests/k3s-defesas.sh --publicacao   # aceitação da publicação com token e mTLS
python3 tests/siem-integrado.py todos    # percurso agente → regra → bloqueio, com registos sintéticos
```

## Reinstalar se necessário

```bash
cd ~/Projects/ssle
bash infra/00-deploy-all.sh
```

O comando usa os nós K3s e o gestor Wazuh já provisionados na VM e a rede Incus `incusbr0`. Instala também o agente Wazuh nos dois nós K3s (`infra/k3s-wazuh-nos.sh`), que lê as recusas da ingestão e aplica os bloqueios. No fim, fixa os nomes `.incus` dos contentores principais com `host-record` no dnsmasq, para não dependerem das concessões DHCP. O contentor `docker` serve para construir imagens.

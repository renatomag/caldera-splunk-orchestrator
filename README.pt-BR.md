# Orquestrador de Emulação CALDERA + Splunk ES

🇺🇸 [English version](README.md)

Executa 47 operações de emulação de adversários contra uma VM Windows em laboratório de forma recorrente. Cada operação corresponde a um par validado de (detecção ESCU, habilidade CALDERA). Entre cada operação, a VM é revertida para um snapshot conhecido, garantindo que cada técnica seja executada em um ambiente consistente.

> **VMware vCenter é obrigatório.** O mecanismo de revert de snapshot — que restaura a VM alvo para um estado limpo entre as operações — é construído sobre o `govc` e requer acesso à API do vCenter. Sem um ambiente vCenter, este orquestrador não funciona.

---

## O que faz

```
Na inicialização:
  Excluir as 47 operações do ciclo anterior do CALDERA (mantém o CALDERA limpo)

A cada 2 horas:
  Para cada um dos 47 adversários (em ordem de kill-chain):
    1. Pré-verificação: se o agente não for confiável, reconhecê-lo via API
    2. Iniciar uma operação CALDERA para este adversário
    3. Aguardar até que o CALDERA marque a operação como concluída (até 30 min)
    4. Reverter a VM Win10 para o snapshot configurado via vCenter
    5. Aguardar o agente Sandcat reconectar
       → Se retornar como não confiável (timer do CALDERA disparou durante o revert),
         reconhecê-lo automaticamente via API — sem ação manual necessária
  Salvar os 47 IDs de operação em disco para limpeza no próximo ciclo
  Emitir um relatório de operações no log
```

O orquestrador **não** consulta o Splunk nem valida detecções — seu papel é executar as técnicas de ataque no endpoint de forma confiável, para que o Splunk ES tenha telemetria real para acionar suas regras.

---

## Ordem de execução na kill-chain

Os adversários são executados em uma sequência realista de ataque, de modo que a telemetria no Splunk reflita uma intrusão coerente, e não eventos aleatórios.

| Fase | Adversários | Qtd |
|---|---|:---:|
| Discovery | escu_045, escu_046, escu_047 | 3 |
| Command & Control | escu_009 (BITSAdmin primeiro), depois escu_001–008 | 9 |
| Execution | escu_010–015 | 6 |
| Privilege Escalation | escu_016 | 1 |
| Defense Evasion | escu_017–033 | 17 |
| Credential Access | escu_034–042 | 9 |
| Impact | escu_043, escu_044 | 2 |

---

## Pré-requisitos

| Componente | Detalhes |
|---|---|
| CALDERA | Rodando localmente na porta 8888, chave de API red exportada como `CALDERA_API_KEY` |
| Agente Sandcat | Pré-implantado na VM Windows alvo, conectando ao CALDERA |
| VMware vCenter | **Obrigatório** — o orquestrador usa `govc` para reverter o snapshot da VM após cada operação |
| Snapshot da VM | Tirado com a VM **ligada** e o Sandcat em execução, para que o revert retome pelo estado de memória (sem boot do Windows) |
| Binário `govc` | Em `./govc` ou `/usr/local/bin/govc` — CLI VMware para operações de snapshot |
| Credenciais vCenter | Exportadas como `GOVC_USERNAME` e `GOVC_PASSWORD` |

---

## Instalação

```bash
git clone https://github.com/renatomag/caldera-splunk-orchestrator.git
cd caldera-splunk-orchestrator
python3 -m venv venv
venv/bin/pip install -r requirements.txt

# Criar a configuração local a partir do exemplo e preencher com os valores do seu ambiente
cp config/settings.yaml.example config/settings.yaml
```

Edite `config/settings.yaml` e substitua cada `<placeholder>` pelos valores do seu ambiente antes de executar.

> **Nota para usuários de systemd:** o `WorkingDirectory` no arquivo de serviço deve corresponder ao diretório onde você clonou o repositório. Atualize-o com o caminho correto antes de habilitar o serviço.

---

## Credenciais

As credenciais nunca são armazenadas em arquivos YAML. Elas são carregadas pelo arquivo de ambiente do systemd em `/etc/caldera-orchestrator/credentials`:

```
CALDERA_API_KEY=<sua-chave-de-api-red-do-caldera>
GOVC_USERNAME=<usuario-vcenter>
GOVC_PASSWORD=<senha-vcenter>
```

Para uso ad-hoc fora do systemd, carregue o arquivo antes:

```bash
set -a && source /etc/caldera-orchestrator/credentials && set +a
```

---

## Configuração

### `config/settings.yaml` — configurações principais

Preencha os campos marcados com colchetes angulares (`<...>`) de acordo com seu ambiente. Os campos com sintaxe `${VAR}` são carregados do arquivo de credenciais e não devem ser editados.

```yaml
caldera:
  host: localhost
  port: 8888
  api_key: "${CALDERA_API_KEY}"

vmware:
  host: <vcenter-hostname>            # hostname ou IP do vCenter
  username: "${GOVC_USERNAME}"
  password: "${GOVC_PASSWORD}"
  vm_name: <nome-da-vm>               # nome exato da VM conforme exibido no vCenter
  snapshot_name: "<nome-do-snapshot>" # snapshot para reverter após cada operação
  datacenter: <nome-do-datacenter>    # nome do datacenter no vCenter (deixe em branco para o padrão)
  verify_ssl: false
  agent_ready_timeout_minutes: 10     # tempo máximo para aguardar o Sandcat reconectar após o revert

agents:
  - name: <nome-do-agente>
    fqdn: <nome-do-agente>.<dominio>
    role: workstation

schedule:
  mode: interval                      # "interval" | "cron" | "manual"
  interval_hours: 2
  cron_expression: "0 * * * *"        # usado apenas quando mode=cron
  operation_timeout_minutes: 30       # desistir de uma operação travada após este tempo

reporting:
  mode: log_only                      # "webhook" | "email" | "both" | "log_only"

active_adversaries:
  - escu_045   # Discovery — nltest DC
  - escu_046   # Discovery — nltest remote
  # ... todos os 47 em ordem de kill-chain (veja o arquivo completo)
```

### `config/adversaries/escu_NNN.yaml` — um arquivo por adversário

Cada arquivo define um par (detecção ESCU, habilidade CALDERA). São 47 arquivos no total.

```yaml
name: escu_045
display_name: "SPLUNK ES / Domain Controller Discovery with Nltest / Discover domain controller"
description: "T1018 | discovery | Domain Controller Discovery with Nltest"
caldera_adversary_id: "<uuid-do-adversario>"   # deve existir no CALDERA
targets:
  - role: workstation
techniques:
  - id: T1018
    name: "Discover domain controller (nltest)"
    caldera_ability_id: "<uuid-da-habilidade>"
    target_role: workstation
```

O campo `caldera_adversary_id` é obrigatório e deve corresponder a um adversário já existente no CALDERA — o orquestrador não cria adversários automaticamente.

### `detection_ability_map.json` — fonte da verdade

Mapeia cada detecção ESCU para a habilidade CALDERA que a exercita. Foi usado para gerar os 47 perfis de adversários e serve como referência para entender qual técnica corresponde a qual detecção. O orquestrador não lê este arquivo em tempo de execução.

---

## Execução

### Verificar conectividade sem disparar operações

```bash
venv/bin/python main.py --dry-run
```

Valida o `settings.yaml`, testa a conectividade com o CALDERA e a disponibilidade do agente, e verifica a conectividade com o vCenter. Nenhuma operação é iniciada.

### Executar todos os 47 adversários imediatamente

```bash
venv/bin/python main.py --run-now
```

### Executar um único adversário pelo nome

```bash
venv/bin/python main.py --adversary escu_045
```

### Iniciar o agendador persistente (executa indefinidamente, dispara a cada 2 horas)

```bash
venv/bin/python main.py
```

### Todas as opções de linha de comando

```
--config-dir DIR    Caminho para o diretório de configuração (padrão: ./config)
--dry-run           Validar configuração e testar conectividade apenas — sem operações
--run-now           Executar todos os adversários ativos imediatamente
--adversary NAME    Executar um adversário específico pelo nome (implica --run-now)
--log-level LEVEL   DEBUG | INFO | WARNING | ERROR  (padrão: INFO)
```

---

## Executar como serviço systemd

O serviço já está instalado. Comandos padrão:

```bash
# Iniciar / parar / reiniciar
sudo systemctl start caldera-orchestrator
sudo systemctl stop caldera-orchestrator
sudo systemctl restart caldera-orchestrator

# Verificar status
systemctl status caldera-orchestrator

# Acompanhar logs em tempo real
sudo journalctl -u caldera-orchestrator -f
```

---

## Monitorando um ciclo em execução

Carregue as credenciais antes de executar estes comandos ad-hoc (ignore se já estiverem no shell):

```bash
set -a && source /etc/caldera-orchestrator/credentials && set +a
```

**As operações estão executando habilidades?** (verificação mais importante)

```bash
curl -s http://localhost:8888/api/v2/operations \
  -H "KEY: $CALDERA_API_KEY" | python3 -c "
import json, sys
ops = sorted(json.load(sys.stdin), key=lambda o: o.get('start',''), reverse=True)
for o in ops[:10]:
    ran = sum(1 for l in o.get('chain',[]) if l.get('finish') and l.get('status') != -3)
    print(f'ran={ran}  state={o[\"state\"]:<12}  {o[\"name\"][:55]}')
"
```

Uma saída saudável mostra `ran=1` para cada operação concluída. `ran=0` significa que a habilidade foi ignorada — quase sempre porque o agente não está confiável.

**O agente está confiável?**

```bash
curl -s http://localhost:8888/api/v2/agents \
  -H "KEY: $CALDERA_API_KEY" | python3 -c "
import json, sys
for a in json.load(sys.stdin):
    print(f'host={a[\"host\"]}  trusted={a[\"trusted\"]}  last_seen={a[\"last_seen\"]}')
"
```

Se `trusted=False` enquanto o serviço estiver em execução, o orquestrador reconhecerá o agente automaticamente antes da próxima operação. Você também pode fazer isso manualmente:

```bash
PAW=$(curl -s http://localhost:8888/api/v2/agents -H "KEY: $CALDERA_API_KEY" | \
  python3 -c "import json,sys; print([a['paw'] for a in json.load(sys.stdin) if a['host']=='<nome-do-agente>'][0])")

curl -s -X PATCH http://localhost:8888/api/v2/agents/$PAW \
  -H "KEY: $CALDERA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"trusted": true}'
```

---

## Por que o agente volta como não confiável

O CALDERA possui um `untrusted_timer` (definido em 120 segundos). Se um agente ficar em silêncio por mais de `untrusted_timer + sleep_max` segundos (120 + 20 = 140 s), o CALDERA o marca como não confiável. Uma vez marcado, o CALDERA nunca restaura a confiança automaticamente.

O tempo de revert da VM é longo o suficiente para ultrapassar esse limite. O orquestrador contorna isso chamando `PATCH /api/v2/agents/{paw}` com `{"trusted": true}` automaticamente sempre que detecta o agente reconectando como não confiável — tanto em `wait_for_agent_ready` após cada revert quanto em `ensure_agents_trusted` antes de cada operação.

---

## Limpeza de operações do CALDERA

O CALDERA armazena todas as operações permanentemente. Com 47 operações por ciclo a cada 2 horas, o acúmulo é rápido (foram encontradas mais de 7.500 operações quando a limpeza foi implementada pela primeira vez).

O orquestrador resolve isso rastreando os 47 IDs de operação do ciclo anterior em `data/prev_cycle_ops.json`. No início de cada novo ciclo, esses IDs são excluídos do CALDERA antes de qualquer nova operação ser criada. O CALDERA mantém no máximo ~47 operações em estado estável.

Se o serviço for reiniciado, os IDs são recarregados do arquivo JSON e a limpeza ainda ocorre no próximo ciclo.

---

## Adicionando um novo adversário

1. Criar o adversário no CALDERA (adicionar a habilidade) e copiar o UUID gerado
2. Criar `config/adversaries/escu_NNN.yaml` com o `caldera_adversary_id` definido para esse UUID
3. Adicionar `escu_NNN` em `active_adversaries` no `config/settings.yaml`, na posição correta da kill-chain
4. Reiniciar o serviço: `sudo systemctl restart caldera-orchestrator`
5. Verificar com `--dry-run` que o novo adversário carrega sem erros

---

## Estrutura do projeto

```
caldera-splunk-orchestrator/
├── main.py                     # Ponto de entrada da CLI e verificação --dry-run
├── orchestrator.py             # Loop de agendamento, execução por adversário, revert da VM
├── caldera_client.py           # Cliente REST do CALDERA (operações, agentes, confiança)
├── vmware_client.py            # Wrapper do govc — snapshot.revert via vCenter
├── reporter.py                 # Gerador de relatórios (log / webhook)
├── config_loader.py            # Loader de YAML com expansão de variáveis de ambiente
├── models.py                   # Modelos Pydantic para configuração
├── splunk_client.py            # Cliente REST do Splunk (validação de detecções, uso futuro)
├── discover_mappings.py        # Script de configuração: busca habilidades CALDERA + buscas ESCU
├── config/
│   ├── settings.yaml           # Configuração principal (edite este arquivo)
│   └── adversaries/
│       ├── escu_001.yaml       # Um arquivo por adversário (47 no total)
│       └── ...
├── data/
│   └── prev_cycle_ops.json     # IDs de operações persistidos para limpeza no próximo ciclo
├── detection_ability_map.json  # Mapeamento fonte: detecção ESCU ↔ habilidade CALDERA
└── govc                        # Binário govc (VMware CLI)
```

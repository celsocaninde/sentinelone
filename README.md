# 🛡️ GLPI SentinelOne Plugin

> Plugin para GLPI 11 que integra o SentinelOne ao inventario e ao service desk: dashboard operacional, sincronizacao de agentes, ameacas, CVEs e dispositivos rogues, tickets automaticos, alertas por e-mail e relatorio executivo semanal.

🏷️ Versao: `1.0.0` · Autoria: Celso / Claude · Licenca: GPLv3+

---

## ✨ Recursos

### Nucleo

- ⚙️ Tela de configuracao com teste de conexao em tempo real (retorno em ms)
- 🔌 Cliente REST com paginacao por cursor, suporte a `v2.0` / `v2.1` e presets de autenticacao
- 🔄 Sincronizacao de agentes com vinculo automatico a computadores GLPI (serial, UUID, nome, MAC)
- 🚨 Sincronizacao de ameacas com severidade derivada (status + severity + confidenceLevel + analystVerdict)
- 📋 Sincronizacao de atividades e grupos SentinelOne
- 🛡️ Registro do SentinelOne como antivirus nativo no computador GLPI (`glpi_itemantiviruses`)
- 💻 Aba "SentinelOne" dentro de cada computador GLPI
- 🔐 Permissoes dedicadas por perfil (`read`, `sync`, `config`)

### Tickets e alertas

- 🎫 Criacao opcional de tickets para ameacas com regras configuráveis (status e classificacao)
- 🛡️ Anti-duplicidade por `sentinelone_threat_id`
- 🩺 Tickets de saude: agente offline, infectado ou abaixo da versao minima
- 📬 Alertas por e-mail (GLPIMailer) para ameacas criticas e problemas de agente

### Cobertura e diagnostico

- 🔎 Diagnostico de agentes sem vinculo com candidatos GLPI por nome, serial, UUID e MAC
- 💻 Relatorio de computadores GLPI sem agente SentinelOne
- 🚩 Dispositivos rogues: lista e sincronizacao de endpoints detectados mas nao gerenciados

### CVEs (Vulnerability Management)

- 🔬 Dashboard global de CVEs: totais por severidade, top CVEs, aplicacoes mais vulneraveis, endpoints mais expostos
- 🔄 Sincronizacao de CVEs por agente via `/threats/cve` (requer plano Vulnerability Management)
- 🛑 Deteccao automatica quando o endpoint CVE nao esta disponivel no plano

### Automacao avancada

- ⏩ Sincronizacao incremental: usa cursor de timestamp para sincronizar apenas registros novos/atualizados (com overlap de 5 min)
- 📊 Relatorio executivo semanal: resumo HTML enviado por e-mail para lista de destinatarios configurados
- 🛠️ Acoes em massa em ameacas: abrir tickets ou marcar como resolvidas para selecao multipla
- 🧭 Dashboard nativo do GLPI com widgets SentinelOne (KPIs, cobertura, ultimas ameacas)

### Interface

- 🎨 Identidade visual da marca (gradiente roxo → magenta, badges de severidade) via CSS global
- 🖼️ Logo proprio na tela de plugins do GLPI
- 🔗 Deep links opcionais para a console SentinelOne (endpoint e ameaca)
- 🧭 Onboarding guiado quando a integracao ainda nao esta configurada

---

## 📋 Requisitos

- GLPI 11.0.x
- PHP 8.2+
- Acesso HTTPS da instancia GLPI ate a console SentinelOne
- Token de API SentinelOne

---

## 📦 Instalacao

Copie a pasta `sentinelone` para `plugins/` do GLPI:

```
/var/www/html/glpi/plugins/sentinelone
```

Acesse o GLPI como administrador em **Configurar > Plugins**, instale e habilite o plugin `SentinelOne`.

### Docker

```bash
docker compose exec glpi-fpm php /var/www/glpi/bin/console plugin:install sentinelone
docker compose exec glpi-fpm php /var/www/glpi/bin/console plugin:activate sentinelone
```

### Validacao de sintaxe

```bash
docker compose exec glpi-fpm sh -lc \
  "find /var/www/glpi/plugins/sentinelone -name '*.php' -print0 | xargs -0 -n1 php -l"
```

---

## ⚙️ Configuracao

**Configurar > Plugins > SentinelOne**

| Campo | Descricao |
|---|---|
| Integracao ativa | Habilita/desabilita toda a integracao |
| URL da console | Ex.: `https://usea1.sentinelone.net` |
| Endpoint da API | Preset `v2.1` (recomendado), `v2.0` ou Personalizado |
| Autenticacao | Preset `ApiToken` (recomendado) ou Personalizado |
| Token da API | Salvo com `GLPIKey` |
| Entidade padrao | Entidade GLPI onde os objetos sao criados |
| Sincronizacao incremental | Sincroniza apenas registros alterados desde a ultima execucao |
| Criar tickets para ameacas | Ativa a criacao automatica de chamados |
| Rogues: sincronizar | Ativa a sincronizacao de dispositivos rogues |
| CVEs dos endpoints | Ativa a sincronizacao de CVEs (requer plano S1 com Vulnerability Management) |
| Destinatarios do relatorio semanal | Lista de e-mails para o relatorio executivo (um por linha) |

---

## 🔄 Sincronizacao

### Manual (dashboard ou botoes de cada tela)

- Sincronizar agentes
- Sincronizar ameacas
- Sincronizar tudo (agentes + ameacas + atividades + grupos)
- Sincronizar rogues
- Sincronizar CVEs agora

### Automatica (acoes automaticas GLPI)

Criadas desabilitadas na instalacao. Ative em **Configurar > Acoes automaticas**:

| Acao | Frequencia padrao |
|---|---|
| `syncagents` | Configuravel |
| `syncthreats` | Configuravel |
| `syncactivities` | Configuravel |
| `syncgroups` | Configuravel |
| `syncrogues` | Configuravel |
| `synccves` | Configuravel |
| `reportweekly` | 7 dias |

---

## 🎫 Regras de tickets

Na secao **Regras de ticket** da configuracao:

- **Status para abrir ticket**: lista separada por virgula. Ex.: `active, unmitigated`. Vazio = qualquer status.
- **Classificacoes para abrir ticket**: Ex.: `malware, ransomware`. Vazio = qualquer classificacao.
- **Trava de seguranca**: se os dois filtros estiverem vazios, nenhum ticket e criado.
- Campos `Categoria`, `Urgencia`, `Impacto` e `Prioridade` sao compartilhados com os tickets de saude de agente.

---

## 🩺 Saude de agentes

Configure em **Saude de agentes e alertas**:

- Horas offline para abrir ticket
- Versao minima esperada do agente
- Criar ticket para agente infectado
- Registrar como antivirus nativo do computador

---

## 🔬 CVEs (Vulnerability Management)

A aba **CVEs globais** exibe:

- Totais por severidade (CRITICAL / HIGH / MEDIUM / LOW)
- Top CVEs por numero de endpoints afetados
- Aplicacoes mais vulneraveis
- Endpoints com mais CVEs criticos

> Requer plano SentinelOne com Vulnerability Management add-on. Se o endpoint `/threats/cve` nao estiver disponivel, o plugin detecta automaticamente e registra um unico aviso nos logs.

---

## 🚩 Dispositivos rogues

Acesse via **Dashboard > Rogues** ou menu lateral. Lista endpoints detectados pela rede SentinelOne que ainda nao sao gerenciados. Sincronizacao via cron `syncrogues` ou botao manual.

---

## 📊 Acoes em massa em ameacas

Na lista de ameacas (**Plugins > SentinelOne > Ameacas**), selecione multiplas linhas e use as acoes em massa:

- **Abrir tickets para selecionadas**: cria ticket para cada ameaca selecionada sem ticket existente
- **Marcar como resolvidas (local)**: atualiza `status = resolved` localmente sem chamar a API

---

## 📬 Relatorio executivo semanal

Configure **Destinatarios do relatorio semanal** com uma lista de e-mails. A acao automatica `reportweekly` envia um e-mail HTML com:

- Totais de agentes, ameacas, tickets e logs da semana
- Agentes offline, infectados e desatualizados
- Ameacas por severidade e taxa de tickets criados
- CVEs criticos e endpoints mais expostos (quando CVE habilitado)

---

## 🗄️ Tabelas criadas

| Tabela | Conteudo |
|---|---|
| `glpi_plugin_sentinelone_agents` | Agentes SentinelOne |
| `glpi_plugin_sentinelone_threats` | Ameacas |
| `glpi_plugin_sentinelone_logs` | Logs de sincronizacao |
| `glpi_plugin_sentinelone_activities` | Atividades |
| `glpi_plugin_sentinelone_groups` | Grupos S1 |
| `glpi_plugin_sentinelone_rogues` | Dispositivos rogues |
| `glpi_plugin_sentinelone_cves` | CVEs por agente |

Configuracoes ficam no contexto `plugin:sentinelone` do GLPI (`glpi_configs`).

---

## 🔐 Permissoes

| Direito | Descricao |
|---|---|
| `plugin_sentinelone_read` | Visualizar dashboard, agentes, ameacas, logs |
| `plugin_sentinelone_sync` | Executar sincronizacoes e acoes remotas |
| `plugin_sentinelone_config` | Acessar e salvar a configuracao |

Por padrao, `Super-Admin` e `Admin` recebem acesso completo. Revise em **Administracao > Perfis > [perfil] > SentinelOne**.

---

## 🛡️ Boas praticas de seguranca

- Use um token SentinelOne com escopo minimo necessario (somente leitura para inicio)
- O token e salvo cifrado com `GLPIKey`
- Habilite tickets somente apos validar a sincronizacao de ameacas
- Nao exponha o token em logs, prints ou chamados
- Teste em homologacao antes de colocar em producao

---

## 🧩 Observacoes GLPI 11

- CSRF validado pelo listener global antes do arquivo PHP do plugin; nao chamar `Session::checkCSRF()` de novo
- `getTabNameForItem()` deve ser metodo de instancia (nao estatico)
- Assets CSS/JS ficam em `public/css/` e `public/js/`; o hook `add_css` mapeia para `/plugins/sentinelone/...`

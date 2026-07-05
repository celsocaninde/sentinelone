# 🛡️ GLPI SentinelOne Plugin

> Plugin para GLPI 11 que integra o SentinelOne ao inventário e ao service desk: dashboard operacional, sincronização de agentes, ameaças, CVEs e dispositivos rogues, tickets automáticos, alertas por e-mail e **relatório executivo premium** — na tela e no e-mail.

🏷️ Versão: `1.8.0` · Autoria: Celso / Claude · Licença: GPLv3+

---

## ✨ Recursos

### 🏠 Núcleo

- ⚙️ Tela de configuração com teste de conexão em tempo real (retorno em ms)
- 🔌 Cliente REST com paginação por cursor, suporte a `v2.0` / `v2.1` e presets de autenticação
- 🔄 Sincronização de agentes com vínculo automático a computadores GLPI (serial, UUID, nome, MAC)
- 🚨 Sincronização de ameaças com severidade derivada (status + severity + confidenceLevel + analystVerdict)
- 📋 Sincronização de atividades e grupos SentinelOne
- 🛡️ Registro do SentinelOne como antivírus nativo no computador GLPI (`glpi_itemantiviruses`)
- 💻 Aba "SentinelOne" dentro de cada computador GLPI
- 🔐 Permissões dedicadas por perfil (`read`, `sync`, `config`)

### 🎫 Tickets e alertas

- 🎫 Criação opcional de tickets para ameaças com regras configuráveis (status e classificação)
- 🛡️ Anti-duplicidade por `sentinelone_threat_id`
- 🩺 Tickets de saúde: agente offline, infectado ou abaixo da versão mínima
- 📬 Alertas por e-mail (GLPIMailer) para ameaças críticas e problemas de agente

### 🔎 Cobertura e diagnóstico

- 🔎 Diagnóstico de agentes sem vínculo com candidatos GLPI por nome, serial, UUID e MAC
- 💻 Relatório de computadores GLPI sem agente SentinelOne
- 🚩 Dispositivos rogues: lista e sincronização de endpoints detectados mas não gerenciados

### 🔬 CVEs (Vulnerability Management)

- 🔬 Dashboard global de CVEs: totais por severidade, top CVEs, aplicações mais vulneráveis, endpoints mais expostos
- 🔄 Sincronização de CVEs por agente via `/threats/cve` (requer plano Vulnerability Management)
- 🛑 Detecção automática quando o endpoint CVE não está disponível no plano
- 🔥 **EPSS + CISA KEV** (novo em v1.6.0): enriquecimento diário com probabilidade de exploração (FIRST.org) e catálogo de exploração ativa da CISA — badges 🔥 KEV (☠ ransomware), coluna EPSS, Top CVEs priorizado por exploração real e KPI "Exposição KEV" no dashboard
- 🎫 **Auto-ticket KEV** (novo em v1.7.0): opt-in que abre um ticket consolidado por endpoint (urgência máxima) quando um CVE do catálogo KEV é detectado — cada par endpoint+CVE gera ticket uma única vez
- 🩺 **Boletim de Saúde da Frota** (novo em v1.7.0): nota 0–10 por endpoint (conectividade, versão, infecção, quarentena, ameaças abertas, CVEs críticos/KEV), veredito saudável/atenção/crítico, pior nota primeiro e exportação em PDF
- 🔗 **Correlação cross-plugin** (novo em v1.8.0): badges "Tanium ×N" / "Nessus ×N" nas telas de CVE quando o mesmo achado também é reportado por esses plugins — 100% opcional, sem eles instalados nada muda
- 🕵️ **Auditoria de exclusões** (novo em v1.8.0): importa a allowlist da console (paths, hashes, certificados) com quem criou, quando e o escopo; destaca exclusões criadas nos últimos 7 dias — o ponto cego clássico do EDR

### 🤖 Automação avançada

- ⏩ Sincronização incremental: usa cursor de timestamp para sincronizar apenas registros novos/atualizados (com overlap de 5 min)
- 📊 **Relatório executivo semanal por e-mail**: HTML 600 px com índice de proteção, KPIs, trend de ameaças e lista de atenção
- 🌐 **Relatório executivo na tela** (novo em v1.4.0 — veja abaixo)
- 🛠️ Ações em massa em ameaças: abrir tickets ou marcar como resolvidas para seleção múltipla
- 🧭 Dashboard nativo do GLPI com widgets SentinelOne (KPIs, cobertura, últimas ameaças)

### 🎨 Interface

- 🎨 Identidade visual da marca (gradiente roxo → magenta, badges de severidade) via CSS global
- 🖼️ Logo próprio na tela de plugins do GLPI
- 🔗 Deep links opcionais para a console SentinelOne (endpoint e ameaça)
- 🧭 Onboarding guiado quando a integração ainda não está configurada
- 🌐 i18n completa: pt_BR com acentuação correta (406 strings) e en_US (415 strings), `.mo` compilados

---

## 📊 Relatório Executivo (v1.4.0)

Acesse em **Plugins → SentinelOne → Relatório** ou clique no botão **Relatório** no dashboard.

### 🌐 Página web (full-width)

Uma página de alta resolução pensada para apresentações executivas e exportação em PDF:

| Seção | Descrição |
|---|---|
| 🎯 Gauge de proteção | Donut `conic-gradient` com **Índice de Proteção** (0–100 %), código de cor e rótulo semântico |
| 📅 Seletor de período | Botões **7 / 30 / 90 dias** — todos os dados filtram por `first_seen_at` |
| 📦 KPI cards | Agentes totais, ameaças no período, tickets abertos e CVEs críticos |
| 📈 Tendência de ameaças | Barras diárias com destaque em vermelho nos dias críticos |
| ⚠️ Lista de atenção | Endpoints offline, infectados e desatualizados |

**Índice de Proteção** = cobertura % − penalidades (infectado×3, desatualizado×0,5, offline×0,1)

| Faixa | Cor | Rótulo |
|---|---|---|
| ≥ 90 % | 🟢 Verde | Proteção Excelente |
| ≥ 75 % | 🔵 Azul | Proteção Satisfatória |
| ≥ 60 % | 🟡 Âmbar | Proteção em Alerta |
| < 60 % | 🔴 Vermelho | Proteção Crítica |

### 📬 E-mail executivo semanal

Cron `reportweekly` envia HTML de 600 px (compatível com clientes de e-mail) com os mesmos KPIs, barra de progresso de proteção e lista de atenção.

Configure os destinatários em **Configurar → Plugins → SentinelOne → Relatório**.

---

## 🖥️ Dashboard (v1.4.0)

Melhorias visuais e de usabilidade no dashboard operacional:

- 🏷️ **Status traduzidos** para português: `marked_as_benign` → Falso Positivo, `mitigated` → Mitigada, `active` → Ativa, etc.
- 📊 **Barras de classificação maiores** (22 px com gradiente roxo por rank e contagem embutida)
- 🔤 Colunas renomeadas para linguagem de negócio: "Avaliação", "Status S1", "Nome da Ameaça", "Ticket GLPI"
- 🔗 Botão **Relatório** na toolbar para acesso rápido ao relatório executivo

---

## 📋 Requisitos

- GLPI 11.0.x
- PHP 8.2+
- Acesso HTTPS da instância GLPI até a console SentinelOne
- Token de API SentinelOne

---

## 📦 Instalação

Copie a pasta `sentinelone` para `plugins/` do GLPI:

```
/var/www/html/glpi/plugins/sentinelone
```

Acesse o GLPI como administrador em **Configurar > Plugins**, instale e habilite o plugin `SentinelOne`.

### 🐳 Docker

```bash
docker compose exec glpi-fpm php /var/www/glpi/bin/console plugin:install sentinelone
docker compose exec glpi-fpm php /var/www/glpi/bin/console plugin:activate sentinelone
```

### ✅ Validação de sintaxe

```bash
docker compose exec glpi-fpm sh -lc \
  "find /var/www/glpi/plugins/sentinelone -name '*.php' -print0 | xargs -0 -n1 php -l"
```

---

## ⚙️ Configuração

**Configurar > Plugins > SentinelOne**

| Campo | Descrição |
|---|---|
| Integração ativa | Habilita/desabilita toda a integração |
| URL da console | Ex.: `https://usea1.sentinelone.net` |
| Endpoint da API | Preset `v2.1` (recomendado), `v2.0` ou Personalizado |
| Autenticação | Preset `ApiToken` (recomendado) ou Personalizado |
| Token da API | Salvo com `GLPIKey` |
| Entidade padrão | Entidade GLPI onde os objetos são criados |
| Sincronização incremental | Sincroniza apenas registros alterados desde a última execução |
| Criar tickets para ameaças | Ativa a criação automática de chamados |
| Rogues: sincronizar | Ativa a sincronização de dispositivos rogues |
| CVEs dos endpoints | Ativa a sincronização de CVEs (requer plano S1 com Vulnerability Management) |
| Destinatários do relatório semanal | Lista de e-mails para o relatório executivo (um por linha) |

---

## 🔄 Sincronização

### Manual (dashboard ou botões de cada tela)

- Sincronizar agentes
- Sincronizar ameaças
- Sincronizar tudo (agentes + ameaças + atividades + grupos)
- Sincronizar rogues
- Sincronizar CVEs agora

### Automática (ações automáticas GLPI)

Criadas desabilitadas na instalação. Ative em **Configurar > Ações automáticas**:

| Ação | Frequência padrão |
|---|---|
| `syncagents` | Configurável |
| `syncthreats` | Configurável |
| `syncactivities` | Configurável |
| `syncgroups` | Configurável |
| `syncsoftware` | 24 h |
| `syncrogues` | Configurável |
| `synccves` | Configurável |
| `enrichcves` | 24 h |
| `syncexclusions` | 24 h |
| `alertoffline` | 4 h |
| `reportweekly` | 7 dias |
| `purgelogs` | 24 h |
| `retryfailedtickets` | 1 h |

---

## 🎫 Regras de tickets

Na seção **Regras de ticket** da configuração:

- **Status para abrir ticket**: lista separada por vírgula. Ex.: `active, unmitigated`. Vazio = qualquer status.
- **Classificações para abrir ticket**: Ex.: `malware, ransomware`. Vazio = qualquer classificação.
- **Trava de segurança**: se os dois filtros estiverem vazios, nenhum ticket é criado.
- Campos `Categoria`, `Urgência`, `Impacto` e `Prioridade` são compartilhados com os tickets de saúde de agente.

---

## 🩺 Saúde de agentes

Configure em **Saúde de agentes e alertas**:

- Horas offline para abrir ticket
- Versão mínima esperada do agente
- Criar ticket para agente infectado
- Registrar como antivírus nativo do computador

---

## 🔬 CVEs (Vulnerability Management)

A aba **CVEs globais** exibe:

- Totais por severidade (CRITICAL / HIGH / MEDIUM / LOW)
- Top CVEs priorizado por exploração real: KEV primeiro, depois severidade e EPSS
- Aplicações mais vulneráveis
- Endpoints com mais CVEs críticos
- KPI **Exposição KEV**: CVEs da frota presentes no catálogo CISA de exploração ativa

### 🩺 Boletim de Saúde da Frota (v1.7.0)

Página **Boletim** (botão no dashboard): cada endpoint recebe nota 0–10 calculada só com dados locais do plugin — infecção ativa (-4), quarentena (-2), silêncio/offline (até -3), versão desatualizada (-1), ameaças não mitigadas (até -2), CVEs críticos/altos (até -2) e CVEs KEV (-2). Cards de resumo da frota, tabela do pior para o melhor com fatores de risco por máquina e **Exportar PDF** com letterhead.

### 🔥 Threat intel EPSS / CISA KEV (v1.6.0)

A cron `enrichcves` (diária) baixa dois feeds públicos e cruza com os CVEs da frota:

- **EPSS** (FIRST.org): probabilidade de exploração nos próximos 30 dias — vira coluna nas tabelas de CVE
- **CISA KEV**: catálogo de vulnerabilidades com exploração ativa confirmada — vira badge 🔥 KEV (com ☠ quando há uso em campanhas de ransomware)

Isso muda a priorização de "CVSS alto" para "CVSS alto **e sendo explorado agora**". Sem configuração: basta ativar a cron (requer saída HTTPS para `epss.cyentia.com` e `cisa.gov`).

> Requer plano SentinelOne com Vulnerability Management add-on. Se o endpoint `/threats/cve` não estiver disponível, o plugin detecta automaticamente e registra um único aviso nos logs.

---

## 🚩 Dispositivos rogues

Acesse via **Dashboard > Rogues** ou menu lateral. Lista endpoints detectados pela rede SentinelOne que ainda não são gerenciados. Sincronização via cron `syncrogues` ou botão manual.

---

## 📊 Ações em massa em ameaças

Na lista de ameaças (**Plugins > SentinelOne > Ameaças**), selecione múltiplas linhas e use as ações em massa:

- **Abrir tickets para selecionadas**: cria ticket para cada ameaça selecionada sem ticket existente
- **Marcar como resolvidas (local)**: atualiza `status = resolved` localmente sem chamar a API

---

## 🗄️ Tabelas criadas

| Tabela | Conteúdo |
|---|---|
| `glpi_plugin_sentinelone_agents` | Agentes SentinelOne |
| `glpi_plugin_sentinelone_threats` | Ameaças |
| `glpi_plugin_sentinelone_logs` | Logs de sincronização |
| `glpi_plugin_sentinelone_activities` | Atividades |
| `glpi_plugin_sentinelone_groups` | Grupos S1 |
| `glpi_plugin_sentinelone_rogues` | Dispositivos rogues |
| `glpi_plugin_sentinelone_cves` | CVEs por agente |

Configurações ficam no contexto `plugin:sentinelone` do GLPI (`glpi_configs`).

---

## 🔐 Permissões

| Direito | Descrição |
|---|---|
| `plugin_sentinelone_read` | Visualizar dashboard, agentes, ameaças, logs |
| `plugin_sentinelone_sync` | Executar sincronizações e ações remotas |
| `plugin_sentinelone_config` | Acessar e salvar a configuração |

Por padrão, `Super-Admin` e `Admin` recebem acesso completo. Revise em **Administração > Perfis > [perfil] > SentinelOne**.

---

## 🛡️ Boas práticas de segurança

- Use um token SentinelOne com escopo mínimo necessário (somente leitura para início)
- O token é salvo cifrado com `GLPIKey`
- Habilite tickets somente após validar a sincronização de ameaças
- Não exponha o token em logs, prints ou chamados
- Teste em homologação antes de colocar em produção

---

## 🧩 Observações GLPI 11

- CSRF validado pelo listener global antes do arquivo PHP do plugin; não chamar `Session::checkCSRF()` de novo
- `getTabNameForItem()` deve ser método de instância (não estático)
- Assets CSS/JS ficam em `public/css/` e `public/js/`; o hook `add_css` mapeia para `/plugins/sentinelone/...`

---

## 📅 Changelog

### v1.4.0
- 🌐 Novo relatório executivo web full-width (`front/report.php`) com gauge conic-gradient, seletor de período 7/30/90 dias, KPIs, trend chart e lista de atenção
- 📬 E-mail executivo reformulado com Índice de Proteção e penalidades por risco
- 🏷️ Dashboard: status S1 traduzidos para português, barras de classificação 22 px com gradiente, botão Relatório
- ⚙️ Cron `purgelogs` para retenção configurável de logs

### v1.3.0
- 🔁 Retry com exponential backoff no cliente REST (429/5xx)
- 🔒 `protectSecret` seguro: falha na criptografia emite warning, não salva em plaintext
- 📅 Filtro `sync_date_from` e `agent_inactive_days` na sincronização
- 🗑️ Retenção de logs configurável (`log_retention_days`)

### v1.0.0
- 🚀 Release inicial com sincronização incremental, CVEs, rogues, tickets, alertas e relatório semanal

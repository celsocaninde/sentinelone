# 🛡️ GLPI SentinelOne Plugin

> 🛡️ **PT-BR:** Plugin para GLPI 11 que integra dados do SentinelOne ao inventario e ao service desk, com dashboard operacional, sincronizacao de agentes e ameacas, tickets automaticos, alertas por e-mail e relatorios de cobertura de endpoints.
>
> 🛡️ **English:** A GLPI 11 plugin that integrates SentinelOne endpoint security data into inventory and service desk workflows, with an operational dashboard, agent and threat synchronization, automatic tickets, email alerts, and endpoint coverage reports.

🚀 Plugin para GLPI 11 que integra dados do SentinelOne em modo inicialmente somente leitura, com interface alinhada a identidade visual da marca (roxo -> magenta).

🏷️ Versao atual: `0.4.6`. Autoria: Celso / Codex / Claude.

📝 Descricoes prontas para GitHub, README, releases e divulgacao estao em [`DESCRIPTIONS.md`](DESCRIPTIONS.md).

## 🚦 Estado atual

Este plugin ja possui um MVP instalavel no GLPI 11:

- 📦 Instalacao e ativacao pelo gerenciador de plugins do GLPI.
- ⚙️ Configuracao da API via tela propria.
- 🧪 Teste de conexao com SentinelOne exibindo tempo de resposta em ms.
- 🔄 Sincronizacao manual e automatica de agentes e ameacas.
- 🧭 Dashboard operacional com status, contadores, ameacas recentes, endpoints em atencao e logs.
- 💻 Aba "SentinelOne" em computadores do GLPI.
- 🎫 Criacao opcional de tickets para ameacas.

⚠️ As acoes remotas, permissoes dedicadas por perfil e migracoes versionadas ainda ficam fora deste MVP.

## ✨ Recursos implementados

- ⚙️ Tela de configuracao da API SentinelOne.
- 🧪 Teste de conexao com a API sem recarregar a tela, com retorno visual e tempo em ms.
- 🔌 Cliente REST com suporte a paginacao por cursor.
- 🔄 Sincronizacao de agentes.
- 🔗 Relacionamento automatico com computadores GLPI por serial, UUID, hostname e MAC.
- 💻 Aba "SentinelOne" dentro do computador GLPI.
- 🚨 Sincronizacao de ameacas.
- 🎫 Criacao opcional de tickets para ameacas.
- 🛡️ Protecao contra tickets duplicados usando o ID da ameaca.
- 🧭 Dashboard com contadores, cobertura de vinculo GLPI, ultimos logs, ultimas sincronizacoes, ameacas recentes e endpoints em atencao.
- 🔎 Diagnostico de agentes sem vinculo com checagens por nome, serial, UUID e MAC.
- ▶️ Sincronizacao manual pela interface.
- ⏱️ Acoes automaticas GLPI para sincronizacao periodica.
- 🔐 Permissoes dedicadas por perfil GLPI.
- 🎨 Identidade visual da SentinelOne (gradiente roxo -> magenta, logo e badges de severidade) carregada via CSS global do plugin.
- 🧩 Endpoint da API e esquema de autenticacao como escolhas pre-configuradas (presets), com opcao `Personalizado` para tenants diferentes.
- 🧭 Onboarding guiado no dashboard quando a integracao ainda nao esta configurada.
- 📊 Barras de cobertura GLPI e de agentes online no dashboard.
- 🚦 Severidade derivada das ameacas (status + severity + confidenceLevel + analystVerdict) com badge colorido no dashboard, na aba do computador e como colunas pesquisaveis.
- 🔗 Deep links opcionais para a console SentinelOne (ameaca e endpoint) com tokens `{threatId}` e `{agentId}`.
- 🖼️ Logo proprio do plugin (logo.png/logo.svg) exibido na tela de plugins do GLPI.
- 🔎 Relatorio de endpoints sem agente: computadores ativos do GLPI que nao possuem agente SentinelOne (com contador no dashboard).
- 🛡️ Registro do SentinelOne como antivirus nativo do computador (aba Antivirus / `glpi_itemantiviruses`) com versao, ativo e atualizado.
- 🩺 Tickets de saude do agente: offline ha X horas, infectado e versao abaixo da minima configurada (com vinculo ao computador e sem duplicidade).
- 📬 Alertas por e-mail (via GLPIMailer do GLPI) para ameacas criticas e problemas de agente, para uma lista de destinatarios.

## 📋 Requisitos

- 🧱 GLPI 11.0.x.
- 🐘 PHP 8.2 ou superior.
- 🌐 Acesso HTTPS da instancia GLPI ate a console SentinelOne.
- 🔑 Token de API SentinelOne.

## 📦 Instalacao

Copie a pasta `sentinelone` para a pasta `plugins` do GLPI:

```text
/var/www/html/glpi/plugins/sentinelone
```

Depois acesse o GLPI como administrador:

```text
Configurar > Plugins
```

Instale e habilite o plugin `SentinelOne`.

## ✅ Validacao antes de instalar

Em uma maquina com PHP disponivel, valide a sintaxe dos arquivos:

```text
php -l setup.php
php -l hook.php
php -l src/Config.php
php -l src/ApiClient.php
php -l src/Sync.php
php -l src/Agent.php
php -l src/Threat.php
php -l src/Log.php
php -l src/TicketManager.php
php -l front/config.form.php
php -l front/dashboard.php
php -l front/sync.form.php
php -l front/agent.php
php -l front/threat.php
```

No ambiente Docker/Nginx deste repositorio, use o runtime do container:

```text
docker compose exec glpi-fpm sh -lc "find /var/www/glpi/plugins/sentinelone -name '*.php' -print0 | xargs -0 -n1 php -l"
docker compose exec glpi-fpm php /var/www/glpi/bin/console plugin:list
docker compose exec glpi-fpm php /var/www/glpi/bin/console plugin:install sentinelone
docker compose exec glpi-fpm php /var/www/glpi/bin/console plugin:activate sentinelone
```

Para subir o GLPI com Nginx:

```text
docker compose up -d
```

Depois acesse:

```text
https://localhost
```

## ⚙️ Configuracao

Acesse:

```text
Configurar > Plugins > SentinelOne
```

Configure:

- ✅ Integracao ativa: `Sim`.
- 🌐 URL da console SentinelOne.
- 🔌 Endpoint da API: lista pre-configurada (`API v2.1` recomendado, `API v2.0` legado, ou `Personalizado`).
- 🔐 Autenticacao: lista pre-configurada (`ApiToken` recomendado, `Bearer`, `Token`, ou `Personalizado`).
- 🔑 Token da API.
- 🚨 Deep link de ameaca (opcional): caminho na console usando `{threatId}`, ex.: `/incidents/threats/{threatId}/overview`.
- 💻 Deep link de endpoint (opcional): caminho na console usando `{agentId}`, ex.: `/inventory/devices/{agentId}`.
- 📄 Limite de itens por pagina.
- 📚 Maximo de paginas por sincronizacao.
- 🏢 Entidade padrao GLPI, selecionada pela lista de entidades permitidas ao usuario.
- 🔎 Filtros opcionais de agentes e ameacas em formato query string da API SentinelOne.
- 🎫 Criacao de tickets para ameacas.
- 🛡️ Registrar como antivirus do computador (grava SentinelOne na aba Antivirus de cada computador vinculado).
- 🩺 Saude de agentes: criar tickets de saude, horas offline para abrir ticket, versao minima do agente.
- 📬 Alertas: lista de e-mails, enviar e-mail em ameaca critica, enviar e-mail em problema de agente.

Use `Salvar` para gravar a configuracao. Use `Testar conexao` para validar os dados informados sem salvar alteracoes; quando a API responder, a tela mostra `Conexao OK` em verde com o tempo da chamada em ms.

## 🔌 API SentinelOne

Valide os endpoints, permissoes e formato de autenticacao dentro da propria console SentinelOne:

```text
Help > API Hub
```

O plugin usa por padrao:

```text
GET /web/api/v2.1/agents
GET /web/api/v2.1/threats
```

Se o seu tenant usar outra versao ou path, selecione outra opcao no campo `Endpoint da API` ou escolha `Personalizado...` para informar o caminho manualmente.

Filtros adicionais podem ser informados na configuracao usando o mesmo formato de parametros da API, por exemplo:

```text
isActive=true
mitigationStatuses=unmitigated
```

Os campos `limit` e `cursor` sao controlados pelo plugin durante a paginacao.

## 🔄 Sincronizacao manual

Acesse o menu:

```text
Plugins > SentinelOne
```

Use:

- 💻 `Sincronizar agentes`.
- 🚨 `Sincronizar ameacas`.
- 🚀 `Sincronizar tudo`.

## ⏱️ Sincronizacao automatica

Na instalacao, o plugin registra duas acoes automaticas:

```text
syncagents
syncthreats
```

🛡️ Por seguranca, elas sao criadas desabilitadas.

Ative em:

```text
Configurar > Acoes automaticas
```

🧭 Recomenda-se executar o cron do GLPI via CLI:

```text
* * * * * php /caminho/do/glpi/front/cron.php
```

## 🔐 Permissoes

O plugin cria direitos dedicados por perfil:

```text
plugin_sentinelone_read
plugin_sentinelone_sync
plugin_sentinelone_config
```

Depois de instalar ou atualizar, revise em:

```text
Administracao > Perfis > [perfil] > SentinelOne
```

✅ Por padrao, `Super-Admin` e `Admin` recebem acesso completo. Os demais perfis ficam sem acesso ate serem liberados manualmente.

## 🎫 Tickets de ameaca e regras

A secao `Regras de ticket` controla **quando** o plugin abre um chamado automatico para uma **ameaca** e **com quais valores**.

### 🧩 Pre-requisito

No painel `Automacao`, a opcao `Criar tickets para ameacas` precisa estar em `Sim`. E o interruptor geral; sem ele, nada e criado.

### 🧾 Campos

- 🚦 `Criar tickets somente para status`: lista de status (separados por virgula) que autorizam abrir ticket. Ex.: `active, unmitigated, not_mitigated`. Vazio = qualquer status.
- 🚨 `Criar tickets somente para classificacoes`: mesma ideia para a classificacao. Ex.: `malware, ransomware, trojan`. Vazio = qualquer classificacao.
- 🗂️ `Categoria GLPI do ticket`: categoria ITIL onde o chamado e aberto.
- 📌 `Urgencia` / `Impacto` / `Prioridade`: valores com que o ticket nasce.

### 🧠 Logica de decisao

Para cada ameaca sincronizada (`Sync::shouldCreateTicket`):

1. 🛡️ Trava de seguranca: se os **dois** filtros (status e classificacao) estiverem vazios, **nao cria nada** (dashboard mostra `Aguardando regras`).
2. ✅ Se a ameaca ja esta resolvida/mitigada (`mitigated`, `resolved`, `benign`, `false_positive`, `marked_as_benign`), **nao cria**.
3. 🎯 Caso contrario, o status precisa casar com o filtro de status **E** a classificacao precisa casar com o filtro de classificacao.

Regras da combinacao:

- 🔀 Dentro de um campo, a lista e **OU** (basta casar com um dos valores).
- 🔗 Entre os dois campos, e **E** (os dois precisam passar).
- ✅ Campo vazio = "passa sempre".

### 🧮 Exemplos

```text
status filter        | classification filter   | resultado
---------------------|-------------------------|----------------------------------------
(vazio)              | (vazio)                 | nunca abre (trava de seguranca)
active               | (vazio)                 | abre para qualquer ameaca status=active
(vazio)              | ransomware, malware     | abre para essas classificacoes
active, unmitigated  | ransomware              | status in {active,unmitigated} E class=ransomware
```

### 🛡️ Anti-duplicidade

Cada ameaca e unica pelo `sentinelone_threat_id`. Quando o ticket e criado, o `tickets_id` fica gravado na ameaca e e preservado nas proximas sincronizacoes, evitando um segundo ticket para a mesma ameaca.

### 🩺 Relacao com os tickets de saude do agente

Os tickets de saude do agente (offline/infectado/desatualizado) sao um mecanismo separado (painel `Saude de agentes e alertas`), mas reaproveitam a `Categoria`, `Urgencia`, `Impacto` e `Prioridade` definidas aqui.

## 🩺 Saude de agentes, antivirus e alertas

- 🛡️ Quando `Registrar como antivirus do computador` esta ativo, cada agente vinculado grava/atualiza um registro em `glpi_itemantiviruses` (nome `SentinelOne`, versao do agente, ativo conforme online, atualizado conforme a versao minima). Aparece na aba Antivirus do computador.
- 🎫 `Criar tickets de saude do agente` abre um unico ticket por agente quando ele esta offline ha mais que as horas configuradas, esta infectado ou abaixo da versao minima. O ticket e vinculado ao computador e o `tickets_id` e gravado no agente para evitar duplicidade.
- 📬 Os alertas por e-mail usam o `GLPIMailer` (mesma configuracao de e-mail/SMTP do GLPI). E necessario ter o `admin_email` configurado em `Configurar > Notificacoes`. O e-mail de ameaca critica e disparado quando uma nova ameaca critica e sincronizada; o e-mail de problema de agente e disparado junto com a abertura do ticket de saude.

## 🗄️ Tabelas criadas

```text
glpi_plugin_sentinelone_configs
glpi_plugin_sentinelone_agents
glpi_plugin_sentinelone_threats
glpi_plugin_sentinelone_logs
```

⚙️ As configuracoes ativas do plugin sao salvas pelo mecanismo de configuracao do GLPI no contexto `plugin:sentinelone`. A tabela `glpi_plugin_sentinelone_configs` existe no schema do MVP para compatibilidade com evolucoes futuras.

## 🧭 Arquivos principais

- ⚙️ `setup.php`: metadados, hooks e registro de classes.
- 🪝 `hook.php`: instalacao, uninstall e cron tasks.
- ⚙️ `src/Config.php`: tela e persistencia da configuracao.
- 🔌 `src/ApiClient.php`: cliente REST SentinelOne.
- 🔐 `src/Profile.php`: permissoes dedicadas por perfil GLPI.
- 🔄 `src/Sync.php`: sincronizacao e normalizacao de payloads.
- 💻 `src/Agent.php`: listagem e aba no computador GLPI.
- 🚨 `src/Threat.php`: listagem e exibicao de ameacas.
- 🎫 `src/TicketManager.php`: criacao de tickets de ameacas.
- 🧾 `src/Log.php`: logs de sincronizacao.
- 🧭 `front/dashboard.php`: dashboard e sincronizacao manual.
- 🔎 `front/unlinked.php`: diagnostico de agentes sem vinculo GLPI.
- ⚙️ `front/config.form.php`: formulario de configuracao.
- 🔄 `front/sync.form.php`: acao manual de sincronizacao.
- 🔐 `front/profile.rights.php`: salvamento de permissoes por perfil.
- 💻 `front/unprotected.php`: relatorio de computadores GLPI sem agente SentinelOne.
- 📬 `src/Notifier.php`: alertas por e-mail (GLPIMailer) de ameacas e agentes.
- 🎨 `public/css/sentinelone.css`: tema da marca (roxo -> magenta) carregado globalmente via hook add_css.
- 🖼️ `logo.png`: logo exibido na tela de plugins do GLPI (256x256).
- 🧩 `logo.svg`: versao vetorial do logo da marca.

## 🧠 Como funciona cada modulo

Explicacao em linguagem simples do papel de cada parte do plugin.

### ⚙️ setup.php

Declara o plugin para o GLPI: nome, versao, autor, requisitos (GLPI 11, PHP 8.2). Registra os hooks (CSRF, pagina de configuracao, CSS global da marca) e as classes que ganham aba (Config em Config, Agent em Computer, Profile em Profile). E o ponto de entrada lido a cada carregamento.

### 🪝 hook.php

Roda na instalacao/atualizacao e na desinstalacao. Cria as tabelas do plugin, registra as acoes automaticas (cron) `syncagents` e `syncthreats` (desabilitadas por seguranca), aplica migracoes de colunas novas em instalacoes existentes e, no uninstall, remove tabelas, configuracoes, crons e permissoes.

### ⚙️ src/Config.php

Tela e persistencia da configuracao. Guarda console, token (criptografado com `GLPIKey`), presets de endpoint/autenticacao, parametros de sincronizacao, regras de ticket, saude de agentes e alertas. Tambem monta os deep links da console e expoe a lista de e-mails de alerta. As configuracoes ficam no contexto `plugin:sentinelone` do GLPI.

### 🔌 src/ApiClient.php

Cliente HTTP REST da API SentinelOne. Monta a URL (base + base path), envia o header de autenticacao, usa cURL (com fallback para stream wrapper), trata erros HTTP (401/403/429/500) e percorre a paginacao por cursor ate o limite de paginas configurado.

### 🔄 src/Sync.php

Orquestra a sincronizacao. Busca agentes e ameacas, normaliza os campos vindos da API (nomes variam por tenant), faz upsert nas tabelas locais, vincula o agente ao computador GLPI (serial, UUID, nome, nome curto, MAC), avalia a saude do agente (offline/infectado/desatualizado), grava o antivirus nativo, decide a criacao de tickets de ameaca e dispara os alertas. Tambem produz as estatisticas do dashboard.

### 💻 src/Agent.php

Modelo do agente SentinelOne. Renderiza a aba `SentinelOne` dentro do computador, define as colunas de busca, faz o diagnostico de agentes sem vinculo (candidatos por nome/serial/UUID/MAC) e o relatorio de computadores GLPI sem agente (endpoints desprotegidos).

### 🚨 src/Threat.php

Modelo da ameaca. Define as colunas de busca, deriva a severidade legivel (Critica/Suspeita/Ativa/Resolvida) a partir de status + severity + confidenceLevel + analystVerdict e lista as ameacas recentes de um agente com badge de severidade e deep link.

### 🎫 src/TicketManager.php

Monta e cria os tickets no GLPI: titulo, conteudo, entidade, urgencia/impacto/prioridade e categoria. Cria tanto o ticket de ameaca quanto o de saude do agente, e vincula o computador ao chamado (`Item_Ticket`).

### 📬 src/Notifier.php

Envia os alertas por e-mail usando o `GLPIMailer` (mesma config de e-mail/SMTP do GLPI). Trata ameaca critica e problema de agente, sempre com try/catch para nunca quebrar a sincronizacao, e registra o resultado nos logs.

### 🔐 src/Profile.php

Permissoes dedicadas por perfil (`plugin_sentinelone_read`, `_sync`, `_config`). Cria os direitos na instalacao, sincroniza os direitos do perfil atual na sessao e renderiza a aba de permissoes dentro do perfil GLPI.

### 🧾 src/Log.php

Registro das execucoes (sincronizacoes e alertas): acao, status, mensagem e contagem de itens. Alimenta o painel de logs do dashboard.

### 🖥️ front/

- 🧭 `dashboard.php`: painel operacional (status, cobertura, contadores, ameacas recentes, endpoints em atencao, logs, sincronizacao manual).
- 🔎 `unlinked.php`: diagnostico de agentes SentinelOne sem computador associado.
- 💻 `unprotected.php`: relatorio de computadores GLPI sem agente SentinelOne.
- 📋 `agent.php` / `threat.php`: listas de busca padrao do GLPI.
- ⚙️ `config.form.php`: salva a configuracao e responde ao teste de conexao (inclusive via AJAX).
- 🔄 `sync.form.php`: executa a sincronizacao manual (agentes/ameacas/tudo).
- 🔐 `profile.rights.php`: salva as permissoes por perfil.

### 🎨 public/css/sentinelone.css e logo

Tema da marca (gradiente roxo -> magenta, badges de severidade, componentes) carregado em todas as paginas via hook `add_css`. `logo.png`/`logo.svg` aparecem na tela de plugins do GLPI.

## 🔎 Diagnostico de vinculo GLPI

Quando agentes SentinelOne aparecem como `Sem vinculo`, acesse:

```text
Plugins > SentinelOne > Diagnostico
```

A tela mostra uma amostra dos agentes sem computador associado, os identificadores recebidos do SentinelOne e possiveis candidatos no GLPI por:

- 🖥️ Nome completo.
- 🧩 Nome curto.
- 🏷️ Serial.
- 🆔 UUID.
- 🌐 MAC.

Se muitos agentes estiverem sem vinculo e o GLPI tiver poucos computadores ativos, primeiro valide o inventario GLPI antes de criar regras customizadas de casamento.

## 🛡️ Observacoes de seguranca

- 🔑 Comece usando um token SentinelOne somente leitura.
- 🔐 O token e salvo usando `GLPIKey` quando disponivel no GLPI.
- 🎫 Habilite tickets apenas depois de validar a sincronizacao de ameacas.
- 🧾 Nao habilite acoes remotas sem criar permissoes especificas e auditoria.
- 🙈 Nao exponha o token em logs, prints ou chamados.
- 🧪 Teste primeiro em homologacao.

## 🧩 Observacoes para GLPI 11

- 🧱 `getTabNameForItem()` deve ser metodo de instancia, seguindo `CommonGLPI`.
- 🧭 Evite criar helpers com nome equivalente a metodos do core, como `getFormURL()`.
- 🛡️ Formularios POST devem enviar token CSRF; no GLPI 11 a validacao e feita pelo listener global antes do arquivo legacy do plugin.
- 🔒 Saidas HTML dinamicas devem ser escapadas.

## 🚀 Proximos passos tecnicos

- 🧪 Validar campos reais retornados pelo seu tenant SentinelOne.
- 🎯 Ajustar filtros de ameacas conforme a operacao.
- 🔐 Criar permissoes dedicadas do plugin.
- 🔗 Adicionar links profundos para endpoint/ameaca na console SentinelOne quando o padrao de URL do tenant estiver validado.
- 🧬 Criar testes unitarios para normalizacao de payloads.
- 🗃️ Implementar migracoes versionadas para upgrades futuros.

<?php

namespace GlpiPlugin\Sentinelone;

class Config extends \CommonGLPI
{
   public const CONTEXT = 'plugin:sentinelone';
   private const SECRET_PREFIX = 'glpikey:';
   private const CONNECTION_FLASH_KEY = 'plugin_sentinelone_connection_test';

   public static $rightname = 'plugin_sentinelone_config';

   public static function getTypeName($nb = 0): string
   {
      return 'SentinelOne';
   }

   public function getTabNameForItem(\CommonGLPI $item, $withtemplate = 0): string
   {
      if ($item instanceof \Config && Profile::hasConfigReadRight()) {
         return 'SentinelOne';
      }

      return '';
   }

   public static function displayTabContentForItem(\CommonGLPI $item, $tabnum = 1, $withtemplate = 0): bool
   {
      self::showForm();
      return true;
   }

   public static function defaults(): array
   {
      return [
         'enabled'              => '0',
         'base_url'             => '',
         'base_path'            => '/web/api/v2.1',
         'auth_scheme'          => 'ApiToken',
         'api_token'            => '',
         'console_threat_path'  => '',
         'console_endpoint_path' => '',
         'timeout'              => '30',
         'max_pages'            => '10',
         'sync_limit'           => '100',
         'agent_filter_query'   => '',
         'threat_filter_query'  => '',
         'entity_id'            => '0',
         'create_tickets'       => '0',
         'auto_close_tickets'   => '1',
         'ticket_threat_details' => '1',
         'sync_threat_notes'    => '0',
         'ticket_status_filter' => '',
         'ticket_classification_filter' => '',
         'ticket_category_id'   => '0',
         'ticket_requester_id'  => '0',
         'ticket_auto_priority' => '1',
         'ticket_urgency'       => '4',
         'ticket_impact'        => '4',
         'ticket_priority'      => '4',
         'write_antivirus'      => '1',
         'create_agent_tickets' => '0',
         'ticket_offline_hours' => '24',
         'min_agent_version'    => '',
         'alert_emails'         => '',
         'alert_on_critical_threat' => '0',
         'alert_on_agent_issue' => '0',
         'sync_activities'      => '0',
         'site_entity_map'      => '',
         'ticket_group_id'      => '0',
         'sync_software'        => '0',
         'sync_software_limit'  => '30',
         'sync_cves'            => '0',
         'sync_cves_limit'      => '30',
         'sync_rogues'          => '0',
         'sync_incremental'     => '0',
         'report_recipients'    => '',
         'sync_date_from'       => '',
         'agent_inactive_days'  => '0',
         'log_retention_days'   => '90',
         'token_expires_at'     => '',
      ];
   }

   /**
    * Endpoints da API SentinelOne pre-configurados (escolhas automaticas).
    */
   public static function basePathPresets(): array
   {
      return [
         '/web/api/v2.1' => __('API v2.1 - recomendado', 'sentinelone'),
         '/web/api/v2.0' => __('API v2.0 - legado', 'sentinelone'),
      ];
   }

   /**
    * Esquemas de autenticacao suportados pela API SentinelOne.
    */
   public static function authSchemePresets(): array
   {
      return [
         'ApiToken' => __('ApiToken - recomendado', 'sentinelone'),
         'Bearer'   => 'Bearer',
         'Token'    => 'Token',
      ];
   }

   private static function resolvePreset(array $input, string $name, array $presetKeys, string $default): string
   {
      $preset = trim((string)($input[$name . '_preset'] ?? ''));

      if ($preset === '__custom__') {
         $custom = trim((string)($input[$name . '_custom'] ?? ''));
         return $custom !== '' ? $custom : $default;
      }

      if ($preset !== '' && in_array($preset, $presetKeys, true)) {
         return $preset;
      }

      $direct = trim((string)($input[$name] ?? ''));

      return $direct !== '' ? $direct : $default;
   }

   /**
    * Monta o link profundo para a ameaca na console SentinelOne.
    * Retorna '' quando o padrao nao foi configurado.
    */
   public static function consoleThreatUrl(array $config, string $threatId): string
   {
      return self::buildConsoleUrl(
         (string)($config['console_threat_path'] ?? ''),
         (string)($config['base_url'] ?? ''),
         ['{threatId}' => $threatId]
      );
   }

   /**
    * Monta o link profundo para o endpoint/agente na console SentinelOne.
    * Retorna '' quando o padrao nao foi configurado.
    */
   public static function consoleEndpointUrl(array $config, string $agentId): string
   {
      return self::buildConsoleUrl(
         (string)($config['console_endpoint_path'] ?? ''),
         (string)($config['base_url'] ?? ''),
         ['{agentId}' => $agentId]
      );
   }

   private static function buildConsoleUrl(string $pattern, string $baseUrl, array $tokens): string
   {
      $pattern = trim($pattern);
      $baseUrl = rtrim(trim($baseUrl), '/');

      if ($pattern === '' || $baseUrl === '') {
         return '';
      }

      foreach ($tokens as $token => $value) {
         if (str_contains($pattern, $token) && trim($value) === '') {
            return '';
         }
      }

      $path = strtr($pattern, $tokens);

      if (preg_match('#^https?://#i', $path) === 1) {
         return $path;
      }

      return $baseUrl . '/' . ltrim($path, '/');
   }

   public static function installDefaults(): void
   {
      $existing = \Config::getConfigurationValues(self::CONTEXT, array_keys(self::defaults()));

      if ($existing === []) {
         \Config::setConfigurationValues(self::CONTEXT, self::defaults());
      }
   }

   public static function getConfig(): array
   {
      $defaults = self::defaults();
      $values = \Config::getConfigurationValues(self::CONTEXT, array_keys($defaults));

      $config = array_merge($defaults, $values ?: []);
      $stored = (string)$config['api_token'];
      $decrypted = self::unprotectSecret($stored);
      $config['api_token'] = $decrypted;
      // Sinaliza quando o token estava armazenado mas nao pode ser descriptografado.
      $config['_token_decrypt_failed'] = str_starts_with($stored, self::SECRET_PREFIX) && $decrypted === '';

      return $config;
   }

   public static function buildConfigFromInput(array $input, bool $keepExistingToken = true): array
   {
      $config = self::getConfig();

      $config['enabled'] = self::boolInput($input, 'enabled');
      $config['base_url'] = rtrim(trim((string)($input['base_url'] ?? '')), '/');
      $config['base_path'] = '/' . trim(self::resolvePreset($input, 'base_path', array_keys(self::basePathPresets()), '/web/api/v2.1'), '/');
      $config['auth_scheme'] = self::resolvePreset($input, 'auth_scheme', array_keys(self::authSchemePresets()), 'ApiToken') ?: 'ApiToken';
      $config['console_threat_path'] = trim((string)($input['console_threat_path'] ?? ''));
      $config['console_endpoint_path'] = trim((string)($input['console_endpoint_path'] ?? ''));
      $config['timeout'] = (string)max(5, min(120, (int)($input['timeout'] ?? 30)));
      $config['max_pages'] = (string)max(1, min(500, (int)($input['max_pages'] ?? 10)));
      $config['sync_limit'] = (string)max(1, min(1000, (int)($input['sync_limit'] ?? 100)));
      $config['agent_filter_query'] = self::cleanQueryString($input['agent_filter_query'] ?? '');
      $config['threat_filter_query'] = self::cleanQueryString($input['threat_filter_query'] ?? '');
      $config['entity_id'] = (string)max(0, (int)($input['entity_id'] ?? 0));
      $config['create_tickets'] = self::boolInput($input, 'create_tickets');
      $config['auto_close_tickets'] = self::boolInput($input, 'auto_close_tickets');
      $config['ticket_threat_details'] = self::boolInput($input, 'ticket_threat_details');
      $config['sync_threat_notes'] = self::boolInput($input, 'sync_threat_notes');
      $config['ticket_status_filter'] = self::cleanList($input['ticket_status_filter'] ?? '');
      $config['ticket_classification_filter'] = self::cleanList($input['ticket_classification_filter'] ?? '');
      $config['ticket_category_id'] = (string)max(0, (int)($input['ticket_category_id'] ?? 0));
      $config['ticket_requester_id'] = (string)max(0, (int)($input['ticket_requester_id'] ?? 0));
      $config['ticket_auto_priority'] = self::boolInput($input, 'ticket_auto_priority');
      $config['ticket_urgency'] = (string)max(1, min(5, (int)($input['ticket_urgency'] ?? 4)));
      $config['ticket_impact'] = (string)max(1, min(5, (int)($input['ticket_impact'] ?? 4)));
      $config['ticket_priority'] = (string)max(1, min(6, (int)($input['ticket_priority'] ?? 4)));
      $config['write_antivirus'] = self::boolInput($input, 'write_antivirus');
      $config['create_agent_tickets'] = self::boolInput($input, 'create_agent_tickets');
      $config['ticket_offline_hours'] = (string)max(1, min(8760, (int)($input['ticket_offline_hours'] ?? 24)));
      $config['min_agent_version'] = trim((string)($input['min_agent_version'] ?? ''));
      $config['alert_emails'] = self::cleanEmailList($input['alert_emails'] ?? '');
      $config['alert_on_critical_threat'] = self::boolInput($input, 'alert_on_critical_threat');
      $config['alert_on_agent_issue'] = self::boolInput($input, 'alert_on_agent_issue');
      $config['sync_activities'] = self::boolInput($input, 'sync_activities');
      $config['site_entity_map'] = self::cleanSiteEntityMap($input['site_entity_map'] ?? '');
      $config['ticket_group_id'] = (string)max(0, (int)($input['ticket_group_id'] ?? 0));
      $config['sync_software'] = self::boolInput($input, 'sync_software');
      $config['sync_software_limit'] = (string)max(1, min(200, (int)($input['sync_software_limit'] ?? 30)));
      $config['sync_cves'] = self::boolInput($input, 'sync_cves');
      $config['sync_cves_limit'] = (string)max(1, min(200, (int)($input['sync_cves_limit'] ?? 30)));
      $config['sync_rogues'] = self::boolInput($input, 'sync_rogues');
      $config['sync_incremental'] = self::boolInput($input, 'sync_incremental');
      $config['report_recipients'] = self::cleanEmailList($input['report_recipients'] ?? '');
      $config['sync_date_from'] = self::cleanDate($input['sync_date_from'] ?? '');
      $config['agent_inactive_days'] = (string)max(0, min(3650, (int)($input['agent_inactive_days'] ?? 0)));
      $config['log_retention_days'] = (string)max(30, min(3650, (int)($input['log_retention_days'] ?? 90)));
      $config['token_expires_at'] = self::cleanDate($input['token_expires_at'] ?? '');

      $token = trim((string)($input['api_token'] ?? ''));
      if ($token !== '' || !$keepExistingToken) {
         $config['api_token'] = $token;
      }

      return $config;
   }

   /**
    * Persiste a data de expiracao do token obtida via API.
    * @param string $isoDate ISO-8601 retornado pela API (ex: "2026-08-15T00:00:00Z")
    */
   public static function saveTokenExpiry(string $isoDate): void
   {
      $ts = strtotime($isoDate);
      if ($ts === false) {
         return;
      }
      \Config::setConfigurationValues(self::CONTEXT, ['token_expires_at' => date('Y-m-d', $ts)]);
   }

   /**
    * Retorna quantos dias faltam para o token expirar, ou null se nao configurado.
    * Valor negativo = ja expirou.
    */
   public static function getTokenExpiryDays(?array $config = null): ?int
   {
      $config ??= self::getConfig();
      $raw = trim((string)($config['token_expires_at'] ?? ''));
      if ($raw === '') {
         return null;
      }
      $ts = strtotime($raw);
      if ($ts === false) {
         return null;
      }
      return (int)floor(($ts - time()) / 86400);
   }

   public static function saveFromInput(array $input): void
   {
      $config = self::buildConfigFromInput($input);
      $config['api_token'] = self::protectSecret((string)$config['api_token']);

      \Config::setConfigurationValues(self::CONTEXT, $config);
   }

   public static function setConnectionTestFlash(array $payload): void
   {
      $_SESSION[self::CONNECTION_FLASH_KEY] = [
         'ok'          => (bool)($payload['ok'] ?? false),
         'duration_ms' => (int)($payload['duration_ms'] ?? 0),
         'status'      => (int)($payload['status'] ?? 0),
         'message'     => (string)($payload['message'] ?? ''),
      ];
   }

   public static function isConfigured(?array $config = null): bool
   {
      $config ??= self::getConfig();

      return (string)$config['enabled'] === '1'
         && trim((string)$config['base_url']) !== ''
         && trim((string)$config['api_token']) !== '';
   }

   public static function showForm(): void
   {
      $config = self::getConfig();
      $formUrl = self::getPluginFormUrl();
      $tokenStatus = !empty($config['_token_decrypt_failed'])
         ? __('Token ilegivel — recadastre', 'sentinelone')
         : (trim((string)$config['api_token']) !== '' ? __('Token cadastrado', 'sentinelone') : __('Token nao cadastrado', 'sentinelone'));
      $canUpdate = Profile::hasConfigUpdateRight();
      $configured = self::isConfigured($config);
      $flash = self::pullConnectionTestFlash();

      echo "<div class='sentinelone-config'>";
      echo "<form method='post' action='" . self::h($formUrl) . "' id='sentinelone-config-form'>";
      echo "<div class='sentinelone-config__hero'>";
      echo "<div class='s1-hero__brand'>";
      echo "<span class='s1-logo'><span class='ti ti-shield-half-filled'></span></span>";
      echo "<div>";
      echo "<div class='sentinelone-config__eyebrow'>SentinelOne</div>";
      echo "<h2>" . __('Integracao da API', 'sentinelone') . "</h2>";
      echo "<p>" . __('Console, token, sincronizacao e automacoes do plugin.', 'sentinelone') . "</p>";
      echo "</div>";
      echo "</div>";
      echo "<div class='sentinelone-config__status " . ($configured ? 'is-ok' : 'is-warn') . "'>";
      echo "<span class='ti " . ($configured ? 'ti-circle-check' : 'ti-alert-triangle') . "'></span>";
      echo $configured ? __('Configurada', 'sentinelone') : __('Pendente', 'sentinelone');
      echo "</div>";
      echo "</div>";

      if (!empty($config['_token_decrypt_failed'])) {
         echo "<div class='sentinelone-test-result sentinelone-test-result--error'>";
         echo "<strong>" . __('Token ilegivel — recadastre o token', 'sentinelone') . "</strong>";
         echo "<span>" . __('O token da API estava gravado mas nao pode ser descriptografado (a chave de criptografia do GLPI pode ter mudado apos uma reinicializacao do container ou migracao). Digite o token novamente no campo abaixo e salve.', 'sentinelone') . "</span>";
         echo "</div>";
      }

      if ($flash !== null) {
         self::renderConnectionTestFlash($flash);
      }

      echo "<div id='sentinelone-test-result' class='sentinelone-test-result sentinelone-test-result--hidden' aria-live='polite'></div>";

      echo "<div class='sentinelone-config__grid'>";

      echo "<section class='sentinelone-panel sentinelone-panel--wide'>";
      self::panelHead(__('Conexao', 'sentinelone'), __('Console, endpoint da API, autenticacao e links da console.', 'sentinelone'), 'ti-plug-connected', "<span class='sentinelone-token-state'>" . self::h($tokenStatus) . "</span>");
      echo "<div class='sentinelone-panel__body sentinelone-fields'>";
      self::renderYesNo('enabled', __('Integracao ativa', 'sentinelone'), (string)$config['enabled'] === '1', $canUpdate, __('Interruptor geral: sincronizacoes e automacoes so rodam com isto em Sim.', 'sentinelone'));
      self::renderText('base_url', __('URL da console', 'sentinelone'), (string)$config['base_url'], 'https://sua-console.sentinelone.net', $canUpdate, false, __('Endereco da sua console, sem barra no final.', 'sentinelone'));
      self::renderPreset('base_path', __('Endpoint da API', 'sentinelone'), self::basePathPresets(), (string)$config['base_path'], __('Escolha a versao da API. Use "Personalizado" so para tenants com caminho diferente.', 'sentinelone'), $canUpdate, '/web/api/v2.1');
      self::renderPreset('auth_scheme', __('Autenticacao', 'sentinelone'), self::authSchemePresets(), (string)$config['auth_scheme'], __('ApiToken atende a maioria dos tenants SentinelOne.', 'sentinelone'), $canUpdate, 'ApiToken');
      self::renderPassword('api_token', __('Token da API', 'sentinelone'), $tokenStatus, $canUpdate);
      self::renderNumber('timeout', __('Timeout HTTP em segundos', 'sentinelone'), (int)$config['timeout'], 5, 120, $canUpdate, __('Tempo maximo de espera por resposta da API.', 'sentinelone'));
      self::renderTokenExpiry($config, $canUpdate);
      self::renderText('console_threat_path', __('Deep link de ameaca (opcional, use {threatId})', 'sentinelone'), (string)$config['console_threat_path'], '/incidents/threats/{threatId}/overview', $canUpdate, true, __('Abre a ameaca direto na console. Vazio = sem link.', 'sentinelone'));
      self::renderText('console_endpoint_path', __('Deep link de endpoint (opcional, use {agentId})', 'sentinelone'), (string)$config['console_endpoint_path'], '/inventory/devices/{agentId}', $canUpdate, true, __('Abre o endpoint direto na console. Vazio = sem link.', 'sentinelone'));
      echo "</div>";
      echo "</section>";

      echo "<section class='sentinelone-panel'>";
      self::panelHead(__('Sincronizacao', 'sentinelone'), __('Quanto buscar por execucao e onde gravar.', 'sentinelone'), 'ti-refresh');
      echo "<div class='sentinelone-panel__body sentinelone-fields'>";
      self::renderNumber('sync_limit', __('Itens por pagina', 'sentinelone'), (int)$config['sync_limit'], 1, 1000, $canUpdate, __('Quantos itens o plugin pede por pagina a API.', 'sentinelone'));
      self::renderNumber('max_pages', __('Maximo de paginas', 'sentinelone'), (int)$config['max_pages'], 1, 500, $canUpdate, __('Limite de paginas por execucao (protege contra cargas enormes).', 'sentinelone'));
      self::renderEntityDropdown('entity_id', __('Entidade padrao GLPI', 'sentinelone'), (int)$config['entity_id'], $canUpdate);
      self::renderText('agent_filter_query', __('Filtro de agentes', 'sentinelone'), (string)$config['agent_filter_query'], 'isActive=true', $canUpdate, true, __('Opcional, no formato query string da API SentinelOne.', 'sentinelone'));
      self::renderText('threat_filter_query', __('Filtro de ameacas', 'sentinelone'), (string)$config['threat_filter_query'], 'mitigationStatuses=unmitigated', $canUpdate, true, __('Opcional, no formato query string da API SentinelOne.', 'sentinelone'));
      self::renderTextarea('site_entity_map', __('Mapa site SentinelOne → entidade GLPI', 'sentinelone'), (string)($config['site_entity_map'] ?? ''), "Site Principal=1\nFilial SP=2", $canUpdate, __('Mapeamento de sites SentinelOne para entidades GLPI. Um por linha no formato NomeSite=id_entidade. Agentes desse site serao gravados na entidade correspondente.', 'sentinelone'));
      echo "</div>";
      echo "</section>";

      echo "<section class='sentinelone-panel'>";
      self::panelHead(__('Automacao', 'sentinelone'), __('O que o plugin faz automaticamente.', 'sentinelone'), 'ti-robot');
      echo "<div class='sentinelone-panel__body sentinelone-fields'>";
      self::renderYesNo('create_tickets', __('Criar tickets para ameacas', 'sentinelone'), (string)$config['create_tickets'] === '1', $canUpdate, __('Interruptor geral dos tickets de ameaca. Precisa de pelo menos uma regra abaixo.', 'sentinelone'));
      self::renderYesNo('auto_close_tickets', __('Fechar tickets quando ameaca for resolvida', 'sentinelone'), (string)($config['auto_close_tickets'] ?? '1') === '1', $canUpdate, __('Quando o SentinelOne marcar a ameaca como mitigada/resolvida, o ticket correspondente e marcado como Solucionado com uma nota de resolucao.', 'sentinelone'));
      self::renderYesNo('ticket_threat_details', __('Postar nota forense detalhada ao abrir o ticket', 'sentinelone'), (string)($config['ticket_threat_details'] ?? '1') === '1', $canUpdate, __('Logo apos abrir o ticket, adiciona uma nota interna (privada) com os detalhes forenses da ameaca: processo e linha de comando, engine de deteccao, editor/assinatura, IP/usuario logado, acoes de mitigacao e MITRE ATT&CK.', 'sentinelone'));
      self::renderYesNo('sync_threat_notes', __('Sincronizar notas da console como comentarios no ticket', 'sentinelone'), (string)($config['sync_threat_notes'] ?? '0') === '1', $canUpdate, __('Para cada ameaca com ticket aberto, busca as notas da console SentinelOne e adiciona como acompanhamentos no GLPI. Aumenta o volume de chamadas a API.', 'sentinelone'));
      self::renderYesNo('write_antivirus', __('Registrar como antivirus do computador', 'sentinelone'), (string)$config['write_antivirus'] === '1', $canUpdate, __('Grava o SentinelOne na aba Antivirus de cada computador vinculado.', 'sentinelone'));
      self::renderYesNo('sync_activities', __('Sincronizar feed de atividades dos agentes', 'sentinelone'), (string)($config['sync_activities'] ?? '0') === '1', $canUpdate, __('Busca as ultimas atividades (eventos) dos agentes na console SentinelOne e exibe na aba do computador. Aumenta o volume de chamadas a API.', 'sentinelone'));
      self::renderYesNo('sync_software', __('Sincronizar inventario de software dos endpoints', 'sentinelone'), (string)($config['sync_software'] ?? '0') === '1', $canUpdate, __('Busca os aplicativos instalados de cada endpoint via API e grava no inventario de software do GLPI. Recomendado para cobrir estacoes que o Nessus nao alcanca. Opt-in: aumenta chamadas a API.', 'sentinelone'));
      self::renderNumber('sync_software_limit', __('Agentes por execucao de software sync', 'sentinelone'), (int)($config['sync_software_limit'] ?? 30), 1, 200, $canUpdate, __('Quantos agentes sao processados por execucao da cron de software (para controlar o volume de chamadas a API).', 'sentinelone'));
      self::renderYesNo('sync_cves', __('Sincronizar CVEs dos endpoints', 'sentinelone'), (string)($config['sync_cves'] ?? '0') === '1', $canUpdate, __('Busca CVEs detectados em cada endpoint via API SentinelOne e exibe na aba do computador no GLPI. Opt-in: aumenta chamadas a API. Requer plano com Vulnerability Management habilitado.', 'sentinelone'));
      self::renderNumber('sync_cves_limit', __('Agentes por execucao de CVE sync', 'sentinelone'), (int)($config['sync_cves_limit'] ?? 30), 1, 200, $canUpdate, __('Quantos agentes sao processados por execucao da cron de CVEs.', 'sentinelone'));
      self::renderYesNo('sync_rogues', __('Sincronizar dispositivos rogues (Ranger)', 'sentinelone'), (string)($config['sync_rogues'] ?? '0') === '1', $canUpdate, __('Busca endpoints detectados na rede pelo Ranger SentinelOne que nao possuem agente instalado. Opt-in: requer licenca Ranger.', 'sentinelone'));
      self::renderYesNo('sync_incremental', __('Sync incremental (somente atualizacoes)', 'sentinelone'), (string)($config['sync_incremental'] ?? '0') === '1', $canUpdate, __('Quando ativo, as syncs de agentes e ameacas passam updatedAt__gt para buscar apenas o que mudou desde a ultima execucao. Reduz drasticamente o tempo de cron e o volume de chamadas a API. A primeira sync apos ativar sera completa.', 'sentinelone'));
      self::renderDateInput('sync_date_from', __('Sincronizar a partir de (data de corte)', 'sentinelone'), (string)($config['sync_date_from'] ?? ''), $canUpdate, __('Opcional. Quando preenchido, a primeira sync (ou syncs sem cursor incremental) ignoram agentes e ameacas anteriores a essa data. Formato AAAA-MM-DD. Util para nao importar historico antigo na primeira execucao.', 'sentinelone'));
      self::renderNumber('agent_inactive_days', __('Ignorar agentes sem contato ha (dias)', 'sentinelone'), (int)($config['agent_inactive_days'] ?? 0), 0, 3650, $canUpdate, __('Quando maior que 0, agentes que nao comunicaram com a console SentinelOne nos ultimos N dias nao sao sincronizados. Use para excluir maquinas desativadas ou fora de operacao. 0 = desabilitado (sincroniza todos).', 'sentinelone'));
      self::renderNumber('log_retention_days', __('Retencao de logs internos (dias)', 'sentinelone'), (int)($config['log_retention_days'] ?? 90), 30, 3650, $canUpdate, __('Logs do plugin mais antigos que este numero de dias sao removidos automaticamente pela cron de manutencao. Minimo 30 dias.', 'sentinelone'));
      echo "</div>";
      echo "</section>";

      echo "<section class='sentinelone-panel sentinelone-panel--wide'>";
      self::panelHead(__('Relatorio semanal', 'sentinelone'), __('E-mail de resumo executivo enviado automaticamente toda semana.', 'sentinelone'), 'ti-report');
      echo "<div class='sentinelone-panel__body sentinelone-fields'>";
      self::renderText('report_recipients', __('Destinatarios do relatorio (e-mails separados por virgula)', 'sentinelone'), (string)($config['report_recipients'] ?? ''), 'operador@empresa.com,gestor@empresa.com', $canUpdate, true, __('O relatorio semanal sera enviado a esses enderecos pelo cron reportweekly. Deixe vazio para desativar.', 'sentinelone'));
      echo "</div>";
      echo "</section>";

      echo "<section class='sentinelone-panel sentinelone-panel--wide'>";
      self::panelHead(__('Regras de ticket', 'sentinelone'), __('Status E classificacao precisam casar; campo vazio = todos; ameacas resolvidas sao ignoradas.', 'sentinelone'), 'ti-ticket');
      $ticketRulesConfigured = trim((string)$config['ticket_status_filter']) !== ''
         || trim((string)$config['ticket_classification_filter']) !== '';
      if ((string)$config['create_tickets'] === '1' && !$ticketRulesConfigured) {
         echo "<div class='sentinelone-inline-warning'>";
         echo "<span class='ti ti-alert-triangle'></span>";
         echo "<span><strong>" . __('Aguardando regras.', 'sentinelone') . "</strong> " . __('A criacao de tickets esta ligada, mas nenhuma regra de status ou classificacao foi definida &mdash; nenhum ticket sera aberto ate preencher pelo menos um dos campos abaixo.', 'sentinelone') . "</span>";
         echo "</div>";
      }
      echo "<div class='sentinelone-panel__body sentinelone-fields'>";
      self::renderMultiSelect('ticket_status_filter', __('Criar tickets somente para status', 'sentinelone'), self::threatStatusOptions(), (string)$config['ticket_status_filter'], $canUpdate, __('Vazio = qualquer status (OU entre os escolhidos). Ameacas resolvidas/mitigadas sao sempre ignoradas.', 'sentinelone'));
      self::renderMultiSelect('ticket_classification_filter', __('Criar tickets somente para classificacoes', 'sentinelone'), self::threatClassificationOptions(), (string)$config['ticket_classification_filter'], $canUpdate, __('Vazio = qualquer classificacao. Combina em E (AND) com o filtro de status.', 'sentinelone'));
      self::renderTicketCategoryDropdown('ticket_category_id', __('Categoria GLPI do ticket', 'sentinelone'), (int)$config['ticket_category_id'], $canUpdate);
      self::renderUserDropdown('ticket_requester_id', __('Usuario solicitante (integracao)', 'sentinelone'), (int)$config['ticket_requester_id'], $canUpdate, __('Todos os tickets abrem com este usuario como solicitante/autor. Crie um usuario dedicado (ex.: "integracao") para identificar os chamados do plugin.', 'sentinelone'));
      self::renderGroupDropdown('ticket_group_id', __('Grupo responsavel (atribuicao)', 'sentinelone'), (int)($config['ticket_group_id'] ?? 0), $canUpdate, __('Grupo GLPI atribuido como responsavel em todos os tickets criados pelo plugin. Deixe em branco para nao atribuir.', 'sentinelone'));
      self::renderYesNo('ticket_auto_priority', __('Prioridade automatica pela severidade', 'sentinelone'), (string)($config['ticket_auto_priority'] ?? '1') === '1', $canUpdate, __('Define urgencia/impacto/prioridade do ticket conforme a severidade da ameaca (Critica > Suspeita > Ativa). Quando desligado, usa os valores fixos abaixo.', 'sentinelone'));
      self::renderSelectFromArray('ticket_urgency', __('Urgencia (quando prioridade automatica desligada)', 'sentinelone'), self::ticketScaleOptions(false), (int)$config['ticket_urgency'], $canUpdate);
      self::renderSelectFromArray('ticket_impact', __('Impacto', 'sentinelone'), self::ticketScaleOptions(false), (int)$config['ticket_impact'], $canUpdate);
      self::renderSelectFromArray('ticket_priority', __('Prioridade', 'sentinelone'), self::ticketScaleOptions(true), (int)$config['ticket_priority'], $canUpdate);
      global $CFG_GLPI;
      $previewUrl = (string)($CFG_GLPI['root_doc'] ?? '') . '/plugins/sentinelone/front/ticket_preview.php';
      echo "<div class='sentinelone-field'><a class='btn btn-sm btn-outline-primary' href='" . self::h($previewUrl) . "' target='_blank' rel='noopener'><span class='ti ti-eye'></span> " . __('Pre-visualizar HTML do ticket', 'sentinelone') . "</a></div>";
      echo "</div>";
      echo "</section>";

      echo "<section class='sentinelone-panel sentinelone-panel--wide'>";
      self::panelHead(__('Saude de agentes e alertas', 'sentinelone'), __('Tickets por problema de agente e e-mails de alerta.', 'sentinelone'), 'ti-heartbeat');
      echo "<div class='sentinelone-panel__body sentinelone-fields'>";
      self::renderYesNo('create_agent_tickets', __('Criar tickets de saude do agente', 'sentinelone'), (string)$config['create_agent_tickets'] === '1', $canUpdate, __('Abre um ticket por agente com problema (offline/infectado/desatualizado).', 'sentinelone'));
      self::renderNumber('ticket_offline_hours', __('Horas offline para abrir ticket', 'sentinelone'), (int)$config['ticket_offline_hours'], 1, 8760, $canUpdate, __('A partir de quantas horas sem contato o agente vira um problema.', 'sentinelone'));
      self::renderText('min_agent_version', __('Versao minima do agente (opcional)', 'sentinelone'), (string)$config['min_agent_version'], 'ex.: 23.4.2.14', $canUpdate, false, __('Abaixo desta versao o agente e considerado desatualizado. Vazio = nao checa.', 'sentinelone'));
      self::renderText('alert_emails', __('E-mails para alertas (separados por virgula)', 'sentinelone'), (string)$config['alert_emails'], 'soc@empresa.com, ti@empresa.com', $canUpdate, true, __('Destinatarios dos alertas. Requer e-mail/SMTP configurado no GLPI.', 'sentinelone'));
      self::renderYesNo('alert_on_critical_threat', __('Enviar e-mail em ameaca critica', 'sentinelone'), (string)$config['alert_on_critical_threat'] === '1', $canUpdate, __('Envia quando uma nova ameaca critica e sincronizada.', 'sentinelone'));
      self::renderYesNo('alert_on_agent_issue', __('Enviar e-mail em problema de agente', 'sentinelone'), (string)$config['alert_on_agent_issue'] === '1', $canUpdate, __('Enviado junto com a abertura do ticket de saude do agente.', 'sentinelone'));

      if ($canUpdate) {
         echo "<div class='sentinelone-field'>";
         echo "<div class='sentinelone-field__label'><span>" . __('Testar envio de e-mail', 'sentinelone') . "</span></div>";
         echo "<div class='sentinelone-field__control'>";
         echo "<button type='button' class='btn btn-outline-secondary' id='sentinelone-test-email-btn'><span class='ti ti-mail'></span>" . __('Enviar e-mail de teste', 'sentinelone') . "</button>";
         echo "<div id='sentinelone-test-email-result' style='margin-top:8px;font-size:13px'></div>";
         echo "</div>";
         echo "<div class='sentinelone-field__help'>" . __('Envia um e-mail de teste imediato para os destinatarios configurados acima.', 'sentinelone') . "</div>";
         echo "</div>";
      }

      echo "</div>";
      echo "</section>";
      echo "</div>";

      echo "<div class='sentinelone-config__actions'>";
      echo "<button class='btn btn-primary' type='submit' name='update' value='1'" . (!$canUpdate ? ' disabled' : '') . "><span class='ti ti-device-floppy'></span>" . __('Salvar', 'sentinelone') . "</button>";
      echo "<button class='btn btn-outline-primary' type='submit' name='test' value='1' data-sentinelone-test" . (!$canUpdate ? ' disabled' : '') . "><span class='ti ti-plug-connected'></span>" . __('Testar conexao', 'sentinelone') . "</button>";
      echo "</div>";
      \Html::closeForm();
      self::renderScript();
      echo "</div>";
   }

   public static function getPluginFormUrl(): string
   {
      global $CFG_GLPI;

      return $CFG_GLPI['root_doc'] . '/plugins/sentinelone/front/config.form.php';
   }

   private static function renderTextarea(string $name, string $label, string $value, string $placeholder = '', bool $enabled = true, ?string $help = null): void
   {
      echo "<label class='sentinelone-field sentinelone-field--wide'>";
      echo "<span>" . self::h($label) . "</span>";
      echo "<textarea class='form-control' name='" . self::h($name) . "' rows='4' placeholder='" . self::h($placeholder) . "'" . self::disabled(!$enabled) . ">" . self::h($value) . "</textarea>";
      self::renderHelp($help);
      echo "</label>";
   }

   private static function renderTokenExpiry(array $config, bool $canUpdate = true): void
   {
      $expiresAt = trim((string)($config['token_expires_at'] ?? ''));
      $days = self::getTokenExpiryDays($config);

      echo "<div class='sentinelone-field sentinelone-field--wide'>";
      echo "<span>" . __('Validade do token', 'sentinelone') . "</span>";
      echo "<div class='sentinelone-field__control' style='display:flex;gap:.6rem;align-items:center;flex-wrap:wrap'>";

      // Badge de status
      if ($days === null) {
         echo "<span class='s1-token-expiry s1-token-expiry--unknown'>"
            . "<span class='ti ti-calendar-question'></span> "
            . __('Nao disponivel', 'sentinelone')
            . "</span>";
      } elseif ($days < 0) {
         echo "<span class='s1-token-expiry s1-token-expiry--expired'>"
            . "<span class='ti ti-calendar-x'></span> "
            . __('TOKEN EXPIRADO', 'sentinelone')
            . "</span>";
      } else {
         $cssClass = $days <= 7 ? 'critical' : ($days <= 30 ? 'warn' : 'ok');
         $icon = $days <= 7 ? 'ti-calendar-exclamation' : ($days <= 30 ? 'ti-calendar-stats' : 'ti-calendar-check');
         echo "<span class='s1-token-expiry s1-token-expiry--{$cssClass}'>"
            . "<span class='ti {$icon}'></span> "
            . sprintf(_n('%d dia restante', '%d dias restantes', $days, 'sentinelone'), $days)
            . "</span>";
      }

      // Campo de data manual
      echo "<input class='form-control' style='width:160px' type='date' "
         . "name='token_expires_at' "
         . "value='" . self::h($expiresAt) . "'"
         . ($canUpdate ? '' : ' disabled')
         . " title='" . __('Data de expiracao do token (preenchida automaticamente ao testar conexao ou manualmente)', 'sentinelone') . "'"
         . ">";

      echo "</div>";
      echo "<small>" . __('Preenchida automaticamente ao testar conexao. Se a API nao retornar, informe manualmente a data de vencimento do token.', 'sentinelone') . "</small>";
      echo "</div>";
   }

   private static function renderText(string $name, string $label, string $value, string $placeholder = '', bool $enabled = true, bool $wide = false, ?string $help = null): void
   {
      echo "<label class='sentinelone-field" . ($wide ? ' sentinelone-field--wide' : '') . "'>";
      echo "<span>" . self::h($label) . "</span>";
      echo "<input class='form-control' type='text' name='" . self::h($name) . "' value='" . self::h($value) . "' placeholder='" . self::h($placeholder) . "'" . self::disabled(!$enabled) . ">";
      self::renderHelp($help);
      echo "</label>";
   }

   private static function renderHelp(?string $help): void
   {
      if ($help !== null && $help !== '') {
         echo "<small>" . self::h($help) . "</small>";
      }
   }

   private static function panelHead(string $title, string $subtitle, string $icon, string $rightHtml = ''): void
   {
      echo "<div class='sentinelone-panel__head'>";
      echo "<div class='sentinelone-panel__title'>";
      if ($icon !== '') {
         echo "<span class='sentinelone-panel__icon ti " . self::h($icon) . "'></span>";
      }
      echo "<div>";
      echo "<h3>" . self::h($title) . "</h3>";
      if ($subtitle !== '') {
         echo "<p>" . self::h($subtitle) . "</p>";
      }
      echo "</div>";
      echo "</div>";
      if ($rightHtml !== '') {
         echo $rightHtml;
      }
      echo "</div>";
   }

   private static function renderPassword(string $name, string $label, string $help, bool $enabled = true): void
   {
      echo "<label class='sentinelone-field'>";
      echo "<span>" . self::h($label) . "</span>";
      echo "<input class='form-control' type='password' name='" . self::h($name) . "' autocomplete='new-password' placeholder='" . self::h($help) . "'" . self::disabled(!$enabled) . ">";
      echo "<small>" . __('Deixe em branco para manter o token atual.', 'sentinelone') . "</small>";
      echo "</label>";
   }

   private static function renderPreset(string $name, string $label, array $presets, string $value, string $help, bool $enabled, string $customPlaceholder): void
   {
      $value = trim($value);
      $isCustom = $value !== '' && !array_key_exists($value, $presets);

      echo "<label class='sentinelone-field'>";
      echo "<span>" . self::h($label) . "</span>";
      echo "<select class='form-select' name='" . self::h($name) . "_preset' data-s1-preset='" . self::h($name) . "'" . self::disabled(!$enabled) . ">";
      foreach ($presets as $optionValue => $optionLabel) {
         $selected = (!$isCustom && (string)$optionValue === $value) ? ' selected' : '';
         echo "<option value='" . self::h((string)$optionValue) . "'{$selected}>" . self::h((string)$optionLabel) . "</option>";
      }
      echo "<option value='__custom__'" . ($isCustom ? ' selected' : '') . ">" . __('Personalizado...', 'sentinelone') . "</option>";
      echo "</select>";
      echo "<input class='form-control" . ($isCustom ? '' : ' sentinelone-field--hidden') . "' type='text' name='" . self::h($name) . "_custom' data-s1-preset-custom='" . self::h($name) . "' value='" . self::h($isCustom ? $value : '') . "' placeholder='" . self::h($customPlaceholder) . "'" . self::disabled(!$enabled) . ">";
      if ($help !== '') {
         echo "<small>" . self::h($help) . "</small>";
      }
      echo "</label>";
   }

   private static function renderNumber(string $name, string $label, int $value, int $min, int $max, bool $enabled = true, ?string $help = null): void
   {
      echo "<label class='sentinelone-field'>";
      echo "<span>" . self::h($label) . "</span>";
      echo "<input class='form-control' type='number' min='" . self::h((string)$min) . "' max='" . self::h((string)$max) . "' name='" . self::h($name) . "' value='" . self::h((string)$value) . "'" . self::disabled(!$enabled) . ">";
      self::renderHelp($help);
      echo "</label>";
   }

   private static function renderDateInput(string $name, string $label, string $value, bool $enabled = true, ?string $help = null): void
   {
      echo "<label class='sentinelone-field'>";
      echo "<span>" . self::h($label) . "</span>";
      echo "<input class='form-control' type='date' name='" . self::h($name) . "' value='" . self::h($value) . "'" . self::disabled(!$enabled) . ">";
      self::renderHelp($help);
      echo "</label>";
   }

   private static function renderYesNo(string $name, string $label, bool $selected, bool $enabled = true, ?string $help = null): void
   {
      echo "<label class='sentinelone-field'>";
      echo "<span>" . self::h($label) . "</span>";
      echo "<select class='form-select' name='" . self::h($name) . "'" . self::disabled(!$enabled) . ">";
      echo "<option value='0'" . (!$selected ? ' selected' : '') . ">" . __('Nao', 'sentinelone') . "</option>";
      echo "<option value='1'" . ($selected ? ' selected' : '') . ">" . __('Sim', 'sentinelone') . "</option>";
      echo "</select>";
      self::renderHelp($help);
      echo "</label>";
   }

   private static function renderEntityDropdown(string $name, string $label, int $value, bool $enabled = true): void
   {
      $entities = $_SESSION['glpiactiveentities'] ?? -1;

      echo "<label class='sentinelone-field sentinelone-field--entity'>";
      echo "<span>" . self::h($label) . "</span>";
      \Entity::dropdown([
         'name'                 => $name,
         'value'                => $value,
         'entity'               => $entities,
         'comments'             => false,
         'width'                => '100%',
         'addicon'              => false,
         'display_emptychoice'  => false,
         'permit_select_parent' => true,
         'readonly'             => !$enabled,
      ]);
      echo "<small>" . __('Usada para gravar agentes, ameacas e tickets criados pela integracao.', 'sentinelone') . "</small>";
      echo "</label>";
   }

   private static function renderTicketCategoryDropdown(string $name, string $label, int $value, bool $enabled = true): void
   {
      $entities = $_SESSION['glpiactiveentities'] ?? -1;

      echo "<label class='sentinelone-field'>";
      echo "<span>" . self::h($label) . "</span>";
      \ITILCategory::dropdown([
         'name'                => $name,
         'value'               => $value,
         'entity'              => $entities,
         'comments'            => false,
         'width'               => '100%',
         'addicon'             => false,
         'display_emptychoice' => true,
         'emptylabel'          => __('Sem categoria', 'sentinelone'),
         'readonly'            => !$enabled,
      ]);
      echo "</label>";
   }

   private static function renderGroupDropdown(string $name, string $label, int $value, bool $enabled = true, ?string $help = null): void
   {
      echo "<label class='sentinelone-field'>";
      echo "<span>" . self::h($label) . "</span>";
      \Group::dropdown([
         'name'                => $name,
         'value'               => $value,
         'width'               => '100%',
         'comments'            => false,
         'display_emptychoice' => true,
         'emptylabel'          => __('Sem grupo (padrao do GLPI)', 'sentinelone'),
         'readonly'            => !$enabled,
      ]);
      self::renderHelp($help);
      echo "</label>";
   }

   private static function renderUserDropdown(string $name, string $label, int $value, bool $enabled = true, ?string $help = null): void
   {
      $entities = $_SESSION['glpiactiveentities'] ?? -1;

      echo "<label class='sentinelone-field'>";
      echo "<span>" . self::h($label) . "</span>";
      \User::dropdown([
         'name'                => $name,
         'value'               => $value,
         'right'               => 'all',
         'entity'              => $entities,
         'width'               => '100%',
         'comments'            => false,
         'display_emptychoice' => true,
         'emptylabel'          => __('Sem usuario (padrao do GLPI)', 'sentinelone'),
         'readonly'            => !$enabled,
      ]);
      self::renderHelp($help);
      echo "</label>";
   }

   /**
    * Multi-select (select2) para listas de regras (status / classificacao).
    * Mantem o mesmo formato de armazenamento (lista separada por virgula),
    * preservando valores antigos que nao estejam na lista de opcoes.
    *
    * @param array<string, string> $options
    */
   private static function renderMultiSelect(string $name, string $label, array $options, string $storedCsv, bool $enabled = true, ?string $help = null): void
   {
      $selected = self::parseList($storedCsv);

      // preserva valores ja salvos que nao estejam nas opcoes conhecidas
      foreach ($selected as $value) {
         if (!array_key_exists($value, $options)) {
            $options[$value] = $value;
         }
      }

      echo "<label class='sentinelone-field'>";
      echo "<span>" . self::h($label) . "</span>";
      \Dropdown::showFromArray($name, $options, [
         'values'   => $selected,
         'multiple' => true,
         'width'    => '100%',
         'readonly' => !$enabled,
      ]);
      self::renderHelp($help);
      echo "</label>";
   }

   /**
    * @return string[]
    */
   private static function parseList(string $csv): array
   {
      $parts = preg_split('/[\r\n,;]+/', strtolower($csv)) ?: [];
      $out = [];

      foreach ($parts as $part) {
         $part = trim($part);
         if ($part !== '') {
            $out[$part] = $part;
         }
      }

      return array_values($out);
   }

   /**
    * Status de mitigacao do SentinelOne (threatInfo.mitigationStatus) onde faz
    * sentido abrir ticket. @return array<string, string>
    */
   private static function threatStatusOptions(): array
   {
      return [
         'active'        => __('Ativo (active)', 'sentinelone'),
         'unmitigated'   => __('Nao mitigado (unmitigated)', 'sentinelone'),
         'not_mitigated' => __('Nao mitigado (not_mitigated)', 'sentinelone'),
         'blocked'       => __('Bloqueado (blocked)', 'sentinelone'),
         'suspicious'    => __('Suspeito (suspicious)', 'sentinelone'),
         'pending'       => __('Pendente (pending)', 'sentinelone'),
      ];
   }

   /**
    * Classificacoes de ameaca do SentinelOne (threatInfo.classification).
    * @return array<string, string>
    */
   private static function threatClassificationOptions(): array
   {
      return [
         'malware'     => __('Malware', 'sentinelone'),
         'ransomware'  => __('Ransomware', 'sentinelone'),
         'trojan'      => __('Trojan', 'sentinelone'),
         'virus'       => __('Virus', 'sentinelone'),
         'worm'        => __('Worm', 'sentinelone'),
         'backdoor'    => __('Backdoor', 'sentinelone'),
         'exploit'     => __('Exploit', 'sentinelone'),
         'pua'         => __('PUA (potencialmente indesejado)', 'sentinelone'),
         'adware'      => __('Adware', 'sentinelone'),
         'spyware'     => __('Spyware', 'sentinelone'),
         'rootkit'     => __('Rootkit', 'sentinelone'),
         'hacktool'    => __('Hacktool', 'sentinelone'),
         'downloader'  => __('Downloader', 'sentinelone'),
         'dropper'     => __('Dropper', 'sentinelone'),
         'infostealer' => __('Infostealer', 'sentinelone'),
         'phishing'    => __('Phishing', 'sentinelone'),
         'generic'     => __('Generic', 'sentinelone'),
         'unknown'     => __('Unknown', 'sentinelone'),
      ];
   }

   private static function renderSelectFromArray(string $name, string $label, array $options, int $value, bool $enabled = true, ?string $help = null): void
   {
      echo "<label class='sentinelone-field'>";
      echo "<span>" . self::h($label) . "</span>";
      echo "<select class='form-select' name='" . self::h($name) . "'" . self::disabled(!$enabled) . ">";
      foreach ($options as $optionValue => $optionLabel) {
         echo "<option value='" . self::h((string)$optionValue) . "'" . ((int)$optionValue === $value ? ' selected' : '') . ">" . self::h((string)$optionLabel) . "</option>";
      }
      echo "</select>";
      self::renderHelp($help);
      echo "</label>";
   }

   private static function ticketScaleOptions(bool $includeMajor): array
   {
      $options = [
         1 => __('1 - Muito baixa', 'sentinelone'),
         2 => __('2 - Baixa', 'sentinelone'),
         3 => __('3 - Media', 'sentinelone'),
         4 => __('4 - Alta', 'sentinelone'),
         5 => __('5 - Muito alta', 'sentinelone'),
      ];

      if ($includeMajor) {
         $options[6] = __('6 - Critica', 'sentinelone');
      }

      return $options;
   }

   private static function pullConnectionTestFlash(): ?array
   {
      $flash = $_SESSION[self::CONNECTION_FLASH_KEY] ?? null;
      unset($_SESSION[self::CONNECTION_FLASH_KEY]);

      return is_array($flash) ? $flash : null;
   }

   private static function renderConnectionTestFlash(array $flash): void
   {
      $ok = (bool)($flash['ok'] ?? false);
      $status = (int)($flash['status'] ?? 0);
      $message = (string)($flash['message'] ?? '');
      $class = $ok ? 'sentinelone-test-result--ok' : 'sentinelone-test-result--error';
      $title = $ok ? __('Conexao OK', 'sentinelone') : __('Falha na conexao', 'sentinelone');

      echo "<div class='sentinelone-test-result {$class}'>";
      echo "<strong>" . self::h($title) . "</strong>";
      echo "<span>" . self::h($message);
      if ($status > 0) {
         echo " HTTP " . self::h((string)$status) . ".";
      }
      echo "</span>";
      echo "</div>";
   }

   private static function renderScript(): void
   {
      echo <<<'HTML'
<script>
(function () {
   const form = document.getElementById('sentinelone-config-form');
   const button = form ? form.querySelector('[data-sentinelone-test]') : null;
   const result = document.getElementById('sentinelone-test-result');

   if (!form || !button || !result) {
      return;
   }

   const originalButton = button.innerHTML;

   function showResult(ok, message, status) {
      result.className = 'sentinelone-test-result ' + (ok ? 'sentinelone-test-result--ok' : 'sentinelone-test-result--error');
      result.innerHTML = '';

      const title = document.createElement('strong');
      title.textContent = ok ? 'Conexao OK' : 'Falha na conexao';

      const detail = document.createElement('span');
      let text = message || (ok ? 'Conexao validada.' : 'Nao foi possivel validar a conexao.');
      if (status && status > 0) {
         text += ' HTTP ' + status + '.';
      }
      detail.textContent = text;

      result.appendChild(title);
      result.appendChild(detail);
   }

   button.addEventListener('click', function (event) {
      event.preventDefault();

      if (button.disabled) {
         return;
      }

      const token = form.querySelector('input[name="_glpi_csrf_token"]');
      const data = new FormData(form);
      data.set('ajax_test', '1');
      data.set('test', '1');

      button.disabled = true;
      button.innerHTML = '<span class="spinner-border spinner-border-sm" aria-hidden="true"></span>Testando';
      result.className = 'sentinelone-test-result sentinelone-test-result--loading';
      result.innerHTML = '<strong>Testando</strong><span>Chamando a API SentinelOne...</span>';

      fetch(form.action, {
         method: 'POST',
         body: data,
         credentials: 'same-origin',
         headers: {
            'X-Requested-With': 'XMLHttpRequest',
            'X-Glpi-Csrf-Token': token ? token.value : ''
         }
      })
         .then(function (response) {
            return response.json();
         })
         .then(function (payload) {
            showResult(Boolean(payload.ok), payload.message, Number(payload.status || 0));
         })
         .catch(function () {
            showResult(false, 'Falha inesperada ao testar a conexao.', 0);
         })
         .finally(function () {
            button.disabled = false;
            button.innerHTML = originalButton;
         });
   });
})();

(function () {
   const form = document.getElementById('sentinelone-config-form');
   if (!form) {
      return;
   }

   form.querySelectorAll('[data-s1-preset]').forEach(function (select) {
      const key = select.getAttribute('data-s1-preset');
      const custom = form.querySelector('[data-s1-preset-custom="' + key + '"]');
      if (!custom) {
         return;
      }

      function apply(focusOnCustom) {
         const isCustom = select.value === '__custom__';
         custom.classList.toggle('sentinelone-field--hidden', !isCustom);
         if (isCustom && focusOnCustom) {
            custom.focus();
         }
      }

      select.addEventListener('change', function () {
         apply(true);
      });
      apply(false);
   });
})();

(function () {
   const btn = document.getElementById('sentinelone-test-email-btn');
   if (!btn) {
      return;
   }

   const resultEl = document.getElementById('sentinelone-test-email-result');
   const form = document.getElementById('sentinelone-config-form');
   const originalHtml = btn.innerHTML;

   btn.addEventListener('click', function () {
      if (btn.disabled) {
         return;
      }

      const data = new FormData(form);
      data.set('ajax_test_email', '1');
      data.set('test_email', '1');

      btn.disabled = true;
      btn.innerHTML = '<span class="spinner-border spinner-border-sm" aria-hidden="true"></span>Enviando...';
      resultEl.innerHTML = '';

      const token = form.querySelector('input[name="_glpi_csrf_token"]');

      fetch(form.action, {
         method: 'POST',
         body: data,
         credentials: 'same-origin',
         headers: {
            'X-Requested-With': 'XMLHttpRequest',
            'X-Glpi-Csrf-Token': token ? token.value : ''
         }
      })
         .then(function (r) { return r.json(); })
         .then(function (payload) {
            const color = payload.ok ? '#2b7a0b' : '#b5179e';
            resultEl.innerHTML = '<span style="color:' + color + ';font-weight:600">' +
               (payload.ok ? '✅ ' : '❌ ') + (payload.message || '') + '</span>';
         })
         .catch(function () {
            resultEl.innerHTML = '<span style="color:#b5179e;font-weight:600">❌ Falha inesperada ao enviar.</span>';
         })
         .finally(function () {
            btn.disabled = false;
            btn.innerHTML = originalHtml;
         });
   });
})();
</script>
HTML;
   }

   private static function disabled(bool $disabled): string
   {
      return $disabled ? ' disabled' : '';
   }

   private static function cleanQueryString($value): string
   {
      $value = trim(str_replace(["\r\n", "\r", "\n"], '&', (string)$value));

      if ($value === '') {
         return '';
      }

      if (str_contains($value, '?')) {
         $query = parse_url($value, PHP_URL_QUERY);
         if (is_string($query)) {
            $value = $query;
         }
      }

      return ltrim(trim($value), '?&');
   }

   private static function cleanList($value): string
   {
      if (is_array($value)) {
         $value = implode(',', $value);
      }

      $parts = preg_split('/[\r\n,;]+/', (string)$value) ?: [];
      $clean = [];

      foreach ($parts as $part) {
         $part = trim($part);
         if ($part !== '') {
            $clean[strtolower($part)] = $part;
         }
      }

      return implode(', ', array_values($clean));
   }

   private static function cleanEmailList($value): string
   {
      $parts = preg_split('/[\r\n,;\s]+/', (string)$value) ?: [];
      $clean = [];

      foreach ($parts as $part) {
         $part = trim($part);
         if ($part !== '' && filter_var($part, FILTER_VALIDATE_EMAIL)) {
            $clean[strtolower($part)] = $part;
         }
      }

      return implode(', ', array_values($clean));
   }

   /**
    * @return string[] Lista de e-mails de alerta configurados.
    */
   public static function alertEmails(?array $config = null): array
   {
      $config ??= self::getConfig();
      $emails = preg_split('/[\r\n,;\s]+/', (string)($config['alert_emails'] ?? '')) ?: [];

      return array_values(array_filter(array_map('trim', $emails), static fn($e): bool => $e !== ''));
   }

   public static function parseSiteEntityMap(string $map): array
   {
      $result = [];

      foreach (preg_split('/[\r\n]+/', $map) ?: [] as $line) {
         $line = trim($line);
         if ($line === '' || !str_contains($line, '=')) {
            continue;
         }

         [$site, $entityId] = explode('=', $line, 2);
         $site = trim($site);
         $entityId = (int)trim($entityId);

         if ($site !== '' && $entityId >= 0) {
            $result[$site] = $entityId;
         }
      }

      return $result;
   }

   private static function cleanSiteEntityMap($value): string
   {
      $lines = [];

      foreach (preg_split('/[\r\n]+/', (string)$value) ?: [] as $line) {
         $line = trim($line);
         if ($line === '' || !str_contains($line, '=')) {
            continue;
         }

         [$site, $entityId] = explode('=', $line, 2);
         $site = trim($site);
         $entityId = (int)trim($entityId);

         if ($site !== '' && $entityId >= 0) {
            $lines[] = $site . '=' . $entityId;
         }
      }

      return implode("\n", $lines);
   }

   private static function boolInput(array $input, string $key): string
   {
      return isset($input[$key]) && (string)$input[$key] === '1' ? '1' : '0';
   }

   private static function cleanDate(string $value): string
   {
      $value = trim($value);
      if ($value === '') {
         return '';
      }
      $ts = strtotime($value);
      return $ts !== false ? date('Y-m-d', $ts) : '';
   }

   private static function protectSecret(string $secret): string
   {
      if ($secret === '' || str_starts_with($secret, self::SECRET_PREFIX)) {
         return $secret;
      }

      if (class_exists(\GLPIKey::class)) {
         $key = new \GLPIKey();
         if (method_exists($key, 'encrypt')) {
            $encrypted = $key->encrypt($secret);
            if (is_string($encrypted) && $encrypted !== '') {
               return self::SECRET_PREFIX . $encrypted;
            }
         }
      }

      // Fallback: armazena em texto puro quando a criptografia nao esta disponivel.
      // Preferivel a perder o token silenciosamente (o que causaria erro 401 no sync).
      trigger_error(
         'SentinelOne: GLPIKey indisponivel ou falhou — token salvo em texto puro. Configure a chave do GLPI para habilitar criptografia.',
         E_USER_WARNING
      );
      return $secret;
   }

   private static function unprotectSecret(string $secret): string
   {
      if ($secret === '' || !str_starts_with($secret, self::SECRET_PREFIX)) {
         return $secret;
      }

      if (!class_exists(\GLPIKey::class)) {
         trigger_error('SentinelOne: GLPIKey indisponivel — token nao pode ser descriptografado. Recadastre o token na configuracao do plugin.', E_USER_WARNING);
         return '';
      }

      $key = new \GLPIKey();
      if (!method_exists($key, 'decrypt')) {
         trigger_error('SentinelOne: GLPIKey sem metodo decrypt — token nao pode ser descriptografado. Recadastre o token na configuracao do plugin.', E_USER_WARNING);
         return '';
      }

      try {
         $decrypted = (string)$key->decrypt(substr($secret, strlen(self::SECRET_PREFIX)));
         if ($decrypted === '') {
            trigger_error('SentinelOne: Descriptografia do token retornou vazio (a chave GLPI pode ter mudado apos reinicializacao do container). Recadastre o token na configuracao do plugin.', E_USER_WARNING);
         }
         return $decrypted;
      } catch (\Throwable $error) {
         trigger_error('SentinelOne: Falha ao descriptografar token (' . $error->getMessage() . '). Recadastre o token na configuracao do plugin.', E_USER_WARNING);
         return '';
      }
   }

   private static function h(string $value): string
   {
      return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
   }
}

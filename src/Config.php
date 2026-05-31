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
         'ticket_status_filter' => '',
         'ticket_classification_filter' => '',
         'ticket_category_id'   => '0',
         'ticket_requester_id'  => '0',
         'ticket_urgency'       => '4',
         'ticket_impact'        => '4',
         'ticket_priority'      => '4',
         'allow_remote_actions' => '0',
         'write_antivirus'      => '1',
         'create_agent_tickets' => '0',
         'ticket_offline_hours' => '24',
         'min_agent_version'    => '',
         'alert_emails'         => '',
         'alert_on_critical_threat' => '0',
         'alert_on_agent_issue' => '0',
      ];
   }

   /**
    * Endpoints da API SentinelOne pre-configurados (escolhas automaticas).
    */
   public static function basePathPresets(): array
   {
      return [
         '/web/api/v2.1' => 'API v2.1 - recomendado',
         '/web/api/v2.0' => 'API v2.0 - legado',
      ];
   }

   /**
    * Esquemas de autenticacao suportados pela API SentinelOne.
    */
   public static function authSchemePresets(): array
   {
      return [
         'ApiToken' => 'ApiToken - recomendado',
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
      $config['api_token'] = self::unprotectSecret((string)$config['api_token']);

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
      $config['ticket_status_filter'] = self::cleanList($input['ticket_status_filter'] ?? '');
      $config['ticket_classification_filter'] = self::cleanList($input['ticket_classification_filter'] ?? '');
      $config['ticket_category_id'] = (string)max(0, (int)($input['ticket_category_id'] ?? 0));
      $config['ticket_requester_id'] = (string)max(0, (int)($input['ticket_requester_id'] ?? 0));
      $config['ticket_urgency'] = (string)max(1, min(5, (int)($input['ticket_urgency'] ?? 4)));
      $config['ticket_impact'] = (string)max(1, min(5, (int)($input['ticket_impact'] ?? 4)));
      $config['ticket_priority'] = (string)max(1, min(6, (int)($input['ticket_priority'] ?? 4)));
      $config['allow_remote_actions'] = self::boolInput($input, 'allow_remote_actions');
      $config['write_antivirus'] = self::boolInput($input, 'write_antivirus');
      $config['create_agent_tickets'] = self::boolInput($input, 'create_agent_tickets');
      $config['ticket_offline_hours'] = (string)max(1, min(8760, (int)($input['ticket_offline_hours'] ?? 24)));
      $config['min_agent_version'] = trim((string)($input['min_agent_version'] ?? ''));
      $config['alert_emails'] = self::cleanEmailList($input['alert_emails'] ?? '');
      $config['alert_on_critical_threat'] = self::boolInput($input, 'alert_on_critical_threat');
      $config['alert_on_agent_issue'] = self::boolInput($input, 'alert_on_agent_issue');

      $token = trim((string)($input['api_token'] ?? ''));
      if ($token !== '' || !$keepExistingToken) {
         $config['api_token'] = $token;
      }

      return $config;
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
      $tokenStatus = trim((string)$config['api_token']) !== '' ? 'Token cadastrado' : 'Token nao cadastrado';
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
      echo "<h2>Integracao da API</h2>";
      echo "<p>Console, token, sincronizacao e automacoes do plugin.</p>";
      echo "</div>";
      echo "</div>";
      echo "<div class='sentinelone-config__status " . ($configured ? 'is-ok' : 'is-warn') . "'>";
      echo "<span class='ti " . ($configured ? 'ti-circle-check' : 'ti-alert-triangle') . "'></span>";
      echo $configured ? 'Configurada' : 'Pendente';
      echo "</div>";
      echo "</div>";

      if ($flash !== null) {
         self::renderConnectionTestFlash($flash);
      }

      echo "<div id='sentinelone-test-result' class='sentinelone-test-result sentinelone-test-result--hidden' aria-live='polite'></div>";

      echo "<div class='sentinelone-config__grid'>";

      echo "<section class='sentinelone-panel sentinelone-panel--wide'>";
      self::panelHead('Conexao', 'Console, endpoint da API, autenticacao e links da console.', 'ti-plug-connected', "<span class='sentinelone-token-state'>" . self::h($tokenStatus) . "</span>");
      echo "<div class='sentinelone-panel__body sentinelone-fields'>";
      self::renderYesNo('enabled', 'Integracao ativa', (string)$config['enabled'] === '1', $canUpdate, 'Interruptor geral: sincronizacoes e automacoes so rodam com isto em Sim.');
      self::renderText('base_url', 'URL da console', (string)$config['base_url'], 'https://sua-console.sentinelone.net', $canUpdate, false, 'Endereco da sua console, sem barra no final.');
      self::renderPreset('base_path', 'Endpoint da API', self::basePathPresets(), (string)$config['base_path'], 'Escolha a versao da API. Use "Personalizado" so para tenants com caminho diferente.', $canUpdate, '/web/api/v2.1');
      self::renderPreset('auth_scheme', 'Autenticacao', self::authSchemePresets(), (string)$config['auth_scheme'], 'ApiToken atende a maioria dos tenants SentinelOne.', $canUpdate, 'ApiToken');
      self::renderPassword('api_token', 'Token da API', $tokenStatus, $canUpdate);
      self::renderNumber('timeout', 'Timeout HTTP em segundos', (int)$config['timeout'], 5, 120, $canUpdate, 'Tempo maximo de espera por resposta da API.');
      self::renderText('console_threat_path', 'Deep link de ameaca (opcional, use {threatId})', (string)$config['console_threat_path'], '/incidents/threats/{threatId}/overview', $canUpdate, true, 'Abre a ameaca direto na console. Vazio = sem link.');
      self::renderText('console_endpoint_path', 'Deep link de endpoint (opcional, use {agentId})', (string)$config['console_endpoint_path'], '/inventory/devices/{agentId}', $canUpdate, true, 'Abre o endpoint direto na console. Vazio = sem link.');
      echo "</div>";
      echo "</section>";

      echo "<section class='sentinelone-panel'>";
      self::panelHead('Sincronizacao', 'Quanto buscar por execucao e onde gravar.', 'ti-refresh');
      echo "<div class='sentinelone-panel__body sentinelone-fields'>";
      self::renderNumber('sync_limit', 'Itens por pagina', (int)$config['sync_limit'], 1, 1000, $canUpdate, 'Quantos itens o plugin pede por pagina a API.');
      self::renderNumber('max_pages', 'Maximo de paginas', (int)$config['max_pages'], 1, 500, $canUpdate, 'Limite de paginas por execucao (protege contra cargas enormes).');
      self::renderEntityDropdown('entity_id', 'Entidade padrao GLPI', (int)$config['entity_id'], $canUpdate);
      self::renderText('agent_filter_query', 'Filtro de agentes', (string)$config['agent_filter_query'], 'isActive=true', $canUpdate, true, 'Opcional, no formato query string da API SentinelOne.');
      self::renderText('threat_filter_query', 'Filtro de ameacas', (string)$config['threat_filter_query'], 'mitigationStatuses=unmitigated', $canUpdate, true, 'Opcional, no formato query string da API SentinelOne.');
      echo "</div>";
      echo "</section>";

      echo "<section class='sentinelone-panel'>";
      self::panelHead('Automacao', 'O que o plugin faz automaticamente.', 'ti-robot');
      echo "<div class='sentinelone-panel__body sentinelone-fields'>";
      self::renderYesNo('create_tickets', 'Criar tickets para ameacas', (string)$config['create_tickets'] === '1', $canUpdate, 'Interruptor geral dos tickets de ameaca. Precisa de pelo menos uma regra abaixo.');
      self::renderYesNo('write_antivirus', 'Registrar como antivirus do computador', (string)$config['write_antivirus'] === '1', $canUpdate, 'Grava o SentinelOne na aba Antivirus de cada computador vinculado.');
      self::renderYesNo('allow_remote_actions', 'Permitir acoes remotas', (string)$config['allow_remote_actions'] === '1', $canUpdate, 'Reservado para acoes remotas (isolar/scan). Ainda nao executa nada.');
      echo "</div>";
      echo "</section>";

      echo "<section class='sentinelone-panel sentinelone-panel--wide'>";
      self::panelHead('Regras de ticket', 'Status E classificacao precisam casar; campo vazio = todos; ameacas resolvidas sao ignoradas.', 'ti-ticket');
      $ticketRulesConfigured = trim((string)$config['ticket_status_filter']) !== ''
         || trim((string)$config['ticket_classification_filter']) !== '';
      if ((string)$config['create_tickets'] === '1' && !$ticketRulesConfigured) {
         echo "<div class='sentinelone-inline-warning'>";
         echo "<span class='ti ti-alert-triangle'></span>";
         echo "<span><strong>Aguardando regras.</strong> A criacao de tickets esta ligada, mas nenhuma regra de status ou classificacao foi definida &mdash; nenhum ticket sera aberto ate preencher pelo menos um dos campos abaixo.</span>";
         echo "</div>";
      }
      echo "<div class='sentinelone-panel__body sentinelone-fields'>";
      self::renderMultiSelect('ticket_status_filter', 'Criar tickets somente para status', self::threatStatusOptions(), (string)$config['ticket_status_filter'], $canUpdate, 'Vazio = qualquer status (OU entre os escolhidos). Ameacas resolvidas/mitigadas sao sempre ignoradas.');
      self::renderMultiSelect('ticket_classification_filter', 'Criar tickets somente para classificacoes', self::threatClassificationOptions(), (string)$config['ticket_classification_filter'], $canUpdate, 'Vazio = qualquer classificacao. Combina em E (AND) com o filtro de status.');
      self::renderTicketCategoryDropdown('ticket_category_id', 'Categoria GLPI do ticket', (int)$config['ticket_category_id'], $canUpdate);
      self::renderUserDropdown('ticket_requester_id', 'Usuario solicitante (integracao)', (int)$config['ticket_requester_id'], $canUpdate, 'Todos os tickets abrem com este usuario como solicitante/autor. Crie um usuario dedicado (ex.: "integracao") para identificar os chamados do plugin.');
      self::renderSelectFromArray('ticket_urgency', 'Urgencia', self::ticketScaleOptions(false), (int)$config['ticket_urgency'], $canUpdate);
      self::renderSelectFromArray('ticket_impact', 'Impacto', self::ticketScaleOptions(false), (int)$config['ticket_impact'], $canUpdate);
      self::renderSelectFromArray('ticket_priority', 'Prioridade', self::ticketScaleOptions(true), (int)$config['ticket_priority'], $canUpdate);
      echo "</div>";
      echo "</section>";

      echo "<section class='sentinelone-panel sentinelone-panel--wide'>";
      self::panelHead('Saude de agentes e alertas', 'Tickets por problema de agente e e-mails de alerta.', 'ti-heartbeat');
      echo "<div class='sentinelone-panel__body sentinelone-fields'>";
      self::renderYesNo('create_agent_tickets', 'Criar tickets de saude do agente', (string)$config['create_agent_tickets'] === '1', $canUpdate, 'Abre um ticket por agente com problema (offline/infectado/desatualizado).');
      self::renderNumber('ticket_offline_hours', 'Horas offline para abrir ticket', (int)$config['ticket_offline_hours'], 1, 8760, $canUpdate, 'A partir de quantas horas sem contato o agente vira um problema.');
      self::renderText('min_agent_version', 'Versao minima do agente (opcional)', (string)$config['min_agent_version'], 'ex.: 23.4.2.14', $canUpdate, false, 'Abaixo desta versao o agente e considerado desatualizado. Vazio = nao checa.');
      self::renderText('alert_emails', 'E-mails para alertas (separados por virgula)', (string)$config['alert_emails'], 'soc@empresa.com, ti@empresa.com', $canUpdate, true, 'Destinatarios dos alertas. Requer e-mail/SMTP configurado no GLPI.');
      self::renderYesNo('alert_on_critical_threat', 'Enviar e-mail em ameaca critica', (string)$config['alert_on_critical_threat'] === '1', $canUpdate, 'Envia quando uma nova ameaca critica e sincronizada.');
      self::renderYesNo('alert_on_agent_issue', 'Enviar e-mail em problema de agente', (string)$config['alert_on_agent_issue'] === '1', $canUpdate, 'Enviado junto com a abertura do ticket de saude do agente.');
      echo "</div>";
      echo "</section>";
      echo "</div>";

      echo "<div class='sentinelone-config__actions'>";
      echo "<button class='btn btn-primary' type='submit' name='update' value='1'" . (!$canUpdate ? ' disabled' : '') . "><span class='ti ti-device-floppy'></span>Salvar</button>";
      echo "<button class='btn btn-outline-primary' type='submit' name='test' value='1' data-sentinelone-test" . (!$canUpdate ? ' disabled' : '') . "><span class='ti ti-plug-connected'></span>Testar conexao</button>";
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
      echo "<small>Deixe em branco para manter o token atual.</small>";
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
      echo "<option value='__custom__'" . ($isCustom ? ' selected' : '') . ">Personalizado...</option>";
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

   private static function renderYesNo(string $name, string $label, bool $selected, bool $enabled = true, ?string $help = null): void
   {
      echo "<label class='sentinelone-field'>";
      echo "<span>" . self::h($label) . "</span>";
      echo "<select class='form-select' name='" . self::h($name) . "'" . self::disabled(!$enabled) . ">";
      echo "<option value='0'" . (!$selected ? ' selected' : '') . ">Nao</option>";
      echo "<option value='1'" . ($selected ? ' selected' : '') . ">Sim</option>";
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
      echo "<small>Usada para gravar agentes, ameacas e tickets criados pela integracao.</small>";
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
         'emptylabel'          => 'Sem categoria',
         'readonly'            => !$enabled,
      ]);
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
         'emptylabel'          => 'Sem usuario (padrao do GLPI)',
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
         'active'        => 'Ativo (active)',
         'unmitigated'   => 'Nao mitigado (unmitigated)',
         'not_mitigated' => 'Nao mitigado (not_mitigated)',
         'blocked'       => 'Bloqueado (blocked)',
         'suspicious'    => 'Suspeito (suspicious)',
         'pending'       => 'Pendente (pending)',
      ];
   }

   /**
    * Classificacoes de ameaca do SentinelOne (threatInfo.classification).
    * @return array<string, string>
    */
   private static function threatClassificationOptions(): array
   {
      return [
         'malware'     => 'Malware',
         'ransomware'  => 'Ransomware',
         'trojan'      => 'Trojan',
         'virus'       => 'Virus',
         'worm'        => 'Worm',
         'backdoor'    => 'Backdoor',
         'exploit'     => 'Exploit',
         'pua'         => 'PUA (potencialmente indesejado)',
         'adware'      => 'Adware',
         'spyware'     => 'Spyware',
         'rootkit'     => 'Rootkit',
         'hacktool'    => 'Hacktool',
         'downloader'  => 'Downloader',
         'dropper'     => 'Dropper',
         'infostealer' => 'Infostealer',
         'phishing'    => 'Phishing',
         'generic'     => 'Generic',
         'unknown'     => 'Unknown',
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
         1 => '1 - Muito baixa',
         2 => '2 - Baixa',
         3 => '3 - Media',
         4 => '4 - Alta',
         5 => '5 - Muito alta',
      ];

      if ($includeMajor) {
         $options[6] = '6 - Critica';
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
      $title = $ok ? 'Conexao OK' : 'Falha na conexao';

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

   private static function boolInput(array $input, string $key): string
   {
      return isset($input[$key]) && (string)$input[$key] === '1' ? '1' : '0';
   }

   private static function protectSecret(string $secret): string
   {
      if ($secret === '' || str_starts_with($secret, self::SECRET_PREFIX)) {
         return $secret;
      }

      if (class_exists(\GLPIKey::class)) {
         $key = new \GLPIKey();
         if (method_exists($key, 'encrypt')) {
            return self::SECRET_PREFIX . $key->encrypt($secret);
         }
      }

      return $secret;
   }

   private static function unprotectSecret(string $secret): string
   {
      if ($secret === '' || !str_starts_with($secret, self::SECRET_PREFIX)) {
         return $secret;
      }

      if (!class_exists(\GLPIKey::class)) {
         return '';
      }

      $key = new \GLPIKey();
      if (!method_exists($key, 'decrypt')) {
         return '';
      }

      try {
         return (string)$key->decrypt(substr($secret, strlen(self::SECRET_PREFIX)));
      } catch (\Throwable $error) {
         return '';
      }
   }

   private static function h(string $value): string
   {
      return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
   }
}

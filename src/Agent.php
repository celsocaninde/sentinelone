<?php

namespace GlpiPlugin\Sentinelone;

class Agent extends \CommonDBTM
{
   public static $rightname = 'plugin_sentinelone_read';

   public static function getTypeName($nb = 0): string
   {
      return $nb > 1 ? __('Agentes SentinelOne', 'sentinelone') : __('Agente SentinelOne', 'sentinelone');
   }

   public static function getMenuName(): string
   {
      return 'SentinelOne';
   }

   public static function getFormURL($full = true): string
   {
      global $CFG_GLPI;
      $url = $CFG_GLPI['root_doc'] . '/plugins/sentinelone/front/agent.form.php';
      return $full ? $url : $url;
   }

   public static function getFormURLWithID($id = 0, $full = true): string
   {
      return static::getFormURL($full) . '?id=' . (int)$id;
   }

   public static function getMenuContent(): array
   {
      global $CFG_GLPI;

      return [
         'title' => self::getMenuName(),
         'page'  => $CFG_GLPI['root_doc'] . '/plugins/sentinelone/front/dashboard.php',
         'icon'  => 'ti ti-shield',
         'links' => [
            'search' => $CFG_GLPI['root_doc'] . '/plugins/sentinelone/front/agent.php',
            __('Rogues', 'sentinelone') => $CFG_GLPI['root_doc'] . '/plugins/sentinelone/front/rogues.php',
            'config' => $CFG_GLPI['root_doc'] . '/plugins/sentinelone/front/config.form.php',
         ],
      ];
   }

   public function rawSearchOptions(): array
   {
      $tab = [];

      $tab[] = [
         'id'   => 'common',
         'name' => self::getTypeName(2),
      ];
      $tab[] = [
         'id'       => 1,
         'table'    => self::getTable(),
         'field'    => 'computer_name',
         'name'     => __('Computador', 'sentinelone'),
         'datatype' => 'string',
      ];
      $tab[] = [
         'id'       => 2,
         'table'    => self::getTable(),
         'field'    => 'sentinelone_id',
         'name'     => __('ID SentinelOne', 'sentinelone'),
         'datatype' => 'string',
      ];
      $tab[] = [
         'id'       => 3,
         'table'    => self::getTable(),
         'field'    => 'agent_version',
         'name'     => __('Versao do agente', 'sentinelone'),
         'datatype' => 'string',
      ];
      $tab[] = [
         'id'       => 4,
         'table'    => self::getTable(),
         'field'    => 'is_online',
         'name'     => __('Online', 'sentinelone'),
         'datatype' => 'bool',
      ];
      $tab[] = [
         'id'       => 5,
         'table'    => self::getTable(),
         'field'    => 'is_infected',
         'name'     => __('Infectado', 'sentinelone'),
         'datatype' => 'bool',
      ];
      $tab[] = [
         'id'       => 6,
         'table'    => self::getTable(),
         'field'    => 'last_active_at',
         'name'     => __('Ultimo contato', 'sentinelone'),
         'datatype' => 'datetime',
      ];
      $tab[] = [
         'id'       => 7,
         'table'    => self::getTable(),
         'field'    => 'is_network_quarantine',
         'name'     => __('Em quarentena', 'sentinelone'),
         'datatype' => 'bool',
      ];
      $tab[] = [
         'id'       => 8,
         'table'    => self::getTable(),
         'field'    => 'group_name',
         'name'     => __('Grupo', 'sentinelone'),
         'datatype' => 'string',
      ];
      $tab[] = [
         'id'       => 9,
         'table'    => self::getTable(),
         'field'    => 'site_name',
         'name'     => __('Site', 'sentinelone'),
         'datatype' => 'string',
      ];
      $tab[] = [
         'id'       => 10,
         'table'    => self::getTable(),
         'field'    => 'os_name',
         'name'     => __('Sistema operacional', 'sentinelone'),
         'datatype' => 'string',
      ];
      $tab[] = [
         'id'       => 11,
         'table'    => self::getTable(),
         'field'    => 'ip',
         'name'     => __('IP', 'sentinelone'),
         'datatype' => 'string',
      ];

      return $tab;
   }

   public function getTabNameForItem(\CommonGLPI $item, $withtemplate = 0): string
   {
      if ($item instanceof \Computer && Profile::hasReadRight()) {
         return 'SentinelOne';
      }

      return '';
   }

   public static function displayTabContentForItem(\CommonGLPI $item, $tabnum = 1, $withtemplate = 0): bool
   {
      if ($item instanceof \Computer) {
         self::showForComputer((int)$item->getID());
      }

      return true;
   }

   public static function showForComputer(int $computersId): void
   {
      global $DB;

      $agent = null;
      foreach ($DB->request([
         'FROM'  => self::getTable(),
         'WHERE' => ['computers_id' => $computersId],
         'LIMIT' => 1,
      ]) as $row) {
         $agent = $row;
      }

      if ($agent === null) {
         echo "<div class='alert alert-info'>" . __('Nenhum agente SentinelOne vinculado a este computador.', 'sentinelone') . "</div>";
         return;
      }

      $config = Config::getConfig();
      $consoleUrl = trim((string)($config['base_url'] ?? ''));
      $endpointUrl = Config::consoleEndpointUrl($config, (string)$agent['sentinelone_id']);
      $linkUrl = $endpointUrl !== '' ? $endpointUrl : $consoleUrl;
      $linkLabel = $endpointUrl !== '' ? __('Abrir endpoint', 'sentinelone') : __('Console', 'sentinelone');
      $online = (int)$agent['is_online'] === 1;
      $infected = (int)$agent['is_infected'] === 1;
      $title = trim((string)$agent['computer_name']) !== '' ? (string)$agent['computer_name'] : 'Endpoint';
      $agentVersion = trim((string)($agent['agent_version'] ?? ''));
      $minVersion = trim((string)($config['min_agent_version'] ?? ''));
      $versionOutdated = $minVersion !== '' && $agentVersion !== '' && version_compare($agentVersion, $minVersion, '<');

      echo "<div class='s1-asset-card'>";
      echo "<div class='s1-asset-card__head'>";
      echo "<span class='s1-logo'><span class='ti ti-shield-half-filled'></span></span>";
      echo "<div>";
      echo "<h3>SentinelOne</h3>";
      echo "<small>" . self::h($title) . "</small>";
      echo "</div>";
      echo "<div class='s1-asset-card__spacer'></div>";
      echo $infected
         ? "<span class='s1-badge s1-badge--critical'>" . __('infectado', 'sentinelone') . "</span>"
         : "<span class='s1-badge s1-badge--ok'>" . __('limpo', 'sentinelone') . "</span>";
      echo $online
         ? "<span class='s1-badge s1-badge--ok'>" . __('online', 'sentinelone') . "</span>"
         : "<span class='s1-badge s1-badge--muted'>" . __('offline', 'sentinelone') . "</span>";
      if ($versionOutdated) {
         echo "<span class='s1-badge s1-badge--warning' title='" . sprintf(__('Versao minima configurada: %s', 'sentinelone'), self::h($minVersion)) . "'>\u{26A0} " . __('versao desatualizada', 'sentinelone') . "</span>";
      }
      if ($linkUrl !== '') {
         echo "<a class='btn btn-sm btn-light' href='" . self::h($linkUrl) . "' target='_blank' rel='noopener'><span class='ti ti-external-link'></span>" . self::h($linkLabel) . "</a>";
      }
      echo "</div>";
      echo "<div class='s1-asset-card__body'>";
      echo "<div class='s1-kv'>";
      self::kv(__('ID SentinelOne', 'sentinelone'), (string)$agent['sentinelone_id']);
      self::kv(__('Serial', 'sentinelone'), (string)$agent['serial']);
      self::kv(__('UUID', 'sentinelone'), (string)$agent['uuid']);
      self::kv(__('Sistema operacional', 'sentinelone'), (string)$agent['os_name']);
      self::kv(__('Versao do agente', 'sentinelone'), $agentVersion . ($versionOutdated ? ' ⚠ (' . sprintf(__('desatualizada, min: %s', 'sentinelone'), $minVersion) . ')' : ''));
      self::kv(__('Site', 'sentinelone'), (string)$agent['site_name']);
      self::kv(__('Grupo', 'sentinelone'), (string)$agent['group_name']);
      self::kv(__('IP', 'sentinelone'), (string)($agent['ip'] ?? ''));
      self::kv(__('MAC', 'sentinelone'), (string)($agent['mac'] ?? ''));
      self::kv(__('Ultimo contato', 'sentinelone'), (string)$agent['last_active_at']);
      $extra = self::extractExtraFields((string)($agent['raw_json'] ?? ''));
      if ($extra !== []) {
         echo "<div class='sentinelone-panel sentinelone-panel--extra' style='margin-top:12px;padding:0 20px 12px'>";
         echo "<div class='sentinelone-panel__head' style='padding-left:0;padding-right:0'><h3 style='font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:#6b7280'>" . __('Detalhes do endpoint', 'sentinelone') . "</h3></div>";
         echo "<div class='s1-kv'>";
         foreach ($extra as $label => $value) {
            self::kv($label, $value);
         }
         echo "</div>";
         echo "</div>";
      }

      echo "</div>";
      echo "</div>";
      echo "</div>";

      Threat::showForAgent((string)$agent['sentinelone_id']);
      self::showActivityFeed((string)$agent['sentinelone_id']);
      Cve::showForAgent((int)$agent['id']);
   }

   public static function getUnlinkedDiagnostics(int $limit = 80): array
   {
      global $DB;

      $limit = max(10, min(200, $limit));
      $rows = [];

      foreach ($DB->request([
         'FROM'  => self::getTable(),
         'WHERE' => ['computers_id' => null],
         'ORDER' => ['last_active_at DESC', 'id DESC'],
         'LIMIT' => $limit,
      ]) as $agent) {
         $checks = self::getComputerMatchChecks($agent);
         $rows[] = [
            'agent'      => $agent,
            'checks'     => $checks,
            'summary'    => self::summarizeMatch($checks),
         ];
      }

      return [
         'summary' => [
            'agents_total'       => self::countRows(self::getTable()),
            'agents_unlinked'    => self::countRows(self::getTable(), ['computers_id' => null]),
            'agents_with_name'   => self::countRows(self::getTable(), ['NOT' => ['computer_name' => null]]),
            'agents_with_serial' => self::countRows(self::getTable(), ['NOT' => ['serial' => null]]),
            'agents_with_uuid'   => self::countRows(self::getTable(), ['NOT' => ['uuid' => null]]),
            'agents_with_mac'    => self::countRows(self::getTable(), ['NOT' => ['mac' => null]]),
            'glpi_computers'     => self::countRows('glpi_computers', ['is_deleted' => 0]),
         ],
         'rows'    => $rows,
         'limit'   => $limit,
      ];
   }

   /**
    * Computadores do GLPI que NAO possuem agente SentinelOne vinculado.
    */
   public static function getUnprotectedComputers(int $limit = 100): array
   {
      global $DB;

      $limit = max(10, min(500, $limit));
      $rows = [];

      if ($DB->tableExists('glpi_computers')) {
         foreach ($DB->request([
            'SELECT'    => ['c.id', 'c.name', 'c.serial', 'c.entities_id', 'c.date_mod'],
            'FROM'      => 'glpi_computers AS c',
            'LEFT JOIN' => [
               self::getTable() . ' AS a' => [
                  'ON' => ['a' => 'computers_id', 'c' => 'id'],
               ],
            ],
            'WHERE'     => self::unprotectedWhere(),
            'ORDER'     => ['c.name ASC'],
            'LIMIT'     => $limit,
         ]) as $row) {
            $rows[] = $row;
         }
      }

      return [
         'rows'    => $rows,
         'limit'   => $limit,
         'summary' => [
            'computers_total'   => self::countRows('glpi_computers', ['is_deleted' => 0, 'is_template' => 0]),
            'agents_total'      => self::countRows(self::getTable()),
            'agents_linked'     => self::countRows(self::getTable(), ['NOT' => ['computers_id' => null]]),
            'unprotected_total' => self::countUnprotectedComputers(),
         ],
      ];
   }

   public static function countUnprotectedComputers(): int
   {
      global $DB;

      if (!$DB->tableExists('glpi_computers') || !$DB->tableExists(self::getTable())) {
         return 0;
      }

      $row = $DB->request([
         'COUNT'     => 'cpt',
         'FROM'      => 'glpi_computers AS c',
         'LEFT JOIN' => [
            self::getTable() . ' AS a' => [
               'ON' => ['a' => 'computers_id', 'c' => 'id'],
            ],
         ],
         'WHERE'     => self::unprotectedWhere(),
      ])->current();

      return (int)($row['cpt'] ?? 0);
   }

   private static function unprotectedWhere(): array
   {
      $where = [
         'a.id'          => null,
         'c.is_deleted'  => 0,
         'c.is_template' => 0,
      ];

      $entities = $_SESSION['glpiactiveentities'] ?? null;
      if (is_array($entities) && $entities !== []) {
         $where['c.entities_id'] = $entities;
      }

      return $where;
   }

   private static function getComputerMatchChecks(array $agent): array
   {
      $checks = [];
      $name = trim((string)($agent['computer_name'] ?? ''));
      $serial = trim((string)($agent['serial'] ?? ''));
      $uuid = trim((string)($agent['uuid'] ?? ''));
      $mac = trim((string)($agent['mac'] ?? ''));

      $checks[] = [
         'label'      => __('Nome exato', 'sentinelone'),
         'value'      => $name,
         'candidates' => self::findComputerCandidatesByField('name', $name),
      ];

      $shortName = $name !== '' ? preg_replace('/\..*$/', '', $name) : '';
      if (is_string($shortName) && $shortName !== '' && $shortName !== $name) {
         $checks[] = [
            'label'      => __('Nome curto', 'sentinelone'),
            'value'      => $shortName,
            'candidates' => self::findComputerCandidatesByField('name', $shortName),
         ];
      }

      $checks[] = [
         'label'      => __('Serial', 'sentinelone'),
         'value'      => $serial,
         'candidates' => self::findComputerCandidatesByField('serial', $serial),
      ];

      $checks[] = [
         'label'      => __('UUID', 'sentinelone'),
         'value'      => $uuid,
         'candidates' => self::findComputerCandidatesByField('uuid', $uuid),
      ];

      $checks[] = [
         'label'      => __('MAC', 'sentinelone'),
         'value'      => $mac,
         'candidates' => self::findComputerCandidatesByMac($mac),
      ];

      return $checks;
   }

   private static function summarizeMatch(array $checks): array
   {
      $candidateIds = [];

      foreach ($checks as $check) {
         foreach ($check['candidates'] as $candidate) {
            $candidateIds[(int)$candidate['id']] = true;
         }
      }

      if ($candidateIds !== []) {
         return [
            'status'  => 'candidate',
            'message' => sprintf(__('%d possivel(is) computador(es) GLPI encontrado(s). Rode nova sincronizacao de agentes para tentar vincular.', 'sentinelone'), count($candidateIds)),
         ];
      }

      if (self::countRows('glpi_computers', ['is_deleted' => 0]) <= 1) {
         return [
            'status'  => 'inventory',
            'message' => __('Inventario GLPI insuficiente: ha poucos computadores ativos para casar com os agentes SentinelOne.', 'sentinelone'),
         ];
      }

      return [
         'status'  => 'missing',
         'message' => __('Nenhum match exato por nome, serial, UUID ou MAC.', 'sentinelone'),
      ];
   }

   private static function findComputerCandidatesByField(string $field, string $value): array
   {
      global $DB;

      $value = trim($value);
      if ($value === '' || !self::fieldExists('glpi_computers', $field)) {
         return [];
      }

      return self::findComputers([
         $field       => $value,
         'is_deleted' => 0,
      ]);
   }

   private static function findComputerCandidatesByMac(string $mac): array
   {
      global $DB;

      $mac = strtolower(trim($mac));
      if ($mac === '' || !$DB->tableExists('glpi_networkports')) {
         return [];
      }

      $computerIds = [];
      foreach ($DB->request([
         'SELECT' => ['items_id'],
         'FROM'   => 'glpi_networkports',
         'WHERE'  => [
            'mac'      => array_values(array_unique([$mac, strtoupper($mac)])),
            'itemtype' => 'Computer',
         ],
         'LIMIT'  => 5,
      ]) as $row) {
         $computerIds[] = (int)$row['items_id'];
      }

      if ($computerIds === []) {
         return [];
      }

      return self::findComputers([
         'id'         => array_values(array_unique($computerIds)),
         'is_deleted' => 0,
      ]);
   }

   private static function findComputers(array $where): array
   {
      global $DB;

      $rows = [];
      if (!$DB->tableExists('glpi_computers')) {
         return $rows;
      }

      foreach ($DB->request([
         'SELECT' => ['id', 'name'],
         'FROM'   => 'glpi_computers',
         'WHERE'  => $where,
         'ORDER'  => ['name ASC'],
         'LIMIT'  => 5,
      ]) as $row) {
         $rows[] = [
            'id'   => (int)$row['id'],
            'name' => (string)$row['name'],
         ];
      }

      return $rows;
   }

   private static function countRows(string $table, array $where = []): int
   {
      global $DB;

      if (!$DB->tableExists($table)) {
         return 0;
      }

      $criteria = [
         'COUNT' => 'cpt',
         'FROM'  => $table,
      ];

      if ($where !== []) {
         $criteria['WHERE'] = $where;
      }

      $row = $DB->request($criteria)->current();

      return (int)($row['cpt'] ?? 0);
   }

   private static function fieldExists(string $table, string $field): bool
   {
      global $DB;

      return method_exists($DB, 'fieldExists') && $DB->fieldExists($table, $field);
   }

   private static function showActivityFeed(string $sentineloneAgentId): void
   {
      $config = Config::getConfig();

      if ((string)($config['sync_activities'] ?? '0') !== '1') {
         return;
      }

      $activities = Activity::getForAgent($sentineloneAgentId, 12);

      echo "<div class='sentinelone-panel' style='margin-top:16px'>";
      echo "<div class='sentinelone-panel__head'><h3>" . __('Atividades recentes (SentinelOne)', 'sentinelone') . "</h3></div>";
      echo "<div class='sentinelone-panel__body' style='padding:0'>";

      if ($activities === []) {
         echo "<div class='sentinelone-empty'>" . __('Nenhuma atividade sincronizada para este endpoint. Rode a sync de atividades para atualizar.', 'sentinelone') . "</div>";
      } else {
         echo "<ul class='s1-activity-feed'>";
         foreach ($activities as $act) {
            $typeCode = trim((string)($act['activity_type'] ?? ''));
            $label = Activity::labelForType($typeCode);
            $icon = Activity::iconForType($typeCode);
            $desc = trim((string)($act['description'] ?? ''));
            $date = trim((string)($act['occurred_at'] ?? ''));
            echo "<li class='s1-activity-feed__item'>";
            echo "<span class='ti " . self::h($icon) . " s1-activity-feed__icon'></span>";
            echo "<div class='s1-activity-feed__body'>";
            echo "<strong>" . self::h($label) . "</strong>";
            if ($desc !== '' && $desc !== $label) {
               echo "<span class='s1-activity-feed__desc'>" . self::h($desc) . "</span>";
            }
            if ($date !== '') {
               echo "<time class='s1-activity-feed__time'>" . self::h($date) . "</time>";
            }
            echo "</div>";
            echo "</li>";
         }
         echo "</ul>";
      }

      echo "</div>";
      echo "</div>";
   }

   private static function extractExtraFields(string $rawJson): array
   {
      if ($rawJson === '') {
         return [];
      }

      $raw = json_decode($rawJson, true);
      if (!is_array($raw)) {
         return [];
      }

      $fields = [];

      $policyName = self::deepGet($raw, ['policy', 'name']) ?? $raw['policyName'] ?? null;
      if ($policyName !== null && trim((string)$policyName) !== '') {
         $fields[__('Politica', 'sentinelone')] = (string)$policyName;
      }

      $accountName = $raw['accountName'] ?? null;
      if ($accountName !== null && trim((string)$accountName) !== '') {
         $fields[__('Conta', 'sentinelone')] = (string)$accountName;
      }

      $machineType = $raw['machineType'] ?? null;
      if ($machineType !== null && trim((string)$machineType) !== '') {
         $fields[__('Tipo de maquina', 'sentinelone')] = (string)$machineType;
      }

      $domain = $raw['domain'] ?? null;
      if ($domain !== null && trim((string)$domain) !== '') {
         $fields[__('Dominio', 'sentinelone')] = (string)$domain;
      }

      $networkStatus = $raw['networkStatus'] ?? null;
      if ($networkStatus !== null && trim((string)$networkStatus) !== '') {
         $fields[__('Status de rede', 'sentinelone')] = (string)$networkStatus;
      }

      $scanStatus = $raw['scanStatus'] ?? null;
      if ($scanStatus !== null && trim((string)$scanStatus) !== '') {
         $fields[__('Status de scan', 'sentinelone')] = (string)$scanStatus;
      }

      $externalIp = $raw['externalIp'] ?? null;
      if ($externalIp !== null && trim((string)$externalIp) !== '') {
         $fields[__('IP externo', 'sentinelone')] = (string)$externalIp;
      }

      $cpuCount = $raw['cpuCount'] ?? null;
      if ($cpuCount !== null && (int)$cpuCount > 0) {
         $fields[__('Nucleos de CPU', 'sentinelone')] = (string)(int)$cpuCount;
      }

      $totalMemory = $raw['totalMemory'] ?? null;
      if ($totalMemory !== null && (int)$totalMemory > 0) {
         $fields[__('Memoria (MB)', 'sentinelone')] = number_format((int)$totalMemory, 0, ',', '.');
      }

      $rebootRequired = $raw['threatRebootRequired'] ?? null;
      if ($rebootRequired !== null && (bool)$rebootRequired) {
         $fields[__('Reboot necessario', 'sentinelone')] = '⚠ ' . __('Sim', 'sentinelone');
      }

      $osType = $raw['osType'] ?? null;
      if ($osType !== null && trim((string)$osType) !== '') {
         $fields[__('Tipo de OS', 'sentinelone')] = (string)$osType;
      }

      return $fields;
   }

   private static function deepGet(array $array, array $keys)
   {
      $current = $array;
      foreach ($keys as $key) {
         if (!is_array($current) || !array_key_exists($key, $current)) {
            return null;
         }
         $current = $current[$key];
      }
      return $current !== null && $current !== '' ? $current : null;
   }

   private static function kv(string $label, string $value): void
   {
      $value = trim($value);
      echo "<div class='s1-kv__item'>";
      echo "<span>" . self::h($label) . "</span>";
      echo "<strong>" . self::h($value !== '' ? $value : '-') . "</strong>";
      echo "</div>";
   }

   private static function h(string $value): string
   {
      return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
   }
}

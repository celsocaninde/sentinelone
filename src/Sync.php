<?php

namespace GlpiPlugin\Sentinelone;

class Sync
{
   public static function getTypeName($nb = 0): string
   {
      return 'Sincronizacao SentinelOne';
   }

   public static function cronInfo(string $name): array
   {
      $info = [
         'syncagents' => [
            'description' => 'Sincroniza agentes SentinelOne com ativos do GLPI',
         ],
         'syncthreats' => [
            'description' => 'Sincroniza ameacas SentinelOne e cria tickets opcionais',
         ],
      ];

      return $info[strtolower($name)] ?? [];
   }

   public static function cronSyncagents(?\CronTask $task = null): int
   {
      try {
         $result = self::syncAgents();

         if ($task !== null) {
            $task->addVolume($result['processed']);
         }

         return 1;
      } catch (\Throwable $error) {
         Log::record('syncagents', 'error', $error->getMessage());
         return 0;
      }
   }

   public static function cronSyncthreats(?\CronTask $task = null): int
   {
      try {
         $result = self::syncThreats();

         if ($task !== null) {
            $task->addVolume($result['processed']);
         }

         return 1;
      } catch (\Throwable $error) {
         Log::record('syncthreats', 'error', $error->getMessage());
         return 0;
      }
   }

   public static function syncAgents(): array
   {
      $config = Config::getConfig();

      if (!Config::isConfigured($config)) {
         Log::record('syncagents', 'skipped', 'Integracao SentinelOne nao configurada.');
         return ['processed' => 0, 'created' => 0, 'updated' => 0];
      }

      $client = ApiClient::fromConfig($config);
      $params = self::apiParamsFromQueryString((string)($config['agent_filter_query'] ?? ''));
      $params['limit'] = (int)$config['sync_limit'];
      $agents = $client->getAgents($params, (int)$config['max_pages']);

      $created = 0;
      $updated = 0;

      foreach ($agents as $agent) {
         $result = self::upsertAgent($agent, $config);
         $created += $result === 'created' ? 1 : 0;
         $updated += $result === 'updated' ? 1 : 0;
      }

      Log::record('syncagents', 'ok', 'Sincronizacao de agentes concluida.', count($agents));

      return ['processed' => count($agents), 'created' => $created, 'updated' => $updated];
   }

   public static function syncThreats(): array
   {
      $config = Config::getConfig();

      if (!Config::isConfigured($config)) {
         Log::record('syncthreats', 'skipped', 'Integracao SentinelOne nao configurada.');
         return ['processed' => 0, 'created' => 0, 'updated' => 0, 'tickets' => 0];
      }

      $client = ApiClient::fromConfig($config);
      $params = self::apiParamsFromQueryString((string)($config['threat_filter_query'] ?? ''));
      $params['limit'] = (int)$config['sync_limit'];
      $threats = $client->getThreats($params, (int)$config['max_pages']);

      $created = 0;
      $updated = 0;
      $tickets = 0;

      foreach ($threats as $threat) {
         $result = self::upsertThreat($threat, $config);
         $created += $result['status'] === 'created' ? 1 : 0;
         $updated += $result['status'] === 'updated' ? 1 : 0;
         $tickets += $result['ticket_created'] ? 1 : 0;
      }

      Log::record('syncthreats', 'ok', 'Sincronizacao de ameacas concluida.', count($threats));

      return ['processed' => count($threats), 'created' => $created, 'updated' => $updated, 'tickets' => $tickets];
   }

   public static function stats(): array
   {
      return [
         'agents_total'      => self::countRows(Agent::getTable()),
         'agents_online'     => self::countRows(Agent::getTable(), ['is_online' => 1]),
         'agents_offline'    => self::countRows(Agent::getTable(), ['is_online' => 0]),
         'agents_infected'   => self::countRows(Agent::getTable(), ['is_infected' => 1]),
         'agents_linked'     => self::countRows(Agent::getTable(), ['NOT' => ['computers_id' => null]]),
         'agents_unlinked'   => self::countRows(Agent::getTable(), ['computers_id' => null]),
         'glpi_computers'    => self::countRows('glpi_computers', ['is_deleted' => 0]),
         'computers_unprotected' => Agent::countUnprotectedComputers(),
         'threats_total'     => self::countRows(Threat::getTable()),
         'threats_no_ticket' => self::countRows(Threat::getTable(), ['tickets_id' => null]),
         'recent_threats'    => self::getRows(Threat::getTable(), [], ['detected_at DESC', 'id DESC'], 6),
         'attention_agents'  => self::getRows(Agent::getTable(), ['is_infected' => 1], ['last_active_at DESC', 'id DESC'], 6),
         'unlinked_agents'   => self::getRows(Agent::getTable(), ['computers_id' => null], ['last_active_at DESC', 'id DESC'], 6),
         'offline_agents'    => self::getRows(Agent::getTable(), ['is_online' => 0], ['last_active_at DESC', 'id DESC'], 6),
         'last_agents_sync'  => self::getLastLog('syncagents'),
         'last_threats_sync' => self::getLastLog('syncthreats'),
         'logs'              => Log::getRecent(10),
      ];
   }

   private static function apiParamsFromQueryString(string $query): array
   {
      $query = trim(ltrim($query, '?&'));

      if ($query === '') {
         return [];
      }

      parse_str($query, $params);
      unset($params['cursor'], $params['limit']);

      return array_filter(
         $params,
         static fn($value, $key): bool => is_string($key) && $key !== '' && $value !== null && $value !== '',
         ARRAY_FILTER_USE_BOTH
      );
   }

   private static function upsertAgent(array $raw, array $config): string
   {
      global $DB;

      $data = self::normalizeAgent($raw);
      $existingId = self::findExistingId(Agent::getTable(), 'sentinelone_id', $data['sentinelone_id']);
      $existing = $existingId !== null ? self::getRowById(Agent::getTable(), $existingId) : null;
      $now = date('Y-m-d H:i:s');

      $data['date_mod'] = $now;

      // preserva o ticket de saude ja vinculado ao agente
      if ($existing !== null && !empty($existing['tickets_id'])) {
         $data['tickets_id'] = (int)$existing['tickets_id'];
      }

      if ($existingId !== null) {
         $DB->update(Agent::getTable(), $data, ['id' => $existingId]);
         $agentId = $existingId;
         $status = 'updated';
      } else {
         $data['date_creation'] = $now;
         $DB->insert(Agent::getTable(), $data);
         $agentId = (int)$DB->insertId();
         $status = 'created';
      }

      $data['id'] = $agentId;

      if ((string)($config['write_antivirus'] ?? '0') === '1' && !empty($data['computers_id'])) {
         self::writeAntivirus((int)$data['computers_id'], $data, $config);
      }

      self::handleAgentHealth($agentId, $data, $config);

      return $status;
   }

   private static function handleAgentHealth(int $agentId, array $agent, array $config): void
   {
      if ((string)($config['create_agent_tickets'] ?? '0') !== '1') {
         return;
      }

      if (!empty($agent['tickets_id'])) {
         return;
      }

      $issues = self::agentIssues($agent, $config);
      if ($issues === []) {
         return;
      }

      try {
         $ticketId = TicketManager::createForAgent($agent, $issues, $config);

         global $DB;
         $DB->update(Agent::getTable(), ['tickets_id' => $ticketId], ['id' => $agentId]);
         $agent['tickets_id'] = $ticketId;

         Notifier::alertAgentIssue($agent, $issues, $config);
      } catch (\Throwable $error) {
         Log::record('syncagents', 'error', 'Falha ao criar ticket de saude do agente: ' . $error->getMessage());
      }
   }

   /**
    * @return string[]
    */
   private static function agentIssues(array $agent, array $config): array
   {
      $issues = [];
      $offlineHours = max(1, (int)($config['ticket_offline_hours'] ?? 24));

      if ((int)($agent['is_infected'] ?? 0) === 1) {
         $issues[] = 'Endpoint marcado como infectado.';
      }

      if ((int)($agent['is_online'] ?? 0) === 0) {
         $hoursOffline = self::hoursSince((string)($agent['last_active_at'] ?? ''));
         if ($hoursOffline === null) {
            $issues[] = 'Agente offline (sem ultimo contato registrado).';
         } elseif ($hoursOffline >= $offlineHours) {
            $issues[] = sprintf('Agente offline ha %d horas.', $hoursOffline);
         }
      }

      $minVersion = trim((string)($config['min_agent_version'] ?? ''));
      $version = trim((string)($agent['agent_version'] ?? ''));
      if ($minVersion !== '' && $version !== '' && version_compare($version, $minVersion, '<')) {
         $issues[] = sprintf('Versao do agente desatualizada (%s < %s).', $version, $minVersion);
      }

      return $issues;
   }

   private static function hoursSince(string $datetime): ?int
   {
      $datetime = trim($datetime);
      if ($datetime === '') {
         return null;
      }

      try {
         $then = new \DateTimeImmutable($datetime);
      } catch (\Throwable $error) {
         return null;
      }

      $diff = time() - $then->getTimestamp();

      return $diff > 0 ? (int)floor($diff / 3600) : 0;
   }

   private static function writeAntivirus(int $computersId, array $agent, array $config): void
   {
      global $DB;

      $table = 'glpi_itemantiviruses';
      if (!$DB->tableExists($table)) {
         return;
      }

      $version = trim((string)($agent['agent_version'] ?? ''));
      $minVersion = trim((string)($config['min_agent_version'] ?? ''));
      $upToDate = 1;
      if ($minVersion !== '' && $version !== '') {
         $upToDate = version_compare($version, $minVersion, '>=') ? 1 : 0;
      }

      $now = date('Y-m-d H:i:s');
      $fields = [
         'antivirus_version' => $version !== '' ? $version : null,
         'is_active'         => (int)($agent['is_online'] ?? 0) === 1 ? 1 : 0,
         'is_uptodate'       => $upToDate,
         'date_mod'          => $now,
      ];

      $existingId = null;
      foreach ($DB->request([
         'SELECT' => ['id'],
         'FROM'   => $table,
         'WHERE'  => [
            'itemtype'   => 'Computer',
            'items_id'   => $computersId,
            'name'       => 'SentinelOne',
            'is_deleted' => 0,
         ],
         'LIMIT'  => 1,
      ]) as $row) {
         $existingId = (int)$row['id'];
      }

      if ($existingId !== null) {
         $DB->update($table, $fields, ['id' => $existingId]);
         return;
      }

      $DB->insert($table, $fields + [
         'itemtype'      => 'Computer',
         'items_id'      => $computersId,
         'name'          => 'SentinelOne',
         'is_dynamic'    => 0,
         'is_deleted'    => 0,
         'date_creation' => $now,
      ]);
   }

   private static function upsertThreat(array $raw, array $config): array
   {
      global $DB;

      $data = self::normalizeThreat($raw);
      $existingId = self::findExistingId(Threat::getTable(), 'sentinelone_threat_id', $data['sentinelone_threat_id']);
      $existing = $existingId !== null ? self::getRowById(Threat::getTable(), $existingId) : null;
      $agent = self::findAgentBySentineloneId((string)$data['sentinelone_agent_id']);

      if ($agent !== null) {
         $data['plugin_sentinelone_agents_id'] = (int)$agent['id'];
         $data['entities_id'] = (int)$agent['entities_id'];
         $data['computer_name'] = $data['computer_name'] ?: (string)$agent['computer_name'];
      }

      $ticketCreated = false;

      if ($existing !== null && !empty($existing['tickets_id'])) {
         $data['tickets_id'] = (int)$existing['tickets_id'];
      }

      if ((string)$config['create_tickets'] === '1' && empty($data['tickets_id']) && self::shouldCreateTicket($data, $config)) {
         $data['tickets_id'] = TicketManager::createForThreat($data, $agent, $config);
         $ticketCreated = true;
      }

      $now = date('Y-m-d H:i:s');
      $data['date_mod'] = $now;

      if ($existingId !== null) {
         $DB->update(Threat::getTable(), $data, ['id' => $existingId]);
         return ['status' => 'updated', 'ticket_created' => $ticketCreated];
      }

      $data['date_creation'] = $now;
      $DB->insert(Threat::getTable(), $data);

      self::maybeAlertThreat($data, $config);

      return ['status' => 'created', 'ticket_created' => $ticketCreated];
   }

   private static function maybeAlertThreat(array $threat, array $config): void
   {
      [$label] = Threat::severity($threat);

      if ($label === 'Critica') {
         Notifier::alertCriticalThreat($threat, $config);
      }
   }

   private static function normalizeAgent(array $raw): array
   {
      $id = self::pick($raw, ['id', 'uuid', 'agentId', 'agentUuid']);
      $computerName = self::pick($raw, ['computerName', 'computer_name', 'hostName', 'hostname', 'name']);
      $serial = self::pick($raw, ['serialNumber', 'serial_number', 'serial']);
      $uuid = self::pick($raw, ['uuid', 'machineUuid', 'agentUuid']);
      $mac = self::extractFirstMac($raw);
      $ip = self::extractFirstIp($raw);

      if ($id === null || $id === '') {
         $id = hash('sha256', json_encode($raw, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
      }

      return [
         'sentinelone_id' => (string)$id,
         'computers_id'   => self::findComputerId((string)$computerName, (string)$serial, (string)$uuid, $mac),
         'entities_id'    => (int)Config::getConfig()['entity_id'],
         'computer_name'  => self::nullable($computerName),
         'serial'         => self::nullable($serial),
         'uuid'           => self::nullable($uuid),
         'mac'            => self::nullable($mac),
         'ip'             => self::nullable($ip),
         'os_name'        => self::nullable(self::pick($raw, ['osName', 'os_name', 'osRevision', 'operatingSystem'])),
         'agent_version'  => self::nullable(self::pick($raw, ['agentVersion', 'agent_version', 'version'])),
         'site_name'      => self::nullable(self::pick($raw, ['siteName', 'site_name'])),
         'group_name'     => self::nullable(self::pick($raw, ['groupName', 'group_name'])),
         'is_online'      => self::toBool(self::pick($raw, ['isActive', 'isOnline', 'online', 'active'])),
         'is_infected'    => self::toBool(self::pick($raw, ['infected', 'isInfected'])),
         'last_active_at' => self::normalizeDate(self::pick($raw, ['lastActiveDate', 'last_active_date', 'lastSeen', 'lastContact'])),
         'raw_json'       => json_encode($raw, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
      ];
   }

   private static function normalizeThreat(array $raw): array
   {
      $threatId = self::pickPath($raw, [
         'threatInfo.threatId',
         'threatInfo.id',
         'id',
         'threatId',
      ]);
      $agentId = self::pickPath($raw, [
         'agentRealtimeInfo.agentId',
         'agentDetectionInfo.agentId',
         'agentId',
         'sentineloneAgentId',
      ]);

      if ($threatId === null || $threatId === '') {
         $threatId = hash('sha256', json_encode($raw, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
      }

      return [
         'sentinelone_threat_id'       => (string)$threatId,
         'sentinelone_agent_id'        => self::nullable($agentId),
         'plugin_sentinelone_agents_id'=> null,
         'tickets_id'                  => null,
         'entities_id'                 => (int)Config::getConfig()['entity_id'],
         'computer_name'               => self::nullable(self::pickPath($raw, [
            'agentRealtimeInfo.agentComputerName',
            'agentDetectionInfo.agentComputerName',
            'computerName',
         ])),
         'threat_name'                 => self::nullable(self::pickPath($raw, [
            'threatInfo.threatName',
            'threatInfo.name',
            'name',
         ])),
         'classification'              => self::nullable(self::pickPath($raw, [
            'threatInfo.classification',
            'classification',
            'threatInfo.classificationSource',
         ])),
         'status'                      => self::nullable(self::pickPath($raw, [
            'threatInfo.mitigationStatus',
            'threatInfo.status',
            'status',
         ])),
         'confidence_level'            => self::nullable(self::pickPath($raw, [
            'threatInfo.confidenceLevel',
            'confidenceLevel',
         ])),
         'analyst_verdict'             => self::nullable(self::pickPath($raw, [
            'threatInfo.analystVerdict',
            'analystVerdict',
         ])),
         'severity'                    => self::nullable(self::pickPath($raw, [
            'threatInfo.severity',
            'alertInfo.severity',
            'severity',
         ])),
         'file_path'                   => self::nullable(self::pickPath($raw, [
            'threatInfo.filePath',
            'threatInfo.fileDisplayName',
            'filePath',
         ])),
         'hash_sha1'                   => self::nullable(self::pickPath($raw, [
            'threatInfo.sha1',
            'sha1',
         ])),
         'hash_sha256'                 => self::nullable(self::pickPath($raw, [
            'threatInfo.sha256',
            'sha256',
         ])),
         'detected_at'                 => self::normalizeDate(self::pickPath($raw, [
            'threatInfo.createdAt',
            'createdAt',
            'detectedAt',
         ])),
         'resolved_at'                 => self::normalizeDate(self::pickPath($raw, [
            'threatInfo.resolvedAt',
            'resolvedAt',
         ])),
         'raw_json'                    => json_encode($raw, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
      ];
   }

   private static function shouldCreateTicket(array $threat, array $config): bool
   {
      $status = strtolower(trim((string)($threat['status'] ?? '')));
      $classification = strtolower(trim((string)($threat['classification'] ?? '')));
      $statusFilter = (string)($config['ticket_status_filter'] ?? '');
      $classificationFilter = (string)($config['ticket_classification_filter'] ?? '');

      if (trim($statusFilter) === '' && trim($classificationFilter) === '') {
         return false;
      }

      if ($status === '') {
         return self::listAllows($statusFilter, $status)
            && self::listAllows($classificationFilter, $classification);
      }

      if (in_array($status, ['mitigated', 'resolved', 'benign', 'false_positive', 'marked_as_benign'], true)) {
         return false;
      }

      return self::listAllows($statusFilter, $status)
         && self::listAllows($classificationFilter, $classification);
   }

   private static function listAllows(string $filter, string $value): bool
   {
      $filter = trim($filter);
      if ($filter === '') {
         return true;
      }

      $allowed = preg_split('/[\r\n,;]+/', strtolower($filter)) ?: [];
      $allowed = array_filter(array_map('trim', $allowed), static fn($item): bool => $item !== '');

      if ($allowed === []) {
         return true;
      }

      return in_array(strtolower(trim($value)), $allowed, true);
   }

   private static function findComputerId(string $computerName, string $serial, string $uuid, ?string $mac): ?int
   {
      if ($serial !== '') {
         $id = self::findComputerByField('serial', $serial);
         if ($id !== null) {
            return $id;
         }
      }

      if ($uuid !== '' && self::fieldExists('glpi_computers', 'uuid')) {
         $id = self::findComputerByField('uuid', $uuid);
         if ($id !== null) {
            return $id;
         }
      }

      if ($computerName !== '') {
         $id = self::findComputerByField('name', $computerName);
         if ($id !== null) {
            return $id;
         }

         $shortName = preg_replace('/\..*$/', '', $computerName);
         if ($shortName !== null && $shortName !== $computerName) {
            $id = self::findComputerByField('name', $shortName);
            if ($id !== null) {
               return $id;
            }
         }
      }

      if ($mac !== null && $mac !== '') {
         return self::findComputerByMac($mac);
      }

      return null;
   }

   private static function findComputerByField(string $field, string $value): ?int
   {
      global $DB;

      foreach ($DB->request([
         'SELECT' => ['id'],
         'FROM'   => 'glpi_computers',
         'WHERE'  => [
            $field       => $value,
            'is_deleted' => 0,
         ],
         'LIMIT'  => 1,
      ]) as $row) {
         return (int)$row['id'];
      }

      return null;
   }

   private static function findComputerByMac(string $mac): ?int
   {
      global $DB;

      if (!$DB->tableExists('glpi_networkports')) {
         return null;
      }

      foreach ($DB->request([
         'SELECT' => ['items_id'],
         'FROM'   => 'glpi_networkports',
         'WHERE'  => [
            'mac'      => $mac,
            'itemtype' => 'Computer',
         ],
         'LIMIT'  => 1,
      ]) as $row) {
         return (int)$row['items_id'];
      }

      return null;
   }

   private static function findExistingId(string $table, string $field, string $value): ?int
   {
      global $DB;

      if ($value === '') {
         return null;
      }

      foreach ($DB->request([
         'SELECT' => ['id'],
         'FROM'   => $table,
         'WHERE'  => [$field => $value],
         'LIMIT'  => 1,
      ]) as $row) {
         return (int)$row['id'];
      }

      return null;
   }

   private static function getRowById(string $table, int $id): ?array
   {
      global $DB;

      foreach ($DB->request([
         'FROM'  => $table,
         'WHERE' => ['id' => $id],
         'LIMIT' => 1,
      ]) as $row) {
         return $row;
      }

      return null;
   }

   private static function findAgentBySentineloneId(string $sentineloneAgentId): ?array
   {
      if ($sentineloneAgentId === '') {
         return null;
      }

      global $DB;

      foreach ($DB->request([
         'FROM'  => Agent::getTable(),
         'WHERE' => ['sentinelone_id' => $sentineloneAgentId],
         'LIMIT' => 1,
      ]) as $row) {
         return $row;
      }

      return null;
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

   private static function getRows(string $table, array $where = [], array $order = ['id DESC'], int $limit = 6): array
   {
      global $DB;

      $rows = [];
      $limit = max(1, min(20, $limit));

      if (!$DB->tableExists($table)) {
         return $rows;
      }

      $criteria = [
         'FROM'  => $table,
         'ORDER' => $order,
         'LIMIT' => $limit,
      ];

      if ($where !== []) {
         $criteria['WHERE'] = $where;
      }

      foreach ($DB->request($criteria) as $row) {
         $rows[] = $row;
      }

      return $rows;
   }

   private static function getLastLog(string $action): ?array
   {
      global $DB;

      if (!$DB->tableExists(Log::getTable())) {
         return null;
      }

      foreach ($DB->request([
         'FROM'  => Log::getTable(),
         'WHERE' => ['action' => $action],
         'ORDER' => ['id DESC'],
         'LIMIT' => 1,
      ]) as $row) {
         return $row;
      }

      return null;
   }

   private static function pick(array $row, array $keys)
   {
      foreach ($keys as $key) {
         if (array_key_exists($key, $row) && $row[$key] !== null && $row[$key] !== '') {
            return $row[$key];
         }
      }

      return null;
   }

   private static function pickPath(array $row, array $paths)
   {
      foreach ($paths as $path) {
         $value = $row;
         foreach (explode('.', $path) as $part) {
            if (!is_array($value) || !array_key_exists($part, $value)) {
               $value = null;
               break;
            }
            $value = $value[$part];
         }

         if ($value !== null && $value !== '') {
            return $value;
         }
      }

      return null;
   }

   private static function extractFirstMac(array $row): ?string
   {
      foreach (['macAddress', 'mac_address', 'mac'] as $key) {
         if (!empty($row[$key])) {
            return strtolower((string)$row[$key]);
         }
      }

      foreach (['networkInterfaces', 'network_interfaces'] as $key) {
         if (!empty($row[$key]) && is_array($row[$key])) {
            foreach ($row[$key] as $network) {
               if (is_array($network)) {
                  $mac = self::pick($network, ['physical', 'macAddress', 'mac']);
                  if ($mac !== null) {
                     return strtolower((string)$mac);
                  }
               }
            }
         }
      }

      return null;
   }

   private static function extractFirstIp(array $row): ?string
   {
      foreach (['lastIpToMgmt', 'externalIp', 'ipAddress', 'ip'] as $key) {
         if (!empty($row[$key])) {
            return (string)$row[$key];
         }
      }

      return null;
   }

   private static function normalizeDate($value): ?string
   {
      if ($value === null || $value === '') {
         return null;
      }

      if (is_numeric($value)) {
         return date('Y-m-d H:i:s', (int)$value);
      }

      try {
         return (new \DateTimeImmutable((string)$value))->format('Y-m-d H:i:s');
      } catch (\Throwable $error) {
         return null;
      }
   }

   private static function nullable($value): ?string
   {
      if ($value === null) {
         return null;
      }

      $value = trim((string)$value);

      return $value === '' ? null : $value;
   }

   private static function toBool($value): int
   {
      if (is_bool($value)) {
         return $value ? 1 : 0;
      }

      $value = strtolower(trim((string)$value));

      return in_array($value, ['1', 'true', 'yes', 'online', 'active', 'connected'], true) ? 1 : 0;
   }

   private static function fieldExists(string $table, string $field): bool
   {
      global $DB;

      return method_exists($DB, 'fieldExists') && $DB->fieldExists($table, $field);
   }
}

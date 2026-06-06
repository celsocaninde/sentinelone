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
         'syncactivities' => [
            'description' => 'Sincroniza feed de atividades recentes dos agentes SentinelOne',
         ],
         'syncgroups' => [
            'description' => 'Sincroniza grupos e politicas de protecao SentinelOne',
         ],
         'syncsoftware' => [
            'description' => 'Sincroniza inventario de software dos agentes SentinelOne para o GLPI',
         ],
         'synccves' => [
            'description' => 'Sincroniza CVEs detectados nos endpoints SentinelOne',
         ],
         'syncrogues' => [
            'description' => 'Sincroniza dispositivos rogues detectados pelo Ranger SentinelOne',
         ],
         'alertoffline' => [
            'description' => 'Envia alertas por e-mail para agentes SentinelOne offline ha muito tempo',
         ],
         'reportweekly' => [
            'description' => 'Envia relatorio executivo semanal com resumo operacional do SentinelOne',
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

   public static function cronSyncsoftware(?\CronTask $task = null): int
   {
      try {
         $result = self::syncSoftware();

         if ($task !== null) {
            $task->addVolume($result['processed']);
         }

         return 1;
      } catch (\Throwable $error) {
         Log::record('syncsoftware', 'error', $error->getMessage());
         return 0;
      }
   }

   public static function cronSynccves(?\CronTask $task = null): int
   {
      try {
         $result = self::syncCves();

         if ($task !== null) {
            $task->addVolume($result['processed']);
         }

         return 1;
      } catch (\Throwable $error) {
         Log::record('synccves', 'error', $error->getMessage());
         return 0;
      }
   }

   public static function cronSyncrogues(?\CronTask $task = null): int
   {
      try {
         $result = self::syncRogues();

         if ($task !== null) {
            $task->addVolume($result['total']);
         }

         return 1;
      } catch (\Throwable $error) {
         Log::record('syncrogues', 'error', $error->getMessage());
         return 0;
      }
   }

   public static function cronSyncactivities(?\CronTask $task = null): int
   {
      try {
         $result = self::syncActivities();

         if ($task !== null) {
            $task->addVolume($result['processed']);
         }

         return 1;
      } catch (\Throwable $error) {
         Log::record('syncactivities', 'error', $error->getMessage());
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

   public static function cronSyncgroups(?\CronTask $task = null): int
   {
      try {
         $result = self::syncGroups();

         if ($task !== null) {
            $task->addVolume($result['processed']);
         }

         return 1;
      } catch (\Throwable $error) {
         Log::record('syncgroups', 'error', $error->getMessage());
         return 0;
      }
   }

   /**
    * Tenta vincular todos os agentes sem computers_id usando os mesmos criterios
    * de matching do upsertAgent (serial > UUID > nome > MAC).
    */
   public static function relinkAgents(): array
   {
      global $DB;

      $unlinked = [];
      foreach ($DB->request([
         'SELECT' => ['id', 'computer_name', 'serial', 'uuid', 'mac'],
         'FROM'   => Agent::getTable(),
         'WHERE'  => ['computers_id' => null],
         'LIMIT'  => 500,
      ]) as $row) {
         $unlinked[] = $row;
      }

      $linked = 0;
      foreach ($unlinked as $agent) {
         $computerId = self::findComputerId(
            (string)($agent['computer_name'] ?? ''),
            (string)($agent['serial'] ?? ''),
            (string)($agent['uuid'] ?? ''),
            ($agent['mac'] !== null && $agent['mac'] !== '') ? (string)$agent['mac'] : null
         );

         if ($computerId !== null) {
            $DB->update(Agent::getTable(), ['computers_id' => $computerId], ['id' => $agent['id']]);
            $linked++;
         }
      }

      Log::record('syncagents', 'ok', "Re-vinculacao concluida: {$linked} de " . count($unlinked) . " agentes vinculados.", $linked);

      return ['total' => count($unlinked), 'linked' => $linked];
   }

   /**
    * Vincula um agente especifico a um computador GLPI.
    * Retorna false se o agente ou computador nao existir.
    */
   public static function linkAgent(int $agentId, int $computersId): bool
   {
      global $DB;

      if ($agentId <= 0 || $computersId <= 0) {
         return false;
      }

      if (self::getRowById('glpi_computers', $computersId) === null) {
         return false;
      }

      $existing = self::getRowById(Agent::getTable(), $agentId);
      if ($existing === null) {
         return false;
      }

      $DB->update(Agent::getTable(), ['computers_id' => $computersId, 'date_mod' => date('Y-m-d H:i:s')], ['id' => $agentId]);

      Log::record('syncagents', 'ok', "Agente #{$agentId} vinculado manualmente ao computador #{$computersId}.", 1);

      return true;
   }

   public static function syncGroups(): array
   {
      global $DB;

      $config = Config::getConfig();

      if (!Config::isConfigured($config)) {
         Log::record('syncgroups', 'skipped', 'Integracao SentinelOne nao configurada.');
         return ['processed' => 0, 'updated' => 0];
      }

      $client  = ApiClient::fromConfig($config);
      $groups  = $client->getGroups([], 5);
      $updated = 0;
      $now     = date('Y-m-d H:i:s');

      foreach ($groups as $raw) {
         $sid        = (string)($raw['id'] ?? '');
         $name       = (string)($raw['name'] ?? '');
         $type       = (string)($raw['type'] ?? '');
         $agentCount = (int)($raw['totalAgents'] ?? 0);
         $siteName   = (string)($raw['siteName'] ?? $raw['site_name'] ?? '');
         $siteId     = (string)($raw['siteId'] ?? '');
         $policyMode = 'unknown';

         if ($sid === '') {
            continue;
         }

         // Best-effort: fetch effective policy for this group
         try {
            $policy     = $client->getGroupPolicy($sid);
            $rawMode    = $policy['mitigationMode'] ?? $policy['mitigation_mode'] ?? null;
            if ($rawMode !== null) {
               $policyMode = strtolower((string)$rawMode);
            }
         } catch (\Throwable) {
            // policy endpoint may require extra permissions; keep 'unknown'
         }

         $existingId = null;
         foreach ($DB->request([
            'SELECT' => ['id'],
            'FROM'   => Group::getTable(),
            'WHERE'  => ['sentinelone_id' => $sid],
            'LIMIT'  => 1,
         ]) as $row) {
            $existingId = (int)$row['id'];
         }

         $data = [
            'name'        => $name,
            'type'        => $type,
            'policy_mode' => $policyMode,
            'agent_count' => $agentCount,
            'site_name'   => $siteName,
            'site_id'     => $siteId,
            'date_mod'    => $now,
         ];

         if ($existingId !== null) {
            $DB->update(Group::getTable(), $data, ['id' => $existingId]);
         } else {
            $data['sentinelone_id'] = $sid;
            $data['date_creation']  = $now;
            $DB->insert(Group::getTable(), $data);
         }
         $updated++;
      }

      Log::record('syncgroups', 'ok', 'Sincronizacao de grupos concluida.', count($groups));

      return ['processed' => count($groups), 'updated' => $updated];
   }

   public static function quarantineAgent(int $agentId): bool
   {
      global $DB;

      $agent = self::getRowById(Agent::getTable(), $agentId);
      if ($agent === null) {
         return false;
      }

      $sid = (string)($agent['sentinelone_id'] ?? '');
      if ($sid === '') {
         return false;
      }

      $config = Config::getConfig();
      if (!Config::isConfigured($config)) {
         return false;
      }

      $client = ApiClient::fromConfig($config);
      $client->quarantineAgent($sid);

      $DB->update(Agent::getTable(), ['is_network_quarantine' => 1, 'date_mod' => date('Y-m-d H:i:s')], ['id' => $agentId]);
      Log::record('quarantine', 'ok', "Agente #{$agentId} isolado da rede.", 1);

      return true;
   }

   public static function unquarantineAgent(int $agentId): bool
   {
      global $DB;

      $agent = self::getRowById(Agent::getTable(), $agentId);
      if ($agent === null) {
         return false;
      }

      $sid = (string)($agent['sentinelone_id'] ?? '');
      if ($sid === '') {
         return false;
      }

      $config = Config::getConfig();
      if (!Config::isConfigured($config)) {
         return false;
      }

      $client = ApiClient::fromConfig($config);
      $client->unquarantineAgent($sid);

      $DB->update(Agent::getTable(), ['is_network_quarantine' => 0, 'date_mod' => date('Y-m-d H:i:s')], ['id' => $agentId]);
      Log::record('quarantine', 'ok', "Agente #{$agentId} reintegrado a rede.", 1);

      return true;
   }

   public static function syncSoftware(): array
   {
      global $DB;

      $config = Config::getConfig();

      if (!Config::isConfigured($config)) {
         Log::record('syncsoftware', 'skipped', 'Integracao SentinelOne nao configurada.');
         return ['processed' => 0, 'apps' => 0];
      }

      if ((string)($config['sync_software'] ?? '0') !== '1') {
         return ['processed' => 0, 'apps' => 0];
      }

      $client = ApiClient::fromConfig($config);
      $limit = max(1, min(200, (int)($config['sync_software_limit'] ?? 30)));

      $agents = [];
      foreach ($DB->request([
         'SELECT' => ['id', 'sentinelone_id', 'computers_id', 'entities_id'],
         'FROM'   => Agent::getTable(),
         'WHERE'  => ['NOT' => ['computers_id' => null]],
         'ORDER'  => ['last_active_at DESC'],
         'LIMIT'  => $limit,
      ]) as $row) {
         $agents[] = $row;
      }

      $totalApps = 0;

      foreach ($agents as $agent) {
         try {
            $apps = $client->getAgentApplications((string)$agent['sentinelone_id']);
            if ($apps !== []) {
               self::upsertSoftwareForAgent((int)$agent['computers_id'], (int)$agent['entities_id'], $apps);
               $totalApps += count($apps);
            }
         } catch (\Throwable $error) {
            Log::record('syncsoftware', 'error', 'Falha ao sincronizar software do agente ' . $agent['sentinelone_id'] . ': ' . $error->getMessage());
         }
      }

      Log::record('syncsoftware', 'ok', 'Sincronizacao de software concluida.', count($agents));

      return ['processed' => count($agents), 'apps' => $totalApps];
   }

   public static function syncCves(bool $force = false): array
   {
      global $DB;

      $config = Config::getConfig();

      if (!Config::isConfigured($config)) {
         Log::record('synccves', 'skipped', 'Integracao SentinelOne nao configurada.');
         return ['processed' => 0, 'cves' => 0];
      }

      if (!$force && (string)($config['sync_cves'] ?? '0') !== '1') {
         return ['processed' => 0, 'cves' => 0];
      }

      $client = ApiClient::fromConfig($config);
      $limit = max(1, min(200, (int)($config['sync_cves_limit'] ?? 30)));

      $agents = [];
      foreach ($DB->request([
         'SELECT' => ['id', 'sentinelone_id'],
         'FROM'   => Agent::getTable(),
         'ORDER'  => ['last_active_at DESC'],
         'LIMIT'  => $limit,
      ]) as $row) {
         $agents[] = $row;
      }

      $totalCves = 0;

      // Testa o endpoint com o primeiro agente antes de iterar todos.
      // Se falhar (ex.: plano sem Vulnerability Management), aborta com uma unica mensagem.
      if ($agents !== []) {
         try {
            $client->getAgentCves((string)$agents[0]['sentinelone_id']);
         } catch (\Throwable $probe) {
            $msg = 'Endpoint /threats/cve indisponivel (verifique plano/permissoes): ' . $probe->getMessage();
            Log::record('synccves', 'error', $msg, 0);
            return ['processed' => 0, 'cves' => 0, 'error' => $msg];
         }
      }

      foreach ($agents as $agent) {
         try {
            $cves = $client->getAgentCves((string)$agent['sentinelone_id']);
            self::upsertCvesForAgent((int)$agent['id'], $cves);
            $totalCves += count($cves);
         } catch (\Throwable $error) {
            Log::record('synccves', 'warning', 'Agente ' . $agent['sentinelone_id'] . ': ' . $error->getMessage());
         }
      }

      Log::record('synccves', 'ok', 'Sincronizacao de CVEs concluida.', count($agents));

      return ['processed' => count($agents), 'cves' => $totalCves];
   }

   public static function syncRogues(): array
   {
      $config = Config::getConfig();

      if (!Config::isConfigured($config)) {
         Log::record('syncrogues', 'skipped', 'Integracao SentinelOne nao configurada.');
         return ['total' => 0];
      }

      if ((string)($config['sync_rogues'] ?? '0') !== '1') {
         return ['total' => 0];
      }

      $client  = ApiClient::fromConfig($config);
      $devices = $client->getRogueDevices();

      self::upsertRogueDevices($devices);

      Log::record('syncrogues', 'ok', 'Sincronizacao de dispositivos rogues concluida.', count($devices));

      return ['total' => count($devices)];
   }

   private static function upsertRogueDevices(array $devices): void
   {
      global $DB;

      if (!$DB->tableExists(RogueDevice::getTable())) {
         return;
      }

      $now = date('Y-m-d H:i:s');

      foreach ($devices as $item) {
         $s1id = trim((string)($item['id'] ?? ''));
         if ($s1id === '') {
            continue;
         }

         $hostname  = trim((string)($item['networkName'] ?? $item['hostname'] ?? ''));
         $ip        = trim((string)($item['ip'] ?? ''));
         $extIp     = trim((string)($item['externalIp'] ?? $item['external_ip'] ?? ''));
         $mac       = trim((string)($item['mac'] ?? ''));
         $os        = trim((string)($item['os'] ?? ''));
         $classif   = trim((string)($item['classification'] ?? ''));
         $vendor    = trim((string)($item['vendor'] ?? ''));
         $siteName  = trim((string)($item['siteName'] ?? $item['site_name'] ?? ''));
         $agentName = trim((string)($item['agentComputerName'] ?? $item['detecting_agent_name'] ?? ''));

         // open_ports: array of int or array of {port,protocol}
         $rawPorts = $item['openPorts'] ?? $item['open_ports'] ?? [];
         $portsJson = is_array($rawPorts) && $rawPorts !== [] ? json_encode($rawPorts) : null;

         $tsFirst = self::parseTimestamp($item['firstSeen'] ?? $item['first_seen'] ?? '');
         $tsLast  = self::parseTimestamp($item['lastSeen']  ?? $item['last_seen']  ?? '');

         $existing = null;
         foreach ($DB->request([
            'SELECT' => ['id'],
            'FROM'   => RogueDevice::getTable(),
            'WHERE'  => ['sentinelone_id' => $s1id],
            'LIMIT'  => 1,
         ]) as $row) {
            $existing = (int)$row['id'];
         }

         $data = [
            'hostname'             => $hostname !== '' ? $hostname : null,
            'ip'                   => $ip        !== '' ? $ip        : null,
            'external_ip'          => $extIp     !== '' ? $extIp     : null,
            'mac'                  => $mac        !== '' ? $mac        : null,
            'os'                   => $os         !== '' ? $os         : null,
            'classification'       => $classif    !== '' ? $classif    : null,
            'vendor'               => $vendor     !== '' ? $vendor     : null,
            'site_name'            => $siteName   !== '' ? $siteName   : null,
            'detecting_agent_name' => $agentName  !== '' ? $agentName  : null,
            'open_ports'           => $portsJson,
            'first_seen'           => $tsFirst,
            'last_seen'            => $tsLast,
            'date_mod'             => $now,
         ];

         if ($existing !== null) {
            $DB->update(RogueDevice::getTable(), $data, ['id' => $existing]);
         } else {
            $DB->insert(RogueDevice::getTable(), array_merge($data, [
               'sentinelone_id' => $s1id,
               'date_creation'  => $now,
            ]));
         }
      }
   }

   private static function parseTimestamp(string $value): ?string
   {
      if ($value === '') {
         return null;
      }
      $ts = strtotime($value);
      return $ts !== false ? date('Y-m-d H:i:s', $ts) : null;
   }

   private static function upsertCvesForAgent(int $agentId, array $cves): void
   {
      global $DB;

      if (!$DB->tableExists(Cve::getTable())) {
         return;
      }

      // Limpa CVEs antigos antes de reinserir (refresh completo por agente).
      Cve::deleteForAgent($agentId);

      $now = date('Y-m-d H:i:s');

      foreach ($cves as $item) {
         $cveId = trim((string)($item['cveId'] ?? $item['cve_id'] ?? ''));
         if ($cveId === '') {
            continue;
         }

         $severity = strtoupper(trim((string)($item['severity'] ?? 'UNKNOWN')));
         $cvssScore = isset($item['cvssScore']) ? (float)$item['cvssScore'] : (isset($item['cvss']) ? (float)$item['cvss'] : null);
         $appName = trim((string)($item['applicationName'] ?? $item['application_name'] ?? ''));
         $appVersion = trim((string)($item['applicationVersion'] ?? $item['application_version'] ?? ''));
         $description = trim((string)($item['description'] ?? ''));
         $link = trim((string)($item['link'] ?? ''));

         $publishedRaw = trim((string)($item['publishedAt'] ?? $item['published_at'] ?? $item['published'] ?? ''));
         $publishedDate = null;
         if ($publishedRaw !== '') {
            $ts = strtotime($publishedRaw);
            if ($ts !== false) {
               $publishedDate = date('Y-m-d H:i:s', $ts);
            }
         }

         $DB->insert(Cve::getTable(), [
            'plugin_sentinelone_agents_id' => $agentId,
            'cve_id'                       => $cveId,
            'severity'                     => $severity,
            'severity_rank'                => Cve::severityRank($severity),
            'cvss_score'                   => $cvssScore,
            'application_name'             => $appName !== '' ? $appName : null,
            'application_version'          => $appVersion !== '' ? $appVersion : null,
            'description'                  => $description !== '' ? $description : null,
            'cve_link'                     => $link !== '' ? $link : null,
            'published_date'               => $publishedDate,
            'date_creation'                => $now,
            'date_mod'                     => $now,
         ]);
      }
   }

   public static function syncActivities(): array
   {
      $config = Config::getConfig();

      if (!Config::isConfigured($config)) {
         Log::record('syncactivities', 'skipped', 'Integracao SentinelOne nao configurada.');
         return ['processed' => 0, 'created' => 0];
      }

      if ((string)($config['sync_activities'] ?? '0') !== '1') {
         return ['processed' => 0, 'created' => 0];
      }

      $client = ApiClient::fromConfig($config);
      $limit = min((int)$config['sync_limit'], 200);
      $activities = $client->getActivities([
         'limit'     => $limit,
         'sortBy'    => 'activityTime',
         'sortOrder' => 'desc',
      ], 3);

      $created = 0;
      foreach ($activities as $activity) {
         if (self::upsertActivity($activity)) {
            $created++;
         }
      }

      Log::record('syncactivities', 'ok', 'Sincronizacao de atividades concluida.', count($activities));

      return ['processed' => count($activities), 'created' => $created];
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

      $incremental = (string)($config['sync_incremental'] ?? '0') === '1';
      $syncStart = gmdate('Y-m-d\TH:i:s.000\Z');
      if ($incremental) {
         $cursor = \Config::getConfigurationValues(Config::CONTEXT, ['sync_cursor_agents'])['sync_cursor_agents'] ?? '';
         if ($cursor !== '') {
            $ts = strtotime($cursor) - 300; // 5min overlap
            $params['updatedAt__gt'] = gmdate('Y-m-d\TH:i:s.000\Z', max(0, $ts));
         }
      }

      $agents = $client->getAgents($params, (int)$config['max_pages']);

      $created = 0;
      $updated = 0;

      foreach ($agents as $agent) {
         $result = self::upsertAgent($agent, $config);
         $created += $result === 'created' ? 1 : 0;
         $updated += $result === 'updated' ? 1 : 0;
      }

      if ($incremental) {
         \Config::setConfigurationValues(Config::CONTEXT, ['sync_cursor_agents' => $syncStart]);
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
      $params['limit']     = (int)$config['sync_limit'];
      $params['sortBy']    = $params['sortBy'] ?? 'createdAt';
      $params['sortOrder'] = $params['sortOrder'] ?? 'desc';

      $incremental = (string)($config['sync_incremental'] ?? '0') === '1';
      $syncStart = gmdate('Y-m-d\TH:i:s.000\Z');
      if ($incremental) {
         $cursor = \Config::getConfigurationValues(Config::CONTEXT, ['sync_cursor_threats'])['sync_cursor_threats'] ?? '';
         if ($cursor !== '') {
            $ts = strtotime($cursor) - 300;
            $params['updatedAt__gt'] = gmdate('Y-m-d\TH:i:s.000\Z', max(0, $ts));
         }
      }

      $threats = $client->getThreats($params, (int)$config['max_pages']);

      $created = 0;
      $updated = 0;
      $tickets = 0;
      $ticketsClosed = 0;

      foreach ($threats as $threat) {
         $result = self::upsertThreat($threat, $config, $client);
         $created += $result['status'] === 'created' ? 1 : 0;
         $updated += $result['status'] === 'updated' ? 1 : 0;
         $tickets += $result['ticket_created'] ? 1 : 0;
         $ticketsClosed += $result['ticket_closed'] ? 1 : 0;
      }

      if ($incremental) {
         \Config::setConfigurationValues(Config::CONTEXT, ['sync_cursor_threats' => $syncStart]);
      }

      Log::record('syncthreats', 'ok', 'Sincronizacao de ameacas concluida.', count($threats));

      return ['processed' => count($threats), 'created' => $created, 'updated' => $updated, 'tickets' => $tickets, 'tickets_closed' => $ticketsClosed];
   }

   public static function cronReportweekly(?\CronTask $task = null): int
   {
      try {
         $sent = self::sendWeeklyReport();

         if ($task !== null) {
            $task->addVolume($sent);
         }

         return 1;
      } catch (\Throwable $error) {
         Log::record('reportweekly', 'error', $error->getMessage());
         return 0;
      }
   }

   public static function sendWeeklyReport(): int
   {
      global $DB;

      $config = Config::getConfig();
      $recipients = array_filter(
         array_map('trim', explode(',', (string)($config['report_recipients'] ?? ''))),
         static fn($e) => filter_var($e, FILTER_VALIDATE_EMAIL) !== false
      );

      if ($recipients === []) {
         Log::record('reportweekly', 'skipped', 'Nenhum destinatario configurado para o relatorio semanal.');
         return 0;
      }

      $s = self::stats();
      $cveStats    = Cve::getGlobalStats();
      $cvesBySev   = $cveStats['by_severity'] ?? [];
      $rogues      = $DB->tableExists(RogueDevice::getTable()) ? RogueDevice::countTotal() : 0;

      $weekAgo = date('Y-m-d H:i:s', strtotime('-7 days'));
      $newThreats = 0;
      foreach ($DB->request(['COUNT' => 'cpt', 'FROM' => Threat::getTable(), 'WHERE' => ['detected_at' => ['>', $weekAgo]]]) as $r) {
         $newThreats = (int)($r['cpt'] ?? 0);
      }

      $week = date('d/m/Y', strtotime('-7 days')) . ' – ' . date('d/m/Y');
      $subject = '[SentinelOne] Relatório operacional – ' . $week;

      $sectionStyle = 'margin:24px 0 8px;padding:0;font-size:15px;font-weight:700;color:#2d1f6e;border-bottom:2px solid #6b2cf5';
      $thStyle  = 'padding:6px 12px;text-align:left;background:#f3f0ff;color:#2d1f6e;font-size:12px;text-transform:uppercase;letter-spacing:.5px';
      $tdStyle  = 'padding:6px 12px;border-bottom:1px solid #eee;font-size:13px';
      $valStyle = 'font-weight:700;font-size:16px;color:#2d1f6e';

      $body = <<<HTML
      <div style="font-family:Arial,sans-serif;max-width:640px;margin:0 auto;background:#fff;border:1px solid #e3e1ee;border-radius:8px;overflow:hidden">
        <div style="background:#2d1f6e;padding:24px 32px;text-align:center">
          <h1 style="color:#fff;margin:0;font-size:22px">SentinelOne</h1>
          <p style="color:#c4b8f5;margin:4px 0 0;font-size:13px">Relatório executivo semanal &bull; {$week}</p>
        </div>
        <div style="padding:24px 32px">

          <p style="{$sectionStyle}">Agentes</p>
          <table style="width:100%;border-collapse:collapse">
            <tr><th style="{$thStyle}">Métrica</th><th style="{$thStyle}">Valor</th></tr>
            <tr><td style="{$tdStyle}">Total de agentes</td><td style="{$tdStyle} {$valStyle}">{$s['agents_total']}</td></tr>
            <tr><td style="{$tdStyle}">Online</td><td style="{$tdStyle}">{$s['agents_online']}</td></tr>
            <tr><td style="{$tdStyle}">Offline</td><td style="{$tdStyle}">{$s['agents_offline']}</td></tr>
            <tr><td style="{$tdStyle}">Infectados</td><td style="{$tdStyle} color:#dc3545">{$s['agents_infected']}</td></tr>
            <tr><td style="{$tdStyle}">Desatualizados</td><td style="{$tdStyle}">{$s['agents_outdated']}</td></tr>
            <tr><td style="{$tdStyle}">Em quarentena</td><td style="{$tdStyle}">{$s['agents_quarantined']}</td></tr>
            <tr><td style="{$tdStyle}">Sem vínculo GLPI</td><td style="{$tdStyle}">{$s['agents_unlinked']}</td></tr>
          </table>

          <p style="{$sectionStyle}">Ameaças</p>
          <table style="width:100%;border-collapse:collapse">
            <tr><th style="{$thStyle}">Métrica</th><th style="{$thStyle}">Valor</th></tr>
            <tr><td style="{$tdStyle}">Total sincronizadas</td><td style="{$tdStyle} {$valStyle}">{$s['threats_total']}</td></tr>
            <tr><td style="{$tdStyle}">Novas nos últimos 7 dias</td><td style="{$tdStyle} color:#dc3545">{$newThreats}</td></tr>
            <tr><td style="{$tdStyle}">Sem ticket</td><td style="{$tdStyle}">{$s['threats_no_ticket']}</td></tr>
          </table>

          <p style="{$sectionStyle}">CVEs</p>
          <table style="width:100%;border-collapse:collapse">
            <tr><th style="{$thStyle}">Severidade</th><th style="{$thStyle}">Quantidade</th></tr>
            <tr><td style="{$tdStyle}">Total</td><td style="{$tdStyle} {$valStyle}">{$cveStats['total']}</td></tr>
            <tr><td style="{$tdStyle}">Críticos</td><td style="{$tdStyle} color:#dc3545">{$cvesBySev['CRITICAL']}</td></tr>
            <tr><td style="{$tdStyle}">Altos</td><td style="{$tdStyle}">{$cvesBySev['HIGH']}</td></tr>
            <tr><td style="{$tdStyle}">Médios</td><td style="{$tdStyle}">{$cvesBySev['MEDIUM']}</td></tr>
          </table>

          <p style="{$sectionStyle}">Ranger / Rogues</p>
          <table style="width:100%;border-collapse:collapse">
            <tr><th style="{$thStyle}">Métrica</th><th style="{$thStyle}">Valor</th></tr>
            <tr><td style="{$tdStyle}">Dispositivos sem agente</td><td style="{$tdStyle} {$valStyle}">{$rogues}</td></tr>
          </table>

        </div>
        <div style="background:#f3f0ff;padding:12px 32px;font-size:11px;color:#6b7280;text-align:center">
          Gerado automaticamente pelo plugin SentinelOne para GLPI &bull; {$week}
        </div>
      </div>
      HTML;

      $now  = date('Y-m-d H:i:s');
      $sent = 0;

      foreach ($recipients as $email) {
         $DB->insert('glpi_queuednotifications', [
            'itemtype'                  => 'PluginSentineloneSync',
            'items_id'                  => 0,
            'notificationtemplates_id'  => 0,
            'entities_id'               => 0,
            'is_deleted'                => 0,
            'name'                      => $subject,
            'sender'                    => '',
            'sendername'                => 'SentinelOne GLPI',
            'recipient'                 => $email,
            'recipientname'             => '',
            'replyto'                   => '',
            'replytoname'               => '',
            'headers'                   => '',
            'body_html'                 => $body,
            'body_text'                 => strip_tags(str_replace(['</tr>', '</p>'], ["\n", "\n"], $body)),
            'date_creation'             => $now,
            'date_mod'                  => $now,
            'sent_try'                  => 0,
            'date_send'                 => null,
         ]);
         $sent++;
      }

      Log::record('reportweekly', 'ok', "Relatorio semanal enfileirado para {$sent} destinatario(s).", $sent);

      return $sent;
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
         'threats_per_day'   => self::getThreatsPerDay(7),
         'attention_agents'  => self::getRows(Agent::getTable(), ['is_infected' => 1], ['last_active_at DESC', 'id DESC'], 6),
         'unlinked_agents'   => self::getRows(Agent::getTable(), ['computers_id' => null], ['last_active_at DESC', 'id DESC'], 6),
         'offline_agents'    => self::getRows(Agent::getTable(), ['is_online' => 0], ['last_active_at DESC', 'id DESC'], 6),
         'threats_by_classification' => self::getThreatsGroupedBy('classification', 5),
         'agents_quarantined'       => self::countRows(Agent::getTable(), ['is_network_quarantine' => 1]),
         'latest_agent_version'     => self::getCommonAgentVersion(),
         'agents_outdated'          => self::countOutdatedAgents(),
         'groups_total'             => self::countRows(Group::getTable()),
         'groups_detect'            => self::countRows(Group::getTable(), ['policy_mode' => 'detect']),
         'groups_none'              => self::countRows(Group::getTable(), ['policy_mode' => 'none']),
         'recent_groups'            => self::getRows(Group::getTable(), [], ['date_mod DESC'], 20),
         'last_agents_sync'         => self::getLastLog('syncagents'),
         'last_threats_sync'        => self::getLastLog('syncthreats'),
         'last_activities_sync'     => self::getLastLog('syncactivities'),
         'last_software_sync'       => self::getLastLog('syncsoftware'),
         'last_groups_sync'         => self::getLastLog('syncgroups'),
         'logs'                     => Log::getRecent(10),
      ];
   }

   private static function getCommonAgentVersion(): string
   {
      global $DB;

      if (!$DB->tableExists(Agent::getTable())) {
         return '';
      }

      $table  = $DB->quoteName(Agent::getTable());
      $result = $DB->doQuery(
         "SELECT `agent_version`, COUNT(*) AS cnt FROM {$table}"
         . " WHERE `agent_version` IS NOT NULL AND `agent_version` != ''"
         . " GROUP BY `agent_version` ORDER BY cnt DESC LIMIT 1"
      );

      if (!$result) {
         return '';
      }

      $row = $result->fetch_assoc();
      return (string)($row['agent_version'] ?? '');
   }

   public static function countOutdatedAgentsPublic(): int
   {
      return self::countOutdatedAgents();
   }

   private static function countOutdatedAgents(): int
   {
      global $DB;

      $latest = self::getCommonAgentVersion();
      if ($latest === '' || !$DB->tableExists(Agent::getTable())) {
         return 0;
      }

      $table  = $DB->quoteName(Agent::getTable());
      $quoted = $DB->quote($latest);
      $result = $DB->doQuery(
         "SELECT COUNT(*) AS cnt FROM {$table}"
         . " WHERE `agent_version` IS NOT NULL AND `agent_version` != ''"
         . " AND `agent_version` != {$quoted}"
      );

      if (!$result) {
         return 0;
      }

      $row = $result->fetch_assoc();
      return (int)($row['cnt'] ?? 0);
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

   private static function upsertThreat(array $raw, array $config, ?ApiClient $client = null): array
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
      $ticketClosed  = false;

      if ($existing !== null && !empty($existing['tickets_id'])) {
         // Preserva o ticket apenas se ainda nao foi fechado; se fechado, permite abrir novo
         if (!self::isTicketClosed((int)$existing['tickets_id'])) {
            $data['tickets_id'] = (int)$existing['tickets_id'];
         }
      }

      if ((string)$config['create_tickets'] === '1' && empty($data['tickets_id']) && self::shouldCreateTicket($data, $config)) {
         $data['tickets_id'] = TicketManager::createForThreat($data, $agent, $config);
         $ticketCreated = true;
      }

      // Fecha o ticket quando a ameaca passa para resolvida/mitigada no SentinelOne
      if (
         (string)($config['auto_close_tickets'] ?? '1') === '1'
         && !empty($data['tickets_id'])
         && self::isResolvedStatus((string)($data['status'] ?? ''))
         && !self::isResolvedStatus((string)($existing['status'] ?? ''))
      ) {
         try {
            TicketManager::closeForThreat((int)$data['tickets_id'], $data);
            $ticketClosed = true;
         } catch (\Throwable $error) {
            Log::record('syncthreats', 'error', 'Falha ao fechar ticket automaticamente: ' . $error->getMessage());
         }
      }

      $now = date('Y-m-d H:i:s');
      $data['date_mod'] = $now;

      if ($existingId !== null) {
         $DB->update(Threat::getTable(), $data, ['id' => $existingId]);
         $data['id'] = $existingId;
         self::maybeSyncNotes($data, $config, $client);
         return ['status' => 'updated', 'ticket_created' => $ticketCreated, 'ticket_closed' => $ticketClosed];
      }

      $data['date_creation'] = $now;
      $DB->insert(Threat::getTable(), $data);
      $data['id'] = (int)$DB->insertId();

      self::maybeAlertThreat($data, $config);
      self::maybeSyncNotes($data, $config, $client);

      return ['status' => 'created', 'ticket_created' => $ticketCreated, 'ticket_closed' => $ticketClosed];
   }

   private static function maybeSyncNotes(array $threat, array $config, ?ApiClient $client): void
   {
      if ((string)($config['sync_threat_notes'] ?? '0') !== '1') {
         return;
      }

      $ticketId = (int)($threat['tickets_id'] ?? 0);
      $threatId = (string)($threat['sentinelone_threat_id'] ?? '');

      if ($ticketId <= 0 || $threatId === '' || $client === null) {
         return;
      }

      try {
         $notes = $client->getThreatNotes($threatId);
      } catch (\Throwable $error) {
         Log::record('syncthreats', 'error', 'Falha ao buscar notas da ameaca ' . $threatId . ': ' . $error->getMessage());
         return;
      }

      if ($notes === []) {
         return;
      }

      $syncedIds = [];
      $raw = (string)($threat['synced_note_ids'] ?? '');
      if ($raw !== '') {
         $syncedIds = json_decode($raw, true) ?: [];
      }

      $newSyncedIds = $syncedIds;
      foreach ($notes as $note) {
         $noteId = (string)($note['id'] ?? $note['noteId'] ?? '');
         if ($noteId === '' || in_array($noteId, $syncedIds, true)) {
            continue;
         }
         TicketManager::addNoteAsFollowup($ticketId, $note);
         $newSyncedIds[] = $noteId;
      }

      if ($newSyncedIds !== $syncedIds && !empty($threat['id'])) {
         global $DB;
         $DB->update(Threat::getTable(), [
            'synced_note_ids' => json_encode($newSyncedIds),
         ], ['id' => (int)$threat['id']]);
      }
   }

   private static function upsertSoftwareForAgent(int $computerId, int $entitiesId, array $apps): void
   {
      global $DB;

      if (
         !$DB->tableExists('glpi_softwares')
         || !$DB->tableExists('glpi_softwareversions')
         || !$DB->tableExists('glpi_computers_softwareversions')
      ) {
         return;
      }

      $now = date('Y-m-d H:i:s');

      foreach ($apps as $app) {
         $name = trim((string)($app['name'] ?? ''));
         if ($name === '') {
            continue;
         }

         $version = trim((string)($app['version'] ?? ''));
         $publisher = trim((string)($app['publisher'] ?? ''));
         $versionName = $version !== '' ? $version : 'N/A';

         $manufacturerId = 0;
         if ($publisher !== '') {
            $manufacturerId = self::findOrCreateRecord('glpi_manufacturers', ['name' => $publisher], [
               'name'          => $publisher,
               'date_creation' => $now,
               'date_mod'      => $now,
            ]);
         }

         $softwareWhere = ['name' => $name, 'is_deleted' => 0];
         if ($manufacturerId > 0) {
            $softwareWhere['manufacturers_id'] = $manufacturerId;
         }
         $softwareId = self::findOrCreateRecord('glpi_softwares', $softwareWhere, [
            'name'             => $name,
            'manufacturers_id' => $manufacturerId,
            'entities_id'      => $entitiesId,
            'is_recursive'     => 1,
            'is_deleted'       => 0,
            'is_template'      => 0,
            'date_creation'    => $now,
            'date_mod'         => $now,
         ]);

         $versionId = self::findOrCreateRecord(
            'glpi_softwareversions',
            ['softwares_id' => $softwareId, 'name' => $versionName],
            [
               'softwares_id'  => $softwareId,
               'name'          => $versionName,
               'entities_id'   => $entitiesId,
               'is_deleted'    => 0,
               'date_creation' => $now,
               'date_mod'      => $now,
            ]
         );

         // Link to computer only if not already linked
         $linked = false;
         foreach ($DB->request([
            'COUNT' => 'cpt',
            'FROM'  => 'glpi_computers_softwareversions',
            'WHERE' => [
               'computers_id'        => $computerId,
               'softwareversions_id' => $versionId,
               'is_deleted'          => 0,
            ],
         ]) as $row) {
            $linked = (int)($row['cpt'] ?? 0) > 0;
         }

         if (!$linked) {
            $DB->insert('glpi_computers_softwareversions', [
               'computers_id'        => $computerId,
               'softwareversions_id' => $versionId,
               'entities_id'         => $entitiesId,
               'is_deleted'          => 0,
               'is_dynamic'          => 1,
            ]);
         }
      }
   }

   private static function findOrCreateRecord(string $table, array $searchWhere, array $insertData): int
   {
      global $DB;

      foreach ($DB->request([
         'SELECT' => ['id'],
         'FROM'   => $table,
         'WHERE'  => $searchWhere,
         'LIMIT'  => 1,
      ]) as $row) {
         return (int)$row['id'];
      }

      $DB->insert($table, $insertData);

      return (int)$DB->insertId();
   }

   private static function getThreatsGroupedBy(string $field, int $limit): array
   {
      global $DB;

      if (!$DB->tableExists(Threat::getTable())) {
         return [];
      }

      $counts = [];
      $limit = max(1, min(20, $limit));

      foreach ($DB->request([
         'SELECT' => [$field],
         'FROM'   => Threat::getTable(),
         'WHERE'  => ['NOT' => [$field => null]],
      ]) as $row) {
         $val = trim((string)($row[$field] ?? ''));
         if ($val !== '') {
            $counts[$val] = ($counts[$val] ?? 0) + 1;
         }
      }

      arsort($counts);

      return array_slice($counts, 0, $limit, true);
   }

   private static function upsertActivity(array $raw): bool
   {
      global $DB;

      $activityId = (string)($raw['id'] ?? $raw['activityId'] ?? '');
      if ($activityId === '') {
         return false;
      }

      $table = Activity::getTable();

      if (!$DB->tableExists($table)) {
         return false;
      }

      if (self::findExistingId($table, 'sentinelone_activity_id', $activityId) !== null) {
         return false;
      }

      $agentId = self::nullable($raw['agentId'] ?? $raw['agent_id'] ?? null);
      $pluginAgentId = null;

      if ($agentId !== null) {
         $agent = self::findAgentBySentineloneId($agentId);
         if ($agent !== null) {
            $pluginAgentId = (int)$agent['id'];
         }
      }

      $occurredAt = self::normalizeDate(
         $raw['activityTime'] ?? $raw['occurred_at'] ?? $raw['createdAt'] ?? null
      );

      $activityType = self::nullable($raw['activityType'] ?? $raw['type'] ?? null);
      $description = self::nullable($raw['primaryDescription'] ?? $raw['description'] ?? null);

      $DB->insert($table, [
         'sentinelone_activity_id'    => $activityId,
         'sentinelone_agent_id'       => $agentId,
         'plugin_sentinelone_agents_id' => $pluginAgentId,
         'activity_type'              => $activityType,
         'description'                => $description,
         'occurred_at'                => $occurredAt,
         'date_creation'              => date('Y-m-d H:i:s'),
      ]);

      return true;
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

      $config = Config::getConfig();
      $siteName = (string)(self::pick($raw, ['siteName', 'site_name']) ?? '');
      $siteMap = Config::parseSiteEntityMap((string)($config['site_entity_map'] ?? ''));
      $entitiesId = isset($siteMap[$siteName]) ? $siteMap[$siteName] : (int)$config['entity_id'];

      return [
         'sentinelone_id' => (string)$id,
         'computers_id'   => self::findComputerId((string)$computerName, (string)$serial, (string)$uuid, $mac),
         'entities_id'    => $entitiesId,
         'computer_name'  => self::nullable($computerName),
         'serial'         => self::nullable($serial),
         'uuid'           => self::nullable($uuid),
         'mac'            => self::nullable($mac),
         'ip'             => self::nullable($ip),
         'os_name'        => self::nullable(self::pick($raw, ['osName', 'os_name', 'osRevision', 'operatingSystem'])),
         'agent_version'  => self::nullable(self::pick($raw, ['agentVersion', 'agent_version', 'version'])),
         'site_name'      => self::nullable(self::pick($raw, ['siteName', 'site_name'])),
         'group_name'     => self::nullable(self::pick($raw, ['groupName', 'group_name'])),
         'is_online'             => self::toBool(self::pick($raw, ['isActive', 'isOnline', 'online', 'active'])),
         'is_infected'           => self::toBool(self::pick($raw, ['infected', 'isInfected'])),
         'is_network_quarantine' => self::toBool(self::pick($raw, ['isNetworkQuarantined', 'networkQuarantine', 'is_network_quarantine'])),
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

   private static function isResolvedStatus(string $status): bool
   {
      return in_array(
         strtolower(trim($status)),
         ['mitigated', 'resolved', 'benign', 'false_positive', 'marked_as_benign'],
         true
      );
   }

   private static function isTicketClosed(int $ticketId): bool
   {
      global $DB;

      if (!$DB->tableExists('glpi_tickets')) {
         return false;
      }

      $closedStatus = defined('Ticket::CLOSED') ? \Ticket::CLOSED : 6;

      foreach ($DB->request([
         'SELECT' => ['status'],
         'FROM'   => 'glpi_tickets',
         'WHERE'  => ['id' => $ticketId],
         'LIMIT'  => 1,
      ]) as $row) {
         return (int)$row['status'] === $closedStatus;
      }

      return false;
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

   private static function getThreatsPerDay(int $days): array
   {
      global $DB;

      $days = max(1, min(30, $days));
      $result = [];
      for ($i = $days - 1; $i >= 0; $i--) {
         $result[date('Y-m-d', strtotime("-{$i} days"))] = 0;
      }

      $oldest = date('Y-m-d 00:00:00', strtotime('-' . ($days - 1) . ' days'));

      foreach ($DB->request([
         'SELECT' => ['detected_at'],
         'FROM'   => Threat::getTable(),
         'WHERE'  => ['NOT' => ['detected_at' => null]],
      ]) as $row) {
         $dt = (string)($row['detected_at'] ?? '');
         if ($dt < $oldest) {
            continue;
         }
         $day = substr($dt, 0, 10);
         if (array_key_exists($day, $result)) {
            $result[$day]++;
         }
      }

      return $result;
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

   // ---- Ações em ameaças ----

   public static function mitigateThreat(int $threatId): bool
   {
      return self::threatAction($threatId, 'mitigate');
   }

   public static function rollbackThreat(int $threatId): bool
   {
      return self::threatAction($threatId, 'rollback');
   }

   public static function setThreatVerdict(int $threatId, string $verdict): bool
   {
      return self::threatAction($threatId, 'verdict', $verdict);
   }

   private static function threatAction(int $threatId, string $action, string $extra = ''): bool
   {
      global $DB;

      $threat = self::getRowById(Threat::getTable(), $threatId);
      if ($threat === null) {
         return false;
      }

      $config = Config::getConfig();
      if (!Config::isConfigured($config)) {
         return false;
      }

      $s1Id = (string)($threat['sentinelone_threat_id'] ?? '');
      if ($s1Id === '') {
         return false;
      }

      try {
         $client = ApiClient::fromConfig($config);

         if ($action === 'mitigate') {
            $client->mitigateThreat($s1Id);
            $DB->update(Threat::getTable(), ['status' => 'mitigated', 'date_mod' => date('Y-m-d H:i:s')], ['id' => $threatId]);
         } elseif ($action === 'rollback') {
            $client->rollbackThreat($s1Id);
         } elseif ($action === 'verdict') {
            $client->setThreatVerdict($s1Id, $extra);
            $DB->update(Threat::getTable(), ['analyst_verdict' => $extra, 'date_mod' => date('Y-m-d H:i:s')], ['id' => $threatId]);
         }

         Log::record('action', 'ok', "Ameaca #{$threatId} acao={$action} executada.");
         return true;
      } catch (\Throwable $e) {
         Log::record('action', 'error', "Ameaca #{$threatId} acao={$action} falhou: " . $e->getMessage());
         return false;
      }
   }

   // ---- Ações remotas em agentes ----

   public static function scanAgent(int $agentId): bool
   {
      return self::agentRemoteAction($agentId, 'scan');
   }

   public static function updateAgent(int $agentId): bool
   {
      return self::agentRemoteAction($agentId, 'update');
   }

   public static function restartAgent(int $agentId): bool
   {
      return self::agentRemoteAction($agentId, 'restart');
   }

   private static function agentRemoteAction(int $agentId, string $action): bool
   {
      $agent = self::getRowById(Agent::getTable(), $agentId);
      if ($agent === null) {
         return false;
      }

      $config = Config::getConfig();
      if (!Config::isConfigured($config)) {
         return false;
      }

      $s1Id = (string)($agent['sentinelone_id'] ?? '');
      if ($s1Id === '') {
         return false;
      }

      try {
         $client = ApiClient::fromConfig($config);

         match ($action) {
            'scan'    => $client->scanAgent($s1Id),
            'update'  => $client->updateAgent($s1Id),
            'restart' => $client->restartAgent($s1Id),
         };

         Log::record('action', 'ok', "Agente #{$agentId} acao={$action} executada.");
         return true;
      } catch (\Throwable $e) {
         Log::record('action', 'error', "Agente #{$agentId} acao={$action} falhou: " . $e->getMessage());
         return false;
      }
   }

   // ---- Cron: alertas de agente offline ----

   public static function cronAlertoffline(?\CronTask $task = null): int
   {
      $config = Config::getConfig();

      if (!Config::isConfigured($config)) {
         return 0;
      }

      $hours = max(1, (int)($config['offline_alert_hours'] ?? 24));
      $threshold = date('Y-m-d H:i:s', strtotime("-{$hours} hours"));

      global $DB;
      $sent = 0;

      foreach ($DB->request([
         'FROM'  => Agent::getTable(),
         'WHERE' => [
            'is_online'    => 0,
            'NOT'          => ['last_active_at' => null],
         ],
      ]) as $agent) {
         $lastActive = (string)($agent['last_active_at'] ?? '');
         if ($lastActive === '' || $lastActive >= $threshold) {
            continue;
         }

         try {
            Notifier::alertAgentOffline($agent, $config);
            $sent++;
         } catch (\Throwable $e) {
            Log::record('alertoffline', 'error', 'Falha ao alertar agente offline: ' . $e->getMessage());
         }
      }

      if ($task !== null) {
         $task->addVolume($sent);
      }

      Log::record('alertoffline', 'ok', "Alertas de agente offline: {$sent} enviados.");
      return 1;
   }

   private static function fieldExists(string $table, string $field): bool
   {
      global $DB;

      return method_exists($DB, 'fieldExists') && $DB->fieldExists($table, $field);
   }
}

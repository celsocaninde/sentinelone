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
         'syncexclusions' => [
            'description' => 'Auditoria: importa as exclusoes (allowlist) configuradas na console SentinelOne',
         ],
         'alertoffline' => [
            'description' => 'Envia alertas por e-mail para agentes SentinelOne offline ha muito tempo',
         ],
         'reportweekly' => [
            'description' => 'Envia relatorio executivo semanal com resumo operacional do SentinelOne',
         ],
         'purgelogs' => [
            'description' => 'Remove logs antigos do plugin SentinelOne conforme politica de retencao configurada',
         ],
         'retryfailedtickets' => [
            'description' => 'Reprocessa tickets de ameaca que falharam ao serem criados (fila de retry)',
         ],
         'enrichcves' => [
            'description' => 'Enriquece CVEs da frota com EPSS (FIRST.org) e catalogo CISA KEV de exploracao ativa',
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

   public static function cronEnrichcves(?\CronTask $task = null): int
   {
      try {
         $result = Enrichment::refresh();

         Log::record('enrichcves', 'success', sprintf(
            'Threat intel atualizada: %d CVEs com EPSS, %d no catalogo KEV.',
            $result['epss'],
            $result['kev']
         ));

         // Opt-in: ticket consolidado por endpoint para CVEs KEV ineditos.
         [$kevTickets, ] = KevTicket::processNewFindings();

         if ($task !== null) {
            $task->addVolume($result['epss'] + $result['kev'] + $kevTickets);
         }

         return 1;
      } catch (\Throwable $error) {
         Log::record('enrichcves', 'error', $error->getMessage());
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

   public static function cronSyncexclusions(?\CronTask $task = null): int
   {
      try {
         $result = self::syncExclusions();

         if ($task !== null) {
            $task->addVolume($result['total']);
         }

         return 1;
      } catch (\Throwable $error) {
         Log::record('syncexclusions', 'error', $error->getMessage());
         return 0;
      }
   }

   public static function syncExclusions(): array
   {
      $config = Config::getConfig();

      if (!Config::isConfigured($config)) {
         Log::record('syncexclusions', 'skipped', 'Integracao SentinelOne nao configurada.');
         return ['total' => 0, 'status' => 'not_configured'];
      }

      if ((string)($config['sync_exclusions'] ?? '0') !== '1') {
         Log::record('syncexclusions', 'skipped', 'Sincronizacao de exclusoes desativada nas configuracoes (opt-in).');
         return ['total' => 0, 'status' => 'disabled'];
      }

      try {
         $client = ApiClient::fromConfig($config);
         $items  = $client->getExclusions();
      } catch (\Throwable $e) {
         $msg = $e->getMessage();
         Log::record('syncexclusions', 'error', $msg);
         $forbidden = str_contains($msg, '403') || stripos($msg, 'permission') !== false;
         return [
            'total'  => 0,
            'status' => $forbidden ? 'forbidden' : 'error',
            'error'  => $msg,
         ];
      }

      $result = Exclusion::upsertFromApi($items);

      Log::record('syncexclusions', 'ok', sprintf(
         'Auditoria de exclusoes concluida: %d importadas, %d removidas (nao existem mais na console).',
         $result['imported'],
         $result['removed']
      ), $result['imported']);

      return ['total' => $result['imported'], 'status' => 'ok'];
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

   /**
    * Sonda cada modulo da API SentinelOne com uma chamada minima (limit=1) e
    * reporta se o token tem acesso (200), se foi negado (403) ou se houve outro
    * erro. Util para diagnosticar "por que tal sync nao traz nada" — tipicamente
    * token sem escopo de Ranger (rogues) ou Vulnerability Management (CVEs).
    *
    * @return array{configured:bool, modules:array<int,array{name:string,ok:bool,status:string,detail:string,ms:int}>}
    */
   public static function checkPermissions(): array
   {
      $config = Config::getConfig();

      if (!Config::isConfigured($config)) {
         return ['configured' => false, 'modules' => []];
      }

      // Cliente fail-fast (timeout curto, sem retry): o probe deve responder
      // rapido para nao travar o painel quando um modulo erra ou demora.
      $client = ApiClient::probe($config);

      $probes = [
         'Agentes'                  => static fn() => $client->getAgents(['limit' => 1], 1),
         'Ameacas'                  => static fn() => $client->getThreats(['limit' => 1], 1),
         'Atividades'               => static fn() => $client->getActivities(['limit' => 1], 1),
         'Grupos'                   => static fn() => $client->getGroups(['limit' => 1], 1),
         'Aplicacoes / CVE (Vuln.)' => static fn() => $client->getRiskyApplications(['limit' => 1], 1),
         'Rogues (Ranger)'          => static fn() => $client->getRogueDevices(['limit' => 1], 1),
      ];

      $modules = [];
      foreach ($probes as $name => $probe) {
         $start = microtime(true);
         try {
            $probe();
            $modules[] = [
               'name'   => $name,
               'ok'     => true,
               'status' => 'OK',
               'detail' => '',
               'ms'     => (int)round((microtime(true) - $start) * 1000),
            ];
         } catch (\Throwable $error) {
            $msg = $error->getMessage();
            $forbidden = str_contains($msg, '403') || stripos($msg, 'permission') !== false;
            $modules[] = [
               'name'   => $name,
               'ok'     => false,
               'status' => $forbidden ? 'Sem permissao (403)' : 'Erro',
               'detail' => $msg,
               'ms'     => (int)round((microtime(true) - $start) * 1000),
            ];
         }
      }

      return ['configured' => true, 'modules' => $modules];
   }

   // ---- Wrappers com lock (impedem execucoes sobrepostas: cron x manual) ----
   // O cron do GLPI ja serializa a mesma tarefa; o lock cobre o caso de um
   // disparo manual (sync.form.php) coincidir com o cron, ou vice-versa.

   public static function syncThreats(): array
   {
      return self::withLock('syncthreats', static fn(): array => self::syncThreatsImpl(), [
         'processed' => 0, 'created' => 0, 'updated' => 0, 'tickets' => 0, 'tickets_closed' => 0, 'status' => 'locked',
      ]);
   }

   public static function syncAgents(): array
   {
      return self::withLock('syncagents', static fn(): array => self::syncAgentsImpl(), [
         'processed' => 0, 'created' => 0, 'updated' => 0, 'status' => 'locked',
      ]);
   }

   public static function syncActivities(): array
   {
      return self::withLock('syncactivities', static fn(): array => self::syncActivitiesImpl(), [
         'processed' => 0, 'created' => 0, 'status' => 'locked',
      ]);
   }

   public static function syncGroups(): array
   {
      return self::withLock('syncgroups', static fn(): array => self::syncGroupsImpl(), [
         'processed' => 0, 'updated' => 0, 'status' => 'locked',
      ]);
   }

   /**
    * Executa $fn sob um lock nomeado do MariaDB (GET_LOCK). Se o lock ja estiver
    * tomado por outra execucao, registra "skipped" e devolve $skippedResult sem
    * rodar. O lock e por conexao e e liberado no finally (e tambem ao encerrar o
    * processo/requisicao, como rede de seguranca).
    *
    * @param array<string,mixed> $skippedResult
    * @return array<string,mixed>
    */
   private static function withLock(string $key, callable $fn, array $skippedResult): array
   {
      global $DB;

      $lockName = $DB->quote('glpi_s1_' . $key);

      $result = $DB->doQuery("SELECT GET_LOCK({$lockName}, 0) AS locked");
      $acquired = $result && (int)(($result->fetch_assoc()['locked']) ?? 0) === 1;

      if (!$acquired) {
         Log::record($key, 'skipped', 'Sincronizacao ignorada: outra execucao ja esta em andamento (lock ativo).');
         return $skippedResult;
      }

      try {
         return $fn();
      } finally {
         $DB->doQuery("SELECT RELEASE_LOCK({$lockName})");
      }
   }

   public static function isSyncLocked(string $key): bool
   {
      global $DB;

      $lockName = $DB->quote('glpi_s1_' . $key);
      // IS_FREE_LOCK = 1 (livre), 0 (tomado), NULL (erro)
      $result = $DB->doQuery("SELECT IS_FREE_LOCK({$lockName}) AS free");
      if (!$result) {
         return false;
      }
      $free = $result->fetch_assoc()['free'] ?? null;

      return $free !== null && (int)$free === 0;
   }

   public static function retryFailedTickets(): array
   {
      return self::withLock('retryfailedtickets', static fn(): array => self::retryFailedTicketsImpl(), [
         'processed' => 0, 'resolved' => 0, 'failed' => 0, 'status' => 'locked',
      ]);
   }

   private static function retryFailedTicketsImpl(): array
   {
      $config = Config::getConfig();
      if (!Config::isConfigured($config)) {
         return ['processed' => 0, 'resolved' => 0, 'failed' => 0, 'status' => 'not_configured'];
      }

      $pending  = FailedTicket::getPending(50);
      $resolved = 0;
      $failed   = 0;

      foreach ($pending as $row) {
         $id       = (int)$row['id'];
         $attempts = (int)($row['attempts'] ?? 0) + 1;

         $threat = json_decode((string)($row['payload'] ?? ''), true);
         if (!is_array($threat)) {
            FailedTicket::registerFailure($id, $attempts, 'Payload invalido (JSON nao decodificavel).');
            $failed++;
            continue;
         }

         $agent = null;
         if (!empty($row['agent_payload'])) {
            $decoded = json_decode((string)$row['agent_payload'], true);
            if (is_array($decoded)) {
               $agent = $decoded;
            }
         }

         // A ameaca pode ter ganhado um ticket num sync posterior; nao duplicar.
         $threatId = (string)($threat['sentinelone_threat_id'] ?? '');
         $existing = self::ticketIdForThreat($threatId);
         if ($existing > 0) {
            FailedTicket::markResolved($id, $existing);
            $resolved++;
            continue;
         }

         try {
            $ticketId = TicketManager::createForThreat($threat, $agent, $config);
            if ($ticketId > 0) {
               self::attachTicketToThreat($threatId, $ticketId);
               if ((string)($config['ticket_threat_details'] ?? '1') === '1') {
                  try {
                     TicketManager::addThreatDetailsFollowup($ticketId, $threat, $agent, $config);
                  } catch (\Throwable) {
                     // nota forense e opcional
                  }
               }
               FailedTicket::markResolved($id, $ticketId);
               $resolved++;
            } else {
               FailedTicket::registerFailure($id, $attempts, 'createForThreat retornou 0.');
               $failed++;
            }
         } catch (\Throwable $error) {
            FailedTicket::registerFailure($id, $attempts, $error->getMessage());
            $failed++;
         }
      }

      if ($resolved > 0 || $failed > 0) {
         Log::record('retryfailedtickets', 'ok', "Retry da fila: {$resolved} resolvido(s), {$failed} ainda pendente(s).", $resolved);
      }

      return ['processed' => count($pending), 'resolved' => $resolved, 'failed' => $failed, 'status' => 'ok'];
   }

   private static function ticketIdForThreat(string $threatId): int
   {
      global $DB;

      if ($threatId === '') {
         return 0;
      }

      foreach ($DB->request([
         'SELECT' => ['tickets_id'],
         'FROM'   => Threat::getTable(),
         'WHERE'  => ['sentinelone_threat_id' => $threatId],
         'LIMIT'  => 1,
      ]) as $row) {
         return (int)($row['tickets_id'] ?? 0);
      }

      return 0;
   }

   private static function attachTicketToThreat(string $threatId, int $ticketId): void
   {
      global $DB;

      if ($threatId === '') {
         return;
      }

      $DB->update(Threat::getTable(), [
         'tickets_id' => $ticketId,
         'date_mod'   => date('Y-m-d H:i:s'),
      ], ['sentinelone_threat_id' => $threatId]);
   }

   private static function syncGroupsImpl(): array
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
      $drift   = [];
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

         // Policy drift: grupos sem bloqueio automatico (Detect / None) sao um risco.
         if (in_array($policyMode, ['detect', 'none'], true)) {
            $drift[] = ($name !== '' ? $name : $sid) . ' (' . $policyMode . ')';
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

      // Alerta de policy drift: registra (e espelha em sentinelone.log) quando ha
      // grupos sem mitigacao automatica — eles so detectam, nao bloqueiam.
      if ($drift !== []) {
         Log::record('syncgroups', 'warning', count($drift) . ' grupo(s) sem bloqueio automatico (modo Detect/None): ' . implode(', ', array_slice($drift, 0, 20)) . '.', count($drift));
      }

      return ['processed' => count($groups), 'updated' => $updated, 'drift' => count($drift)];
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
         return ['processed' => 0, 'cves' => 0, 'status' => 'not_configured'];
      }

      if (!$force && (string)($config['sync_cves'] ?? '0') !== '1') {
         return ['processed' => 0, 'cves' => 0, 'status' => 'disabled'];
      }

      // Pode percorrer varias paginas/aplicacoes; evita estourar o tempo padrao.
      @set_time_limit(0);

      $client = ApiClient::fromConfig($config);

      // Mapa uuid -> id do agente local (uma vez), para cobrir a frota inteira.
      $agentIdByUuid = [];
      foreach ($DB->request([
         'SELECT' => ['id', 'uuid'],
         'FROM'   => Agent::getTable(),
      ]) as $row) {
         $uuid = strtolower(trim((string)($row['uuid'] ?? '')));
         if ($uuid !== '') {
            $agentIdByUuid[$uuid] = (int)$row['id'];
         }
      }

      // 1) Todas as aplicacoes com risco da conta de uma vez (em vez de 1 chamada
      //    por agente). Normalmente sao poucas, entao cobre a frota toda barato.
      try {
         $riskyApps = $client->getRiskyApplications();
      } catch (\Throwable $error) {
         $msg = $error->getMessage();
         $forbidden = str_contains($msg, '403') || stripos($msg, 'permission') !== false;
         Log::record('synccves', 'error', ($forbidden
            ? 'Acesso negado pelo SentinelOne (403): token sem permissao para Application Risk / Vulnerability Management. '
            : 'Falha ao buscar aplicacoes com risco: ') . $msg);
         return ['processed' => 0, 'cves' => 0, 'status' => $forbidden ? 'forbidden' : 'error', 'error' => $msg];
      }

      // 2) Agrupa CVEs por agente local, buscando os CVEs de cada aplicacao uma vez.
      $cvesByAgent = [];
      $appCveCache = [];
      $unmatched   = 0;
      foreach ($riskyApps as $app) {
         $uuid = strtolower(trim((string)($app['agentUuid'] ?? '')));
         if ($uuid === '' || !isset($agentIdByUuid[$uuid])) {
            $unmatched++;
            continue;
         }
         $agentId = $agentIdByUuid[$uuid];

         $appId = trim((string)($app['id'] ?? ''));
         if ($appId === '') {
            continue;
         }

         if (!isset($appCveCache[$appId])) {
            try {
               $appCveCache[$appId] = $client->getApplicationCves($appId);
            } catch (\Throwable $error) {
               Log::record('synccves', 'warning', 'Aplicacao ' . $appId . ': ' . $error->getMessage());
               $appCveCache[$appId] = [];
            }
         }

         foreach ($appCveCache[$appId] as $cve) {
            $cve['application_name']    = $app['name'] ?? null;
            $cve['application_version'] = $app['version'] ?? null;
            $cvesByAgent[$agentId][]    = $cve;
         }
      }

      // 3) Refresh completo: limpa a tabela e reinsere (so apos buscar tudo com sucesso).
      if ($DB->tableExists(Cve::getTable())) {
         $DB->delete(Cve::getTable(), [new \QueryExpression('1 = 1')]);
      }

      $totalCves = 0;
      foreach ($cvesByAgent as $agentId => $cves) {
         self::upsertCvesForAgent((int)$agentId, $cves);
         $totalCves += count($cves);
      }

      Log::record('synccves', 'ok', sprintf(
         'Sincronizacao de CVEs concluida. %d apps com risco, %d endpoints, %d CVEs.',
         count($riskyApps),
         count($cvesByAgent),
         $totalCves
      ), count($cvesByAgent));

      return [
         'processed' => count($cvesByAgent),
         'cves'      => $totalCves,
         'apps'      => count($riskyApps),
         'unmatched' => $unmatched,
         'status'    => 'ok',
      ];
   }

   public static function syncRogues(): array
   {
      $config = Config::getConfig();

      if (!Config::isConfigured($config)) {
         Log::record('syncrogues', 'skipped', 'Integracao SentinelOne nao configurada.');
         return ['total' => 0, 'status' => 'not_configured'];
      }

      if ((string)($config['sync_rogues'] ?? '0') !== '1') {
         Log::record('syncrogues', 'skipped', 'Sincronizacao de rogues desativada nas configuracoes (opt-in).');
         return ['total' => 0, 'status' => 'disabled'];
      }

      try {
         $client  = ApiClient::fromConfig($config);
         $devices = $client->getRogueDevices();
      } catch (\Throwable $e) {
         $msg = $e->getMessage();
         Log::record('syncrogues', 'error', $msg);
         // 403 = a conta/token nao tem acesso ao Ranger (licenca ou permissao).
         $forbidden = str_contains($msg, '403') || stripos($msg, 'permission') !== false;
         return [
            'total'  => 0,
            'status' => $forbidden ? 'forbidden' : 'error',
            'error'  => $msg,
         ];
      }

      self::upsertRogueDevices($devices);

      Log::record('syncrogues', 'ok', 'Sincronizacao de dispositivos rogues concluida.', count($devices));

      return ['total' => count($devices), 'status' => 'ok'];
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

         // Field names follow the SentinelOne /rogues/table-view schema, with the
         // older/snake_case names kept as fallbacks.
         $hostnames = $item['hostnames'] ?? null;
         $hostname  = is_array($hostnames) && $hostnames !== []
            ? trim((string)$hostnames[0])
            : trim((string)($item['networkName'] ?? $item['hostname'] ?? ''));
         $ip        = trim((string)($item['localIp'] ?? $item['ip'] ?? ''));
         $extIp     = trim((string)($item['externalIp'] ?? $item['external_ip'] ?? ''));
         $mac       = trim((string)($item['macAddress'] ?? $item['mac'] ?? ''));
         $os        = trim((string)($item['osName'] ?? $item['os'] ?? ''));
         $osVersion = trim((string)($item['osVersion'] ?? ''));
         if ($os !== '' && $osVersion !== '' && stripos($os, $osVersion) === false) {
            $os .= ' ' . $osVersion;
         }
         $classif   = trim((string)($item['deviceType'] ?? $item['deviceFunction'] ?? $item['classification'] ?? ''));
         $vendor    = trim((string)($item['manufacturer'] ?? $item['vendor'] ?? ''));
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

         // /installed-applications/cves expoe `riskLevel` (none/low/medium/high/critical)
         // e `score` (CVSS). Mantemos os nomes antigos como fallback.
         $severityRaw = (string)($item['severity'] ?? $item['riskLevel'] ?? '');
         $severity = strtoupper(trim($severityRaw !== '' ? $severityRaw : 'UNKNOWN'));
         $cvssScore = $item['cvssScore'] ?? $item['cvss'] ?? $item['score'] ?? null;
         $cvssScore = $cvssScore !== null ? (float)$cvssScore : null;
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

   private static function syncActivitiesImpl(): array
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

   private static function syncAgentsImpl(): array
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

      // Filtro de data de corte: aplica quando nao ha cursor incremental ativo.
      $syncDateFrom = trim((string)($config['sync_date_from'] ?? ''));
      if ($syncDateFrom !== '' && !isset($params['updatedAt__gt'])) {
         $ts = strtotime($syncDateFrom);
         if ($ts !== false) {
            $params['updatedAt__gt'] = gmdate('Y-m-d\TH:i:s.000\Z', $ts);
         }
      }

      // Filtro de agentes inativos: exclui agentes sem contato ha mais de N dias.
      $inactiveDays = (int)($config['agent_inactive_days'] ?? 0);
      if ($inactiveDays > 0) {
         $params['lastActiveDate__gt'] = gmdate('Y-m-d\TH:i:s.000\Z', time() - ($inactiveDays * 86400));
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

   private static function syncThreatsImpl(): array
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

      // Filtro de data de corte: aplica apenas ameacas criadas/atualizadas desde a data configurada.
      $syncDateFrom = trim((string)($config['sync_date_from'] ?? ''));
      if ($syncDateFrom !== '' && !isset($params['updatedAt__gt'])) {
         $ts = strtotime($syncDateFrom);
         if ($ts !== false) {
            $params['createdAt__gt'] = gmdate('Y-m-d\TH:i:s.000\Z', $ts);
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

   public static function cronRetryfailedtickets(?\CronTask $task = null): int
   {
      try {
         $result = self::retryFailedTickets();

         if ($task !== null) {
            $task->addVolume((int)($result['resolved'] ?? 0));
         }

         return 1;
      } catch (\Throwable $error) {
         Log::record('retryfailedtickets', 'error', $error->getMessage());
         return 0;
      }
   }

   public static function cronPurgelogs(?\CronTask $task = null): int
   {
      try {
         $deleted = self::purgeLogs();

         if ($task !== null) {
            $task->addVolume($deleted);
         }

         return 1;
      } catch (\Throwable $error) {
         Log::record('purgelogs', 'error', $error->getMessage());
         return 0;
      }
   }

   private static function purgeLogs(): int
   {
      global $DB;

      $config = Config::getConfig();
      $days = max(30, (int)($config['log_retention_days'] ?? 90));
      $cutoff = date('Y-m-d H:i:s', strtotime("-{$days} days"));

      $table = Log::getTable();
      if (!$DB->tableExists($table)) {
         return 0;
      }

      $DB->delete($table, ['date_creation' => ['<', $cutoff]]);
      $deleted = (int)$DB->affectedRows();

      if ($deleted > 0) {
         Log::record('purgelogs', 'ok', "Logs com mais de {$days} dias removidos: {$deleted} registros.", $deleted);
      }

      return $deleted;
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

      $period  = date('d/m/Y', strtotime('-7 days')) . ' – ' . date('d/m/Y');
      $subject = '[SentinelOne] Relatório Executivo de Segurança – ' . $period;
      $body    = self::buildExecutiveReportHtml(7, $period);

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
            'body_text'                 => strip_tags(str_replace(['</tr>', '</td>', '</p>'], ["\n", "\t", "\n"], $body)),
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

   public static function buildExecutiveReportHtml(int $days = 7, string $periodLabel = ''): string
   {
      global $DB;

      $s         = self::stats();
      $cveStats  = Cve::getGlobalStats();
      $cvesBySev = $cveStats['by_severity'] ?? [];

      $cutoff     = date('Y-m-d H:i:s', strtotime("-{$days} days"));
      $newThreats = 0;
      foreach ($DB->request([
         'COUNT' => 'cpt',
         'FROM'  => Threat::getTable(),
         'WHERE' => ['detected_at' => ['>=', $cutoff]],
      ]) as $r) {
         $newThreats = (int)($r['cpt'] ?? 0);
      }

      $trend = self::getThreatsPerDay(min($days, 30));

      // Protection Index: coverage % minus risk penalties
      $covered     = (int)($s['agents_total'] ?? 0);
      $unprotected = (int)($s['computers_unprotected'] ?? 0);
      $total       = $covered + $unprotected;
      $coveragePct = $total > 0 ? ($covered / $total * 100) : 0;
      $penalty     = min(20, (int)($s['agents_infected'] ?? 0) * 3)
                   + min(10, (int)($s['agents_outdated'] ?? 0) * 0.5)
                   + min(5,  (int)($s['agents_offline']  ?? 0) * 0.1);
      $idx         = max(0, min(100, (int)round($coveragePct - $penalty)));

      [$idxColor, $idxLabel, $idxBg] = match(true) {
         $idx >= 90 => ['#16a34a', 'Proteção em nível excelente',                   '#f0fdf4'],
         $idx >= 75 => ['#2563eb', 'Proteção em nível satisfatório',                '#eff6ff'],
         $idx >= 60 => ['#d97706', 'Proteção requer atenção',                       '#fffbeb'],
         default    => ['#dc2626', 'Proteção crítica — ação imediata necessária',   '#fef2f2'],
      };

      // Bar chart (inline table, email-safe)
      $dayNames = ['Dom', 'Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb'];
      $maxCount = max(1, ...array_values($trend));
      $barsHtml = '';
      foreach ($trend as $date => $count) {
         $lbl = $dayNames[(int)date('w', strtotime($date))];
         $h   = (int)max(4, round($count / $maxCount * 56));
         $bg  = match(true) {
            $count === 0 => '#ddd6fc',
            $count <= 2  => '#a78bfa',
            $count <= 5  => '#7c3aed',
            default      => '#3d0fa0',
         };
         $barsHtml .= '<td style="text-align:center;vertical-align:bottom;padding:0 2px">'
            . '<table cellpadding="0" cellspacing="0" style="margin:0 auto"><tr>'
            . '<td bgcolor="' . $bg . '" width="22" height="' . $h . '" style="background:' . $bg . ';border-radius:3px 3px 0 0"></td>'
            . '</tr></table>'
            . '<div style="font-size:9px;color:#6b7280;margin-top:3px;font-family:Arial,sans-serif">' . $lbl . '</div>'
            . '<div style="font-size:10px;font-weight:700;color:#2d1f6e;font-family:Arial,sans-serif">' . $count . '</div>'
            . '</td>';
      }

      // Devices requiring attention
      $attHtml  = '';
      $infected = array_slice($s['attention_agents'] ?? [], 0, 5);
      if (empty($infected)) {
         $attHtml = '<tr><td colspan="2" style="padding:14px;text-align:center;color:#16a34a;font-size:13px;font-family:Arial,sans-serif">'
            . '&#10003; Nenhum dispositivo com ameaça ativa neste período</td></tr>';
      } else {
         foreach ($infected as $ag) {
            $host    = htmlspecialchars((string)($ag['computer_name'] ?? $ag['hostname'] ?? '—'));
            $attHtml .= '<tr>'
               . '<td style="padding:9px 14px;font-size:12px;color:#2d1f6e;border-bottom:1px solid #ede9fb;font-family:Arial,sans-serif">'
               . '<span style="display:inline-block;width:7px;height:7px;background:#ef4444;border-radius:50%;margin-right:8px"></span>' . $host . '</td>'
               . '<td style="padding:9px 14px;font-size:11px;color:#dc2626;font-weight:600;border-bottom:1px solid #ede9fb;font-family:Arial,sans-serif">Ameaça ativa</td>'
               . '</tr>';
         }
      }

      // Numeric values used in HTML
      $pct          = $total > 0 ? (int)round($covered / $total * 100) : 0;
      $pw           = min(100, $idx);
      $pr           = 100 - $pw;
      $period       = $periodLabel ?: date('d/m/Y', strtotime("-{$days} days")) . ' – ' . date('d/m/Y');
      $genAt        = date('d/m/Y \à\s H:i');
      $nextRep      = date('d/m/Y', strtotime('+7 days'));
      $agTotal      = (int)($s['agents_total']    ?? 0);
      $agInfected   = (int)($s['agents_infected'] ?? 0);
      $agOutdated   = (int)($s['agents_outdated'] ?? 0);
      $thrTotal     = (int)($s['threats_total']   ?? 0);
      $thrNoTicket  = (int)($s['threats_no_ticket'] ?? 0);
      $cveTotal     = (int)($cveStats['total']    ?? 0);
      $cveCritical  = (int)($cvesBySev['CRITICAL'] ?? 0);
      $cveHigh      = (int)($cvesBySev['HIGH']    ?? 0);
      $kevCves      = (int)(Enrichment::getKevSummary()['cves'] ?? 0);

      $h = '<!DOCTYPE html><html><head><meta charset="UTF-8"></head>'
         . '<body style="margin:0;padding:0;background:#f0eeff;font-family:Arial,sans-serif">'
         . '<table width="100%" cellpadding="0" cellspacing="0" bgcolor="#f0eeff" style="background:#f0eeff;padding:24px 0">'
         . '<tr><td align="center">'
         . '<table width="600" cellpadding="0" cellspacing="0" style="border-radius:12px;overflow:hidden;border:1px solid #e0d9f8">'

         // HEADER
         . '<tr><td bgcolor="#2d1f6e" style="background:#2d1f6e;padding:28px 32px;text-align:center">'
         . '<div style="font-size:38px;font-weight:900;color:#fff;letter-spacing:-2px;font-family:Arial,sans-serif">S1</div>'
         . '<div style="color:#9d85e8;font-size:10px;letter-spacing:5px;text-transform:uppercase;margin:2px 0 10px;font-family:Arial,sans-serif">SentinelOne</div>'
         . '<div style="color:#fff;font-size:20px;font-weight:700;margin:0 0 6px;font-family:Arial,sans-serif">Relatório Executivo de Segurança</div>'
         . '<div style="color:#c4b8f5;font-size:12px;font-family:Arial,sans-serif">Período: ' . $period . '</div>'
         . '</td></tr>'

         // PROTECTION INDEX
         . '<tr><td bgcolor="' . $idxBg . '" style="background:' . $idxBg . ';padding:28px 32px;text-align:center">'
         . '<div style="font-size:10px;letter-spacing:4px;text-transform:uppercase;color:#6b7280;margin-bottom:8px;font-family:Arial,sans-serif">Índice de Proteção</div>'
         . '<div style="font-size:62px;font-weight:900;color:' . $idxColor . ';line-height:1.1;font-family:Arial,sans-serif">' . $idx . '%</div>'
         . '<div style="font-size:13px;color:#4b5563;margin:8px 0 18px;font-family:Arial,sans-serif">' . $idxLabel . '</div>'
         . '<table width="320" cellpadding="0" cellspacing="0" style="margin:0 auto;border-radius:8px;overflow:hidden"><tr>'
         . '<td width="' . $pw . '%" bgcolor="' . $idxColor . '" height="8" style="background:' . $idxColor . ';height:8px"></td>'
         . '<td width="' . $pr . '%" bgcolor="#e5e7eb" height="8" style="background:#e5e7eb;height:8px"></td>'
         . '</tr></table>'
         . '</td></tr>'

         // KPI CARDS
         . '<tr><td bgcolor="#ffffff" style="background:#fff;padding:20px 32px 14px">'
         . '<table width="100%" cellpadding="0" cellspacing="0"><tr>'
         . '<td width="48%" bgcolor="#f3f0ff" style="background:#f3f0ff;border-radius:10px;padding:16px 18px;vertical-align:top">'
         . '<div style="font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#7c3aed;margin-bottom:6px;font-family:Arial,sans-serif">Cobertura de Endpoints</div>'
         . '<div style="font-size:30px;font-weight:900;color:#2d1f6e;line-height:1;font-family:Arial,sans-serif">' . $agTotal . '<span style="font-size:14px;font-weight:400;color:#9ca3af"> /' . $total . '</span></div>'
         . '<div style="font-size:11px;color:#6b7280;margin-top:5px;font-family:Arial,sans-serif">' . $pct . '% do parque protegido</div>'
         . '</td><td width="4%"></td>'
         . '<td width="48%" style="border:2px solid #fee2e2;background:#fff5f5;border-radius:10px;padding:16px 18px;vertical-align:top">'
         . '<div style="font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#ef4444;margin-bottom:6px;font-family:Arial,sans-serif">Ameaças Detectadas</div>'
         . '<div style="font-size:30px;font-weight:900;color:#dc2626;line-height:1;font-family:Arial,sans-serif">' . $newThreats . '<span style="font-size:14px;font-weight:400;color:#9ca3af"> no período</span></div>'
         . '<div style="font-size:11px;color:#6b7280;margin-top:5px;font-family:Arial,sans-serif">Acumulado total: ' . $thrTotal . ' · Sem ticket: ' . $thrNoTicket . '</div>'
         . '</td></tr>'
         . '<tr><td colspan="3" height="10"></td></tr><tr>'
         . '<td width="48%" style="border:2px solid #fef3c7;background:#fffbeb;border-radius:10px;padding:16px 18px;vertical-align:top">'
         . '<div style="font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#d97706;margin-bottom:6px;font-family:Arial,sans-serif">Endpoints em Risco Ativo</div>'
         . '<div style="font-size:30px;font-weight:900;color:#92400e;line-height:1;font-family:Arial,sans-serif">' . $agInfected . '<span style="font-size:14px;font-weight:400;color:#9ca3af"> infectados</span></div>'
         . '<div style="font-size:11px;color:#6b7280;margin-top:5px;font-family:Arial,sans-serif">Desatualizados: ' . $agOutdated . '  &nbsp;·&nbsp;  Sem S1: ' . $unprotected . '</div>'
         . '</td><td width="4%"></td>'
         . '<td width="48%" style="border:2px solid #bbf7d0;background:#f0fdf4;border-radius:10px;padding:16px 18px;vertical-align:top">'
         . '<div style="font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#16a34a;margin-bottom:6px;font-family:Arial,sans-serif">Vulnerabilidades CVE</div>'
         . '<div style="font-size:30px;font-weight:900;color:#166534;line-height:1;font-family:Arial,sans-serif">' . $cveTotal . '<span style="font-size:14px;font-weight:400;color:#9ca3af"> total</span></div>'
         . '<div style="font-size:11px;color:#6b7280;margin-top:5px;font-family:Arial,sans-serif">Críticas: ' . $cveCritical . '  &nbsp;·&nbsp;  Altas: ' . $cveHigh . '</div>'
         . ($kevCves > 0
            ? '<div style="font-size:11px;font-weight:700;color:#dc2626;margin-top:4px;font-family:Arial,sans-serif">🔥 ' . $kevCves . ' em exploração ativa (CISA KEV)</div>'
            : '')
         . '</td></tr></table>'
         . '</td></tr>'

         // TREND
         . '<tr><td bgcolor="#ffffff" style="background:#fff;padding:4px 32px 22px">'
         . '<div style="font-size:10px;letter-spacing:4px;text-transform:uppercase;color:#6b7280;margin-bottom:10px;font-family:Arial,sans-serif">Tendência de Ameaças (' . $days . ' dias)</div>'
         . '<table width="100%" cellpadding="0" cellspacing="0" bgcolor="#f8f6ff" style="background:#f8f6ff;border-radius:10px;padding:14px 8px">'
         . '<tr bgcolor="#f8f6ff"><td style="padding:14px 8px">'
         . '<table width="100%" cellpadding="0" cellspacing="0"><tr>' . $barsHtml . '</tr></table>'
         . '</td></tr></table>'
         . '</td></tr>'

         // ATTENTION LIST
         . '<tr><td bgcolor="#ffffff" style="background:#fff;padding:4px 32px 24px">'
         . '<div style="font-size:10px;letter-spacing:4px;text-transform:uppercase;color:#6b7280;margin-bottom:10px;font-family:Arial,sans-serif">Dispositivos Requerendo Atenção</div>'
         . '<table width="100%" cellpadding="0" cellspacing="0" bgcolor="#f8f6ff" style="background:#f8f6ff;border-radius:10px;overflow:hidden">'
         . $attHtml
         . '</table></td></tr>'

         // FOOTER
         . '<tr><td bgcolor="#2d1f6e" style="background:#2d1f6e;padding:16px 32px;text-align:center">'
         . '<div style="font-size:11px;color:#c4b8f5;font-family:Arial,sans-serif">Gerado automaticamente em ' . $genAt . '</div>'
         . '<div style="font-size:11px;color:#7c6db5;margin-top:3px;font-family:Arial,sans-serif">Plugin SentinelOne para GLPI &bull; Próximo relatório: ' . $nextRep . '</div>'
         . '</td></tr>'

         . '</table></td></tr></table>'
         . '</body></html>';

      return $h;
   }

   public static function stats(): array
   {
      $latestVersion = self::getCommonAgentVersion();

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
         'latest_agent_version'     => $latestVersion,
         'agents_outdated'          => self::countOutdatedAgents($latestVersion),
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

   private static function countOutdatedAgents(string $knownLatest = ''): int
   {
      global $DB;

      $latest = $knownLatest !== '' ? $knownLatest : self::getCommonAgentVersion();
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
      $existing   = $existingId !== null ? self::getRowById(Threat::getTable(), $existingId) : null;
      $agent      = self::findAgentBySentineloneId((string)$data['sentinelone_agent_id']);

      if ($agent !== null) {
         $data['plugin_sentinelone_agents_id'] = (int)$agent['id'];
         $data['entities_id'] = (int)$agent['entities_id'];
         $data['computer_name'] = $data['computer_name'] ?: (string)$agent['computer_name'];
      }

      $ticketCreated = false;
      $ticketClosed  = false;
      $isNewThreat   = ($existing === null);
      $oldStatus     = (string)($existing['status'] ?? '');
      $newStatus     = (string)($data['status'] ?? '');
      $statusChanged = $oldStatus !== '' && $newStatus !== '' && $oldStatus !== $newStatus;

      if ((string)$config['create_tickets'] === '1') {

         // 1. Preserva ticket da ameaca existente se ainda estiver aberto
         if (!$isNewThreat && !empty($existing['tickets_id'])) {
            if (!self::isTicketClosed((int)$existing['tickets_id'])) {
               $data['tickets_id'] = (int)$existing['tickets_id'];
            }
         }

         // 2. Sem ticket ainda: verifica se o endpoint ja tem um ticket ativo de outra ameaca
         //    (cobre tanto ameacas novas quanto ameacas reativadas cujo ticket anterior fechou)
         if (empty($data['tickets_id']) && $agent !== null && self::shouldCreateTicket($data, $config)) {
            $activeTicketId = self::findActiveEndpointTicket((int)$agent['id']);

            if ($activeTicketId !== null) {
               $data['tickets_id'] = $activeTicketId;
               // Adiciona followup apenas para ameacas genuinamente novas (nao reativacoes)
               if ($isNewThreat) {
                  try {
                     TicketManager::addNewThreatFollowup($activeTicketId, $data, $agent, $config);
                  } catch (\Throwable $error) {
                     Log::record('syncthreats', 'error', 'Falha ao adicionar followup de nova ameaca: ' . $error->getMessage());
                  }
               }
            }
         }

         // 3. Ainda sem ticket: primeira ameaca ativa no endpoint, cria o ticket.
         //    Falha aqui NAO aborta o sync inteiro: a ameaca vai para a fila de
         //    retry (dead-letter) e e reprocessada depois.
         if (empty($data['tickets_id']) && self::shouldCreateTicket($data, $config)) {
            try {
               $data['tickets_id'] = TicketManager::createForThreat($data, $agent, $config);
               $ticketCreated = true;

               // Nota interna com os detalhes forenses do SentinelOne, logo apos abrir o ticket.
               if ((string)($config['ticket_threat_details'] ?? '1') === '1') {
                  try {
                     TicketManager::addThreatDetailsFollowup((int)$data['tickets_id'], $data, $agent, $config);
                  } catch (\Throwable $error) {
                     Log::record('syncthreats', 'error', 'Falha ao adicionar nota de detalhes da ameaca: ' . $error->getMessage());
                  }
               }
            } catch (\Throwable $error) {
               FailedTicket::record($data, $agent, $error->getMessage());
               Log::record('syncthreats', 'error', 'Falha ao criar ticket para ameaca '
                  . (string)($data['sentinelone_threat_id'] ?? '?') . ': ' . $error->getMessage()
                  . ' — enfileirada para retry.');
            }
         }
      }

      // Mudanca de status intermediaria (ex.: active → blocked) → followup informativo
      if (!empty($data['tickets_id']) && $statusChanged && !self::isResolvedStatus($newStatus)) {
         try {
            TicketManager::addStatusChangeFollowup((int)$data['tickets_id'], $data, $oldStatus, $newStatus);
         } catch (\Throwable $error) {
            Log::record('syncthreats', 'error', 'Falha ao adicionar followup de mudanca de status: ' . $error->getMessage());
         }
      }

      // Ameaca resolvida/mitigada no SentinelOne
      if (
         (string)($config['auto_close_tickets'] ?? '1') === '1'
         && !empty($data['tickets_id'])
         && self::isResolvedStatus($newStatus)
         && !self::isResolvedStatus($oldStatus)
      ) {
         $agentId    = $agent !== null ? (int)$agent['id'] : null;
         $allResolved = $agentId !== null
            ? self::allEndpointThreatsResolved($agentId, (string)$data['sentinelone_threat_id'], $newStatus)
            : true;

         if ($allResolved) {
            // Todas as ameacas do endpoint resolvidas → fecha o ticket
            try {
               TicketManager::closeForThreat((int)$data['tickets_id'], $data);
               $ticketClosed = true;
            } catch (\Throwable $error) {
               Log::record('syncthreats', 'error', 'Falha ao fechar ticket automaticamente: ' . $error->getMessage());
            }
         } else {
            // Outras ameacas ainda ativas → adiciona nota de resolucao parcial; ticket permanece aberto
            try {
               TicketManager::addThreatResolvedFollowup((int)$data['tickets_id'], $data);
            } catch (\Throwable $error) {
               Log::record('syncthreats', 'error', 'Falha ao adicionar followup de resolucao parcial: ' . $error->getMessage());
            }
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
      $manufacturerCache = [];

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
            if (!isset($manufacturerCache[$publisher])) {
               $manufacturerCache[$publisher] = self::findOrCreateRecord('glpi_manufacturers', ['name' => $publisher], [
                  'name'          => $publisher,
                  'date_creation' => $now,
                  'date_mod'      => $now,
               ]);
            }
            $manufacturerId = $manufacturerCache[$publisher];
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

      $limit  = max(1, min(20, $limit));
      $table  = $DB->quoteName(Threat::getTable());
      $result = $DB->doQuery(
         "SELECT `{$field}` AS val, COUNT(*) AS cnt"
         . " FROM {$table}"
         . " WHERE `{$field}` IS NOT NULL AND `{$field}` != ''"
         . " GROUP BY `{$field}` ORDER BY cnt DESC LIMIT {$limit}"
      );

      if (!$result) {
         return [];
      }

      $counts = [];
      while ($row = $result->fetch_assoc()) {
         $counts[(string)$row['val']] = (int)$row['cnt'];
      }

      return $counts;
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

   /**
    * Retorna o ID do ticket aberto de ameaca SentinelOne para o endpoint (agente),
    * ou null se nao houver nenhum. Usa a tabela de ameacas como fonte de verdade
    * para evitar conflito com o campo tickets_id de saude do agente.
    */
   private static function findActiveEndpointTicket(int $agentId): ?int
   {
      global $DB;

      $table  = $DB->quoteName(Threat::getTable());
      $result = $DB->doQuery(
         "SELECT `tickets_id` FROM {$table}"
         . " WHERE `plugin_sentinelone_agents_id` = " . $agentId
         . " AND `tickets_id` IS NOT NULL"
         . " AND (`status` IS NULL OR `status` NOT IN"
         . " ('mitigated','resolved','benign','false_positive','marked_as_benign'))"
         . " LIMIT 1"
      );

      if (!$result) {
         return null;
      }

      $row = $result->fetch_assoc();
      if (!$row || empty($row['tickets_id'])) {
         return null;
      }

      $ticketId = (int)$row['tickets_id'];

      return self::isTicketClosed($ticketId) ? null : $ticketId;
   }

   /**
    * Verifica se todas as ameacas com ticket vinculado para este agente estao resolvidas.
    * Recebe a ameaca atual (ainda nao salva) via $currentThreatId/$currentNewStatus
    * para simular corretamente o estado pos-save.
    */
   private static function allEndpointThreatsResolved(int $agentId, string $currentThreatId, string $currentNewStatus): bool
   {
      global $DB;

      $table  = $DB->quoteName(Threat::getTable());
      $result = $DB->doQuery(
         "SELECT `sentinelone_threat_id`, `status` FROM {$table}"
         . " WHERE `plugin_sentinelone_agents_id` = " . $agentId
         . " AND `tickets_id` IS NOT NULL"
      );

      if (!$result) {
         return true;
      }

      while ($row = $result->fetch_assoc()) {
         $threatId = (string)$row['sentinelone_threat_id'];
         $status   = $threatId === $currentThreatId ? $currentNewStatus : (string)($row['status'] ?? '');

         if (!self::isResolvedStatus($status)) {
            return false;
         }
      }

      return true;
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
         'WHERE'  => [
            'NOT'         => ['detected_at' => null],
            'detected_at' => ['>=', $oldest],
         ],
      ]) as $row) {
         $day = substr((string)($row['detected_at'] ?? ''), 0, 10);
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
         // A API SentinelOne devolve timestamps em UTC (sufixo Z). Convertemos
         // para o fuso configurado no sistema (date_default_timezone_get) antes
         // de formatar, para ficar consistente com o resto do plugin, que grava
         // em hora local via date(). Sem isto, detected_at ficava em UTC e
         // aparecia adiantado (ex.: ~4h no horario de Campo Grande, UTC-4).
         return (new \DateTimeImmutable((string)$value))
            ->setTimezone(new \DateTimeZone(date_default_timezone_get()))
            ->format('Y-m-d H:i:s');
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

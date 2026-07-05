<?php

namespace GlpiPlugin\Sentinelone;

/**
 * Auto-ticket para CVEs em exploracao ativa (CISA KEV), opt-in via config
 * `kev_auto_ticket`. Roda apos a cron `enrichcves`: para cada endpoint com
 * pares (agente, CVE KEV) ainda nao tratados, abre UM ticket consolidado
 * listando os CVEs novos e registra os pares na tabela de controle — cada
 * par gera ticket uma unica vez (sem spam em re-execucoes).
 */
class KevTicket
{
   public static string $table = 'glpi_plugin_sentinelone_kev_tickets';

   public static function ensureTable(): void
   {
      global $DB;

      if ($DB->tableExists(self::$table)) {
         return;
      }

      $DB->doQuery(
         "CREATE TABLE IF NOT EXISTS `" . self::$table . "` (
            `id`                           int unsigned NOT NULL AUTO_INCREMENT,
            `plugin_sentinelone_agents_id` int unsigned NOT NULL DEFAULT 0,
            `cve_id`                       varchar(50) NOT NULL DEFAULT '',
            `tickets_id`                   int unsigned NOT NULL DEFAULT 0,
            `date_creation`                timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            UNIQUE KEY `agent_cve` (`plugin_sentinelone_agents_id`, `cve_id`),
            KEY `tickets_id` (`tickets_id`)
         ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
      );
   }

   /**
    * Abre tickets para pares (agente, CVE KEV) ineditos.
    * Retorna [tickets criados, pares registrados].
    *
    * @return array{0:int,1:int}
    */
   public static function processNewFindings(?array $config = null): array
   {
      global $DB;

      $config ??= Config::getConfig();
      if ((string)($config['kev_auto_ticket'] ?? '0') !== '1') {
         return [0, 0];
      }

      self::ensureTable();
      Enrichment::ensureTable();

      if (!$DB->tableExists(Cve::getTable()) || !$DB->tableExists(Agent::getTable())) {
         return [0, 0];
      }

      // Pares (agente, CVE KEV) sem registro de tratamento.
      $result = $DB->doQuery(
         "SELECT c.plugin_sentinelone_agents_id AS aid, c.cve_id,"
         . " MAX(c.severity) AS severity, MAX(c.cvss_score) AS cvss_score,"
         . " MAX(c.application_name) AS application_name,"
         . " MAX(e.epss_score) AS epss_score, MAX(e.kev_ransomware) AS kev_ransomware"
         . " FROM `" . Cve::getTable() . "` c"
         . " INNER JOIN `" . Enrichment::$table . "` e ON e.cve_id = c.cve_id AND e.is_kev = 1"
         . " LEFT JOIN `" . self::$table . "` t ON t.plugin_sentinelone_agents_id = c.plugin_sentinelone_agents_id AND t.cve_id = c.cve_id"
         . " WHERE t.id IS NULL AND c.plugin_sentinelone_agents_id > 0"
         . " GROUP BY c.plugin_sentinelone_agents_id, c.cve_id"
      );

      if (!$result) {
         return [0, 0];
      }

      $byAgent = [];
      while ($row = $result->fetch_assoc()) {
         $byAgent[(int)$row['aid']][] = $row;
      }
      if ($byAgent === []) {
         return [0, 0];
      }

      $tickets = 0;
      $pairs   = 0;
      $now     = date('Y-m-d H:i:s');

      foreach ($byAgent as $agentId => $cves) {
         $agent = $DB->request([
            'FROM'  => Agent::getTable(),
            'WHERE' => ['id' => $agentId],
            'LIMIT' => 1,
         ])->current();
         if (!$agent) {
            continue;
         }

         try {
            $ticketId = TicketManager::createForKev($agent, $cves, $config);
         } catch (\Throwable $e) {
            Log::record('enrichcves', 'error', 'Falha ao abrir ticket KEV para ' . ($agent['computer_name'] ?? '#' . $agentId) . ': ' . $e->getMessage());
            continue;
         }

         foreach ($cves as $cve) {
            $DB->insert(self::$table, [
               'plugin_sentinelone_agents_id' => $agentId,
               'cve_id'                       => (string)$cve['cve_id'],
               'tickets_id'                   => $ticketId,
               'date_creation'                => $now,
            ]);
            $pairs++;
         }
         $tickets++;
      }

      if ($tickets > 0) {
         Log::record('enrichcves', 'success', sprintf('Auto-ticket KEV: %d ticket(s) para %d CVE(s) em exploracao ativa.', $tickets, $pairs));
      }

      return [$tickets, $pairs];
   }
}

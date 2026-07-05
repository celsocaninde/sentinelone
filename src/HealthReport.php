<?php

namespace GlpiPlugin\Sentinelone;

/**
 * Boletim de Saude da Frota: nota 0-10 por endpoint calculada apenas com
 * dados locais do plugin (agentes, ameacas, CVEs e enriquecimento EPSS/KEV).
 * Nao depende de nenhum outro plugin nem de chamadas a API.
 *
 * Modelo: cada endpoint parte de 10 e perde pontos por fator de risco
 * (infeccao, quarentena, silencio, versao antiga, ameacas abertas, CVEs).
 * Veredito: >= 8 saudavel, >= 5 atencao, < 5 critico.
 */
class HealthReport
{
   public const VERDICT_HEALTHY  = 'healthy';
   public const VERDICT_WARNING  = 'warning';
   public const VERDICT_CRITICAL = 'critical';

   /**
    * Calcula a nota de todos os agentes.
    *
    * @return array<int,array{agent:array,score:float,verdict:string,factors:array<int,string>}>
    *         ordenado do pior para o melhor.
    */
   public static function computeScores(): array
   {
      global $DB;

      if (!$DB->tableExists(Agent::getTable())) {
         return [];
      }

      // Referencia de versao: configuracao explicita ou a versao mais comum da frota.
      $config     = Config::getConfig();
      $minVersion = trim((string)($config['min_agent_version'] ?? ''));
      $reference  = $minVersion !== '' ? $minVersion : self::mostCommonVersion();

      $openThreats = self::openThreatsByAgent();
      $cveStats    = self::cveStatsByAgent();

      $rows = [];
      foreach ($DB->request(['FROM' => Agent::getTable()]) as $agent) {
         $agentId = (int)$agent['id'];
         $score   = 10.0;
         $factors = [];

         if ((int)($agent['is_infected'] ?? 0) === 1) {
            $score -= 4;
            $factors[] = __('Infeccao ativa', 'sentinelone');
         }
         if ((int)($agent['is_network_quarantine'] ?? 0) === 1) {
            $score -= 2;
            $factors[] = __('Em quarentena de rede', 'sentinelone');
         }

         $silentDays = self::daysSince((string)($agent['last_active_at'] ?? ''));
         if ((int)($agent['is_online'] ?? 0) !== 1) {
            if ($silentDays !== null && $silentDays > 30) {
               $score -= 3;
               $factors[] = sprintf(__('%d dias sem contato', 'sentinelone'), $silentDays);
            } elseif ($silentDays !== null && $silentDays > 7) {
               $score -= 2;
               $factors[] = sprintf(__('%d dias sem contato', 'sentinelone'), $silentDays);
            } else {
               $score -= 1;
               $factors[] = __('Offline agora', 'sentinelone');
            }
         }

         $version = trim((string)($agent['agent_version'] ?? ''));
         if ($reference !== '' && $version !== '' && version_compare($version, $reference, '<')) {
            $score -= 1;
            $factors[] = sprintf(__('Agente desatualizado (%s)', 'sentinelone'), $version);
         }

         $threats = (int)($openThreats[$agentId] ?? 0);
         if ($threats > 0) {
            $score -= min(2.0, $threats * 0.5);
            $factors[] = sprintf(_n('%d ameaca nao mitigada', '%d ameacas nao mitigadas', $threats, 'sentinelone'), $threats);
         }

         $cve = $cveStats[$agentId] ?? ['critical_high' => 0, 'kev' => 0];
         if ($cve['critical_high'] > 0) {
            $score -= min(2.0, $cve['critical_high'] * 0.25);
            $factors[] = sprintf(__('%d CVEs criticos/altos', 'sentinelone'), $cve['critical_high']);
         }
         if ($cve['kev'] > 0) {
            $score -= 2;
            $factors[] = sprintf(__('%d CVEs em exploracao ativa (KEV)', 'sentinelone'), $cve['kev']);
         }

         $score = round(max(0.0, min(10.0, $score)), 1);

         $rows[] = [
            'agent'   => $agent,
            'score'   => $score,
            'verdict' => self::verdictFor($score),
            'factors' => $factors,
         ];
      }

      usort($rows, static fn(array $a, array $b): int => $a['score'] <=> $b['score']);

      return $rows;
   }

   /**
    * Agregados da frota para o cabecalho do boletim.
    *
    * @param array<int,array> $rows saida de computeScores()
    * @return array{total:int,avg:float,healthy:int,warning:int,critical:int}
    */
   public static function summary(array $rows): array
   {
      $out = ['total' => count($rows), 'avg' => 0.0, 'healthy' => 0, 'warning' => 0, 'critical' => 0];
      if ($rows === []) {
         return $out;
      }

      $sum = 0.0;
      foreach ($rows as $row) {
         $sum += $row['score'];
         if ($row['verdict'] === self::VERDICT_HEALTHY) {
            $out['healthy']++;
         } elseif ($row['verdict'] === self::VERDICT_WARNING) {
            $out['warning']++;
         } else {
            $out['critical']++;
         }
      }
      $out['avg'] = round($sum / count($rows), 1);

      return $out;
   }

   public static function verdictFor(float $score): string
   {
      if ($score >= 8) {
         return self::VERDICT_HEALTHY;
      }
      return $score >= 5 ? self::VERDICT_WARNING : self::VERDICT_CRITICAL;
   }

   public static function verdictLabel(string $verdict): string
   {
      return match ($verdict) {
         self::VERDICT_HEALTHY  => __('Saudavel', 'sentinelone'),
         self::VERDICT_WARNING  => __('Atencao', 'sentinelone'),
         default                => __('Critico', 'sentinelone'),
      };
   }

   // ---- Internos -------------------------------------------------------

   /** Versao de agente mais frequente na frota (referencia de "atualizado"). */
   private static function mostCommonVersion(): string
   {
      global $DB;

      $row = $DB->request([
         'SELECT'  => ['agent_version', 'COUNT' => 'id AS cnt'],
         'FROM'    => Agent::getTable(),
         'WHERE'   => ['NOT' => ['agent_version' => ['', null]]],
         'GROUPBY' => 'agent_version',
         'ORDER'   => 'cnt DESC',
         'LIMIT'   => 1,
      ])->current();

      return $row ? (string)$row['agent_version'] : '';
   }

   /** @return array<int,int> ameacas nao mitigadas por agente */
   private static function openThreatsByAgent(): array
   {
      global $DB;

      if (!$DB->tableExists(Threat::getTable())) {
         return [];
      }

      $map = [];
      foreach ($DB->request([
         'SELECT'  => ['plugin_sentinelone_agents_id', 'COUNT' => 'id AS cnt'],
         'FROM'    => Threat::getTable(),
         'WHERE'   => ['NOT' => ['status' => ['mitigated', 'resolved', 'benign', 'false_positive', 'marked_as_benign']]],
         'GROUPBY' => 'plugin_sentinelone_agents_id',
      ]) as $row) {
         $map[(int)$row['plugin_sentinelone_agents_id']] = (int)$row['cnt'];
      }
      return $map;
   }

   /** @return array<int,array{critical_high:int,kev:int}> CVEs por agente */
   private static function cveStatsByAgent(): array
   {
      global $DB;

      if (!$DB->tableExists(Cve::getTable())) {
         return [];
      }

      $map = [];
      foreach ($DB->request([
         'SELECT'  => ['plugin_sentinelone_agents_id', 'COUNT' => 'id AS cnt'],
         'FROM'    => Cve::getTable(),
         'WHERE'   => ['severity_rank' => ['<=', 2]],
         'GROUPBY' => 'plugin_sentinelone_agents_id',
      ]) as $row) {
         $map[(int)$row['plugin_sentinelone_agents_id']]['critical_high'] = (int)$row['cnt'];
      }

      Enrichment::ensureTable();
      $result = $DB->doQuery(
         "SELECT c.plugin_sentinelone_agents_id AS aid, COUNT(DISTINCT c.cve_id) AS cnt"
         . " FROM `" . Cve::getTable() . "` c"
         . " INNER JOIN `" . Enrichment::$table . "` e ON e.cve_id = c.cve_id AND e.is_kev = 1"
         . " GROUP BY c.plugin_sentinelone_agents_id"
      );
      if ($result) {
         while ($row = $result->fetch_assoc()) {
            $map[(int)$row['aid']]['kev'] = (int)$row['cnt'];
         }
      }

      foreach ($map as $aid => $vals) {
         $map[$aid] += ['critical_high' => 0, 'kev' => 0];
      }

      return $map;
   }

   private static function daysSince(string $timestamp): ?int
   {
      if ($timestamp === '') {
         return null;
      }
      $ts = strtotime($timestamp);
      if ($ts === false) {
         return null;
      }
      return (int)floor((time() - $ts) / 86400);
   }
}

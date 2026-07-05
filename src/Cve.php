<?php

namespace GlpiPlugin\Sentinelone;

class Cve extends \CommonDBTM
{
   public static $rightname = 'plugin_sentinelone_read';

   public static function getTypeName($nb = 0): string
   {
      return $nb > 1 ? __('CVEs SentinelOne', 'sentinelone') : __('CVE SentinelOne', 'sentinelone');
   }

   public static function getTable($classname = null): string
   {
      return 'glpi_plugin_sentinelone_cves';
   }

   public static function countForAgent(int $agentId): int
   {
      global $DB;

      if (!$DB->tableExists(self::getTable())) {
         return 0;
      }

      foreach ($DB->request([
         'COUNT' => 'cpt',
         'FROM'  => self::getTable(),
         'WHERE' => ['plugin_sentinelone_agents_id' => $agentId],
      ]) as $row) {
         return (int)($row['cpt'] ?? 0);
      }

      return 0;
   }

   public static function countCriticalForAgent(int $agentId): int
   {
      global $DB;

      if (!$DB->tableExists(self::getTable())) {
         return 0;
      }

      foreach ($DB->request([
         'COUNT' => 'cpt',
         'FROM'  => self::getTable(),
         'WHERE' => [
            'plugin_sentinelone_agents_id' => $agentId,
            'severity' => ['CRITICAL', 'HIGH'],
         ],
      ]) as $row) {
         return (int)($row['cpt'] ?? 0);
      }

      return 0;
   }

   public static function deleteForAgent(int $agentId): void
   {
      global $DB;

      if (!$DB->tableExists(self::getTable())) {
         return;
      }

      $DB->delete(self::getTable(), ['plugin_sentinelone_agents_id' => $agentId]);
   }

   public static function showForAgent(int $agentId): void
   {
      global $DB;

      if (!$DB->tableExists(self::getTable())) {
         return;
      }

      $total = self::countForAgent($agentId);
      $critical = self::countCriticalForAgent($agentId);

      $badgeClass = $total === 0 ? 's1-badge--ok' : ($critical > 0 ? 's1-badge--critical' : 's1-badge--warning');
      $badgeLabel = $total === 0
         ? __('sem CVEs', 'sentinelone')
         : sprintf(_n('%d CVE', '%d CVEs', $total, 'sentinelone'), $total);

      echo "<div class='sentinelone-panel sentinelone-panel--cves' style='margin-top:12px'>";
      echo "<div class='sentinelone-panel__head'>";
      echo "<span class='ti ti-shield-exclamation'></span>";
      echo "<h3>" . __('CVEs detectados', 'sentinelone') . "</h3>";
      echo "<span class='s1-badge {$badgeClass}'>{$badgeLabel}</span>";
      echo "</div>";

      if ($total === 0) {
         echo "<div class='sentinelone-panel__body'>";
         echo "<p style='color:#6b7280;font-size:13px;margin:0'>" . __('Nenhum CVE encontrado para este endpoint.', 'sentinelone') . "</p>";
         echo "</div>";
         echo "</div>";
         return;
      }

      $rows = [];
      foreach ($DB->request([
         'FROM'  => self::getTable(),
         'WHERE' => ['plugin_sentinelone_agents_id' => $agentId],
         'ORDER' => ['severity_rank ASC', 'cvss_score DESC', 'cve_id ASC'],
      ]) as $row) {
         $rows[] = $row;
      }
      $enrich = Enrichment::forCves(array_column($rows, 'cve_id'));
      $cross  = CrossPlugin::forCves(array_column($rows, 'cve_id'));

      echo "<div class='sentinelone-panel__body' style='padding:0'>";
      echo "<table class='s1-cve-table'>";
      echo "<thead><tr>";
      echo "<th>" . __('CVE', 'sentinelone') . "</th>";
      echo "<th>" . __('Severidade', 'sentinelone') . "</th>";
      echo "<th>" . __('CVSS', 'sentinelone') . "</th>";
      echo "<th title='" . __('Probabilidade de exploracao em 30 dias (FIRST.org)', 'sentinelone') . "'>EPSS</th>";
      echo "<th>" . __('Aplicacao', 'sentinelone') . "</th>";
      echo "<th>" . __('Versao', 'sentinelone') . "</th>";
      echo "<th>" . __('Publicado', 'sentinelone') . "</th>";
      echo "</tr></thead>";
      echo "<tbody>";

      foreach ($rows as $row) {
         $cveId = \Html::cleanInputText((string)$row['cve_id']);
         $severity = (string)($row['severity'] ?? '');
         $cvss = $row['cvss_score'] !== null ? number_format((float)$row['cvss_score'], 1) : '—';
         $appName = \Html::cleanInputText((string)($row['application_name'] ?? ''));
         $appVer = \Html::cleanInputText((string)($row['application_version'] ?? ''));
         $published = $row['published_date'] ? date('d/m/Y', strtotime((string)$row['published_date'])) : '—';
         $link = \Html::cleanInputText((string)($row['cve_link'] ?? ''));

         $sevClass = self::severityClass($severity);

         $e = $enrich[strtoupper((string)$row['cve_id'])] ?? null;
         $kevBadge = '';
         if ($e !== null && !empty($e['is_kev'])) {
            $kevTitle = !empty($e['kev_ransomware'])
               ? __('CISA KEV — exploracao ativa E uso em ransomware', 'sentinelone')
               : __('CISA KEV — exploracao ativa confirmada', 'sentinelone');
            $kevBadge = " <span class='s1-badge s1-badge--critical' style='font-size:.62rem' title='" . \Html::cleanInputText($kevTitle) . "'>&#128293; KEV" . (!empty($e['kev_ransomware']) ? ' &#9760;' : '') . "</span>";
         }
         $kevBadge .= CrossPlugin::badgesHtml($cross[strtoupper((string)$row['cve_id'])] ?? null);
         if ($e !== null && $e['epss_score'] !== null) {
            $epssPct = (float)$e['epss_score'] * 100;
            $epssStyle = $epssPct >= 50 ? 'color:#b5179e;font-weight:700' : ($epssPct >= 10 ? 'font-weight:600' : '');
            $epss = "<span style='{$epssStyle}'>" . number_format($epssPct, $epssPct >= 10 ? 0 : 1) . "%</span>";
         } else {
            $epss = "<span class='s1-muted'>—</span>";
         }

         echo "<tr>";

         if ($link !== '') {
            echo "<td><a href='" . \Html::cleanInputText($link) . "' target='_blank' rel='noopener' class='s1-cve-link'>" . $cveId . " <span class='ti ti-external-link' style='font-size:10px'></span></a>{$kevBadge}</td>";
         } else {
            echo "<td><span class='s1-cve-id'>{$cveId}</span>{$kevBadge}</td>";
         }

         echo "<td><span class='s1-badge {$sevClass}'>" . htmlspecialchars($severity) . "</span></td>";
         echo "<td>{$cvss}</td>";
         echo "<td>{$epss}</td>";
         echo "<td>" . htmlspecialchars($appName) . "</td>";
         echo "<td>" . htmlspecialchars($appVer) . "</td>";
         echo "<td>{$published}</td>";
         echo "</tr>";
      }

      echo "</tbody></table>";
      echo "</div>";
      echo "</div>";
   }

   private static function severityClass(string $severity): string
   {
      return match (strtoupper($severity)) {
         'CRITICAL' => 's1-badge--critical',
         'HIGH'     => 's1-badge--high',
         'MEDIUM'   => 's1-badge--warning',
         'LOW'      => 's1-badge--muted',
         default    => 's1-badge--muted',
      };
   }

   public static function severityRank(string $severity): int
   {
      return match (strtoupper($severity)) {
         'CRITICAL' => 1,
         'HIGH'     => 2,
         'MEDIUM'   => 3,
         'LOW'      => 4,
         default    => 5,
      };
   }

   public static function getGlobalStats(): array
   {
      global $DB;

      if (!$DB->tableExists(self::getTable())) {
         return ['total' => 0, 'by_severity' => []];
      }

      $totals = [];
      $result = $DB->doQuery(
         "SELECT severity, COUNT(*) AS cnt FROM `" . self::getTable() . "` GROUP BY severity ORDER BY MIN(severity_rank)"
      );
      if ($result) {
         while ($row = $result->fetch_assoc()) {
            $totals[(string)$row['severity']] = (int)$row['cnt'];
         }
      }

      return [
         'total'       => array_sum($totals),
         'by_severity' => $totals,
      ];
   }

   /**
    * Aggregated headline metrics for the CVE overview page.
    *
    * @return array{records:int,distinct:int,endpoints:int,apps:int,critical_high:int}
    */
   public static function getSummary(): array
   {
      global $DB;

      $out = ['records' => 0, 'distinct' => 0, 'endpoints' => 0, 'apps' => 0, 'critical_high' => 0];

      if (!$DB->tableExists(self::getTable())) {
         return $out;
      }

      $result = $DB->doQuery(
         "SELECT COUNT(*) AS records,"
         . " COUNT(DISTINCT cve_id) AS distinct_cves,"
         . " COUNT(DISTINCT plugin_sentinelone_agents_id) AS endpoints,"
         . " COUNT(DISTINCT NULLIF(application_name, '')) AS apps,"
         . " SUM(CASE WHEN severity_rank <= 2 THEN 1 ELSE 0 END) AS critical_high"
         . " FROM `" . self::getTable() . "`"
      );

      if ($result && ($row = $result->fetch_assoc())) {
         $out['records']       = (int)$row['records'];
         $out['distinct']      = (int)$row['distinct_cves'];
         $out['endpoints']     = (int)$row['endpoints'];
         $out['apps']          = (int)$row['apps'];
         $out['critical_high'] = (int)$row['critical_high'];
      }

      return $out;
   }

   public static function getTopCves(int $limit = 10): array
   {
      global $DB;

      if (!$DB->tableExists(self::getTable())) {
         return [];
      }

      // KEV (exploracao ativa confirmada) sempre no topo; empates resolvidos
      // por severidade, probabilidade de exploracao (EPSS) e alcance na frota.
      Enrichment::ensureTable();

      $rows = [];
      $result = $DB->doQuery(
         "SELECT c.cve_id, MIN(c.severity_rank) AS top_rank, MAX(c.severity) AS severity,"
         . " MAX(c.cvss_score) AS cvss_score, COUNT(DISTINCT c.plugin_sentinelone_agents_id) AS agents_count,"
         . " MAX(e.is_kev) AS is_kev, MAX(e.epss_score) AS epss_score"
         . " FROM `" . self::getTable() . "` c"
         . " LEFT JOIN `" . Enrichment::$table . "` e ON e.cve_id = c.cve_id"
         . " GROUP BY c.cve_id"
         . " ORDER BY is_kev DESC, top_rank ASC, epss_score DESC, agents_count DESC, cvss_score DESC"
         . " LIMIT " . (int)$limit
      );
      if ($result) {
         while ($row = $result->fetch_assoc()) {
            $rows[] = $row;
         }
      }

      return $rows;
   }

   public static function getTopApplications(int $limit = 10): array
   {
      global $DB;

      if (!$DB->tableExists(self::getTable())) {
         return [];
      }

      $rows = [];
      $result = $DB->doQuery(
         "SELECT application_name, COUNT(*) AS cve_count, COUNT(DISTINCT plugin_sentinelone_agents_id) AS agents_count,"
         . " MIN(severity_rank) AS top_rank"
         . " FROM `" . self::getTable() . "`"
         . " WHERE application_name IS NOT NULL AND application_name != ''"
         . " GROUP BY application_name"
         . " ORDER BY top_rank ASC, cve_count DESC"
         . " LIMIT " . (int)$limit
      );
      if ($result) {
         while ($row = $result->fetch_assoc()) {
            $rows[] = $row;
         }
      }

      return $rows;
   }

   public static function getAgentsWithMostCves(int $limit = 20): array
   {
      global $DB;

      if (!$DB->tableExists(self::getTable()) || !$DB->tableExists(Agent::getTable())) {
         return [];
      }

      $rows = [];
      $result = $DB->doQuery(
         "SELECT a.id AS agent_id, a.computer_name, a.computers_id,"
         . " COUNT(c.id) AS cve_count,"
         . " SUM(CASE WHEN c.severity_rank = 1 THEN 1 ELSE 0 END) AS critical_count"
         . " FROM `" . Agent::getTable() . "` a"
         . " INNER JOIN `" . self::getTable() . "` c ON c.plugin_sentinelone_agents_id = a.id"
         . " GROUP BY a.id, a.computer_name, a.computers_id"
         . " ORDER BY critical_count DESC, cve_count DESC"
         . " LIMIT " . (int)$limit
      );
      if ($result) {
         while ($row = $result->fetch_assoc()) {
            $rows[] = $row;
         }
      }

      return $rows;
   }
}

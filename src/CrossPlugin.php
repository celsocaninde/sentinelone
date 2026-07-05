<?php

namespace GlpiPlugin\Sentinelone;

use Plugin;

/**
 * Correlacao de CVEs entre plugins de seguranca: marca CVEs do SentinelOne
 * que tambem sao reportados por outros scanners instalados neste GLPI
 * (Tanium e Tenable Nessus), confirmando o achado por mais de uma fonte.
 *
 * Degradacao graciosa: se o plugin par nao estiver instalado/ativo ou a
 * tabela nao existir, a fonte e simplesmente ignorada — nenhum badge
 * aparece e nenhuma query e executada. Funciona 100% standalone.
 */
class CrossPlugin
{
   /** Plugins pares ativos E com a tabela de dados presente. */
   public static function sources(): array
   {
      global $DB;
      static $cache = null;

      if ($cache !== null) {
         return $cache;
      }

      $cache = [
         'tanium' => Plugin::isPluginActive('tanium')
            && $DB->tableExists('glpi_plugin_tanium_endpoint_cves'),
         'nessus' => Plugin::isPluginActive('nessusglpi')
            && $DB->tableExists('glpi_plugin_nessusglpi_vulnerabilities'),
      ];
      return $cache;
   }

   public static function hasAnySource(): bool
   {
      return in_array(true, self::sources(), true);
   }

   /**
    * Correlaciona um conjunto de CVE ids com os achados abertos dos pares.
    *
    * @param string[] $cveIds
    * @return array<string,array{tanium:int,nessus:int}> indexado pelo CVE id
    *         em maiusculas; so aparecem CVEs vistos por ao menos um par.
    */
   public static function forCves(array $cveIds): array
   {
      $cveIds = array_values(array_unique(array_filter(array_map('strtoupper', array_map('strval', $cveIds)))));
      if ($cveIds === []) {
         return [];
      }

      $map     = [];
      $sources = self::sources();

      if ($sources['tanium']) {
         foreach (self::taniumCounts($cveIds) as $cve => $n) {
            $map[$cve]['tanium'] = $n;
         }
      }
      if ($sources['nessus']) {
         foreach (self::nessusCounts($cveIds) as $cve => $n) {
            $map[$cve]['nessus'] = $n;
         }
      }

      foreach ($map as &$row) {
         $row += ['tanium' => 0, 'nessus' => 0];
      }
      unset($row);

      return $map;
   }

   /** @return array<string,int> CVE id → achados abertos no Tanium */
   private static function taniumCounts(array $cveIds): array
   {
      global $DB;

      $counts = [];
      foreach ($DB->request([
         'SELECT'  => ['cve_id', 'COUNT' => 'id AS cpt'],
         'FROM'    => 'glpi_plugin_tanium_endpoint_cves',
         'WHERE'   => [
            'cve_id' => $cveIds,
            'NOT'    => ['status' => 'remediated'],
         ],
         'GROUPBY' => 'cve_id',
      ]) as $row) {
         $counts[strtoupper((string)$row['cve_id'])] = (int)$row['cpt'];
      }
      return $counts;
   }

   /**
    * Nessus guarda a lista de CVEs como texto livre (varios ids por achado),
    * entao agrega por valor bruto e explode localmente.
    *
    * @return array<string,int> CVE id → achados abertos
    */
   private static function nessusCounts(array $cveIds): array
   {
      global $DB;

      $wanted = array_fill_keys($cveIds, true);
      $counts = [];

      $result = $DB->doQuery("
         SELECT cve, COUNT(*) AS cpt
         FROM glpi_plugin_nessusglpi_vulnerabilities
         WHERE is_current = 1 AND status = 'open'
           AND cve IS NOT NULL AND cve != ''
         GROUP BY cve
      ");
      if (!$result) {
         return [];
      }

      while ($row = $result->fetch_assoc()) {
         foreach (preg_split('/[\s,;]+/', strtoupper((string)$row['cve'])) ?: [] as $cve) {
            if ($cve !== '' && isset($wanted[$cve])) {
               $counts[$cve] = ($counts[$cve] ?? 0) + (int)$row['cpt'];
            }
         }
      }
      return $counts;
   }

   /** Badges inline ("Tanium ×n", "Nessus ×n") para uma linha de CVE. */
   public static function badgesHtml(?array $row): string
   {
      if (!$row) {
         return '';
      }

      $html = '';
      if (!empty($row['tanium'])) {
         $html .= '<span class="s1-badge s1-badge--muted" style="font-size:.62rem;margin-left:4px;background:#0a1628;color:#fff"'
            . ' title="' . sprintf(__('Tambem reportado pelo Tanium em %d achado(s) aberto(s)', 'sentinelone'), (int)$row['tanium']) . '">'
            . 'Tanium ×' . (int)$row['tanium'] . '</span>';
      }
      if (!empty($row['nessus'])) {
         $html .= '<span class="s1-badge s1-badge--muted" style="font-size:.62rem;margin-left:4px;background:#00263e;color:#fff"'
            . ' title="' . sprintf(__('Tambem reportado pelo Tenable Nessus em %d achado(s) aberto(s)', 'sentinelone'), (int)$row['nessus']) . '">'
            . 'Nessus ×' . (int)$row['nessus'] . '</span>';
      }
      return $html;
   }
}

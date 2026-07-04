<?php

namespace GlpiPlugin\Sentinelone;

/**
 * Enriquecimento de CVEs com threat intelligence publica:
 *
 *  - EPSS (FIRST.org): probabilidade [0..1] de exploracao do CVE em ate 30
 *    dias. CSV diario em massa, filtrado para os CVEs presentes na frota.
 *  - CISA KEV: catalogo de vulnerabilidades com exploracao ativa CONFIRMADA
 *    (inclui flag de uso em campanhas de ransomware).
 *
 * Juntos mudam a priorizacao de "CVSS alto" para "CVSS alto E sendo
 * explorado agora". Atualizado diariamente pela cron `enrichcves`.
 */
class Enrichment
{
   public static string $table = 'glpi_plugin_sentinelone_cve_enrichment';

   private const EPSS_BULK_URL = 'https://epss.cyentia.com/epss_scores-current.csv.gz';
   private const KEV_URL       = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

   public static function ensureTable(): void
   {
      global $DB;

      if ($DB->tableExists(self::$table)) {
         return;
      }

      $DB->doQuery(
         "CREATE TABLE IF NOT EXISTS `" . self::$table . "` (
            `id`              int unsigned NOT NULL AUTO_INCREMENT,
            `cve_id`          varchar(50) NOT NULL DEFAULT '',
            `epss_score`      decimal(6,5) DEFAULT NULL,
            `epss_percentile` decimal(6,5) DEFAULT NULL,
            `is_kev`          tinyint(1) NOT NULL DEFAULT 0,
            `kev_date`        date DEFAULT NULL,
            `kev_ransomware`  tinyint(1) NOT NULL DEFAULT 0,
            `date_mod`        timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            UNIQUE KEY `cve_id` (`cve_id`),
            KEY `is_kev` (`is_kev`)
         ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
      );
   }

   /**
    * Atualiza EPSS + KEV para todos os CVEs presentes na tabela local.
    * Retorna ['epss' => n, 'kev' => n] com o total de linhas tocadas.
    */
   public static function refresh(): array
   {
      global $DB;
      self::ensureTable();

      if (!$DB->tableExists(Cve::getTable())) {
         return ['epss' => 0, 'kev' => 0];
      }

      $tracked = [];
      foreach ($DB->request(['SELECT' => ['cve_id'], 'DISTINCT' => true, 'FROM' => Cve::getTable()]) as $row) {
         $tracked[strtoupper((string)$row['cve_id'])] = true;
      }
      if ($tracked === []) {
         return ['epss' => 0, 'kev' => 0];
      }

      return [
         'epss' => self::refreshEpss($tracked),
         'kev'  => self::refreshKev($tracked),
      ];
   }

   /** @param array<string,bool> $tracked ids de CVE (maiusculos) presentes na frota */
   private static function refreshEpss(array $tracked): int
   {
      $raw = self::download(self::EPSS_BULK_URL);
      if ($raw === null) {
         return 0;
      }

      $csv = @gzdecode($raw);
      if ($csv === false || $csv === '') {
         // Alguns proxies entregam o arquivo ja descomprimido.
         $csv = $raw;
      }

      $count = 0;
      $now   = date('Y-m-d H:i:s');
      foreach (explode("\n", $csv) as $line) {
         // Formato: cve,epss,percentile — com bloco de cabecalho em #comentario
         if ($line === '' || $line[0] === '#' || str_starts_with($line, 'cve,')) {
            continue;
         }
         $parts = explode(',', trim($line));
         if (count($parts) < 3) {
            continue;
         }
         $cve = strtoupper($parts[0]);
         if (!isset($tracked[$cve])) {
            continue;
         }

         self::upsert($cve, [
            'epss_score'      => (float)$parts[1],
            'epss_percentile' => (float)$parts[2],
            'date_mod'        => $now,
         ]);
         $count++;
      }

      return $count;
   }

   /** @param array<string,bool> $tracked ids de CVE (maiusculos) presentes na frota */
   private static function refreshKev(array $tracked): int
   {
      global $DB;

      $raw = self::download(self::KEV_URL);
      if ($raw === null) {
         return 0;
      }

      $data = json_decode($raw, true);
      if (!is_array($data) || empty($data['vulnerabilities'])) {
         return 0;
      }

      // Zera antes: CVE removido do catalogo KEV perde a flag.
      $DB->doQuery("UPDATE `" . self::$table . "` SET is_kev = 0, kev_ransomware = 0");

      $count = 0;
      $now   = date('Y-m-d H:i:s');
      foreach ($data['vulnerabilities'] as $vuln) {
         $cve = strtoupper((string)($vuln['cveID'] ?? ''));
         if ($cve === '' || !isset($tracked[$cve])) {
            continue;
         }

         self::upsert($cve, [
            'is_kev'         => 1,
            'kev_date'       => !empty($vuln['dateAdded']) ? date('Y-m-d', strtotime($vuln['dateAdded'])) : null,
            'kev_ransomware' => (stripos((string)($vuln['knownRansomwareCampaignUse'] ?? ''), 'known') !== false) ? 1 : 0,
            'date_mod'       => $now,
         ]);
         $count++;
      }

      return $count;
   }

   private static function upsert(string $cveId, array $fields): void
   {
      global $DB;

      $existing = $DB->request([
         'SELECT' => ['id'],
         'FROM'   => self::$table,
         'WHERE'  => ['cve_id' => $cveId],
         'LIMIT'  => 1,
      ])->current();

      if ($existing) {
         $DB->update(self::$table, $fields, ['id' => $existing['id']]);
      } else {
         $DB->insert(self::$table, $fields + ['cve_id' => $cveId]);
      }
   }

   /**
    * Linhas de enriquecimento indexadas por CVE id para um conjunto de CVEs.
    *
    * @return array<string,array>
    */
   public static function forCves(array $cveIds): array
   {
      global $DB;

      $cveIds = array_values(array_unique(array_filter(array_map('strtoupper', array_map('strval', $cveIds)))));
      if ($cveIds === []) {
         return [];
      }
      self::ensureTable();

      $map = [];
      foreach ($DB->request(['FROM' => self::$table, 'WHERE' => ['cve_id' => $cveIds]]) as $row) {
         $map[strtoupper((string)$row['cve_id'])] = $row;
      }
      return $map;
   }

   /**
    * Resumo da exposicao KEV na frota: CVEs distintos no catalogo KEV,
    * ocorrencias (endpoint x CVE) e endpoints afetados.
    *
    * @return array{cves:int,occurrences:int,endpoints:int,ransomware:int}
    */
   public static function getKevSummary(): array
   {
      global $DB;

      $out = ['cves' => 0, 'occurrences' => 0, 'endpoints' => 0, 'ransomware' => 0];

      self::ensureTable();
      if (!$DB->tableExists(Cve::getTable())) {
         return $out;
      }

      $result = $DB->doQuery(
         "SELECT COUNT(DISTINCT c.cve_id) AS cves,"
         . " COUNT(*) AS occurrences,"
         . " COUNT(DISTINCT c.plugin_sentinelone_agents_id) AS endpoints,"
         . " COUNT(DISTINCT CASE WHEN e.kev_ransomware = 1 THEN c.cve_id END) AS ransomware"
         . " FROM `" . Cve::getTable() . "` c"
         . " INNER JOIN `" . self::$table . "` e ON e.cve_id = c.cve_id AND e.is_kev = 1"
      );

      if ($result && ($row = $result->fetch_assoc())) {
         $out['cves']        = (int)$row['cves'];
         $out['occurrences'] = (int)$row['occurrences'];
         $out['endpoints']   = (int)$row['endpoints'];
         $out['ransomware']  = (int)$row['ransomware'];
      }

      return $out;
   }

   /** Timestamp da ultima atualizacao, ou null se nunca rodou. */
   public static function lastRefresh(): ?string
   {
      global $DB;
      self::ensureTable();

      $row = $DB->doQuery("SELECT MAX(date_mod) AS m FROM `" . self::$table . "`")->fetch_assoc();
      return $row['m'] ?? null;
   }

   private static function download(string $url): ?string
   {
      $ch = curl_init();
      curl_setopt_array($ch, [
         CURLOPT_URL            => $url,
         CURLOPT_RETURNTRANSFER => true,
         CURLOPT_TIMEOUT        => 120,
         CURLOPT_FOLLOWLOCATION => true,
         CURLOPT_SSL_VERIFYPEER => true,
         CURLOPT_SSL_VERIFYHOST => 2,
         CURLOPT_USERAGENT      => 'GLPI-SentinelOne-Plugin',
      ]);
      $body  = curl_exec($ch);
      $error = curl_error($ch);
      $code  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
      curl_close($ch);

      if ($error !== '' || $code >= 400 || !is_string($body) || $body === '') {
         Log::record('enrichcves', 'error', "Falha ao baixar feed ({$url}): HTTP {$code} {$error}");
         return null;
      }
      return $body;
   }
}

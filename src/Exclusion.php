<?php

namespace GlpiPlugin\Sentinelone;

/**
 * Auditoria de exclusoes da console SentinelOne (allowlist de paths, hashes,
 * certificados, browser e tipos de arquivo). Exclusao e o ponto cego classico
 * do EDR: e onde ameacas (ou tecnicos apressados) escondem coisas. O plugin
 * importa a lista para o GLPI com quem criou, quando e com que escopo, e
 * destaca as criadas recentemente.
 */
class Exclusion
{
   public static string $table = 'glpi_plugin_sentinelone_exclusions';

   /** Dias para considerar uma exclusao "recente" (destaque na auditoria). */
   public const RECENT_DAYS = 7;

   public static function ensureTable(): void
   {
      global $DB;

      if ($DB->tableExists(self::$table)) {
         return;
      }

      $DB->doQuery(
         "CREATE TABLE IF NOT EXISTS `" . self::$table . "` (
            `id`              int unsigned NOT NULL AUTO_INCREMENT,
            `sentinelone_id`  varchar(100) NOT NULL DEFAULT '',
            `type`            varchar(50)  NOT NULL DEFAULT '',
            `value`           text,
            `os_type`         varchar(30)  DEFAULT NULL,
            `mode`            varchar(50)  DEFAULT NULL,
            `scope_name`      varchar(255) DEFAULT NULL,
            `created_by`      varchar(255) DEFAULT NULL,
            `description`     text,
            `source`          varchar(50)  DEFAULT NULL,
            `s1_created_at`   timestamp NULL DEFAULT NULL,
            `s1_updated_at`   timestamp NULL DEFAULT NULL,
            `raw_json`        longtext,
            `date_creation`   timestamp NULL DEFAULT NULL,
            `date_mod`        timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            UNIQUE KEY `sentinelone_id` (`sentinelone_id`),
            KEY `type` (`type`),
            KEY `s1_created_at` (`s1_created_at`)
         ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
      );
   }

   /**
    * Importa/atualiza as exclusoes vindas da API. Remove da tabela local as
    * que nao existem mais na console (auditoria reflete o estado atual).
    *
    * @param array<int,array> $items resposta da API
    * @return array{imported:int,removed:int}
    */
   public static function upsertFromApi(array $items): array
   {
      global $DB;
      self::ensureTable();

      $now  = date('Y-m-d H:i:s');
      $seen = [];
      $imported = 0;

      foreach ($items as $item) {
         $s1Id = (string)($item['id'] ?? '');
         if ($s1Id === '') {
            continue;
         }
         $seen[] = $s1Id;

         $row = [
            'type'          => (string)($item['type'] ?? ''),
            'value'         => (string)($item['value'] ?? ''),
            'os_type'       => (string)($item['osType'] ?? $item['os_type'] ?? ''),
            'mode'          => (string)($item['mode'] ?? ''),
            'scope_name'    => (string)($item['scopeName'] ?? $item['scope_name'] ?? ''),
            'created_by'    => (string)($item['userName'] ?? $item['createdBy'] ?? ''),
            'description'   => (string)($item['description'] ?? ''),
            'source'        => (string)($item['source'] ?? ''),
            's1_created_at' => self::toSql((string)($item['createdAt'] ?? '')),
            's1_updated_at' => self::toSql((string)($item['updatedAt'] ?? '')),
            'raw_json'      => json_encode($item, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            'date_mod'      => $now,
         ];

         $existing = $DB->request([
            'SELECT' => ['id'],
            'FROM'   => self::$table,
            'WHERE'  => ['sentinelone_id' => $s1Id],
            'LIMIT'  => 1,
         ])->current();

         if ($existing) {
            $DB->update(self::$table, $row, ['id' => (int)$existing['id']]);
         } else {
            $DB->insert(self::$table, $row + ['sentinelone_id' => $s1Id, 'date_creation' => $now]);
         }
         $imported++;
      }

      // Exclusoes removidas na console saem da auditoria local.
      $removed = 0;
      if ($seen !== []) {
         $quoted  = implode(',', array_map(static fn(string $v): string => "'" . addslashes($v) . "'", $seen));
         $result  = $DB->doQuery("SELECT COUNT(*) AS cpt FROM `" . self::$table . "` WHERE sentinelone_id NOT IN ({$quoted})");
         $removed = $result ? (int)($result->fetch_assoc()['cpt'] ?? 0) : 0;
         if ($removed > 0) {
            $DB->doQuery("DELETE FROM `" . self::$table . "` WHERE sentinelone_id NOT IN ({$quoted})");
         }
      }

      return ['imported' => $imported, 'removed' => $removed];
   }

   /**
    * Lista com filtros simples para a pagina de auditoria.
    *
    * @return array<int,array>
    */
   public static function getAll(string $type = '', string $search = '', int $limit = 500): array
   {
      global $DB;
      self::ensureTable();

      $where = [];
      if ($type !== '') {
         $where['type'] = $type;
      }
      if ($search !== '') {
         $like = '%' . $DB->escape($search) . '%';
         $where['OR'] = [
            ['value LIKE'       => $like],
            ['created_by LIKE'  => $like],
            ['scope_name LIKE'  => $like],
            ['description LIKE' => $like],
         ];
      }

      $rows = [];
      foreach ($DB->request([
         'FROM'  => self::$table,
         'WHERE' => $where ?: [1 => 1],
         'ORDER' => 's1_created_at DESC',
         'LIMIT' => max(1, $limit),
      ]) as $row) {
         $rows[] = $row;
      }
      return $rows;
   }

   /**
    * Resumo para os cards: total, por tipo e criadas nos ultimos N dias.
    *
    * @return array{total:int,recent:int,by_type:array<string,int>}
    */
   public static function summary(): array
   {
      global $DB;
      self::ensureTable();

      $out = ['total' => 0, 'recent' => 0, 'by_type' => []];

      foreach ($DB->request([
         'SELECT'  => ['type', 'COUNT' => 'id AS cnt'],
         'FROM'    => self::$table,
         'GROUPBY' => 'type',
         'ORDER'   => 'cnt DESC',
      ]) as $row) {
         $out['by_type'][(string)$row['type']] = (int)$row['cnt'];
         $out['total'] += (int)$row['cnt'];
      }

      $cutoff = date('Y-m-d H:i:s', strtotime('-' . self::RECENT_DAYS . ' days'));
      $row = $DB->request([
         'COUNT' => 'cpt',
         'FROM'  => self::$table,
         'WHERE' => ['s1_created_at' => ['>=', $cutoff]],
      ])->current();
      $out['recent'] = (int)($row['cpt'] ?? 0);

      return $out;
   }

   public static function isRecent(?string $s1CreatedAt): bool
   {
      if ($s1CreatedAt === null || $s1CreatedAt === '') {
         return false;
      }
      $ts = strtotime($s1CreatedAt);
      return $ts !== false && $ts >= strtotime('-' . self::RECENT_DAYS . ' days');
   }

   public static function typeLabel(string $type): string
   {
      return match ($type) {
         'path'        => __('Caminho', 'sentinelone'),
         'white_hash'  => __('Hash', 'sentinelone'),
         'certificate' => __('Certificado', 'sentinelone'),
         'browser'     => __('Navegador', 'sentinelone'),
         'file_type'   => __('Tipo de arquivo', 'sentinelone'),
         default       => $type !== '' ? $type : __('Outro', 'sentinelone'),
      };
   }

   private static function toSql(string $iso): ?string
   {
      if ($iso === '') {
         return null;
      }
      $ts = strtotime($iso);
      return $ts !== false ? date('Y-m-d H:i:s', $ts) : null;
   }
}

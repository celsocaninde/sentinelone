<?php

namespace GlpiPlugin\Sentinelone;

class Log extends \CommonDBTM
{
   public static $rightname = 'plugin_sentinelone_config';

   public static function getTypeName($nb = 0): string
   {
      return 'SentinelOne logs';
   }

   public static function record(string $action, string $status, string $message = '', int $itemsCount = 0): void
   {
      global $DB;

      $table = self::getTable();

      if (!$DB->tableExists($table)) {
         error_log("[sentinelone] {$action} {$status}: {$message}");
         return;
      }

      $DB->insert($table, [
         'action'        => $action,
         'status'        => $status,
         'message'       => $message,
         'items_count'   => $itemsCount,
         'date_creation' => date('Y-m-d H:i:s'),
      ]);
   }

   public static function getRecent(int $limit = 10): array
   {
      global $DB;

      $rows = [];
      $limit = max(1, min(50, $limit));

      if (!$DB->tableExists(self::getTable())) {
         return $rows;
      }

      foreach ($DB->request([
         'FROM'  => self::getTable(),
         'ORDER' => ['id DESC'],
         'LIMIT' => $limit,
      ]) as $row) {
         $rows[] = $row;
      }

      return $rows;
   }
}

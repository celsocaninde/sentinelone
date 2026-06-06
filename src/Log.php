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

   public static function getPaginated(int $limit, int $offset, array $filters = []): array
   {
      global $DB;

      $rows = [];

      if (!$DB->tableExists(self::getTable())) {
         return $rows;
      }

      $criteria = [
         'FROM'  => self::getTable(),
         'ORDER' => ['id DESC'],
         'LIMIT' => max(1, min(500, $limit)),
         'START' => max(0, $offset),
      ];

      $where = self::buildWhere($filters);
      if ($where !== []) {
         $criteria['WHERE'] = $where;
      }

      foreach ($DB->request($criteria) as $row) {
         $rows[] = $row;
      }

      return $rows;
   }

   public static function countAll(array $filters = []): int
   {
      global $DB;

      if (!$DB->tableExists(self::getTable())) {
         return 0;
      }

      $criteria = [
         'COUNT' => 'cpt',
         'FROM'  => self::getTable(),
      ];

      $where = self::buildWhere($filters);
      if ($where !== []) {
         $criteria['WHERE'] = $where;
      }

      $row = $DB->request($criteria)->current();

      return (int)($row['cpt'] ?? 0);
   }

   public static function getActions(): array
   {
      global $DB;

      $actions = [];

      if (!$DB->tableExists(self::getTable())) {
         return $actions;
      }

      foreach ($DB->request([
         'SELECT DISTINCT' => ['action'],
         'FROM'            => self::getTable(),
         'ORDER'           => ['action ASC'],
      ]) as $row) {
         $action = (string)($row['action'] ?? '');
         if ($action !== '') {
            $actions[] = $action;
         }
      }

      return $actions;
   }

   private static function buildWhere(array $filters): array
   {
      $where = [];

      $action = trim((string)($filters['action'] ?? ''));
      if ($action !== '') {
         $where['action'] = $action;
      }

      $status = trim((string)($filters['status'] ?? ''));
      if ($status !== '') {
         $where['status'] = $status;
      }

      return $where;
   }
}

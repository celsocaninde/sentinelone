<?php

namespace GlpiPlugin\Sentinelone;

class RogueDevice extends \CommonDBTM
{
   public static $rightname = 'plugin_sentinelone_read';

   public static function getTypeName($nb = 0): string
   {
      return $nb > 1
         ? __('Dispositivos rogues SentinelOne', 'sentinelone')
         : __('Dispositivo rogue SentinelOne', 'sentinelone');
   }

   public static function getTable($classname = null): string
   {
      return 'glpi_plugin_sentinelone_rogue_devices';
   }

   public static function countTotal(): int
   {
      global $DB;

      if (!$DB->tableExists(self::getTable())) {
         return 0;
      }

      foreach ($DB->request(['COUNT' => 'cpt', 'FROM' => self::getTable()]) as $row) {
         return (int)($row['cpt'] ?? 0);
      }

      return 0;
   }

   public static function getList(int $limit = 200, int $offset = 0): array
   {
      global $DB;

      if (!$DB->tableExists(self::getTable())) {
         return [];
      }

      $rows = [];
      foreach ($DB->request([
         'FROM'   => self::getTable(),
         'ORDER'  => ['last_seen DESC', 'hostname ASC'],
         'LIMIT'  => $limit,
         'START'  => $offset,
      ]) as $row) {
         $rows[] = $row;
      }

      return $rows;
   }

   /**
    * Decode open_ports JSON and return human-readable string (e.g. "22, 80, 443").
    */
   public static function formatPorts(string $portsJson): string
   {
      if ($portsJson === '') {
         return '—';
      }

      $data = json_decode($portsJson, true);
      if (!is_array($data) || $data === []) {
         return '—';
      }

      $ports = [];
      foreach ($data as $item) {
         if (is_int($item)) {
            $ports[] = (string)$item;
         } elseif (is_array($item)) {
            $port = $item['port'] ?? $item['number'] ?? null;
            if ($port !== null) {
               $proto = isset($item['protocol']) ? '/' . $item['protocol'] : '';
               $ports[] = $port . $proto;
            }
         } elseif (is_string($item)) {
            $ports[] = $item;
         }
      }

      sort($ports, SORT_NATURAL);
      $visible = array_slice($ports, 0, 5);
      $extra   = count($ports) - count($visible);
      $str     = implode(', ', $visible);
      if ($extra > 0) {
         $str .= ' +' . $extra;
      }

      return $str !== '' ? $str : '—';
   }
}

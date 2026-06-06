<?php

namespace GlpiPlugin\Sentinelone;

class Activity extends \CommonDBTM
{
   public static $rightname = 'plugin_sentinelone_read';

   public static function getTypeName($nb = 0): string
   {
      return $nb > 1 ? __('Atividades SentinelOne', 'sentinelone') : __('Atividade SentinelOne', 'sentinelone');
   }

   public static function getTable($classname = null): string
   {
      return 'glpi_plugin_sentinelone_activities';
   }

   public static function getForAgent(string $sentineloneAgentId, int $limit = 12): array
   {
      global $DB;

      if ($sentineloneAgentId === '' || !$DB->tableExists(self::getTable())) {
         return [];
      }

      $rows = [];
      foreach ($DB->request([
         'FROM'  => self::getTable(),
         'WHERE' => ['sentinelone_agent_id' => $sentineloneAgentId],
         'ORDER' => ['occurred_at DESC', 'id DESC'],
         'LIMIT' => max(1, min(50, $limit)),
      ]) as $row) {
         $rows[] = $row;
      }

      return $rows;
   }

   public static function getRecent(int $limit = 10): array
   {
      global $DB;

      if (!$DB->tableExists(self::getTable())) {
         return [];
      }

      $rows = [];
      foreach ($DB->request([
         'FROM'  => self::getTable(),
         'ORDER' => ['occurred_at DESC', 'id DESC'],
         'LIMIT' => max(1, min(50, $limit)),
      ]) as $row) {
         $rows[] = $row;
      }

      return $rows;
   }

   public static function labelForType(string $activityType): string
   {
      $map = [
         '19'   => __('Agente reiniciado', 'sentinelone'),
         '23'   => __('Agente instalado', 'sentinelone'),
         '24'   => __('Agente desinstalado', 'sentinelone'),
         '25'   => __('Agente atualizado', 'sentinelone'),
         '27'   => __('Agente reativado', 'sentinelone'),
         '40'   => __('Politica aplicada', 'sentinelone'),
         '80'   => __('Ameaca detectada', 'sentinelone'),
         '81'   => __('Ameaca mitigada', 'sentinelone'),
         '82'   => __('Ameaca marcada como benigna', 'sentinelone'),
         '83'   => __('Ameaca marcada como falso positivo', 'sentinelone'),
         '86'   => __('Scan concluido', 'sentinelone'),
         '87'   => __('Scan iniciado', 'sentinelone'),
         '90'   => __('Endpoint colocado em quarentena de rede', 'sentinelone'),
         '91'   => __('Quarentena de rede removida', 'sentinelone'),
         '1001' => __('Agente instalado', 'sentinelone'),
         '1002' => __('Agente desinstalado', 'sentinelone'),
         '1003' => __('Agente atualizado', 'sentinelone'),
         '1004' => __('Agente reiniciado', 'sentinelone'),
         '2009' => __('Ameaca detectada', 'sentinelone'),
         '2010' => __('Ameaca mitigada', 'sentinelone'),
         '2011' => __('Ameaca resolvida', 'sentinelone'),
         '2012' => __('Ameaca marcada como benigna', 'sentinelone'),
         '2013' => __('Ameaca marcada como falso positivo', 'sentinelone'),
         '3001' => __('Scan iniciado', 'sentinelone'),
         '3002' => __('Scan concluido', 'sentinelone'),
         '4001' => __('Quarentena aplicada', 'sentinelone'),
         '4002' => __('Quarentena removida', 'sentinelone'),
      ];

      return $map[$activityType] ?? ($activityType !== '' ? __('Evento', 'sentinelone') . ' #' . $activityType : __('Evento', 'sentinelone'));
   }

   public static function iconForType(string $activityType): string
   {
      $intType = (int)$activityType;

      if (in_array($intType, [80, 2009], true)) {
         return 'ti-bug text-danger';
      }

      if (in_array($intType, [81, 82, 83, 2010, 2011, 2012, 2013], true)) {
         return 'ti-shield-check text-success';
      }

      if (in_array($intType, [90, 4001], true)) {
         return 'ti-network-off text-warning';
      }

      if (in_array($intType, [91, 4002], true)) {
         return 'ti-network text-success';
      }

      if (in_array($intType, [23, 24, 25, 27, 1001, 1002, 1003, 1004], true)) {
         return 'ti-cpu text-muted';
      }

      return 'ti-activity text-muted';
   }
}

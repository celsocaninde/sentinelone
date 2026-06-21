<?php

namespace GlpiPlugin\Sentinelone;

/**
 * Coleta de saude operacional do plugin para o painel de auto-diagnostico:
 * estado das tabelas, das tarefas de cron, do ultimo sync de cada tipo, dos
 * locks ativos e da fila de retry. Tudo somente-leitura.
 */
class Diagnostics
{
   /** tabela => rotulo amigavel */
   private const TABLES = [
      'glpi_plugin_sentinelone_agents'        => 'Agentes',
      'glpi_plugin_sentinelone_threats'       => 'Ameacas',
      'glpi_plugin_sentinelone_activities'    => 'Atividades',
      'glpi_plugin_sentinelone_groups'        => 'Grupos',
      'glpi_plugin_sentinelone_cves'          => 'CVEs',
      'glpi_plugin_sentinelone_rogue_devices' => 'Rogues',
      'glpi_plugin_sentinelone_logs'          => 'Logs',
      'glpi_plugin_sentinelone_failedtickets' => 'Fila de retry',
      'glpi_plugin_sentinelone_configs'       => 'Configuracao',
   ];

   /** tarefas de cron e seus rotulos */
   private const CRONS = [
      'syncagents'         => 'Sincronizar agentes',
      'syncthreats'        => 'Sincronizar ameacas',
      'syncactivities'     => 'Sincronizar atividades',
      'syncgroups'         => 'Sincronizar grupos',
      'syncsoftware'       => 'Sincronizar software',
      'synccves'           => 'Sincronizar CVEs',
      'syncrogues'         => 'Sincronizar rogues',
      'alertoffline'       => 'Alerta de agentes offline',
      'reportweekly'       => 'Relatorio semanal',
      'purgelogs'          => 'Expurgo de logs',
      'retryfailedtickets' => 'Retry de tickets',
   ];

   /** chaves dos locks de sync (devem casar com Sync::withLock) */
   private const LOCK_KEYS = ['syncagents', 'syncthreats', 'syncactivities', 'syncgroups', 'retryfailedtickets'];

   /**
    * @return array<int,array{name:string,table:string,exists:bool,rows:int}>
    */
   public static function tables(): array
   {
      global $DB;

      $out = [];
      foreach (self::TABLES as $table => $label) {
         $exists = $DB->tableExists($table);
         $rows = 0;
         if ($exists) {
            foreach ($DB->request(['COUNT' => 'cpt', 'FROM' => $table]) as $r) {
               $rows = (int)($r['cpt'] ?? 0);
            }
         }
         $out[] = ['name' => $label, 'table' => $table, 'exists' => $exists, 'rows' => $rows];
      }

      return $out;
   }

   /**
    * @return array<int,array{name:string,label:string,registered:bool,state:int,state_label:string,frequency:int,lastrun:string,lastcode:string}>
    */
   public static function crons(): array
   {
      global $DB;

      $rows = [];
      foreach ($DB->request([
         'FROM'  => 'glpi_crontasks',
         'WHERE' => ['itemtype' => Sync::class],
      ]) as $r) {
         $rows[(string)$r['name']] = $r;
      }

      $stateLabels = [0 => 'Desativado', 1 => 'Aguardando', 2 => 'Em execucao'];

      $out = [];
      foreach (self::CRONS as $name => $label) {
         $row = $rows[$name] ?? null;
         $state = $row !== null ? (int)$row['state'] : -1;
         $out[] = [
            'name'        => $name,
            'label'       => $label,
            'registered'  => $row !== null,
            'state'       => $state,
            'state_label' => $row !== null ? ($stateLabels[$state] ?? ('?' . $state)) : 'Nao registrado',
            'frequency'   => $row !== null ? (int)$row['frequency'] : 0,
            'lastrun'     => $row !== null ? (string)($row['lastrun'] ?? '') : '',
            'lastcode'    => $row !== null ? (string)($row['lastcode'] ?? '') : '',
         ];
      }

      return $out;
   }

   /**
    * Ultimo registro de log (ok e erro) por acao de sync.
    *
    * @return array<int,array{action:string,last_ok:string,last_error:string,last_error_msg:string}>
    */
   public static function lastSyncs(): array
   {
      global $DB;

      $table = Log::getTable();
      $out = [];
      if (!$DB->tableExists($table)) {
         return $out;
      }

      $actions = ['syncagents', 'syncthreats', 'syncactivities', 'syncgroups', 'syncsoftware', 'synccves', 'syncrogues', 'retryfailedtickets'];
      foreach ($actions as $action) {
         $lastOk = '';
         foreach ($DB->request([
            'SELECT' => ['date_creation'],
            'FROM'   => $table,
            'WHERE'  => ['action' => $action, 'status' => 'ok'],
            'ORDER'  => ['id DESC'],
            'LIMIT'  => 1,
         ]) as $r) {
            $lastOk = (string)$r['date_creation'];
         }

         $lastError = '';
         $lastErrorMsg = '';
         foreach ($DB->request([
            'SELECT' => ['date_creation', 'message'],
            'FROM'   => $table,
            'WHERE'  => ['action' => $action, 'status' => 'error'],
            'ORDER'  => ['id DESC'],
            'LIMIT'  => 1,
         ]) as $r) {
            $lastError = (string)$r['date_creation'];
            $lastErrorMsg = (string)$r['message'];
         }

         if ($lastOk === '' && $lastError === '') {
            continue;
         }

         $out[] = [
            'action'         => $action,
            'last_ok'        => $lastOk,
            'last_error'     => $lastError,
            'last_error_msg' => $lastErrorMsg,
         ];
      }

      return $out;
   }

   /**
    * @return array<int,array{key:string,locked:bool}>
    */
   public static function locks(): array
   {
      $out = [];
      foreach (self::LOCK_KEYS as $key) {
         $out[] = ['key' => $key, 'locked' => Sync::isSyncLocked($key)];
      }

      return $out;
   }

   public static function retryPending(): int
   {
      return FailedTicket::countPending();
   }
}

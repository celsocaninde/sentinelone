<?php

namespace GlpiPlugin\Sentinelone;

/**
 * Fila de "dead-letter" para criacao de ticket de ameaca que falhou.
 *
 * Quando o TicketManager::createForThreat lanca excecao durante o sync (ex.: API
 * do GLPI indisponivel, erro transitorio), em vez de abortar o sync inteiro e
 * perder a ameaca, o payload e registrado aqui e reprocessado depois — manual
 * (painel de diagnostico) ou automaticamente (cron retryfailedtickets).
 */
class FailedTicket extends \CommonDBTM
{
   public static $rightname = 'plugin_sentinelone_config';

   public const STATUS_PENDING  = 'pending';
   public const STATUS_RESOLVED = 'resolved';
   public const STATUS_GIVENUP  = 'given_up';

   public const MAX_ATTEMPTS = 5;

   public static function getTypeName($nb = 0): string
   {
      return $nb > 1 ? 'Tickets de ameaca pendentes' : 'Ticket de ameaca pendente';
   }

   /**
    * Registra (ou atualiza) uma falha de criacao de ticket. Deduplicado por
    * sentinelone_threat_id: se ja houver uma entrada pendente para a mesma
    * ameaca, apenas incrementa o contador e atualiza a mensagem de erro.
    *
    * @param array<string,mixed> $threat Linha normalizada da ameaca (com raw_json).
    * @param array<string,mixed>|null $agent Linha do agente, se houver.
    */
   public static function record(array $threat, ?array $agent, string $error): void
   {
      global $DB;

      $table = self::getTable();
      if (!$DB->tableExists($table)) {
         Log::record('syncthreats', 'error', 'Fila de retry indisponivel (tabela ausente). Erro original: ' . $error);
         return;
      }

      $threatId = trim((string)($threat['sentinelone_threat_id'] ?? ''));
      $now = date('Y-m-d H:i:s');

      $existingId = null;
      if ($threatId !== '') {
         foreach ($DB->request([
            'SELECT' => ['id'],
            'FROM'   => $table,
            'WHERE'  => ['sentinelone_threat_id' => $threatId, 'status' => self::STATUS_PENDING],
            'LIMIT'  => 1,
         ]) as $row) {
            $existingId = (int)$row['id'];
         }
      }

      if ($existingId !== null) {
         $DB->update($table, [
            'error'           => self::truncate($error),
            'attempts'        => new \QueryExpression($DB->quoteName('attempts') . ' + 1'),
            'last_attempt_at' => $now,
            'date_mod'        => $now,
         ], ['id' => $existingId]);
         return;
      }

      $DB->insert($table, [
         'sentinelone_threat_id' => $threatId !== '' ? $threatId : null,
         'threat_name'           => self::nullable($threat['threat_name'] ?? null),
         'computer_name'         => self::nullable($threat['computer_name'] ?? null),
         'payload'               => json_encode($threat, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
         'agent_payload'         => $agent !== null ? json_encode($agent, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : null,
         'error'                 => self::truncate($error),
         'attempts'              => 1,
         'status'                => self::STATUS_PENDING,
         'last_attempt_at'       => $now,
         'date_creation'         => $now,
         'date_mod'              => $now,
      ]);
   }

   public static function countPending(): int
   {
      global $DB;

      if (!$DB->tableExists(self::getTable())) {
         return 0;
      }

      foreach ($DB->request([
         'COUNT' => 'cpt',
         'FROM'  => self::getTable(),
         'WHERE' => ['status' => self::STATUS_PENDING],
      ]) as $row) {
         return (int)($row['cpt'] ?? 0);
      }

      return 0;
   }

   /**
    * @return array<int,array<string,mixed>>
    */
   public static function getPending(int $limit = 50): array
   {
      global $DB;

      $rows = [];
      if (!$DB->tableExists(self::getTable())) {
         return $rows;
      }

      foreach ($DB->request([
         'FROM'  => self::getTable(),
         'WHERE' => ['status' => self::STATUS_PENDING],
         'ORDER' => ['id ASC'],
         'LIMIT' => max(1, min(500, $limit)),
      ]) as $row) {
         $rows[] = $row;
      }

      return $rows;
   }

   /**
    * @return array<int,array<string,mixed>>
    */
   public static function getRecent(int $limit = 50): array
   {
      global $DB;

      $rows = [];
      if (!$DB->tableExists(self::getTable())) {
         return $rows;
      }

      foreach ($DB->request([
         'FROM'  => self::getTable(),
         'ORDER' => ['id DESC'],
         'LIMIT' => max(1, min(500, $limit)),
      ]) as $row) {
         $rows[] = $row;
      }

      return $rows;
   }

   public static function markResolved(int $id, int $ticketId): void
   {
      global $DB;

      $DB->update(self::getTable(), [
         'status'   => self::STATUS_RESOLVED,
         'error'    => 'Resolvido: ticket #' . $ticketId . ' criado.',
         'date_mod' => date('Y-m-d H:i:s'),
      ], ['id' => $id]);
   }

   public static function registerFailure(int $id, int $attempts, string $error): void
   {
      global $DB;

      $status = $attempts >= self::MAX_ATTEMPTS ? self::STATUS_GIVENUP : self::STATUS_PENDING;
      $now = date('Y-m-d H:i:s');

      $DB->update(self::getTable(), [
         'attempts'        => $attempts,
         'status'          => $status,
         'error'           => self::truncate($error),
         'last_attempt_at' => $now,
         'date_mod'        => $now,
      ], ['id' => $id]);
   }

   private static function truncate(string $value): string
   {
      $value = trim($value);

      return function_exists('mb_substr') ? mb_substr($value, 0, 1000) : substr($value, 0, 1000);
   }

   private static function nullable($value): ?string
   {
      $value = trim((string)$value);

      return $value !== '' ? $value : null;
   }
}

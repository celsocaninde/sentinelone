<?php

namespace GlpiPlugin\Sentinelone;

class Threat extends \CommonDBTM
{
   public static $rightname = 'plugin_sentinelone_read';

   public static function getTypeName($nb = 0): string
   {
      return $nb > 1 ? 'Ameacas SentinelOne' : 'Ameaca SentinelOne';
   }

   public function rawSearchOptions(): array
   {
      $tab = [];

      $tab[] = [
         'id'   => 'common',
         'name' => self::getTypeName(2),
      ];
      $tab[] = [
         'id'       => 1,
         'table'    => self::getTable(),
         'field'    => 'threat_name',
         'name'     => 'Ameaca',
         'datatype' => 'string',
      ];
      $tab[] = [
         'id'       => 2,
         'table'    => self::getTable(),
         'field'    => 'sentinelone_threat_id',
         'name'     => 'ID SentinelOne',
         'datatype' => 'string',
      ];
      $tab[] = [
         'id'       => 3,
         'table'    => self::getTable(),
         'field'    => 'computer_name',
         'name'     => 'Computador',
         'datatype' => 'string',
      ];
      $tab[] = [
         'id'       => 4,
         'table'    => self::getTable(),
         'field'    => 'classification',
         'name'     => 'Classificacao',
         'datatype' => 'string',
      ];
      $tab[] = [
         'id'       => 5,
         'table'    => self::getTable(),
         'field'    => 'status',
         'name'     => 'Status',
         'datatype' => 'string',
      ];
      $tab[] = [
         'id'       => 6,
         'table'    => self::getTable(),
         'field'    => 'tickets_id',
         'name'     => 'Ticket',
         'datatype' => 'number',
      ];
      $tab[] = [
         'id'       => 7,
         'table'    => self::getTable(),
         'field'    => 'detected_at',
         'name'     => 'Detectada em',
         'datatype' => 'datetime',
      ];
      $tab[] = [
         'id'       => 8,
         'table'    => self::getTable(),
         'field'    => 'confidence_level',
         'name'     => 'Confianca',
         'datatype' => 'string',
      ];
      $tab[] = [
         'id'       => 9,
         'table'    => self::getTable(),
         'field'    => 'analyst_verdict',
         'name'     => 'Veredito do analista',
         'datatype' => 'string',
      ];
      $tab[] = [
         'id'       => 10,
         'table'    => self::getTable(),
         'field'    => 'severity',
         'name'     => 'Severidade',
         'datatype' => 'string',
      ];

      return $tab;
   }

   /**
    * Deriva uma severidade legivel a partir de status, severity, confianca e veredito.
    *
    * @return array{0: string, 1: string} [label, classe CSS s1-badge]
    */
   public static function severity(array $row): array
   {
      $status = strtolower(trim((string)($row['status'] ?? '')));
      if (in_array($status, ['mitigated', 'resolved', 'benign', 'false_positive', 'marked_as_benign'], true)) {
         return ['Resolvida', 's1-badge--ok'];
      }

      $severity = strtolower(trim((string)($row['severity'] ?? '')));
      $confidence = strtolower(trim((string)($row['confidence_level'] ?? '')));
      $verdict = strtolower(trim((string)($row['analyst_verdict'] ?? '')));

      if (in_array($severity, ['critical', 'high'], true)
         || $confidence === 'malicious'
         || $verdict === 'true_positive') {
         return ['Critica', 's1-badge--critical'];
      }

      if ($severity === 'medium'
         || $confidence === 'suspicious'
         || $verdict === 'suspicious') {
         return ['Suspeita', 's1-badge--danger'];
      }

      if ($status !== '' || $severity !== '' || $confidence !== '') {
         return ['Ativa', 's1-badge--danger'];
      }

      return ['Indefinida', 's1-badge--muted'];
   }

   public static function severityBadge(array $row): string
   {
      [$label, $class] = self::severity($row);
      return "<span class='s1-badge {$class}'>" . self::h($label) . "</span>";
   }

   public static function showForAgent(string $sentineloneAgentId): void
   {
      global $DB;

      $rows = [];
      foreach ($DB->request([
         'FROM'  => self::getTable(),
         'WHERE' => ['sentinelone_agent_id' => $sentineloneAgentId],
         'ORDER' => ['detected_at DESC'],
         'LIMIT' => 10,
      ]) as $row) {
         $rows[] = $row;
      }

      if ($rows === []) {
         return;
      }

      global $CFG_GLPI;
      $config = Config::getConfig();
      $rootDoc = (string)($CFG_GLPI['root_doc'] ?? '');

      echo "<section class='sentinelone-panel mt-3'>";
      echo "<div class='sentinelone-panel__head'><h3>Ameacas SentinelOne</h3></div>";
      echo "<div class='table-responsive'>";
      echo "<table class='table table-vcenter table-hover mb-0'>";
      echo "<thead><tr><th>Ameaca</th><th>Severidade</th><th>Status</th><th>Classificacao</th><th>Detectada em</th><th>Ticket</th></tr></thead>";
      echo "<tbody>";

      foreach ($rows as $row) {
         $name = trim((string)$row['threat_name']) !== '' ? (string)$row['threat_name'] : 'Ameaca';
         $threatUrl = Config::consoleThreatUrl($config, (string)$row['sentinelone_threat_id']);
         $ticketId = (int)($row['tickets_id'] ?? 0);

         echo "<tr>";
         if ($threatUrl !== '') {
            echo "<td><a href='" . self::h($threatUrl) . "' target='_blank' rel='noopener'>" . self::h($name) . " <span class='ti ti-external-link'></span></a></td>";
         } else {
            echo "<td>" . self::h($name) . "</td>";
         }
         echo "<td>" . self::severityBadge($row) . "</td>";
         echo "<td>" . self::h((string)$row['status']) . "</td>";
         echo "<td>" . self::h((string)$row['classification']) . "</td>";
         echo "<td>" . self::h((string)$row['detected_at']) . "</td>";
         if ($ticketId > 0) {
            echo "<td><a href='" . self::h($rootDoc . '/front/ticket.form.php?id=' . $ticketId) . "'>#" . self::h((string)$ticketId) . "</a></td>";
         } else {
            echo "<td><span class='text-muted'>-</span></td>";
         }
         echo "</tr>";
      }

      echo "</tbody>";
      echo "</table>";
      echo "</div>";
      echo "</section>";
   }

   private static function h(string $value): string
   {
      return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
   }
}

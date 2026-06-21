<?php

namespace GlpiPlugin\Sentinelone;

class Threat extends \CommonDBTM
{
   public static $rightname = 'plugin_sentinelone_read';

   public static function getTypeName($nb = 0): string
   {
      return $nb > 1 ? 'Ameacas SentinelOne' : 'Ameaca SentinelOne';
   }

   public static function getFormURL($full = true): string
   {
      global $CFG_GLPI;
      return $CFG_GLPI['root_doc'] . '/plugins/sentinelone/front/threat.form.php';
   }

   public static function getFormURLWithID($id = 0, $full = true): string
   {
      return static::getFormURL($full) . '?id=' . (int)$id;
   }

   public static function getDefaultSearchRequest(): array
   {
      return [
         'criteria' => [
            [
               'field'      => 7,
               'searchtype' => 'morethan',
               'value'      => date('Y-m-d', strtotime('-30 days')),
            ],
         ],
         'sort' => 7,
         'order' => 'DESC',
      ];
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
      $tab[] = [
         'id'       => 11,
         'table'    => self::getTable(),
         'field'    => 'file_path',
         'name'     => 'Caminho do arquivo',
         'datatype' => 'string',
      ];
      $tab[] = [
         'id'       => 12,
         'table'    => self::getTable(),
         'field'    => 'hash_sha1',
         'name'     => 'Hash SHA1',
         'datatype' => 'string',
      ];
      $tab[] = [
         'id'       => 13,
         'table'    => self::getTable(),
         'field'    => 'hash_sha256',
         'name'     => 'Hash SHA256',
         'datatype' => 'string',
      ];
      $tab[] = [
         'id'       => 14,
         'table'    => self::getTable(),
         'field'    => 'resolved_at',
         'name'     => 'Resolvida em',
         'datatype' => 'datetime',
      ];
      $tab[] = [
         'id'       => 15,
         'table'    => self::getTable(),
         'field'    => 'sentinelone_agent_id',
         'name'     => 'ID agente SentinelOne',
         'datatype' => 'string',
      ];
      $tab[] = [
         'id'       => 16,
         'table'    => self::getTable(),
         'field'    => 'entities_id',
         'name'     => 'Entidade ID',
         'datatype' => 'number',
      ];

      // Suprime a coluna de entidade (id=80) que o GLPI adiciona automaticamente
      // para objetos entity-based — sem dados uteis na lista de ameacas.
      $tab[] = [
         'id'            => 80,
         'table'         => 'glpi_entities',
         'field'         => 'completename',
         'name'          => 'Entidade',
         'massiveaction' => false,
         'datatype'      => 'dropdown',
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

   /**
    * Aggregated metrics + recent rows for the threats overview page.
    * Buckets are derived (not a stored column), so rows are bucketed in PHP.
    *
    * @return array{total:int,buckets:array<string,int>,tickets:int,last30:int,recent:array<int,array>}
    */
   public static function getOverview(int $recentLimit = 25): array
   {
      global $DB;

      $out = [
         'total'   => 0,
         'buckets' => ['Critica' => 0, 'Suspeita' => 0, 'Ativa' => 0, 'Resolvida' => 0, 'Indefinida' => 0],
         'tickets' => 0,
         'last30'  => 0,
         'recent'  => [],
      ];

      if (!$DB->tableExists(self::getTable())) {
         return $out;
      }

      $cut30 = date('Y-m-d H:i:s', strtotime('-30 days'));

      foreach ($DB->request([
         'FROM'  => self::getTable(),
         'ORDER' => ['detected_at DESC'],
      ]) as $row) {
         $out['total']++;

         [$label] = self::severity($row);
         $out['buckets'][$label] = ($out['buckets'][$label] ?? 0) + 1;

         if (!empty($row['tickets_id'])) {
            $out['tickets']++;
         }
         if (!empty($row['detected_at']) && (string)$row['detected_at'] >= $cut30) {
            $out['last30']++;
         }
         if (count($out['recent']) < $recentLimit) {
            $out['recent'][] = $row;
         }
      }

      return $out;
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

   public function getSpecificMassiveActions($checkitem = null): array
   {
      $actions = parent::getSpecificMassiveActions($checkitem);

      if (Profile::hasSyncRight()) {
         $sep = \MassiveAction::CLASS_ACTION_SEPARATOR;
         $actions[self::class . $sep . 'open_tickets'] = __('Abrir tickets para selecionadas', 'sentinelone');
         $actions[self::class . $sep . 'mark_resolved'] = __('Marcar como resolvidas (local)', 'sentinelone');
      }

      return $actions;
   }

   public static function processMassiveActionsForOneItemtype(\MassiveAction $ma, \CommonDBTM $item, array $ids): void
   {
      global $DB;

      $action = $ma->getAction();

      if ($action === 'open_tickets') {
         $config = Config::getConfig();
         $ok = 0;
         $ko = 0;
         foreach ($ids as $id) {
            $row = null;
            foreach ($DB->request(['FROM' => self::getTable(), 'WHERE' => ['id' => (int)$id], 'LIMIT' => 1]) as $r) {
               $row = $r;
            }
            if ($row === null || (int)($row['tickets_id'] ?? 0) > 0) {
               $ko++;
               continue;
            }
            try {
               $ticket = TicketManager::createForThreat($row, null, $config);
               if ($ticket > 0) {
                  $DB->update(self::getTable(), ['tickets_id' => $ticket, 'date_mod' => date('Y-m-d H:i:s')], ['id' => (int)$id]);
                  if ((string)($config['ticket_threat_details'] ?? '1') === '1') {
                     try {
                        TicketManager::addThreatDetailsFollowup($ticket, $row, null, $config);
                     } catch (\Throwable) {
                        // nota forense e opcional; nao deve reprovar a abertura do ticket
                     }
                  }
                  $ok++;
               } else {
                  $ko++;
               }
            } catch (\Throwable) {
               $ko++;
            }
         }
         $ma->itemDone($item->getType(), $ids, $ko === 0 ? \MassiveAction::ACTION_OK : \MassiveAction::ACTION_KO);
         return;
      }

      if ($action === 'mark_resolved') {
         $now = date('Y-m-d H:i:s');
         foreach ($ids as $id) {
            $DB->update(self::getTable(), ['status' => 'resolved', 'resolved_at' => $now, 'date_mod' => $now], ['id' => (int)$id]);
         }
         $ma->itemDone($item->getType(), $ids, \MassiveAction::ACTION_OK);
         return;
      }

      parent::processMassiveActionsForOneItemtype($ma, $item, $ids);
   }
}

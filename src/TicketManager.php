<?php

namespace GlpiPlugin\Sentinelone;

class TicketManager
{
   public static function createForThreat(array $threat, ?array $agent = null, ?array $config = null): int
   {
      $config ??= Config::getConfig();
      $ticket = new \Ticket();
      $entityId = self::resolveEntityId($threat, $agent);
      $type = defined('Ticket::INCIDENT_TYPE') ? \Ticket::INCIDENT_TYPE : 1;

      $input = [
         'name'        => self::buildTitle($threat),
         'content'     => self::buildContent($threat, $agent, $config),
         'entities_id' => $entityId,
         'type'        => $type,
         'urgency'     => self::scale($config['ticket_urgency'] ?? 4, 1, 5),
         'impact'      => self::scale($config['ticket_impact'] ?? 4, 1, 5),
         'priority'    => self::scale($config['ticket_priority'] ?? 4, 1, 6),
      ];

      $categoryId = (int)($config['ticket_category_id'] ?? 0);
      if ($categoryId > 0) {
         $input['itilcategories_id'] = $categoryId;
      }

      self::applyRequester($input, $config);

      $ticketId = $ticket->add($input);

      if (!$ticketId) {
         throw new \RuntimeException('Nao foi possivel criar ticket GLPI para ameaca SentinelOne.');
      }

      $computerId = (int)($agent['computers_id'] ?? 0);
      if ($computerId > 0) {
         self::linkComputer((int)$ticketId, $computerId);
      }

      return (int)$ticketId;
   }

   /**
    * Cria um ticket de saude do agente (offline, infectado, versao desatualizada).
    *
    * @param string[] $issues
    */
   public static function createForAgent(array $agent, array $issues, ?array $config = null): int
   {
      $config ??= Config::getConfig();
      $ticket = new \Ticket();
      $entityId = (int)($agent['entities_id'] ?? 0) ?: (int)$config['entity_id'];
      $type = defined('Ticket::INCIDENT_TYPE') ? \Ticket::INCIDENT_TYPE : 1;
      $computer = trim((string)($agent['computer_name'] ?? '')) ?: 'endpoint';

      $input = [
         'name'        => '[SentinelOne] Agente com problema em ' . self::short($computer, 60),
         'content'     => self::buildAgentContent($agent, $issues),
         'entities_id' => $entityId,
         'type'        => $type,
         'urgency'     => self::scale($config['ticket_urgency'] ?? 4, 1, 5),
         'impact'      => self::scale($config['ticket_impact'] ?? 4, 1, 5),
         'priority'    => self::scale($config['ticket_priority'] ?? 4, 1, 6),
      ];

      $categoryId = (int)($config['ticket_category_id'] ?? 0);
      if ($categoryId > 0) {
         $input['itilcategories_id'] = $categoryId;
      }

      self::applyRequester($input, $config);

      $ticketId = $ticket->add($input);

      if (!$ticketId) {
         throw new \RuntimeException('Nao foi possivel criar ticket de saude do agente SentinelOne.');
      }

      $computerId = (int)($agent['computers_id'] ?? 0);
      if ($computerId > 0) {
         self::linkComputer((int)$ticketId, $computerId);
      }

      return (int)$ticketId;
   }

   private static function linkComputer(int $ticketId, int $computerId): void
   {
      if (!class_exists(\Item_Ticket::class)) {
         return;
      }

      try {
         $link = new \Item_Ticket();
         $link->add([
            'tickets_id'    => $ticketId,
            'itemtype'      => 'Computer',
            'items_id'      => $computerId,
            '_disablenotif' => true,
         ]);
      } catch (\Throwable $error) {
         // vinculo e opcional; nao deve quebrar a criacao do ticket
      }
   }

   private static function buildAgentContent(array $agent, array $issues): string
   {
      $issuesHtml = '';
      foreach ($issues as $issue) {
         $issuesHtml .= "<li style=\"margin:0 0 6px\">\u{26A0}\u{FE0F} " . self::esc((string)$issue) . "</li>";
      }
      if ($issuesHtml === '') {
         $issuesHtml = "<li>Sem detalhes adicionais.</li>";
      }

      $online = (int)($agent['is_online'] ?? 0) === 1;
      $infected = (int)($agent['is_infected'] ?? 0) === 1;

      $body  = self::badge("\u{1FA7A} Saude do agente", '#6b2cf5');
      $body .= $infected ? self::badge("\u{1F9A0} Infectado", '#b5179e') : '';
      $body .= !$online ? self::badge("\u{1F50C} Offline", '#495057') : '';
      $body .= "<p style=\"margin:16px 0 6px;font-weight:600;color:#1f0d50\">\u{1F50E} Problemas detectados</p>";
      $body .= "<ul style=\"margin:0;padding-left:20px;font-size:14px\">{$issuesHtml}</ul>";
      $body .= self::kvTable([
         ["\u{1F4BB} Endpoint", $agent['computer_name'] ?? null],
         ["\u{1F194} Agente SentinelOne", $agent['sentinelone_id'] ?? null],
         ["\u{1F3E2} Site", $agent['site_name'] ?? null],
         ["\u{1F465} Grupo", $agent['group_name'] ?? null],
         ["\u{1F3F7}\u{FE0F} Versao do agente", $agent['agent_version'] ?? null],
         ["\u{1F50C} Online", $online ? 'Sim' : 'Nao'],
         ["\u{1F9A0} Infectado", $infected ? 'Sim' : 'Nao'],
         ["\u{1F552} Ultimo contato", $agent['last_active_at'] ?? null],
      ]);
      $body .= self::footerNote("\u{1F916} Ticket criado automaticamente pelo plugin SentinelOne (monitoramento de saude do agente).");

      return self::htmlCard("\u{1F6E1}\u{FE0F} SentinelOne", 'Saude do agente', $agent['computer_name'] ?? null, '#6b2cf5', $body);
   }

   private static function buildTitle(array $threat): string
   {
      $computer = trim((string)($threat['computer_name'] ?? 'endpoint desconhecido'));
      $name = trim((string)($threat['threat_name'] ?? 'ameaca detectada'));

      return '[SentinelOne] ' . self::short($name, 80) . ' em ' . self::short($computer, 60);
   }

   private static function buildContent(array $threat, ?array $agent, array $config): string
   {
      $severity = trim((string)($threat['severity'] ?? ''));
      $accent = self::severityColor($severity);

      $body = '';
      if ($severity !== '') {
         $body .= self::badge("\u{1F6A8} Severidade: " . ucfirst($severity), $accent);
      }
      $classification = trim((string)($threat['classification'] ?? ''));
      if ($classification !== '') {
         $body .= self::badge("\u{1F9EC} " . $classification, '#1f0d50');
      }
      $status = trim((string)($threat['status'] ?? ''));
      if ($status !== '') {
         $body .= self::badge("\u{1F4CA} " . $status, '#495057');
      }

      $body .= self::kvTable([
         ["\u{1F4BB} Endpoint", $threat['computer_name'] ?? null],
         ["\u{1F9EC} Classificacao", $threat['classification'] ?? null],
         ["\u{1F4CA} Status", $threat['status'] ?? null],
         ["\u{1F4C1} Arquivo", $threat['file_path'] ?? null],
         ["\u{1F511} SHA1", $threat['hash_sha1'] ?? null],
         ["\u{1F511} SHA256", $threat['hash_sha256'] ?? null],
         ["\u{1F194} Threat ID", $threat['sentinelone_threat_id'] ?? null],
         ["\u{1F5A5}\u{FE0F} Agent ID", $threat['sentinelone_agent_id'] ?? null],
         ["\u{1F552} Detectada em", $threat['detected_at'] ?? null],
      ]);

      if ($agent !== null) {
         $body .= "<p style=\"margin:16px 0 6px;font-weight:600;color:#1f0d50\">\u{1F5A5}\u{FE0F} Dados do agente</p>";
         $body .= self::kvTable([
            ["\u{1F3E2} Site", $agent['site_name'] ?? null],
            ["\u{1F465} Grupo", $agent['group_name'] ?? null],
            ["\u{1F3F7}\u{FE0F} Versao do agente", $agent['agent_version'] ?? null],
            ["\u{1F552} Ultimo contato", $agent['last_active_at'] ?? null],
         ]);
      }

      $statusFilter = self::esc(self::value($config['ticket_status_filter'] ?? null));
      $classFilter = self::esc(self::value($config['ticket_classification_filter'] ?? null));
      $body .= self::footerNote(
         "\u{1F916} Ticket criado automaticamente conforme as regras do plugin SentinelOne.<br>"
         . "Filtro de status: <b>{$statusFilter}</b> &middot; Filtro de classificacao: <b>{$classFilter}</b>"
      );

      return self::htmlCard("\u{1F6E1}\u{FE0F} SentinelOne", 'Ameaca detectada', $threat['threat_name'] ?? null, $accent, $body);
   }

   private static function resolveEntityId(array $threat, ?array $agent): int
   {
      if (!empty($threat['entities_id'])) {
         return (int)$threat['entities_id'];
      }

      if ($agent !== null && !empty($agent['entities_id'])) {
         return (int)$agent['entities_id'];
      }

      $config = Config::getConfig();

      return (int)$config['entity_id'];
   }

   private static function value($value): string
   {
      $value = trim((string)$value);

      return $value !== '' ? $value : '-';
   }

   private static function scale($value, int $min, int $max): int
   {
      return max($min, min($max, (int)$value));
   }

   private static function short(string $value, int $length): string
   {
      if (function_exists('mb_strlen') && function_exists('mb_substr')) {
         if (mb_strlen($value) <= $length) {
            return $value;
         }

         return mb_substr($value, 0, $length - 3) . '...';
      }

      if (strlen($value) <= $length) {
         return $value;
      }

      return substr($value, 0, $length - 3) . '...';
   }

   /**
    * Define o usuario solicitante/autor do ticket conforme a configuracao
    * (usuario "integracao" criado pelo cliente).
    */
   private static function applyRequester(array &$input, array $config): void
   {
      $requesterId = (int)($config['ticket_requester_id'] ?? 0);
      if ($requesterId <= 0) {
         return;
      }

      $input['_users_id_requester'] = $requesterId;
      $input['users_id_recipient']  = $requesterId;
   }

   private static function esc(string $value): string
   {
      return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
   }

   /**
    * Monta o cartao HTML (cabecalho colorido + corpo) usado no conteudo do
    * ticket. Usa apenas estilos inline para sobreviver ao sanitizador do GLPI.
    */
   private static function htmlCard(string $eyebrow, string $title, $subtitle, string $accent, string $bodyHtml): string
   {
      $header = "<div style=\"background:{$accent};background:linear-gradient(120deg,#2a0f5e 0%,{$accent} 100%);color:#ffffff;padding:16px 20px\">"
         . "<div style=\"font-size:12px;letter-spacing:.08em;text-transform:uppercase;opacity:.85\">" . self::esc($eyebrow) . "</div>"
         . "<div style=\"font-size:18px;font-weight:700;margin-top:2px\">" . self::esc($title) . "</div>"
         . "<div style=\"font-size:14px;margin-top:4px;opacity:.95\">" . self::esc(self::value($subtitle)) . "</div>"
         . "</div>";

      $body = "<div style=\"padding:16px 20px;background:#ffffff;color:#1c2330\">{$bodyHtml}</div>";

      return "<div style=\"font-family:'Segoe UI',Roboto,Arial,sans-serif;max-width:680px;border:1px solid #e3e1ee;border-radius:12px;overflow:hidden\">{$header}{$body}</div>";
   }

   private static function badge(string $text, string $bg): string
   {
      return "<span style=\"display:inline-block;padding:4px 12px;border-radius:999px;background:{$bg};color:#ffffff;font-size:12px;font-weight:700;margin:0 6px 6px 0\">"
         . self::esc($text) . "</span>";
   }

   /**
    * @param array<int, array{0:string,1:mixed}> $rows
    */
   private static function kvTable(array $rows): string
   {
      $html = "<table style=\"width:100%;border-collapse:collapse;margin-top:12px;font-size:14px\"><tbody>";
      foreach ($rows as $row) {
         $label = (string)($row[0] ?? '');
         $value = $row[1] ?? null;
         $html .= "<tr>"
            . "<td style=\"padding:8px 10px 8px 0;border-bottom:1px solid #eeeeee;color:#6b7280;width:42%;vertical-align:top\">" . self::esc($label) . "</td>"
            . "<td style=\"padding:8px 0;border-bottom:1px solid #eeeeee;font-weight:600;word-break:break-word\">" . self::esc(self::value($value)) . "</td>"
            . "</tr>";
      }
      $html .= "</tbody></table>";

      return $html;
   }

   private static function footerNote(string $innerHtml): string
   {
      return "<div style=\"margin-top:16px;padding:12px 14px;background:#f6f4ff;border-radius:8px;color:#4f1ad4;font-size:13px;line-height:1.5\">{$innerHtml}</div>";
   }

   private static function severityColor(string $severity): string
   {
      return match (strtolower(trim($severity))) {
         'critical', 'critica', 'crítica' => '#b5179e',
         'high', 'alta'                   => '#d6336c',
         'medium', 'media', 'média'       => '#e8590c',
         'low', 'baixa'                   => '#f08c00',
         default                          => '#6b2cf5',
      };
   }
}

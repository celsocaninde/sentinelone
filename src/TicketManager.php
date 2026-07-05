<?php

namespace GlpiPlugin\Sentinelone;

class TicketManager
{
   /**
    * Gera o HTML de exemplo (corpo do ticket + nota forense) com uma ameaca
    * ficticia, para a pre-visualizacao na tela de configuracao. Nao toca no
    * banco nem na API.
    *
    * @return array{ticket:string,details:string}
    */
   public static function previewSamples(?array $config = null): array
   {
      $config ??= Config::getConfig();

      $raw = [
         'threatInfo' => [
            'threatName' => 'mimikatz.exe', 'classification' => 'Malware', 'mitigationStatus' => 'unmitigated',
            'confidenceLevel' => 'malicious', 'analystVerdict' => 'true_positive',
            'analystVerdictDescription' => 'Ferramenta de roubo de credenciais',
            'detectionType' => 'static', 'detectionEngines' => [['title' => 'On-Write Static AI'], ['title' => 'Reputation']],
            'classificationSource' => 'Engine', 'initiatedByDescription' => 'Agent Policy',
            'processUser' => 'CORP\\joao.silva',
            'maliciousProcessArguments' => 'C:\\Temp\\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit',
            'originatorProcess' => 'powershell.exe', 'isFileless' => false, 'storyline' => 'A1B2C3D4E5F6',
            'fileSize' => 1376256, 'fileExtension' => 'EXE', 'publisherName' => '',
            'isValidCertificate' => false, 'md5' => 'd41d8cd98f00b204e9800998ecf8427e',
            'rebootRequired' => false, 'pendingActions' => false, 'failedActions' => true,
            'agentMitigationMode' => 'protect',
         ],
         'agentDetectionInfo' => [
            'agentIpV4' => '10.20.30.40', 'externalIp' => '200.158.10.22', 'agentDomain' => 'CORP',
            'agentLastLoggedInUserName' => 'joao.silva', 'agentOsName' => 'Windows 11 Pro', 'agentOsRevision' => '22631',
            'siteName' => 'Matriz', 'groupName' => 'Financeiro', 'accountName' => 'Empresa X', 'agentMitigationMode' => 'protect',
         ],
         'mitigationStatus' => [
            ['action' => 'quarantine', 'status' => 'success', 'lastUpdate' => '2026-06-21T13:00:05Z'],
            ['action' => 'kill', 'status' => 'failed', 'lastUpdate' => '2026-06-21T13:00:06Z'],
         ],
         'indicators' => [
            ['category' => 'Credential Access', 'techniques' => [['id' => 'T1003', 'name' => 'OS Credential Dumping']]],
         ],
      ];

      $sample = [
         'threat_name' => 'mimikatz.exe', 'classification' => 'Malware', 'status' => 'unmitigated',
         'severity' => 'high', 'confidence_level' => 'malicious', 'analyst_verdict' => 'true_positive',
         'computer_name' => 'PC-FINANCEIRO-07', 'file_path' => 'C:\\Temp\\mimikatz.exe',
         'hash_sha1' => 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
         'hash_sha256' => 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
         'sentinelone_threat_id' => 'PREVIEW-0001', 'sentinelone_agent_id' => 'PREVIEW-AG',
         'detected_at' => date('Y-m-d H:i:s'), 'raw_json' => json_encode($raw),
      ];
      $agent = [
         'computer_name' => 'PC-FINANCEIRO-07', 'ip' => '10.20.30.40', 'site_name' => 'Matriz',
         'group_name' => 'Financeiro', 'agent_version' => '23.4.2.14', 'last_active_at' => date('Y-m-d H:i:s'),
         'os_name' => 'Windows 11 Pro',
      ];

      return [
         'ticket'  => self::buildContent($sample, $agent, $config),
         'details' => self::buildThreatDetailsContent($sample, $agent, $config),
      ];
   }

   public static function createForThreat(array $threat, ?array $agent = null, ?array $config = null): int
   {
      $config ??= Config::getConfig();
      $ticket = new \Ticket();
      $entityId = self::resolveEntityId($threat, $agent);
      $type = defined('Ticket::INCIDENT_TYPE') ? \Ticket::INCIDENT_TYPE : 1;

      [$urgency, $impact, $priority] = self::priorityForThreat($threat, $config);

      $input = [
         'name'        => self::buildTitle($threat),
         'content'     => self::buildContent($threat, $agent, $config),
         'entities_id' => $entityId,
         'type'        => $type,
         'urgency'     => $urgency,
         'impact'      => $impact,
         'priority'    => $priority,
      ];

      $categoryId = (int)($config['ticket_category_id'] ?? 0);
      if ($categoryId > 0) {
         $input['itilcategories_id'] = $categoryId;
      }

      self::applyRequester($input, $config);
      self::applyAssignGroup($input, $config);

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
      self::applyAssignGroup($input, $config);

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

   /**
    * Ticket consolidado de CVEs em exploracao ativa (CISA KEV) num endpoint.
    * Urgencia maxima: exploracao confirmada no mundo real.
    *
    * @param array<int,array> $cves linhas com cve_id/severity/cvss/epss/app
    */
   public static function createForKev(array $agent, array $cves, ?array $config = null): int
   {
      $config ??= Config::getConfig();
      $ticket   = new \Ticket();
      $entityId = (int)($agent['entities_id'] ?? 0) ?: (int)$config['entity_id'];
      $type     = defined('Ticket::INCIDENT_TYPE') ? \Ticket::INCIDENT_TYPE : 1;
      $computer = trim((string)($agent['computer_name'] ?? '')) ?: 'endpoint';

      $lines   = [];
      $lines[] = 'CVEs com exploracao ativa confirmada (catalogo CISA KEV) detectados pelo SentinelOne:';
      $lines[] = '';
      foreach ($cves as $cve) {
         $extra = [];
         if (($cve['cvss_score'] ?? null) !== null) {
            $extra[] = 'CVSS ' . number_format((float)$cve['cvss_score'], 1);
         }
         if (($cve['epss_score'] ?? null) !== null) {
            $extra[] = 'EPSS ' . number_format((float)$cve['epss_score'] * 100, 0) . '%';
         }
         if (!empty($cve['kev_ransomware'])) {
            $extra[] = 'usado em RANSOMWARE';
         }
         if (!empty($cve['application_name'])) {
            $extra[] = (string)$cve['application_name'];
         }
         $lines[] = '- ' . $cve['cve_id'] . ' (' . strtoupper((string)($cve['severity'] ?? '')) . ($extra !== [] ? ' — ' . implode(', ', $extra) : '') . ')';
      }
      $lines[] = '';
      $lines[] = 'Endpoint:   ' . $computer;
      $lines[] = 'Site:       ' . (string)($agent['site_name'] ?? '-');
      $lines[] = 'Referencia: https://www.cisa.gov/known-exploited-vulnerabilities-catalog';
      $lines[] = '';
      $lines[] = 'Priorize a atualizacao das aplicacoes afetadas: estes CVEs estao sendo explorados agora.';

      $input = [
         'name'        => '[SentinelOne] CVE em exploracao ativa (KEV) em ' . self::short($computer, 60),
         'content'     => implode("\n", $lines),
         'entities_id' => $entityId,
         'type'        => $type,
         'urgency'     => 5,
         'impact'      => self::scale($config['ticket_impact'] ?? 4, 1, 5),
         'priority'    => 5,
      ];

      $categoryId = (int)($config['ticket_category_id'] ?? 0);
      if ($categoryId > 0) {
         $input['itilcategories_id'] = $categoryId;
      }

      self::applyRequester($input, $config);
      self::applyAssignGroup($input, $config);

      $ticketId = $ticket->add($input);

      if (!$ticketId) {
         throw new \RuntimeException('Nao foi possivel criar ticket KEV do SentinelOne.');
      }

      $computerId = (int)($agent['computers_id'] ?? 0);
      if ($computerId > 0) {
         self::linkComputer((int)$ticketId, $computerId);
      }

      return (int)$ticketId;
   }

   /**
    * Resolucao final da ameaca: registra a SOLUCAO do ticket (ITILSolution) com
    * o que foi declarado no SentinelOne — veredito do analista e sua observacao,
    * ou a indicacao de que a ferramenta resolveu automaticamente. Adicionar a
    * solucao marca o ticket como "Solucionado" nativamente no GLPI.
    */
   public static function closeForThreat(int $ticketId, array $threat): void
   {
      $rich        = self::extractRich($threat);
      $status      = trim((string)($threat['status'] ?? ''));
      $resolvedAt  = trim((string)($threat['resolved_at'] ?? ''));
      $verdict     = trim((string)($rich['analyst_verdict'] ?? ''));
      $verdictDesc = trim((string)($rich['analyst_verdict_desc'] ?? ''));
      $threatName  = trim((string)($threat['threat_name'] ?? 'ameaca'));
      $auto        = ($rich['auto_resolved'] === true);
      // "O que foi escrito": observacao do veredito do analista; se vazio (ou
      // resolucao automatica), usa a descricao do status de mitigacao.
      $written     = $verdictDesc !== '' ? $verdictDesc : trim((string)($rich['mitigation_status_desc'] ?? ''));

      $accent = '#2b7a0b';

      if ($auto) {
         $how = "\u{1F916} Resolvida automaticamente pela ferramenta SentinelOne.";
      } elseif ($verdict !== '') {
         $how = "\u{1F9D1}\u{200D}\u{2696}\u{FE0F} Veredito do analista: <strong>" . self::esc(self::verdictLabel($verdict)) . "</strong>.";
      } else {
         $how = "\u{2705} Ameaca resolvida/mitigada no SentinelOne.";
      }

      $body = "<p style=\"margin:0 0 8px;font-size:14px\">{$how}</p>";
      if ($written !== '') {
         $body .= "<div style=\"border-left:3px solid {$accent};background:#f3faf0;padding:10px 12px;border-radius:6px;margin:0 0 8px;white-space:pre-wrap;word-break:break-word\">" . self::esc($written) . "</div>";
      }
      $body .= self::kvTable([
         ["\u{1F9EC} Ameaca", $threatName],
         ["\u{1F4CA} Status", $status !== '' ? $status : null],
         ["\u{1F9D1}\u{200D}\u{2696}\u{FE0F} Veredito", $verdict !== '' ? self::verdictLabel($verdict) : null],
         ["\u{1F552} Resolvida em", $resolvedAt !== '' ? $resolvedAt : null],
         ["\u{1F194} Threat ID", $threat['sentinelone_threat_id'] ?? null],
      ], true, true);
      $body .= self::footerNote("\u{1F6E1}\u{FE0F} Solucao registrada automaticamente pelo plugin SentinelOne.");

      $hero    = self::heroBlock($accent, "\u{2705}", 'Ameaca resolvida no SentinelOne', $threatName);
      $content = self::executiveCard($hero, $body);

      // Solucao do ticket — marca como "Solucionado" nativamente no GLPI.
      $solved = false;
      if (class_exists(\ITILSolution::class)) {
         try {
            $solutionInput = [
               'itemtype' => 'Ticket',
               'items_id' => $ticketId,
               'content'  => $content,
            ];
            $requesterId = (int)(Config::getConfig()['ticket_requester_id'] ?? 0);
            if ($requesterId > 0) {
               $solutionInput['users_id'] = $requesterId;
            }
            $solution = new \ITILSolution();
            $solved = (bool)$solution->add($solutionInput);
         } catch (\Throwable $error) {
            Log::record('syncthreats', 'error', 'Falha ao registrar solucao do ticket #' . $ticketId . ': ' . $error->getMessage());
         }
      }

      // Se a solucao nao pode ser registrada, grava o texto como nota (fallback).
      if (!$solved && class_exists(\ITILFollowup::class)) {
         try {
            $followup = new \ITILFollowup();
            $followup->add([
               'items_id'        => $ticketId,
               'itemtype'        => 'Ticket',
               'content'         => $content,
               'is_private'      => 0,
               'requesttypes_id' => 0,
            ]);
         } catch (\Throwable $error) {
            // followup e opcional
         }
      }

      // Marca o ticket como "Solucionado". Primeiro pelo fluxo do GLPI (gera log/
      // notificacao); se o contexto (cron/sem sessao) bloquear a mudanca de status,
      // garante via banco com solvedate para o ticket nao ficar preso aberto.
      $solvedStatus = defined('Ticket::SOLVED') ? \Ticket::SOLVED : 5;
      try {
         $ticket = new \Ticket();
         $ticket->update(['id' => $ticketId, 'status' => $solvedStatus]);

         if ($ticket->getFromDB($ticketId) && (int)($ticket->fields['status'] ?? 0) !== $solvedStatus) {
            global $DB;
            $now = date('Y-m-d H:i:s');
            $DB->update('glpi_tickets', [
               'status'    => $solvedStatus,
               'solvedate' => $now,
               'date_mod'  => $now,
            ], ['id' => $ticketId]);
         }
      } catch (\Throwable $error) {
         Log::record('syncthreats', 'error', 'Falha ao marcar ticket #' . $ticketId . ' como solucionado: ' . $error->getMessage());
      }
   }

   public static function addNoteAsFollowup(int $ticketId, array $note): void
   {
      if (!class_exists(\ITILFollowup::class)) {
         return;
      }

      $text = trim((string)($note['text'] ?? $note['body'] ?? ''));
      if ($text === '') {
         return;
      }

      $createdBy = trim((string)($note['creator']['fullName'] ?? $note['creator']['full_name'] ?? $note['createdByUser'] ?? ''));
      $createdAt = trim((string)($note['createdAt'] ?? $note['created_at'] ?? ''));

      $meta = '';
      if ($createdBy !== '') {
         $meta .= "<span style='color:#6b7280;font-size:12px'>\u{1F464} " . self::esc($createdBy);
         if ($createdAt !== '') {
            $meta .= " &middot; " . self::esc($createdAt);
         }
         $meta .= "</span><br>";
      }

      $content = "<div style='border-left:3px solid #6b2cf5;padding:8px 12px;margin:4px 0'>"
         . $meta
         . nl2br(self::esc($text))
         . "</div>"
         . "<p style='font-size:11px;color:#9ca3af;margin-top:6px'>\u{1F4AC} Nota sincronizada da console SentinelOne.</p>";

      try {
         $followup = new \ITILFollowup();
         $followup->add([
            'items_id'        => $ticketId,
            'itemtype'        => 'Ticket',
            'content'         => $content,
            'is_private'      => 0,
            'requesttypes_id' => 0,
         ]);
      } catch (\Throwable $error) {
         // followup nao critico; nao deve interromper o fluxo
      }
   }

   /**
    * Followup adicionado quando uma NOVA ameaca chega para um endpoint que ja tem ticket aberto.
    * Em vez de criar um segundo ticket, a ameaca e registrada aqui como nota no ticket ativo.
    */
   public static function addNewThreatFollowup(int $ticketId, array $threat, ?array $agent, array $config): void
   {
      if (!class_exists(\ITILFollowup::class)) {
         return;
      }

      $threatName = trim((string)($threat['threat_name'] ?? 'ameaca detectada'));
      $computer   = trim((string)($threat['computer_name'] ?? 'endpoint'));
      $severity   = trim((string)($threat['severity'] ?? ''));
      $classif    = trim((string)($threat['classification'] ?? ''));
      $status     = trim((string)($threat['status'] ?? ''));
      $accent     = self::severityColor($severity);

      $body = '';
      if ($severity !== '') {
         $body .= self::badge("\u{1F6A8} Severidade: " . ucfirst($severity), $accent);
      }
      if ($classif !== '') {
         $body .= self::badge("\u{1F9EC} " . $classif, '#1f0d50');
      }
      if ($status !== '') {
         $body .= self::badge("\u{1F4CA} " . $status, '#495057');
      }

      $body .= self::kvTable([
         ["\u{1F9EC} Ameaca", $threatName],
         ["\u{1F4C1} Arquivo", $threat['file_path'] ?? null],
         ["\u{1F511} SHA256", $threat['hash_sha256'] ?? null],
         ["\u{1F194} Threat ID", $threat['sentinelone_threat_id'] ?? null],
         ["\u{1F552} Detectada em", $threat['detected_at'] ?? null],
      ]);

      $body .= self::footerNote(
         "\u{26A0}\u{FE0F} Nova ameaca detectada no mesmo endpoint."
         . " Consolidada neste ticket para evitar duplicidade. Plugin SentinelOne."
      );

      $content = self::htmlCard(
         "\u{1F6E1}\u{FE0F} SentinelOne",
         'Nova ameaca no endpoint',
         $computer,
         $accent,
         $body
      );

      try {
         $followup = new \ITILFollowup();
         $followup->add([
            'items_id'        => $ticketId,
            'itemtype'        => 'Ticket',
            'content'         => $content,
            'is_private'      => 0,
            'requesttypes_id' => 0,
         ]);
      } catch (\Throwable $error) {
         // followup e opcional; nao deve interromper o fluxo
      }
   }

   /**
    * Followup adicionado quando o status de uma ameaca muda para um valor NAO final
    * (ex.: active → blocked, active → suspicious). Mudancas para resolvido/mitigado
    * sao tratadas por closeForThreat() e addThreatResolvedFollowup().
    */
   public static function addStatusChangeFollowup(int $ticketId, array $threat, string $oldStatus, string $newStatus): void
   {
      if (!class_exists(\ITILFollowup::class)) {
         return;
      }

      $threatName = trim((string)($threat['threat_name'] ?? 'ameaca'));

      $statusColors = [
         'blocked'    => '#f08c00',
         'suspicious' => '#e8590c',
         'pending'    => '#6b7280',
         'active'     => '#d6336c',
         'unmitigated' => '#d6336c',
      ];
      $color = $statusColors[strtolower($newStatus)] ?? '#6b2cf5';

      $body  = self::badge(self::esc($oldStatus) . " \u{2192} " . self::esc($newStatus), $color);
      $body .= self::kvTable([
         ["\u{1F9EC} Ameaca", $threatName],
         ["\u{1F194} Threat ID", $threat['sentinelone_threat_id'] ?? null],
         ["\u{1F504} Status anterior", $oldStatus],
         ["\u{2139}\u{FE0F} Novo status", $newStatus],
      ]);
      $body .= self::footerNote("\u{1F504} Status da ameaca atualizado automaticamente pelo plugin SentinelOne.");

      $content = self::htmlCard(
         "\u{1F6E1}\u{FE0F} SentinelOne",
         'Status da ameaca atualizado',
         $threatName,
         $color,
         $body
      );

      try {
         $followup = new \ITILFollowup();
         $followup->add([
            'items_id'        => $ticketId,
            'itemtype'        => 'Ticket',
            'content'         => $content,
            'is_private'      => 0,
            'requesttypes_id' => 0,
         ]);
      } catch (\Throwable $error) {
         // followup e opcional; nao deve interromper o fluxo
      }
   }

   /**
    * Followup adicionado quando uma ameaca e resolvida no SentinelOne MAS o endpoint
    * ainda tem outras ameacas ativas — o ticket permanece aberto.
    */
   public static function addThreatResolvedFollowup(int $ticketId, array $threat): void
   {
      if (!class_exists(\ITILFollowup::class)) {
         return;
      }

      $threatName = trim((string)($threat['threat_name'] ?? 'ameaca'));
      $status     = trim((string)($threat['status'] ?? ''));
      $verdict    = trim((string)($threat['analyst_verdict'] ?? ''));
      $resolvedAt = trim((string)($threat['resolved_at'] ?? ''));

      $body  = self::badge("\u{2705} Ameaca resolvida", '#2b7a0b');
      $body .= self::kvTable([
         ["\u{1F9EC} Ameaca", $threatName],
         ["\u{1F194} Threat ID", $threat['sentinelone_threat_id'] ?? null],
         ["\u{1F4CA} Status", $status !== '' ? $status : null],
         ["\u{1F9D1}\u{200D}\u{2696}\u{FE0F} Veredito", $verdict !== '' ? $verdict : null],
         ["\u{1F552} Resolvida em", $resolvedAt !== '' ? $resolvedAt : null],
      ]);
      $body .= self::footerNote(
         "\u{26A0}\u{FE0F} Esta ameaca foi resolvida no SentinelOne,"
         . " mas ainda ha outras ameacas ativas neste endpoint."
         . " O ticket permanece aberto ate todas serem mitigadas."
      );

      $content = self::htmlCard(
         "\u{1F6E1}\u{FE0F} SentinelOne",
         'Ameaca resolvida (endpoint ainda ativo)',
         $threatName,
         '#2b7a0b',
         $body
      );

      try {
         $followup = new \ITILFollowup();
         $followup->add([
            'items_id'        => $ticketId,
            'itemtype'        => 'Ticket',
            'content'         => $content,
            'is_private'      => 0,
            'requesttypes_id' => 0,
         ]);
      } catch (\Throwable $error) {
         // followup e opcional; nao deve interromper o fluxo
      }
   }

   /**
    * Nota interna (privada) postada logo apos a abertura do ticket, com os
    * detalhes forenses que o SentinelOne traz no payload da ameaca (raw_json)
    * e que nao cabem no corpo do ticket: processo malicioso e linha de comando,
    * engine de deteccao, editor/assinatura do arquivo, IP/usuario logado, modo
    * da politica, acoes de mitigacao e seus resultados, MITRE ATT&CK e storyline.
    *
    * Privada (is_private=1): contem dado de investigacao que nao deve ir ao
    * solicitante do ticket.
    */
   public static function addThreatDetailsFollowup(int $ticketId, array $threat, ?array $agent, array $config): void
   {
      if (!class_exists(\ITILFollowup::class)) {
         return;
      }

      $content = self::buildThreatDetailsContent($threat, $agent, $config);
      if ($content === '') {
         return;
      }

      try {
         $followup = new \ITILFollowup();
         $followup->add([
            'items_id'        => $ticketId,
            'itemtype'        => 'Ticket',
            'content'         => $content,
            'is_private'      => 1,
            'requesttypes_id' => 0,
         ]);
      } catch (\Throwable $error) {
         // followup e opcional; nao deve interromper o fluxo
      }
   }

   /**
    * Monta o HTML da nota forense da ameaca (sem persistir). Separado de
    * addThreatDetailsFollowup para permitir teste/preview do conteudo.
    */
   public static function buildThreatDetailsContent(array $threat, ?array $agent, array $config): string
   {
      $rich       = self::extractRich($threat);
      [$accent]   = self::resolveSeverity($threat);
      $threatName = trim((string)($threat['threat_name'] ?? 'ameaca'));

      $body = '';

      // 1) Deteccao
      $body .= self::section("\u{1F50E} Deteccao", self::kvTable([
         ["Tipo de deteccao", $rich['detection_type'] ?: null],
         ["Engines", $rich['engines'] !== [] ? implode(', ', $rich['engines']) : null],
         ["Confianca", $rich['confidence'] ?: null],
         ["Veredito do analista", self::joinDesc($rich['analyst_verdict'], $rich['analyst_verdict_desc'])],
         ["Origem da classificacao", $rich['classification_source'] ?: null],
         ["Iniciado por", $rich['initiated_by'] ?: null],
         ["Modo da politica", $rich['mitigation_mode'] ?: null],
      ], true, true));

      // 2) Processo / execucao
      $procTable = self::kvTable([
         ["Usuario do processo", $rich['process_user'] ?: null],
         ["Processo originador", $rich['originator_process'] ?: null],
         ["Sem arquivo (fileless)", self::boolLabel($rich['is_fileless'])],
         ["Storyline", $rich['storyline'] ?: null],
      ], true, true);
      if ($rich['process_args'] !== '') {
         $procTable .= self::codeBlock("\u{1F4DF} Linha de comando", $rich['process_args']);
      }
      $body .= self::section("\u{2699}\u{FE0F} Processo / execucao", $procTable);

      // 3) Arquivo
      $body .= self::section("\u{1F4C1} Arquivo", self::kvTable([
         ["Caminho", $threat['file_path'] ?? null],
         ["Tamanho", self::humanSize($rich['file_size'])],
         ["Extensao", $rich['file_extension'] ?: null],
         ["Editor (assinatura)", $rich['publisher'] ?: null],
         ["Certificado valido", self::boolLabel($rich['valid_cert'])],
         ["MD5", $rich['md5'] ?: null],
         ["SHA1", $threat['hash_sha1'] ?? null],
         ["SHA256", $threat['hash_sha256'] ?? null],
      ], true, true));

      // 4) Endpoint
      $osFull = trim($rich['os_name'] . ' ' . $rich['os_revision']);
      $body .= self::section("\u{1F5A5}\u{FE0F} Endpoint", self::kvTable([
         ["Computador", $threat['computer_name'] ?? ($agent['computer_name'] ?? null)],
         ["IP interno", $rich['agent_ip'] !== '' ? $rich['agent_ip'] : ($agent['ip'] ?? null)],
         ["IP externo", $rich['external_ip'] ?: null],
         ["Dominio", $rich['agent_domain'] ?: null],
         ["Ultimo usuario logado", $rich['last_user'] ?: null],
         ["Sistema operacional", $osFull !== '' ? $osFull : ($agent['os_name'] ?? null)],
         ["Site / Grupo", self::joinSlash($rich['site_name'], $rich['group_name'])],
         ["Conta", $rich['account_name'] ?: null],
      ], true, true));

      // 5) Mitigacao / acoes
      $mitHtml = self::mitigationActionsHtml($rich['mitigation_actions']);
      $mitHtml .= self::kvTable([
         ["Reinicializacao necessaria", self::boolLabel($rich['reboot_required'])],
         ["Acoes pendentes", self::boolLabel($rich['pending_actions'])],
         ["Acoes com falha", self::boolLabel($rich['failed_actions'])],
         ["Resolvida automaticamente", self::boolLabel($rich['auto_resolved'])],
      ], true, true);
      if (trim($mitHtml) !== '') {
         $body .= self::section("\u{1F6E0}\u{FE0F} Mitigacao", $mitHtml);
      }

      // 6) MITRE ATT&CK
      $mitre = self::mitreHtml($rich['indicators']);
      if ($mitre !== '') {
         $body .= self::section("\u{1F3AF} MITRE ATT&CK", $mitre);
      }

      // 7) Rodape + link da console
      $consoleUrl  = Config::consoleThreatUrl($config, (string)($threat['sentinelone_threat_id'] ?? ''));
      $footerInner = "\u{1F50D} Detalhes forenses coletados automaticamente do SentinelOne na abertura do ticket. Nota interna (nao visivel ao solicitante).";
      if ($consoleUrl !== '') {
         $footerInner .= "<br><a href=\"" . self::esc($consoleUrl) . "\" style=\"color:#4f1ad4;font-weight:700\">\u{1F517} Abrir esta ameaca na console SentinelOne</a>";
      }
      $body .= self::footerNote($footerInner);

      if (trim($body) === '') {
         return '';
      }

      $hero = self::heroBlock($accent, "\u{1F50D}", 'Detalhes da ameaca', $threatName);

      return self::executiveCard($hero, $body);
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
      $rich = self::extractRich($threat);
      [$accent, $sevLabel, $sevEmoji] = self::resolveSeverity($threat);

      // --- Cabecalho executivo: severidade em destaque + frase-resumo ---
      $hero = self::heroBlock(
         $accent,
         $sevEmoji,
         $sevLabel,
         self::summarySentence($threat, $rich)
      );

      // --- Badges de contexto rapido ---
      $badges = '';
      $classification = trim((string)($threat['classification'] ?? ''));
      if ($classification !== '') {
         $badges .= self::badge("\u{1F9EC} " . $classification, '#1f0d50');
      }
      $status = trim((string)($threat['status'] ?? ''));
      if ($status !== '') {
         $badges .= self::badge("\u{1F4CA} " . $status, '#495057');
      }
      if ($rich['detection_type'] !== '') {
         $badges .= self::badge("\u{1F50E} " . $rich['detection_type'], '#0b7285');
      }
      if ($rich['mitigation_mode'] !== '') {
         $badges .= self::badge("\u{1F6E1}\u{FE0F} " . $rich['mitigation_mode'], $rich['mitigation_mode_color']);
      }

      $body = $badges !== '' ? "<div style=\"margin-bottom:2px\">{$badges}</div>" : '';

      $body .= self::section("\u{1F9EC} Ameaca", self::kvTable([
         ["Nome", $threat['threat_name'] ?? null],
         ["Classificacao", $threat['classification'] ?? null],
         ["Status", $threat['status'] ?? null],
         ["Severidade", self::severityRowValue($threat)],
         ["Confianca", $threat['confidence_level'] ?? null],
         ["Detectada em", $threat['detected_at'] ?? null],
         ["Threat ID", $threat['sentinelone_threat_id'] ?? null],
      ], true, true));

      $body .= self::section("\u{1F4C1} Arquivo", self::kvTable([
         ["Caminho", $threat['file_path'] ?? null],
         ["SHA1", $threat['hash_sha1'] ?? null],
         ["SHA256", $threat['hash_sha256'] ?? null],
      ], true, true));

      $body .= self::section("\u{1F5A5}\u{FE0F} Endpoint", self::kvTable([
         ["Computador", $threat['computer_name'] ?? ($agent['computer_name'] ?? null)],
         ["IP", $rich['agent_ip'] !== '' ? $rich['agent_ip'] : ($agent['ip'] ?? null)],
         ["Site", $agent['site_name'] ?? ($rich['site_name'] !== '' ? $rich['site_name'] : null)],
         ["Grupo", $agent['group_name'] ?? ($rich['group_name'] !== '' ? $rich['group_name'] : null)],
         ["Versao do agente", $agent['agent_version'] ?? null],
         ["Ultimo contato", $agent['last_active_at'] ?? null],
      ], true, true));

      $statusFilter = self::esc(self::value($config['ticket_status_filter'] ?? null));
      $classFilter  = self::esc(self::value($config['ticket_classification_filter'] ?? null));
      $body .= self::footerNote(
         "\u{1F916} Ticket criado automaticamente conforme as regras do plugin SentinelOne.<br>"
         . "Filtro de status: <b>{$statusFilter}</b> &middot; Filtro de classificacao: <b>{$classFilter}</b><br>"
         . "\u{1F50D} Os detalhes forenses completos seguem em uma nota interna logo abaixo."
      );

      return self::executiveCard($hero, $body);
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

   private static function applyAssignGroup(array &$input, array $config): void
   {
      $groupId = (int)($config['ticket_group_id'] ?? 0);
      if ($groupId <= 0) {
         return;
      }

      $input['_groups_id_assign'] = $groupId;
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
    * @param bool $tight     remove a margem superior (uso dentro de secoes)
    * @param bool $skipEmpty omite linhas sem valor, em vez de exibir "-"
    */
   private static function kvTable(array $rows, bool $tight = false, bool $skipEmpty = false): string
   {
      $marginTop = $tight ? '0' : '12px';
      $built = '';
      foreach ($rows as $row) {
         $label = (string)($row[0] ?? '');
         $value = $row[1] ?? null;
         if ($skipEmpty && ($value === null || trim((string)$value) === '')) {
            continue;
         }
         $built .= "<tr>"
            . "<td style=\"border:0px solid transparent;border-bottom:1px solid #eeeeee;padding:8px 10px 8px 0;color:#6b7280;width:42%;vertical-align:top\">" . self::esc($label) . "</td>"
            . "<td style=\"border:0px solid transparent;border-bottom:1px solid #eeeeee;padding:8px 0;font-weight:600;word-break:break-word\">" . self::esc(self::value($value)) . "</td>"
            . "</tr>";
      }

      if ($built === '') {
         return '';
      }

      return "<table style=\"width:100%;border:0px solid transparent;border-collapse:collapse;margin-top:{$marginTop};font-size:14px\"><tbody>{$built}</tbody></table>";
   }

   private static function footerNote(string $innerHtml): string
   {
      return "<div style=\"margin-top:16px;padding:12px 14px;background:#f6f4ff;border-radius:8px;color:#4f1ad4;font-size:13px;line-height:1.5\">{$innerHtml}</div>";
   }

   private static function verdictLabel(string $verdict): string
   {
      return match (strtolower(trim($verdict))) {
         'true_positive'      => 'Verdadeiro positivo',
         'false_positive'     => 'Falso positivo',
         'suspicious'         => 'Suspeito',
         'benign', 'marked_as_benign' => 'Benigno',
         'undefined', ''      => 'Indefinido',
         default              => ucfirst(str_replace('_', ' ', $verdict)),
      };
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

   private static function severityLabel(string $severity): string
   {
      return match (strtolower(trim($severity))) {
         'critical', 'critica', 'crítica' => 'Severidade critica',
         'high', 'alta'                   => 'Severidade alta',
         'medium', 'media', 'média'       => 'Severidade media',
         'low', 'baixa'                   => 'Severidade baixa',
         default                          => $severity !== '' ? 'Severidade ' . $severity : 'Severidade indefinida',
      };
   }

   private static function severityEmoji(string $severity): string
   {
      return match (strtolower(trim($severity))) {
         'critical', 'critica', 'crítica' => "\u{1F534}",
         'high', 'alta'                   => "\u{1F7E0}",
         'medium', 'media', 'média'       => "\u{1F7E1}",
         'low', 'baixa'                   => "\u{1F535}",
         default                          => "\u{26AA}",
      };
   }

   /**
    * Bucket de severidade da ameaca: usa o campo bruto quando presente, senao
    * deriva via Threat::severity (status/confianca/veredito).
    */
   private static function severityBucket(array $threat): string
   {
      $raw = strtolower(trim((string)($threat['severity'] ?? '')));
      if ($raw !== '') {
         return match ($raw) {
            'critical', 'critica', 'crítica', 'high', 'alta' => 'Critica',
            'medium', 'media', 'média'                       => 'Suspeita',
            'low', 'baixa'                                   => 'Ativa',
            default                                          => 'Ativa',
         };
      }

      [$bucket] = Threat::severity($threat);

      return $bucket;
   }

   /**
    * Urgencia/impacto/prioridade do ticket. Com ticket_auto_priority ligado
    * (padrao), deriva da severidade da ameaca; senao usa os valores fixos da
    * configuracao. Escala GLPI: urgencia/impacto 1-5, prioridade 1-6.
    *
    * @return array{0:int,1:int,2:int} [urgency, impact, priority]
    */
   private static function priorityForThreat(array $threat, array $config): array
   {
      if ((string)($config['ticket_auto_priority'] ?? '1') !== '1') {
         return [
            self::scale($config['ticket_urgency'] ?? 4, 1, 5),
            self::scale($config['ticket_impact'] ?? 4, 1, 5),
            self::scale($config['ticket_priority'] ?? 4, 1, 6),
         ];
      }

      return match (self::severityBucket($threat)) {
         'Critica'   => [5, 4, 5],
         'Suspeita'  => [4, 3, 4],
         'Resolvida' => [2, 2, 2],
         default     => [3, 3, 3], // Ativa / Indefinida
      };
   }

   /**
    * Resolve a severidade efetiva da ameaca para o cabecalho: usa o campo bruto
    * quando presente; caso contrario, deriva do bucket do plugin
    * (Threat::severity, baseado em status/confianca/veredito) para que ameacas
    * sem o campo severity ainda mostrem cor e rotulo uteis.
    *
    * @return array{0:string,1:string,2:string} [cor, rotulo, emoji]
    */
   private static function resolveSeverity(array $threat): array
   {
      $raw = trim((string)($threat['severity'] ?? ''));
      if ($raw !== '') {
         return [self::severityColor($raw), self::severityLabel($raw), self::severityEmoji($raw)];
      }

      [$bucket] = Threat::severity($threat);

      return self::severityFromBucket($bucket);
   }

   /**
    * @return array{0:string,1:string,2:string} [cor, rotulo, emoji]
    */
   private static function severityFromBucket(string $bucket): array
   {
      return match ($bucket) {
         'Critica'   => ['#b5179e', 'Severidade critica',  "\u{1F534}"],
         'Suspeita'  => ['#e8590c', 'Ameaca suspeita',     "\u{1F7E0}"],
         'Ativa'     => ['#f08c00', 'Ameaca ativa',        "\u{1F7E1}"],
         'Resolvida' => ['#2b7a0b', 'Ameaca resolvida',    "\u{2705}"],
         default     => ['#6b2cf5', 'Severidade indefinida', "\u{26AA}"],
      };
   }

   /**
    * Valor da linha "Severidade" da tabela: o termo bruto do SentinelOne quando
    * existe, senao o bucket derivado (ou null para omitir a linha).
    */
   private static function severityRowValue(array $threat): ?string
   {
      $raw = trim((string)($threat['severity'] ?? ''));
      if ($raw !== '') {
         return ucfirst($raw);
      }

      [$bucket] = Threat::severity($threat);

      return $bucket !== 'Indefinida' ? $bucket : null;
   }

   /**
    * Frase-resumo curta usada no cabecalho executivo do ticket.
    * Ex.: "Malware detectado em PC-FINANCEIRO (arquivo foo.exe)".
    */
   private static function summarySentence(array $threat, array $rich): string
   {
      $classification = trim((string)($threat['classification'] ?? ''));
      $computer = trim((string)($threat['computer_name'] ?? '')) ?: 'endpoint';
      $status   = strtolower(trim((string)($threat['status'] ?? '')));

      $subject = $classification !== '' ? $classification : 'Ameaca';
      $verb = match (true) {
         in_array($status, ['mitigated', 'resolved', 'marked_as_benign'], true) => 'mitigada',
         str_contains($status, 'block')      => 'bloqueada',
         str_contains($status, 'quarantine') => 'colocada em quarentena',
         default                             => 'detectada',
      };

      $sentence = "{$subject} {$verb} em {$computer}";

      $file = trim((string)($threat['file_path'] ?? ''));
      if ($file !== '') {
         $sentence .= ' (arquivo ' . self::fileBasename($file) . ')';
      }

      return $sentence;
   }

   /**
    * Extrai os campos ricos da ameaca a partir do raw_json (payload bruto da API
    * SentinelOne). Centraliza os caminhos do JSON para que o corpo do ticket e a
    * nota forense compartilhem a mesma normalizacao. Nomes seguem o schema v2.1
    * (threatInfo / agentDetectionInfo / agentRealtimeInfo / mitigationStatus /
    * indicators).
    *
    * @return array<string,mixed>
    */
   private static function extractRich(array $threat): array
   {
      $raw = [];
      if (!empty($threat['raw_json'])) {
         $decoded = json_decode((string)$threat['raw_json'], true);
         if (is_array($decoded)) {
            $raw = $decoded;
         }
      }

      $ti  = is_array($raw['threatInfo'] ?? null) ? $raw['threatInfo'] : [];
      $adi = is_array($raw['agentDetectionInfo'] ?? null) ? $raw['agentDetectionInfo'] : [];
      $ari = is_array($raw['agentRealtimeInfo'] ?? null) ? $raw['agentRealtimeInfo'] : [];
      $ms  = is_array($raw['mitigationStatus'] ?? null) ? $raw['mitigationStatus'] : [];
      $ind = is_array($raw['indicators'] ?? null) ? $raw['indicators'] : [];

      $mode = strtolower(trim((string)($adi['agentMitigationMode'] ?? $ari['agentMitigationMode'] ?? $ti['initiatedBy'] ?? '')));
      $modeLabel = match ($mode) {
         'protect' => 'Politica: Protect (bloqueio)',
         'detect'  => 'Politica: Detect (so alerta)',
         ''        => '',
         default   => 'Politica: ' . ucfirst($mode),
      };
      $modeColor = $mode === 'protect' ? '#2b7a0b' : ($mode === 'detect' ? '#e8590c' : '#495057');

      $rawEngines = $ti['detectionEngines'] ?? $ti['engines'] ?? [];
      $engines = [];
      foreach ((array)$rawEngines as $engine) {
         $name = is_array($engine)
            ? (string)($engine['title'] ?? $engine['name'] ?? $engine['key'] ?? '')
            : (string)$engine;
         $name = trim($name);
         if ($name !== '') {
            $engines[$name] = $name;
         }
      }

      $boolOrNull = static fn(array $src, string $key): ?bool => array_key_exists($key, $src) ? (bool)$src[$key] : null;

      return [
         'detection_type'        => trim((string)($ti['detectionType'] ?? '')),
         'engines'               => array_values($engines),
         'confidence'            => trim((string)($ti['confidenceLevel'] ?? ($threat['confidence_level'] ?? ''))),
         'analyst_verdict'       => trim((string)($ti['analystVerdict'] ?? ($threat['analyst_verdict'] ?? ''))),
         'analyst_verdict_desc'  => trim((string)($ti['analystVerdictDescription'] ?? '')),
         'mitigation_status_desc' => trim((string)($ti['mitigationStatusDescription'] ?? '')),
         'classification_source' => trim((string)($ti['classificationSource'] ?? '')),
         'initiated_by'          => trim((string)($ti['initiatedByDescription'] ?? $ti['initiatedBy'] ?? '')),
         'process_user'          => trim((string)($ti['processUser'] ?? $ti['initiatingUsername'] ?? '')),
         'process_args'          => trim((string)($ti['maliciousProcessArguments'] ?? '')),
         'originator_process'    => trim((string)($ti['originatorProcess'] ?? '')),
         'is_fileless'           => $boolOrNull($ti, 'isFileless'),
         'storyline'             => trim((string)($ti['storyline'] ?? '')),
         'file_size'             => $ti['fileSize'] ?? null,
         'file_extension'        => trim((string)($ti['fileExtension'] ?? '')),
         'publisher'             => trim((string)($ti['publisherName'] ?? '')),
         'valid_cert'            => $boolOrNull($ti, 'isValidCertificate'),
         'md5'                   => trim((string)($ti['md5'] ?? '')),
         'reboot_required'       => $boolOrNull($ti, 'rebootRequired'),
         'pending_actions'       => $boolOrNull($ti, 'pendingActions'),
         'failed_actions'        => $boolOrNull($ti, 'failedActions'),
         'auto_resolved'         => $boolOrNull($ti, 'automaticallyResolved'),
         'mitigation_mode'       => $modeLabel,
         'mitigation_mode_color' => $modeColor,
         'mitigation_actions'    => $ms,
         'indicators'            => $ind,
         'agent_ip'              => trim((string)($adi['agentIpV4'] ?? '')),
         'external_ip'           => trim((string)($adi['externalIp'] ?? '')),
         'agent_domain'          => trim((string)($adi['agentDomain'] ?? '')),
         'last_user'             => trim((string)($adi['agentLastLoggedInUserName'] ?? $adi['agentLastLoggedInUpn'] ?? '')),
         'os_name'               => trim((string)($adi['agentOsName'] ?? $ari['agentOsName'] ?? '')),
         'os_revision'           => trim((string)($adi['agentOsRevision'] ?? $ari['agentOsRevision'] ?? '')),
         'site_name'             => trim((string)($adi['siteName'] ?? $ari['siteName'] ?? '')),
         'group_name'            => trim((string)($adi['groupName'] ?? $ari['groupName'] ?? '')),
         'account_name'          => trim((string)($adi['accountName'] ?? $ari['accountName'] ?? '')),
      ];
   }

   /**
    * Cabecalho executivo: faixa com gradiente, circulo de severidade e
    * frase-resumo. Usa apenas estilos inline para sobreviver ao sanitizador.
    */
   private static function heroBlock(string $accent, string $emoji, string $title, string $summary): string
   {
      return "<div style=\"background:{$accent};background:linear-gradient(135deg,#2a0f5e 0%,{$accent} 100%);color:#ffffff;padding:18px 22px\">"
         . "<div style=\"font-size:11px;letter-spacing:.12em;text-transform:uppercase;opacity:.82;margin-bottom:10px\">\u{1F6E1}\u{FE0F} SentinelOne &middot; Incidente de seguranca</div>"
         . "<table style=\"border:0px solid transparent;border-collapse:collapse;background:transparent\"><tbody><tr>"
         . "<td style=\"border:0px solid transparent;vertical-align:middle;padding:0 14px 0 0\">"
         . "<div style=\"width:54px;height:54px;border-radius:50%;background:rgba(255,255,255,.16);text-align:center;font-size:26px;line-height:54px\">{$emoji}</div>"
         . "</td>"
         . "<td style=\"border:0px solid transparent;vertical-align:middle;padding:0\">"
         . "<div style=\"font-size:20px;font-weight:800;line-height:1.2;color:#ffffff\">" . self::esc($title) . "</div>"
         . "<div style=\"font-size:14px;opacity:.95;margin-top:3px;color:#ffffff\">" . self::esc($summary) . "</div>"
         . "</td>"
         . "</tr></tbody></table>"
         . "</div>";
   }

   private static function executiveCard(string $heroHtml, string $bodyHtml): string
   {
      $body = "<div style=\"padding:18px 22px;background:#ffffff;color:#1c2330\">{$bodyHtml}</div>";

      return "<div style=\"font-family:'Segoe UI',Roboto,Arial,sans-serif;max-width:680px;border:1px solid #e3e1ee;border-radius:14px;overflow:hidden\">{$heroHtml}{$body}</div>";
   }

   /**
    * Bloco de secao com titulo em caixa-alta. Retorna vazio quando o conteudo
    * interno esta vazio, para nao deixar titulos orfaos.
    */
   private static function section(string $title, string $innerHtml): string
   {
      if (trim($innerHtml) === '') {
         return '';
      }

      return "<div style=\"margin-top:18px\">"
         . "<div style=\"font-size:12px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:#6b2cf5;border-bottom:2px solid #efeafe;padding-bottom:5px;margin-bottom:8px\">" . self::esc($title) . "</div>"
         . $innerHtml
         . "</div>";
   }

   private static function codeBlock(string $label, string $text): string
   {
      return "<div style=\"margin-top:10px\">"
         . "<div style=\"font-size:12px;color:#6b7280;margin-bottom:4px\">" . self::esc($label) . "</div>"
         . "<div style=\"font-family:Consolas,Menlo,monospace;font-size:12px;background:#0f0a1e;color:#e8e3ff;padding:10px 12px;border-radius:8px;word-break:break-all;white-space:pre-wrap\">" . self::esc($text) . "</div>"
         . "</div>";
   }

   /**
    * Tabela das acoes de mitigacao executadas pelo SentinelOne (lista
    * threatInfo->mitigationStatus). Cada item tem action / status / lastUpdate.
    *
    * @param array<int,mixed> $actions
    */
   private static function mitigationActionsHtml(array $actions): string
   {
      $rows = '';
      foreach ($actions as $action) {
         if (!is_array($action)) {
            continue;
         }
         $name   = trim((string)($action['action'] ?? ''));
         $status = trim((string)($action['status'] ?? ''));
         $when   = trim((string)($action['lastUpdate'] ?? ''));
         if ($name === '' && $status === '') {
            continue;
         }
         $color = match (strtolower($status)) {
            'success'              => '#2b7a0b',
            'failed', 'failure'    => '#d6336c',
            'pending', 'in_progress' => '#f08c00',
            default                => '#495057',
         };
         $rows .= "<tr>"
            . "<td style=\"border:0px solid transparent;border-bottom:1px solid #eeeeee;padding:6px 10px 6px 0;font-weight:600\">" . self::esc($name !== '' ? $name : '-') . "</td>"
            . "<td style=\"border:0px solid transparent;border-bottom:1px solid #eeeeee;padding:6px 8px\"><span style=\"display:inline-block;padding:2px 9px;border-radius:999px;background:{$color};color:#ffffff;font-size:11px;font-weight:700\">" . self::esc($status !== '' ? $status : '-') . "</span></td>"
            . "<td style=\"border:0px solid transparent;border-bottom:1px solid #eeeeee;padding:6px 0;color:#6b7280;font-size:12px\">" . self::esc($when) . "</td>"
            . "</tr>";
      }

      if ($rows === '') {
         return '';
      }

      return "<table style=\"width:100%;border:0px solid transparent;border-collapse:collapse;font-size:13px;margin-bottom:4px\"><thead><tr>"
         . "<th style=\"border:0px solid transparent;text-align:left;padding:4px 0;color:#6b7280;font-size:11px;text-transform:uppercase\">Acao</th>"
         . "<th style=\"border:0px solid transparent;text-align:left;padding:4px 0;color:#6b7280;font-size:11px;text-transform:uppercase\">Resultado</th>"
         . "<th style=\"border:0px solid transparent;text-align:left;padding:4px 0;color:#6b7280;font-size:11px;text-transform:uppercase\">Atualizado</th>"
         . "</tr></thead><tbody>{$rows}</tbody></table>";
   }

   /**
    * Tecnicas MITRE ATT&CK extraidas dos indicadores da ameaca, renderizadas
    * como badges. Aceita tecnicas tanto em indicators[].techniques quanto em
    * indicators[].tactics[].techniques.
    *
    * @param array<int,mixed> $indicators
    */
   private static function mitreHtml(array $indicators): string
   {
      $items = [];
      foreach ($indicators as $indicator) {
         if (!is_array($indicator)) {
            continue;
         }
         $techniques = is_array($indicator['techniques'] ?? null) ? $indicator['techniques'] : [];
         foreach (($indicator['tactics'] ?? []) as $tactic) {
            if (is_array($tactic) && is_array($tactic['techniques'] ?? null)) {
               $techniques = array_merge($techniques, $tactic['techniques']);
            }
         }
         foreach ($techniques as $technique) {
            if (!is_array($technique)) {
               continue;
            }
            $name = trim((string)($technique['name'] ?? ''));
            $tid  = trim((string)($technique['id'] ?? ''));
            $label = $name !== '' ? $name : $tid;
            if ($label === '') {
               continue;
            }
            $key = $tid !== '' ? $tid : $label;
            $items[$key] = $label . ($tid !== '' ? ' (' . $tid . ')' : '');
         }
      }

      if ($items === []) {
         return '';
      }

      $badges = '';
      foreach ($items as $text) {
         $badges .= self::badge("\u{1F3AF} " . $text, '#5f3dc4');
      }

      return "<div>{$badges}</div>";
   }

   private static function humanSize($bytes): ?string
   {
      if ($bytes === null || $bytes === '') {
         return null;
      }
      $value = (float)$bytes;
      if ($value <= 0) {
         return null;
      }

      $units = ['B', 'KB', 'MB', 'GB', 'TB'];
      $index = 0;
      while ($value >= 1024 && $index < count($units) - 1) {
         $value /= 1024;
         $index++;
      }

      return ($index === 0 ? (string)(int)$value : number_format($value, 1)) . ' ' . $units[$index];
   }

   private static function joinDesc(string $value, string $desc): ?string
   {
      $value = trim($value);
      if ($value === '') {
         return null;
      }
      $desc = trim($desc);

      return ($desc !== '' && strcasecmp($desc, $value) !== 0) ? $value . ' — ' . $desc : $value;
   }

   private static function boolLabel(?bool $value): ?string
   {
      if ($value === null) {
         return null;
      }

      return $value ? 'Sim' : 'Nao';
   }

   private static function joinSlash(string ...$parts): ?string
   {
      $parts = array_values(array_filter(array_map('trim', $parts), static fn($part): bool => $part !== ''));

      return $parts === [] ? null : implode(' / ', $parts);
   }

   private static function fileBasename(string $path): string
   {
      $normalized = str_replace('\\', '/', trim($path));
      $position = strrpos($normalized, '/');

      $base = $position === false ? $normalized : substr($normalized, $position + 1);

      return $base !== '' ? $base : $normalized;
   }
}

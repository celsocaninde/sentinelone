<?php

use GlpiPlugin\Sentinelone\Config;
use GlpiPlugin\Sentinelone\Profile;
use GlpiPlugin\Sentinelone\Sync;
use GlpiPlugin\Sentinelone\Threat;

include('../../../inc/includes.php');

\Session::checkRight(Profile::RIGHT_READ, READ);

global $CFG_GLPI;

$h = static fn($value): string => htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$stats = Sync::stats();
$config = Config::getConfig();
$configured = Config::isConfigured($config);
$rootDoc = (string)($CFG_GLPI['root_doc'] ?? '');
$syncUrl = $rootDoc . '/plugins/sentinelone/front/sync.form.php';
$agentUrl = $rootDoc . '/plugins/sentinelone/front/agent.php';
$diagnosticUrl = $rootDoc . '/plugins/sentinelone/front/unlinked.php';
$unprotectedUrl = $rootDoc . '/plugins/sentinelone/front/unprotected.php';
$threatUrl = $rootDoc . '/plugins/sentinelone/front/threat.php';
$consoleUrl = trim((string)($config['base_url'] ?? ''));

$formatDate = static function ($value) use ($h): string {
   $value = trim((string)$value);
   return $value !== '' ? $h($value) : '-';
};

$statusClass = static function ($status): string {
   $status = strtolower(trim((string)$status));

   return match ($status) {
      'ok', 'success', 'synced' => 'success',
      'error', 'failed'         => 'danger',
      'skipped', 'warning'      => 'warning',
      default                   => 'secondary',
   };
};

$renderStatusBadge = static function ($status) use ($h, $statusClass): string {
   $label = trim((string)$status) !== '' ? (string)$status : 'sem status';
   return "<span class='badge bg-" . $statusClass($status) . "'>" . $h($label) . "</span>";
};

$renderThreatBadge = static function ($status) use ($h): string {
   $raw = strtolower(trim((string)$status));
   $label = trim((string)$status) !== '' ? (string)$status : 'sem status';

   if (in_array($raw, ['mitigated', 'resolved', 'benign', 'false_positive', 'marked_as_benign'], true)) {
      $cls = 's1-badge--ok';
   } elseif ($raw === '') {
      $cls = 's1-badge--muted';
   } elseif (in_array($raw, ['active', 'unmitigated', 'not_mitigated', 'unresolved'], true)) {
      $cls = 's1-badge--critical';
   } else {
      $cls = 's1-badge--danger';
   }

   return "<span class='s1-badge {$cls}'>" . $h($label) . "</span>";
};

$pct = static function ($part, $total): int {
   $total = (int)$total;
   return $total > 0 ? (int)round(((int)$part / $total) * 100) : 0;
};

$renderLastSync = static function (?array $log, string $label) use ($h, $formatDate, $renderStatusBadge): string {
   if ($log === null) {
      return "<div class='sentinelone-sync-chip'><span>" . $h($label) . "</span><strong>Nunca executado</strong></div>";
   }

   return "<div class='sentinelone-sync-chip'><span>" . $h($label) . "</span><strong>"
      . $formatDate($log['date_creation'] ?? '')
      . "</strong>" . $renderStatusBadge($log['status'] ?? '') . "</div>";
};

\Html::header('SentinelOne', $_SERVER['PHP_SELF'], 'plugins', 'sentinelone');


echo "<div class='sentinelone-dashboard'>";
echo "<div class='sentinelone-dashboard__hero'>";
echo "<div class='s1-hero__brand'>";
echo "<span class='s1-logo'><span class='ti ti-shield-half-filled'></span></span>";
echo "<div>";
echo "<div class='sentinelone-dashboard__eyebrow'>Operacao SentinelOne</div>";
echo "<h2>SentinelOne</h2>";
echo "<p>Agentes, ameacas, tickets e sincronizacoes em um painel operacional.</p>";
echo "</div>";
echo "</div>";
echo "<div class='sentinelone-dashboard__actions'>";
echo "<div class='sentinelone-dashboard__status " . ($configured ? 'is-ok' : 'is-warn') . "'>";
echo "<span class='ti " . ($configured ? 'ti-circle-check' : 'ti-alert-triangle') . "'></span>";
echo $configured ? 'Configurada' : 'Pendente';
echo "</div>";
echo "<a class='btn btn-outline-secondary' href='" . $h($agentUrl) . "'><span class='ti ti-devices-pc'></span>Agentes</a>";
echo "<a class='btn btn-outline-secondary' href='" . $h($diagnosticUrl) . "'><span class='ti ti-stethoscope'></span>Diagnostico</a>";
echo "<a class='btn btn-outline-secondary' href='" . $h($unprotectedUrl) . "'><span class='ti ti-shield-off'></span>Sem agente</a>";
echo "<a class='btn btn-outline-secondary' href='" . $h($threatUrl) . "'><span class='ti ti-bug'></span>Ameacas</a>";
if ($consoleUrl !== '') {
   echo "<a class='btn btn-outline-secondary' href='" . $h($consoleUrl) . "' target='_blank' rel='noopener'><span class='ti ti-external-link'></span>Console</a>";
}
if (Profile::hasConfigReadRight()) {
   echo "<a class='btn btn-primary' href='" . $h(Config::getPluginFormUrl()) . "'><span class='ti ti-settings'></span>Configuracao</a>";
}
echo "</div>";
echo "</div>";

if (!$configured) {
   $steps = [
      ['n' => '1', 'title' => 'Informe a console', 'desc' => 'URL e token da API SentinelOne na tela de Configuracao.'],
      ['n' => '2', 'title' => 'Teste a conexao', 'desc' => 'Use "Testar conexao" para validar o endpoint e o token.'],
      ['n' => '3', 'title' => 'Sincronize', 'desc' => 'Rode a sincronizacao de agentes e ameacas e acompanhe por aqui.'],
   ];
   echo "<div class='sentinelone-onboard'>";
   foreach ($steps as $step) {
      echo "<div class='sentinelone-onboard__step'>";
      echo "<span class='sentinelone-onboard__num'>" . $h($step['n']) . "</span>";
      echo "<div><strong>" . $h($step['title']) . "</strong><span>" . $h($step['desc']) . "</span></div>";
      echo "</div>";
   }
   echo "</div>";
}

echo "<div class='sentinelone-dashboard__sync'>";
echo "<div class='sentinelone-dashboard__sync-meta'>";
echo $renderLastSync($stats['last_agents_sync'] ?? null, 'Ultima sync de agentes');
echo $renderLastSync($stats['last_threats_sync'] ?? null, 'Ultima sync de ameacas');
$ticketRulesConfigured = trim((string)($config['ticket_status_filter'] ?? '')) !== ''
   || trim((string)($config['ticket_classification_filter'] ?? '')) !== '';
$ticketStatus = (string)$config['create_tickets'] === '1'
   ? ($ticketRulesConfigured ? 'Ativos' : 'Aguardando regras')
   : 'Desativados';
echo "<div class='sentinelone-sync-chip'><span>Tickets automaticos</span><strong>" . $h($ticketStatus) . "</strong></div>";
echo "<a class='sentinelone-sync-chip text-decoration-none' href='" . $h($diagnosticUrl) . "'><span>Cobertura GLPI</span><strong>" . $h($stats['agents_linked'] ?? 0) . "/" . $h($stats['agents_total'] ?? 0) . " agentes vinculados</strong><span>" . $h($stats['glpi_computers'] ?? 0) . " computadores no GLPI</span></a>";
echo "</div>";

if (Profile::hasSyncRight()) {
   echo "<form method='post' action='" . $h($syncUrl) . "' class='sentinelone-dashboard__sync-actions'>";
   echo "<input type='hidden' name='_glpi_csrf_token' value='" . $h(\Session::getNewCSRFToken()) . "'>";
   echo "<button class='btn btn-primary' type='submit' name='action' value='agents'><span class='ti ti-refresh'></span>Agentes</button>";
   echo "<button class='btn btn-primary' type='submit' name='action' value='threats'><span class='ti ti-shield-search'></span>Ameacas</button>";
   echo "<button class='btn btn-outline-primary' type='submit' name='action' value='all'><span class='ti ti-refresh-dot'></span>Tudo</button>";
   echo "</form>";
}
echo "</div>";

$linkPct = $pct($stats['agents_linked'] ?? 0, $stats['agents_total'] ?? 0);
$onlinePct = $pct($stats['agents_online'] ?? 0, $stats['agents_total'] ?? 0);
echo "<div class='sentinelone-coverage'>";
echo "<div class='sentinelone-coverage__head'><strong>Cobertura GLPI</strong><span>" . $h($stats['agents_linked'] ?? 0) . " de " . $h($stats['agents_total'] ?? 0) . " agentes vinculados a um computador &middot; " . $linkPct . "%</span></div>";
echo "<div class='sentinelone-coverage__bar'><div class='sentinelone-coverage__fill' style='width:" . $linkPct . "%'></div></div>";
echo "<div class='sentinelone-coverage__head'><strong>Agentes online</strong><span>" . $h($stats['agents_online'] ?? 0) . " de " . $h($stats['agents_total'] ?? 0) . " com conexao recente &middot; " . $onlinePct . "%</span></div>";
echo "<div class='sentinelone-coverage__bar'><div class='sentinelone-coverage__fill' style='width:" . $onlinePct . "%'></div></div>";
echo "</div>";

$cards = [
   ['label' => 'Agentes', 'value' => $stats['agents_total'], 'hint' => $stats['agents_online'] . ' online', 'mod' => 'accent'],
   ['label' => 'Offline', 'value' => $stats['agents_offline'], 'hint' => 'Sem conexao recente', 'mod' => ''],
   ['label' => 'Infectados', 'value' => $stats['agents_infected'], 'hint' => 'Prioridade alta', 'mod' => 'danger'],
   ['label' => 'Vinculados', 'value' => $stats['agents_linked'], 'hint' => 'Associados ao GLPI', 'mod' => 'ok'],
   ['label' => 'Sem vinculo', 'value' => $stats['agents_unlinked'], 'hint' => 'Aguardam inventario GLPI', 'mod' => ''],
   ['label' => 'Ameacas', 'value' => $stats['threats_total'], 'hint' => 'Total sincronizado', 'mod' => 'accent'],
   ['label' => 'Sem ticket', 'value' => $stats['threats_no_ticket'], 'hint' => 'Pendentes de atendimento', 'mod' => 'danger'],
   ['label' => 'Sem agente S1', 'value' => $stats['computers_unprotected'] ?? 0, 'hint' => 'Computadores GLPI desprotegidos', 'mod' => 'danger'],
];

echo "<div class='sentinelone-stats'>";
foreach ($cards as $card) {
   $mod = $card['mod'] !== '' ? ' sentinelone-stat--' . $card['mod'] : '';
   echo "<div class='sentinelone-stat" . $mod . "'>";
   echo "<span>" . $h($card['label']) . "</span>";
   echo "<strong>" . $h($card['value']) . "</strong>";
   echo "<small>" . $h($card['hint']) . "</small>";
   echo "</div>";
}
echo "</div>";

echo "<div class='sentinelone-dashboard__grid'>";
echo "<section class='sentinelone-panel'>";
echo "<div class='sentinelone-panel__head'><h3>Ameacas recentes</h3><a href='" . $h($threatUrl) . "'>Ver todas</a></div>";
echo "<div class='table-responsive'>";
echo "<table class='table table-vcenter table-hover mb-0'>";
echo "<thead><tr><th>Ameaca</th><th>Severidade</th><th>Endpoint</th><th>Status</th><th>Detectada em</th><th>Ticket</th></tr></thead>";
echo "<tbody>";
foreach ($stats['recent_threats'] as $threat) {
   $ticketId = (int)($threat['tickets_id'] ?? 0);
   $threatName = trim((string)($threat['threat_name'] ?? '')) !== '' ? (string)$threat['threat_name'] : '-';
   $threatUrl = Config::consoleThreatUrl($config, (string)($threat['sentinelone_threat_id'] ?? ''));
   echo "<tr>";
   if ($threatUrl !== '') {
      echo "<td><a href='" . $h($threatUrl) . "' target='_blank' rel='noopener'>" . $h($threatName) . " <span class='ti ti-external-link'></span></a></td>";
   } else {
      echo "<td>" . $h($threatName) . "</td>";
   }
   echo "<td>" . Threat::severityBadge($threat) . "</td>";
   echo "<td>" . $h($threat['computer_name'] ?? '-') . "</td>";
   echo "<td>" . $renderThreatBadge($threat['status'] ?? '') . "</td>";
   echo "<td>" . $formatDate($threat['detected_at'] ?? '') . "</td>";
   if ($ticketId > 0) {
      echo "<td><a href='" . $h($rootDoc . '/front/ticket.form.php?id=' . $ticketId) . "'>#" . $h($ticketId) . "</a></td>";
   } else {
      echo "<td><span class='text-muted'>-</span></td>";
   }
   echo "</tr>";
}
if (($stats['recent_threats'] ?? []) === []) {
   echo "<tr><td colspan='6'><div class='sentinelone-empty'>Nenhuma ameaca sincronizada ainda.</div></td></tr>";
}
echo "</tbody>";
echo "</table>";
echo "</div>";
echo "</section>";

$attentionAgents = [];
foreach (['attention_agents', 'unlinked_agents', 'offline_agents'] as $agentListKey) {
   foreach (($stats[$agentListKey] ?? []) as $agent) {
      $attentionAgents[(int)($agent['id'] ?? 0)] = $agent;
      if (count($attentionAgents) >= 6) {
         break 2;
      }
   }
}
$attentionAgents = array_values($attentionAgents);
echo "<section class='sentinelone-panel'>";
echo "<div class='sentinelone-panel__head'><h3>Endpoints em atencao</h3><a href='" . $h($agentUrl) . "'>Ver agentes</a></div>";
echo "<div class='sentinelone-panel__body'>";
if ($attentionAgents === []) {
   echo "<div class='sentinelone-empty'>Nenhum endpoint critico encontrado.</div>";
} else {
   echo "<div class='sentinelone-agent-list'>";
   foreach ($attentionAgents as $agent) {
      $computerId = (int)($agent['computers_id'] ?? 0);
      $name = trim((string)($agent['computer_name'] ?? 'Endpoint sem nome'));
      echo "<div class='sentinelone-agent'>";
      if ($computerId > 0) {
         echo "<strong><a href='" . $h($rootDoc . '/front/computer.form.php?id=' . $computerId) . "'>" . $h($name) . "</a></strong>";
      } else {
         echo "<strong>" . $h($name) . "</strong>";
      }
      echo "<span>" . $h(($agent['site_name'] ?? '-') . ' / ' . ($agent['group_name'] ?? '-')) . "</span>";
      echo "<div class='mt-2 d-flex flex-wrap gap-1'>";
      if ((int)($agent['is_infected'] ?? 0) === 1) {
         echo "<span class='s1-badge s1-badge--critical'>infectado</span>";
      }
      if ((int)($agent['is_online'] ?? 0) === 0) {
         echo "<span class='s1-badge s1-badge--muted'>offline</span>";
      }
      if ($computerId === 0) {
         echo "<span class='s1-badge s1-badge--danger'>sem vinculo</span>";
      }
      echo "</div>";
      echo "</div>";
   }
   echo "</div>";
}
echo "</div>";
echo "</section>";
echo "</div>";

echo "<section class='sentinelone-panel'>";
echo "<div class='sentinelone-panel__head'><h3>Ultimos logs</h3></div>";
echo "<div class='table-responsive'>";
echo "<table class='table table-vcenter table-striped mb-0'>";
echo "<thead><tr><th>Data</th><th>Acao</th><th>Status</th><th>Itens</th><th>Mensagem</th></tr></thead>";
echo "<tbody>";
foreach ($stats['logs'] as $log) {
   echo "<tr>";
   echo "<td>" . $formatDate($log['date_creation'] ?? '') . "</td>";
   echo "<td>" . $h($log['action'] ?? '') . "</td>";
   echo "<td>" . $renderStatusBadge($log['status'] ?? '') . "</td>";
   echo "<td>" . $h($log['items_count'] ?? '') . "</td>";
   echo "<td>" . $h($log['message'] ?? '') . "</td>";
   echo "</tr>";
}
if ($stats['logs'] === []) {
   echo "<tr><td colspan='5'><div class='sentinelone-empty'>Nenhum log registrado ainda.</div></td></tr>";
}
echo "</tbody>";
echo "</table>";
echo "</div>";
echo "</section>";
echo "</div>";

\Html::footer();

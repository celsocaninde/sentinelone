<?php

use GlpiPlugin\Sentinelone\Agent;
use GlpiPlugin\Sentinelone\Config;
use GlpiPlugin\Sentinelone\Group;
use GlpiPlugin\Sentinelone\Profile;
use GlpiPlugin\Sentinelone\Cve;
use GlpiPlugin\Sentinelone\RogueDevice;
use GlpiPlugin\Sentinelone\Sync;
use GlpiPlugin\Sentinelone\Threat;

include('../../../inc/includes.php');

\Session::checkRight(Profile::RIGHT_READ, READ);

global $CFG_GLPI, $DB;

$h = static fn($value): string => htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$stats = Sync::stats();
$config = Config::getConfig();
$configured = Config::isConfigured($config);
$rootDoc = (string)($CFG_GLPI['root_doc'] ?? '');
$syncUrl = $rootDoc . '/plugins/sentinelone/front/sync.form.php';
$agentUrl = $rootDoc . '/plugins/sentinelone/front/agent.php';
$diagnosticUrl  = $rootDoc . '/plugins/sentinelone/front/coverage.php?tab=unlinked';
$unprotectedUrl = $rootDoc . '/plugins/sentinelone/front/coverage.php?tab=unprotected';
$threatUrl  = $rootDoc . '/plugins/sentinelone/front/threat.php';
$roguesUrl  = $rootDoc . '/plugins/sentinelone/front/rogues.php';
$cvesUrl    = $rootDoc . '/plugins/sentinelone/front/cves.php';
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
   $label = trim((string)$status) !== '' ? (string)$status : __('sem status', 'sentinelone');
   return "<span class='badge bg-" . $statusClass($status) . "'>" . $h($label) . "</span>";
};

$renderThreatBadge = static function ($status) use ($h): string {
   $raw = strtolower(trim((string)$status));

   static $labels = [
      'marked_as_benign'        => 'Falso Positivo',
      'marked_as_benign_ep'     => 'Falso Positivo (EP)',
      'false_positive'          => 'Falso Positivo',
      'mitigated'               => 'Mitigada',
      'resolved'                => 'Resolvida',
      'benign'                  => 'Benigna',
      'active'                  => 'Ativa',
      'unmitigated'             => 'Não Mitigada',
      'not_mitigated'           => 'Não Mitigada',
      'unresolved'              => 'Não Resolvida',
      'suspicious'              => 'Suspeita',
      'malicious'               => 'Maliciosa',
      'undefined'               => 'Indefinida',
      'rollback_needed'         => 'Rollback Necessário',
      'partially_mitigated'     => 'Parcialmente Mitigada',
   ];
   $label = $labels[$raw] ?? (trim((string)$status) !== '' ? ucwords(str_replace('_', ' ', $raw)) : 'Sem status');

   $cls = match(true) {
      in_array($raw, ['mitigated','resolved','benign','false_positive','marked_as_benign','marked_as_benign_ep'], true) => 's1-badge--ok',
      $raw === '' => 's1-badge--muted',
      in_array($raw, ['active','unmitigated','not_mitigated','unresolved','malicious'], true) => 's1-badge--critical',
      default => 's1-badge--danger',
   };

   return "<span class='s1-badge {$cls}'>" . $h($label) . "</span>";
};

$pct = static function ($part, $total): int {
   $total = (int)$total;
   return $total > 0 ? (int)round(((int)$part / $total) * 100) : 0;
};

$renderLastSync = static function (?array $log, string $label) use ($h, $formatDate, $renderStatusBadge): string {
   if ($log === null) {
      return "<div class='sentinelone-sync-chip'><span>" . $h($label) . "</span><strong>" . __('Nunca executado', 'sentinelone') . "</strong></div>";
   }

   return "<div class='sentinelone-sync-chip'><span>" . $h($label) . "</span><strong>"
      . $formatDate($log['date_creation'] ?? '')
      . "</strong>" . $renderStatusBadge($log['status'] ?? '') . "</div>";
};

\Html::header('SentinelOne', $_SERVER['PHP_SELF'], 'plugins', 'sentinelone');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";


echo "<div class='sentinelone-dashboard'>";
echo "<div class='sentinelone-dashboard__hero'>";
echo "<div class='s1-hero__brand'>";
echo "<span class='s1-logo'><span class='ti ti-shield-half-filled'></span></span>";
echo "<div>";
echo "<div class='sentinelone-dashboard__eyebrow'>" . __('Operacao SentinelOne', 'sentinelone') . "</div>";
echo "<h2>SentinelOne</h2>";
echo "<p>" . __('Agentes, ameacas, tickets e sincronizacoes em um painel operacional.', 'sentinelone') . "</p>";
echo "</div>";
echo "</div>";
echo "<div class='sentinelone-dashboard__actions'>";
echo "<div class='sentinelone-dashboard__status " . ($configured ? 'is-ok' : 'is-warn') . "'>";
echo "<span class='ti " . ($configured ? 'ti-circle-check' : 'ti-alert-triangle') . "'></span>";
echo $configured ? __('Configurada', 'sentinelone') : __('Pendente', 'sentinelone');
echo "</div>";
echo "<a class='btn btn-outline-secondary' href='" . $h($agentUrl) . "'><span class='ti ti-devices-pc'></span>" . __('Agentes', 'sentinelone') . "</a>";
echo "<a class='btn btn-outline-secondary' href='" . $h($diagnosticUrl) . "'><span class='ti ti-stethoscope'></span>" . __('Diagnostico', 'sentinelone') . "</a>";
echo "<a class='btn btn-outline-secondary' href='" . $h($unprotectedUrl) . "'><span class='ti ti-shield-off'></span>" . __('Sem agente', 'sentinelone') . "</a>";
echo "<a class='btn btn-outline-secondary' href='" . $h($threatUrl) . "'><span class='ti ti-bug'></span>" . __('Ameacas', 'sentinelone') . "</a>";
echo "<a class='btn btn-outline-secondary' href='" . $h($roguesUrl) . "'><span class='ti ti-ghost'></span>" . __('Rogues', 'sentinelone') . "</a>";
echo "<a class='btn btn-outline-secondary' href='" . $h($cvesUrl) . "'><span class='ti ti-shield-exclamation'></span>" . __('CVEs', 'sentinelone') . "</a>";
$reportUrl = $rootDoc . '/plugins/sentinelone/front/report.php';
echo "<a class='btn btn-outline-primary s1-btn-report' href='" . $h($reportUrl) . "' title='Relatório executivo com índice de proteção, KPIs e tendências'><span class='ti ti-chart-bar'></span>" . __('Relatorio', 'sentinelone') . "</a>";
if ($consoleUrl !== '') {
   echo "<a class='btn btn-outline-secondary' href='" . $h($consoleUrl) . "' target='_blank' rel='noopener'><span class='ti ti-external-link'></span>" . __('Console', 'sentinelone') . "</a>";
}
if (Profile::hasConfigReadRight()) {
   echo "<a class='btn btn-primary' href='" . $h(Config::getPluginFormUrl()) . "'><span class='ti ti-settings'></span>" . __('Configuracao', 'sentinelone') . "</a>";
}
echo "</div>";
echo "</div>";

if (!$configured) {
   $steps = [
      ['n' => '1', 'title' => __('Informe a console', 'sentinelone'), 'desc' => __('URL e token da API SentinelOne na tela de Configuracao.', 'sentinelone')],
      ['n' => '2', 'title' => __('Teste a conexao', 'sentinelone'), 'desc' => __('Use "Testar conexao" para validar o endpoint e o token.', 'sentinelone')],
      ['n' => '3', 'title' => __('Sincronize', 'sentinelone'), 'desc' => __('Rode a sincronizacao de agentes e ameacas e acompanhe por aqui.', 'sentinelone')],
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

// Healthcheck: alerta se qualquer sync nao rodou nas ultimas 2 horas
if ($configured) {
   $staleThreshold = 7200; // 2 horas em segundos
   $staleChecks = [
      __('agentes', 'sentinelone')  => $stats['last_agents_sync'] ?? null,
      __('ameacas', 'sentinelone')  => $stats['last_threats_sync'] ?? null,
   ];
   if ((string)($config['sync_activities'] ?? '0') === '1') {
      $staleChecks[__('atividades', 'sentinelone')] = $stats['last_activities_sync'] ?? null;
   }
   if ((string)($config['sync_software'] ?? '0') === '1') {
      $staleChecks[__('software', 'sentinelone')] = $stats['last_software_sync'] ?? null;
   }
   $staleLabels = [];
   foreach ($staleChecks as $label => $log) {
      if ($log === null) {
         $staleLabels[] = $label;
      } else {
         $lastRun = strtotime((string)($log['date_creation'] ?? ''));
         if ($lastRun !== false && (time() - $lastRun) > $staleThreshold) {
            $staleLabels[] = $label;
         }
      }
   }
   if ($staleLabels !== []) {
      echo "<div class='alert alert-warning d-flex align-items-center gap-2' style='margin-bottom:16px'>";
      echo "<span class='ti ti-clock-alert' style='font-size:20px;flex-shrink:0'></span>";
      echo "<div><strong>" . __('Sync atrasada.', 'sentinelone') . "</strong> ";
      echo sprintf(__('A sincronizacao de %s nao rodou nas ultimas 2 horas. Verifique se o cron do GLPI esta ativo.', 'sentinelone'), implode(' e ', $staleLabels));
      echo "</div></div>";
   }
}

echo "<div class='sentinelone-dashboard__sync'>";
echo "<div class='sentinelone-dashboard__sync-meta'>";
echo $renderLastSync($stats['last_agents_sync'] ?? null, __('Ultima sync de agentes', 'sentinelone'));
echo $renderLastSync($stats['last_threats_sync'] ?? null, __('Ultima sync de ameacas', 'sentinelone'));
echo $renderLastSync($stats['last_groups_sync'] ?? null, __('Ultima sync de grupos', 'sentinelone'));
if ((string)($config['sync_activities'] ?? '0') === '1') {
   echo $renderLastSync($stats['last_activities_sync'] ?? null, __('Ultima sync de atividades', 'sentinelone'));
}
if ((string)($config['sync_software'] ?? '0') === '1') {
   echo $renderLastSync($stats['last_software_sync'] ?? null, __('Ultima sync de software', 'sentinelone'));
}
$ticketRulesConfigured = trim((string)($config['ticket_status_filter'] ?? '')) !== ''
   || trim((string)($config['ticket_classification_filter'] ?? '')) !== '';
$ticketStatus = (string)$config['create_tickets'] === '1'
   ? ($ticketRulesConfigured ? __('Ativos', 'sentinelone') : __('Aguardando regras', 'sentinelone'))
   : __('Desativados', 'sentinelone');
echo "<div class='sentinelone-sync-chip'><span>" . __('Tickets automaticos', 'sentinelone') . "</span><strong>" . $h($ticketStatus) . "</strong></div>";
echo "<a class='sentinelone-sync-chip text-decoration-none' href='" . $h($diagnosticUrl) . "'><span>" . __('Cobertura GLPI', 'sentinelone') . "</span><strong>" . $h($stats['agents_linked'] ?? 0) . "/" . $h($stats['agents_total'] ?? 0) . " " . __('agentes vinculados', 'sentinelone') . "</strong><span>" . $h($stats['glpi_computers'] ?? 0) . " " . __('computadores no GLPI', 'sentinelone') . "</span></a>";
echo "</div>";

$hasSyncRight = Profile::hasSyncRight();
if ($hasSyncRight) {
   echo "<form method='post' action='" . $h($syncUrl) . "' class='sentinelone-dashboard__sync-actions'>";
   echo "<span class='sentinelone-sync-label'><span class='ti ti-refresh'></span>" . __('Sincronizar', 'sentinelone') . ":</span>";
   echo "<input type='hidden' name='_glpi_csrf_token' value='" . $h(\Session::getNewCSRFToken()) . "'>";
   echo "<button class='btn btn-sm btn-primary' type='submit' name='action' value='agents'><span class='ti ti-devices-pc'></span>" . __('Agentes', 'sentinelone') . "</button>";
   echo "<button class='btn btn-sm btn-primary' type='submit' name='action' value='threats'><span class='ti ti-shield-search'></span>" . __('Ameacas', 'sentinelone') . "</button>";
   echo "<button class='btn btn-sm btn-primary' type='submit' name='action' value='activities'><span class='ti ti-activity'></span>" . __('Atividades', 'sentinelone') . "</button>";
   echo "<button class='btn btn-sm btn-primary' type='submit' name='action' value='groups'><span class='ti ti-sitemap'></span>" . __('Grupos', 'sentinelone') . "</button>";
   echo "<button class='btn btn-sm btn-outline-primary' type='submit' name='action' value='all'><span class='ti ti-refresh-dot'></span>" . __('Tudo', 'sentinelone') . "</button>";
   echo "</form>";
}
echo "</div>";

$linkPct = $pct($stats['agents_linked'] ?? 0, $stats['agents_total'] ?? 0);
$onlinePct = $pct($stats['agents_online'] ?? 0, $stats['agents_total'] ?? 0);
echo "<div class='sentinelone-coverage'>";
echo "<div class='sentinelone-coverage__head'><strong>" . __('Cobertura GLPI', 'sentinelone') . "</strong><span>" . $h($stats['agents_linked'] ?? 0) . " " . __('de', 'sentinelone') . " " . $h($stats['agents_total'] ?? 0) . " " . __('agentes vinculados a um computador', 'sentinelone') . " &middot; " . $linkPct . "%</span></div>";
echo "<div class='sentinelone-coverage__bar'><div class='sentinelone-coverage__fill' style='width:" . $linkPct . "%'></div></div>";
echo "<div class='sentinelone-coverage__head'><strong>" . __('Agentes online', 'sentinelone') . "</strong><span>" . $h($stats['agents_online'] ?? 0) . " " . __('de', 'sentinelone') . " " . $h($stats['agents_total'] ?? 0) . " " . __('com conexao recente', 'sentinelone') . " &middot; " . $onlinePct . "%</span></div>";
echo "<div class='sentinelone-coverage__bar'><div class='sentinelone-coverage__fill' style='width:" . $onlinePct . "%'></div></div>";
echo "</div>";

$groupsRisky = ((int)($stats['groups_detect'] ?? 0)) + ((int)($stats['groups_none'] ?? 0));
$cards = [
   ['label' => __('Agentes', 'sentinelone'),        'value' => $stats['agents_total'],              'hint' => $stats['agents_online'] . ' ' . __('online', 'sentinelone'), 'mod' => 'accent',  'url' => $agentUrl],
   ['label' => __('Infectados', 'sentinelone'),      'value' => $stats['agents_infected'],           'hint' => __('Prioridade alta', 'sentinelone'), 'mod' => ($stats['agents_infected'] > 0 ? 'danger' : ''), 'url' => $agentUrl],
   ['label' => __('Desatualizados', 'sentinelone'),  'value' => $stats['agents_outdated'] ?? 0,      'hint' => ($stats['latest_agent_version'] !== '' ? 'v' . $stats['latest_agent_version'] : __('Sem dados', 'sentinelone')), 'mod' => (($stats['agents_outdated'] ?? 0) > 0 ? 'danger' : ''), 'url' => $agentUrl],
   ['label' => __('Em quarentena', 'sentinelone'),   'value' => $stats['agents_quarantined'] ?? 0,   'hint' => __('Isolados da rede', 'sentinelone'), 'mod' => (($stats['agents_quarantined'] ?? 0) > 0 ? 'danger' : 'ok'), 'url' => $agentUrl],
   ['label' => __('Sem vinculo', 'sentinelone'),     'value' => $stats['agents_unlinked'],           'hint' => __('Aguardam inventario GLPI', 'sentinelone'), 'mod' => '', 'url' => $diagnosticUrl],
   ['label' => __('Ameacas', 'sentinelone'),         'value' => $stats['threats_total'],             'hint' => __('Total sincronizado', 'sentinelone'), 'mod' => 'accent', 'url' => $threatUrl],
   ['label' => __('Sem ticket', 'sentinelone'),      'value' => $stats['threats_no_ticket'],         'hint' => __('Pendentes de atendimento', 'sentinelone'), 'mod' => ($stats['threats_no_ticket'] > 0 ? 'danger' : ''), 'url' => $threatUrl],
   ['label' => __('Grupos risky', 'sentinelone'),    'value' => $groupsRisky,                        'hint' => __('Detect ou desativado', 'sentinelone'), 'mod' => ($groupsRisky > 0 ? 'danger' : 'ok'), 'url' => $rootDoc . '/plugins/sentinelone/front/dashboard.php'],
   ['label' => __('Rogues', 'sentinelone'),          'value' => RogueDevice::countTotal(),           'hint' => __('Sem agente Ranger', 'sentinelone'),    'mod' => '', 'url' => $roguesUrl],
];

$cveStats      = Cve::getGlobalStats();
$cvesBySev     = $cveStats['by_severity'] ?? [];
$cvesCritical  = (int)($cvesBySev['CRITICAL'] ?? 0);
$cvesTotal     = (int)($cveStats['total'] ?? 0);
if ($cvesTotal > 0) {
   $cards[] = ['label' => __('CVEs criticos', 'sentinelone'), 'value' => $cvesCritical, 'hint' => sprintf(__('%d CVEs total', 'sentinelone'), $cvesTotal), 'mod' => $cvesCritical > 0 ? 'danger' : 'ok', 'url' => $cvesUrl];
}

echo "<div class='sentinelone-stats'>";
foreach ($cards as $card) {
   $mod     = $card['mod'] !== '' ? ' sentinelone-stat--' . $card['mod'] : '';
   $cardUrl = $card['url'] ?? '';
   $tag     = $cardUrl !== '' ? "a href='" . $h($cardUrl) . "' style='text-decoration:none'" : 'div';
   $closeTag = $cardUrl !== '' ? 'a' : 'div';
   echo "<" . $tag . " class='sentinelone-stat" . $mod . "'>";
   echo "<span>" . $h($card['label']) . "</span>";
   echo "<strong>" . $h($card['value']) . "</strong>";
   echo "<small>" . $h($card['hint']) . "</small>";
   echo "</" . $closeTag . ">";
}
echo "</div>";

// Calendario de ameacas (ultimos 90 dias)
$calDays = [];
for ($i = 89; $i >= 0; $i--) {
   $calDays[date('Y-m-d', strtotime("-{$i} days"))] = 0;
}
$calStart = date('Y-m-d 00:00:00', strtotime('-89 days'));
foreach ($DB->request([
   'SELECT' => ['detected_at'],
   'FROM'   => Threat::getTable(),
   'WHERE'  => ['NOT' => ['detected_at' => null], 'detected_at' => ['>=', $calStart]],
]) as $row) {
   $d = substr((string)($row['detected_at'] ?? ''), 0, 10);
   if (array_key_exists($d, $calDays)) {
      $calDays[$d]++;
   }
}
$calTotalThreats = array_sum($calDays);
$calMax = max(max(array_values($calDays)), 1);

$calColor = static function (int $n) use ($calMax): string {
   if ($n === 0) return '#ddd6fc';
   $pct = $n / $calMax;
   if ($pct < 0.2) return '#a78bfa';
   if ($pct < 0.5) return '#7c3aed';
   if ($pct < 0.8) return '#6b2cf5';
   return '#3d0fa0';
};
$calTextColor = static function (int $n) use ($calMax): string {
   if ($n === 0) return '#7c6fcd';
   return $n / $calMax >= 0.2 ? '#ffffff' : '#2d1f6e';
};

$monthNames = [
   1 => 'Jan', 2 => 'Fev', 3 => 'Mar', 4 => 'Abr',
   5 => 'Mai', 6 => 'Jun', 7 => 'Jul', 8 => 'Ago',
   9 => 'Set', 10 => 'Out', 11 => 'Nov', 12 => 'Dez',
];
$dayHeaders = ['D', 'S', 'T', 'Q', 'Q', 'S', 'S'];
$calMonths = [];
for ($m = 2; $m >= 0; $m--) {
   $calMonths[] = date('Y-m', strtotime("-{$m} months"));
}

echo "<section class='sentinelone-panel sentinelone-panel--wide' style='margin-bottom:24px'>";
echo "<div class='sentinelone-panel__head'>";
echo "<h3>" . __('Calendario de ameacas (ultimos 90 dias)', 'sentinelone') . "</h3>";
echo "<span style='font-size:13px;color:var(--s1-muted)'>" . $h($calTotalThreats) . " " . __('ameacas no periodo', 'sentinelone') . "</span>";
echo "</div>";
echo "<div style='background:#f5f3ff;border-radius:10px;padding:20px 24px 24px;display:flex;gap:32px;flex-wrap:wrap;align-items:flex-start'>";

foreach ($calMonths as $ym) {
   [$yr, $mo] = explode('-', $ym);
   $yr = (int)$yr; $mo = (int)$mo;
   $daysInMonth = (int)date('t', mktime(0, 0, 0, $mo, 1, $yr));
   $firstDow = (int)date('w', mktime(0, 0, 0, $mo, 1, $yr));

   echo "<div style='flex:1;min-width:220px'>";
   echo "<div style='font-weight:700;font-size:13px;color:#6b2cf5;margin-bottom:12px;letter-spacing:.4px;text-transform:uppercase'>";
   echo $h($monthNames[$mo] . ' ' . $yr);
   echo "</div>";
   echo "<div style='display:grid;grid-template-columns:repeat(7,1fr);gap:4px'>";
   foreach ($dayHeaders as $dh) {
      echo "<div style='text-align:center;font-size:10px;font-weight:700;color:#9d9ab5;padding-bottom:4px'>" . $h($dh) . "</div>";
   }
   for ($blank = 0; $blank < $firstDow; $blank++) {
      echo "<div style='border-radius:4px;aspect-ratio:1;background:#ede9fb'></div>";
   }
   for ($day = 1; $day <= $daysInMonth; $day++) {
      $dateKey = sprintf('%04d-%02d-%02d', $yr, $mo, $day);
      $cnt = $calDays[$dateKey] ?? 0;
      $bg  = $calColor($cnt);
      $fg  = $calTextColor($cnt);
      $isToday = ($dateKey === date('Y-m-d')) ? "outline:2px solid #6b2cf5;outline-offset:1px;" : '';
      $title = $h(date('d/m/Y', mktime(0,0,0,$mo,$day,$yr)) . ': ' . $cnt . ' ameaca(s)');
      echo "<div title='{$title}' style='";
      echo "background:{$bg};border-radius:4px;aspect-ratio:1;min-height:28px;display:flex;flex-direction:column;";
      echo "align-items:center;justify-content:center;cursor:default;{$isToday}";
      echo "transition:transform .15s,box-shadow .15s' ";
      echo "onmouseover=\"this.style.transform='scale(1.2)';this.style.boxShadow='0 3px 10px rgba(107,44,245,.35)'\" ";
      echo "onmouseout=\"this.style.transform='';this.style.boxShadow=''\">";
      echo "<span style='font-size:9px;color:{$fg};opacity:.8;line-height:1'>" . $h((string)$day) . "</span>";
      if ($cnt > 0) {
         echo "<strong style='font-size:11px;color:{$fg};line-height:1.2'>" . $h((string)$cnt) . "</strong>";
      }
      echo "</div>";
   }
   echo "</div></div>";
}

// Legenda
echo "<div style='display:flex;flex-direction:column;justify-content:center;gap:8px;padding:4px 0'>";
echo "<span style='font-size:11px;color:#7c6fcd;font-weight:700;text-transform:uppercase;letter-spacing:.4px'>Escala</span>";
foreach (['#ddd6fc' => 'Nenhuma', '#a78bfa' => '1–2', '#7c3aed' => '3–5', '#3d0fa0' => '6+'] as $bg => $lbl) {
   echo "<div style='display:flex;align-items:center;gap:8px'>";
   echo "<div style='width:20px;height:20px;background:{$bg};border-radius:4px;flex-shrink:0'></div>";
   echo "<span style='font-size:12px;color:#4b5563'>" . $h($lbl) . "</span>";
   echo "</div>";
}
echo "</div>";

echo "</div></section>";

// Top classificacoes de ameacas
$byClass = $stats['threats_by_classification'] ?? [];
if ($byClass !== [] && (int)($stats['threats_total'] ?? 0) > 0) {
   $totalThreats = (int)($stats['threats_total'] ?? 1);
   $barColors = ['#3d0fa0', '#6b2cf5', '#9d6cf5', '#c4b8f5', '#ddd6fc'];
   $i = 0;
   echo "<section class='sentinelone-panel sentinelone-panel--wide' style='margin-bottom:24px'>";
   echo "<div class='sentinelone-panel__head'><h3>Distribuição por Tipo de Ameaça</h3></div>";
   echo "<div style='padding:12px 20px 16px'>";
   foreach ($byClass as $class => $count) {
      $pctVal  = (int)round(($count / $totalThreats) * 100);
      $barColor = $barColors[min($i, count($barColors) - 1)];
      $textColor = $i <= 1 ? '#fff' : '#2d1f6e';
      echo "<div style='display:flex;align-items:center;gap:12px;margin-bottom:10px'>";
      echo "<span style='min-width:120px;font-size:13px;font-weight:600;color:#2d1f6e'>" . $h(ucfirst((string)$class)) . "</span>";
      echo "<div style='flex:1;background:#ede9fb;border-radius:6px;height:22px;overflow:hidden;position:relative'>";
      echo "<div style='background:{$barColor};width:{$pctVal}%;height:100%;border-radius:6px;transition:width .5s;display:flex;align-items:center;padding-left:10px'>";
      if ($pctVal >= 12) {
         echo "<span style='font-size:11px;font-weight:700;color:{$textColor}'>{$count}</span>";
      }
      echo "</div></div>";
      echo "<span style='min-width:52px;text-align:right;font-size:13px;color:#6b7280;font-weight:600'>{$pctVal}%</span>";
      if ($pctVal < 12) {
         echo "<span style='font-size:12px;font-weight:700;color:#2d1f6e;min-width:24px'>{$count}</span>";
      }
      echo "</div>";
      $i++;
   }
   echo "</div></section>";
}

// ----- Ameacas recentes (largura total) -----
echo "<section class='sentinelone-panel sentinelone-panel--wide' style='margin-bottom:1rem'>";
echo "<div class='sentinelone-panel__head'><h3>" . __('Ameacas recentes', 'sentinelone') . "</h3><a href='" . $h($threatUrl) . "'>" . __('Ver todas', 'sentinelone') . "</a></div>";
echo "<div class='table-responsive'>";
echo "<table class='table table-vcenter table-hover mb-0'>";
echo "<thead><tr>"
   . "<th>Nome da Ameaça</th>"
   . "<th>Avaliação</th>"
   . "<th>Endpoint</th>"
   . "<th>Status S1</th>"
   . "<th>Detectada em</th>"
   . "<th>Ticket GLPI</th>"
   . "</tr></thead>";
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
   echo "<tr><td colspan='6'><div class='sentinelone-empty'>" . __('Nenhuma ameaca sincronizada ainda.', 'sentinelone') . "</div></td></tr>";
}
echo "</tbody>";
echo "</table>";
echo "</div>";
echo "</section>";

// ----- Endpoints em atencao (largura total, grade de cards) -----
$attentionAgents = [];
foreach (['attention_agents', 'unlinked_agents', 'offline_agents'] as $agentListKey) {
   foreach (($stats[$agentListKey] ?? []) as $agent) {
      $attentionAgents[(int)($agent['id'] ?? 0)] = $agent;
      if (count($attentionAgents) >= 12) {
         break 2;
      }
   }
}
$attentionAgents = array_values($attentionAgents);
echo "<section class='sentinelone-panel sentinelone-panel--wide' style='margin-bottom:1rem'>";
echo "<div class='sentinelone-panel__head'><h3>" . __('Endpoints em atencao', 'sentinelone') . "</h3><a href='" . $h($agentUrl) . "'>" . __('Ver agentes', 'sentinelone') . "</a></div>";
echo "<div class='sentinelone-panel__body'>";
if ($attentionAgents === []) {
   echo "<div class='sentinelone-empty'>" . __('Nenhum endpoint critico encontrado.', 'sentinelone') . "</div>";
} else {
   echo "<div class='sentinelone-agent-grid'>";
   foreach ($attentionAgents as $agent) {
      $computerId = (int)($agent['computers_id'] ?? 0);
      $name = trim((string)($agent['computer_name'] ?? __('Endpoint sem nome', 'sentinelone')));
      echo "<div class='sentinelone-agent'>";
      if ($computerId > 0) {
         echo "<strong><a href='" . $h($rootDoc . '/front/computer.form.php?id=' . $computerId) . "'>" . $h($name) . "</a></strong>";
      } else {
         echo "<strong>" . $h($name) . "</strong>";
      }
      echo "<span>" . $h(($agent['site_name'] ?? '-') . ' / ' . ($agent['group_name'] ?? '-')) . "</span>";
      echo "<div class='mt-2 d-flex flex-wrap gap-1 align-items-center'>";
      if ((int)($agent['is_infected'] ?? 0) === 1) {
         echo "<span class='s1-badge s1-badge--critical'>" . __('infectado', 'sentinelone') . "</span>";
      }
      if ((int)($agent['is_online'] ?? 0) === 0) {
         echo "<span class='s1-badge s1-badge--muted'>" . __('offline', 'sentinelone') . "</span>";
      }
      if ($computerId === 0) {
         echo "<span class='s1-badge s1-badge--danger'>" . __('sem vinculo', 'sentinelone') . "</span>";
      }
      if ((int)($agent['is_network_quarantine'] ?? 0) === 1) {
         echo "<span class='s1-badge s1-badge--critical'>" . __('quarentena', 'sentinelone') . "</span>";
      }
      if ($hasSyncRight) {
         $isQ   = (int)($agent['is_network_quarantine'] ?? 0) === 1;
         $qAct  = $isQ ? 'unquarantine_agent' : 'quarantine_agent';
         $qIcon = $isQ ? 'ti-network' : 'ti-network-off';
         $qTip  = $isQ ? __('Reintegrar rede', 'sentinelone') : __('Isolar da rede', 'sentinelone');
         $qCls  = $isQ ? 'btn-outline-success' : 'btn-outline-danger';
         echo "<form method='post' action='" . $h($syncUrl) . "' class='d-inline ms-auto'>";
         echo "<input type='hidden' name='_glpi_csrf_token' value='" . $h(\Session::getNewCSRFToken()) . "'>";
         echo "<input type='hidden' name='action' value='" . $h($qAct) . "'>";
         echo "<input type='hidden' name='agent_id' value='" . $h($agent['id']) . "'>";
         echo "<button class='btn btn-sm " . $h($qCls) . "' type='submit' title='" . $h($qTip) . "'>";
         echo "<span class='ti " . $h($qIcon) . "'></span></button>";
         echo "</form>";
      }
      echo "</div>";
      echo "</div>";
   }
   echo "</div>";
}
echo "</div>";
echo "</section>";

$logsUrl = $rootDoc . '/plugins/sentinelone/front/logs.php';
echo "<section class='sentinelone-panel'>";
echo "<div class='sentinelone-panel__head'><h3>" . __('Ultimos logs', 'sentinelone') . "</h3><a href='" . $h($logsUrl) . "'>" . __('Ver historico', 'sentinelone') . "</a></div>";
echo "<div class='table-responsive'>";
echo "<table class='table table-vcenter table-striped mb-0'>";
echo "<thead><tr><th>" . __('Data', 'sentinelone') . "</th><th>" . __('Acao', 'sentinelone') . "</th><th>" . __('Status', 'sentinelone') . "</th><th>" . __('Itens', 'sentinelone') . "</th><th>" . __('Mensagem', 'sentinelone') . "</th></tr></thead>";
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
   echo "<tr><td colspan='5'><div class='sentinelone-empty'>" . __('Nenhum log registrado ainda.', 'sentinelone') . "</div></td></tr>";
}
echo "</tbody>";
echo "</table>";
echo "</div>";
echo "</section>";

// ----- Politicas de grupo -----
$recentGroups = $stats['recent_groups'] ?? [];
if ($recentGroups !== []) {
   $riskyGroups = array_filter($recentGroups, static fn($g) => Group::isRisky((string)($g['policy_mode'] ?? '')));
   echo "<section class='sentinelone-panel sentinelone-panel--wide' style='margin-bottom:1rem'>";
   echo "<div class='sentinelone-panel__head'>";
   echo "<h3>" . __('Politicas de grupo', 'sentinelone') . "</h3>";
   if (count($riskyGroups) > 0) {
      echo "<span class='badge bg-warning text-dark ms-2'>" . count($riskyGroups) . " " . __('nao protegidos', 'sentinelone') . "</span>";
   }
   if ($hasSyncRight) {
      echo "<form method='post' action='" . $h($syncUrl) . "' class='d-inline ms-auto'>";
      echo "<input type='hidden' name='_glpi_csrf_token' value='" . $h(\Session::getNewCSRFToken()) . "'>";
      echo "<input type='hidden' name='action' value='groups'>";
      echo "<button class='btn btn-sm btn-outline-primary' type='submit'><span class='ti ti-refresh'></span> " . __('Sync grupos', 'sentinelone') . "</button>";
      echo "</form>";
   }
   echo "</div>";
   echo "<div class='table-responsive'>";
   echo "<table class='table table-vcenter table-hover mb-0'>";
   echo "<thead><tr><th>" . __('Grupo', 'sentinelone') . "</th><th>" . __('Tipo', 'sentinelone') . "</th><th>" . __('Site', 'sentinelone') . "</th><th class='text-end'>" . __('Agentes', 'sentinelone') . "</th><th>" . __('Politica', 'sentinelone') . "</th></tr></thead>";
   echo "<tbody>";
   foreach ($recentGroups as $grp) {
      $mode = (string)($grp['policy_mode'] ?? 'unknown');
      $isRisky = Group::isRisky($mode);
      echo "<tr" . ($isRisky ? " style='background:rgba(220,53,69,.04)'" : '') . ">";
      echo "<td class='fw-semibold'>" . $h((string)($grp['name'] ?? '')) . "</td>";
      echo "<td><small class='text-muted'>" . $h(ucfirst((string)($grp['type'] ?? ''))) . "</small></td>";
      echo "<td>" . $h((string)($grp['site_name'] ?? '-')) . "</td>";
      echo "<td class='text-end'>" . $h((string)(int)($grp['agent_count'] ?? 0)) . "</td>";
      echo "<td>" . Group::getModeBadge($mode) . ($mode === 'unknown' ? "<small class='text-muted ms-1'>" . __('nao sincronizado', 'sentinelone') . "</small>" : '') . "</td>";
      echo "</tr>";
   }
   echo "</tbody>";
   echo "</table>";
   echo "</div>";
   echo "</section>";
} elseif (Profile::hasSyncRight()) {
   echo "<div class='sentinelone-empty' style='margin-bottom:1rem'>";
   echo "<span class='ti ti-sitemap'></span>";
   echo __('Nenhum grupo sincronizado. Use Sincronizar > Grupos para buscar os grupos da console SentinelOne.', 'sentinelone');
   echo "</div>";
}

// ----- Compliance Panel: agentes em modo risky (Detect/None) -----
$complianceAgents = [];
foreach ($DB->request([
   'FROM'  => Agent::getTable(),
   'WHERE' => ['NOT' => ['group_name' => null]],
   'ORDER' => ['is_infected DESC', 'is_online ASC', 'computer_name ASC'],
   'LIMIT' => 50,
]) as $ag) {
   // Busca o policy_mode do grupo correspondente
   $grpName = (string)($ag['group_name'] ?? '');
   if ($grpName === '') {
      continue;
   }
   $grpRow = null;
   foreach ($DB->request([
      'SELECT' => ['policy_mode'],
      'FROM'   => Group::getTable(),
      'WHERE'  => ['name' => $grpName],
      'LIMIT'  => 1,
   ]) as $g) {
      $grpRow = $g;
   }
   if ($grpRow !== null && Group::isRisky((string)($grpRow['policy_mode'] ?? ''))) {
      $ag['policy_mode'] = $grpRow['policy_mode'];
      $complianceAgents[] = $ag;
   }
}

if ($complianceAgents !== []) {
   echo "<section class='sentinelone-panel sentinelone-panel--wide' style='margin-bottom:1rem'>";
   echo "<div class='sentinelone-panel__head'>";
   echo "<h3>" . __('Compliance: endpoints sem protecao plena', 'sentinelone') . "</h3>";
   echo "<span class='badge bg-danger'>" . count($complianceAgents) . " " . __('endpoints', 'sentinelone') . "</span>";
   echo "</div>";
   echo "<div class='table-responsive'>";
   echo "<table class='table table-vcenter table-hover mb-0'>";
   echo "<thead><tr><th>" . __('Endpoint', 'sentinelone') . "</th><th>" . __('Grupo', 'sentinelone') . "</th><th>" . __('Politica', 'sentinelone') . "</th><th>" . __('Status', 'sentinelone') . "</th><th>" . __('Versao agente', 'sentinelone') . "</th><th>" . __('Ultimo contato', 'sentinelone') . "</th><th></th></tr></thead>";
   echo "<tbody>";
   foreach ($complianceAgents as $ag) {
      $cId   = (int)($ag['computers_id'] ?? 0);
      $agUrl = $rootDoc . '/plugins/sentinelone/front/agent.form.php?id=' . (int)$ag['id'];
      echo "<tr style='background:rgba(220,53,69,.04)'>";
      echo "<td class='fw-semibold'>";
      if ($cId > 0) {
         echo "<a href='" . $h($rootDoc . '/front/computer.form.php?id=' . $cId) . "'>" . $h($ag['computer_name'] ?? '-') . "</a>";
      } else {
         echo "<a href='" . $h($agUrl) . "'>" . $h($ag['computer_name'] ?? '-') . "</a>";
      }
      echo "</td>";
      echo "<td>" . $h($ag['group_name'] ?? '-') . "</td>";
      echo "<td>" . Group::getModeBadge((string)($ag['policy_mode'] ?? '')) . "</td>";
      $statuses = [];
      if ((int)($ag['is_infected'] ?? 0) === 1) {
         $statuses[] = "<span class='s1-badge s1-badge--critical'>infectado</span>";
      }
      if ((int)($ag['is_online'] ?? 0) === 0) {
         $statuses[] = "<span class='s1-badge s1-badge--muted'>offline</span>";
      }
      if ((int)($ag['is_network_quarantine'] ?? 0) === 1) {
         $statuses[] = "<span class='s1-badge s1-badge--critical'>quarentena</span>";
      }
      echo "<td>" . ($statuses !== [] ? implode(' ', $statuses) : "<span class='text-muted'>-</span>") . "</td>";
      echo "<td><small>" . $h($ag['agent_version'] ?? '-') . "</small></td>";
      echo "<td><small>" . $h($ag['last_active_at'] ?? '-') . "</small></td>";
      echo "<td><a href='" . $h($agUrl) . "' class='btn btn-xs btn-outline-secondary'><span class='ti ti-eye'></span></a></td>";
      echo "</tr>";
   }
   echo "</tbody>";
   echo "</table>";
   echo "</div>";
   echo "</section>";
}

echo "</div>";

\Html::footer();

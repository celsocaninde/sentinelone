<?php

use GlpiPlugin\Sentinelone\Agent;
use GlpiPlugin\Sentinelone\Profile;
use GlpiPlugin\Sentinelone\Sync;

include('../../../inc/includes.php');

\Session::checkRight(Profile::RIGHT_READ, READ);

global $CFG_GLPI;

$h = static fn($value): string => htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$rootDoc    = (string)($CFG_GLPI['root_doc'] ?? '');
$dashboardUrl = $rootDoc . '/plugins/sentinelone/front/dashboard.php';
$agentUrl     = $rootDoc . '/plugins/sentinelone/front/agent.php';
$syncUrl      = $rootDoc . '/plugins/sentinelone/front/sync.form.php';
$hasSyncRight = Profile::hasSyncRight();

$tab = $_GET['tab'] ?? 'unlinked';
$tab = in_array($tab, ['unlinked', 'unprotected'], true) ? $tab : 'unlinked';

$limitUnlinked    = max(10, min(200, (int)($_GET['limit_unlinked'] ?? 80)));
$limitUnprotected = max(10, min(500, (int)($_GET['limit_unprotected'] ?? 100)));

// Handle CSV export before any HTML output
if (isset($_GET['export']) && $_GET['export'] === 'csv') {
   $csvLimit = max(10, min(5000, (int)($_GET['csv_limit'] ?? 5000)));
   header('Content-Type: text/csv; charset=UTF-8');
   header('Content-Disposition: attachment; filename="sentinelone-' . $tab . '-' . date('Ymd-His') . '.csv"');
   header('Cache-Control: no-cache, no-store, must-revalidate');
   $out = fopen('php://output', 'w');
   fprintf($out, "\xEF\xBB\xBF"); // UTF-8 BOM for Excel
   if ($tab === 'unlinked') {
      fputcsv($out, ['Endpoint', 'ID SentinelOne', 'Serial', 'UUID', 'MAC', 'IP', 'OS', 'Site', 'Grupo', 'Versao agente', 'Online', 'Infectado', 'Ultimo contato'], ';');
      $exportDiag = Agent::getUnlinkedDiagnostics($csvLimit);
      foreach ($exportDiag['rows'] as $row) {
         $a = $row['agent'];
         fputcsv($out, [
            $a['computer_name'] ?? '',
            $a['sentinelone_id'] ?? '',
            $a['serial'] ?? '',
            $a['uuid'] ?? '',
            $a['mac'] ?? '',
            $a['ip'] ?? '',
            $a['os_name'] ?? '',
            $a['site_name'] ?? '',
            $a['group_name'] ?? '',
            $a['agent_version'] ?? '',
            (int)($a['is_online'] ?? 0) ? 'Sim' : 'Nao',
            (int)($a['is_infected'] ?? 0) ? 'Sim' : 'Nao',
            $a['last_active_at'] ?? '',
         ], ';');
      }
   } else {
      fputcsv($out, ['Computador', 'ID GLPI', 'Serial', 'Entidade ID', 'Ultima modificacao'], ';');
      $exportReport = Agent::getUnprotectedComputers($csvLimit);
      foreach ($exportReport['rows'] as $row) {
         fputcsv($out, [
            $row['name'] ?? '',
            $row['id'] ?? '',
            $row['serial'] ?? '',
            $row['entities_id'] ?? '',
            $row['date_mod'] ?? '',
         ], ';');
      }
   }
   fclose($out);
   exit;
}

$diagnostics = Agent::getUnlinkedDiagnostics($limitUnlinked);
$report      = Agent::getUnprotectedComputers($limitUnprotected);

$unlinkedSummary    = $diagnostics['summary'];
$unprotectedSummary = $report['summary'];

$statusBadge = static function (array $summary) use ($h): string {
   $status  = (string)($summary['status'] ?? 'missing');
   $message = (string)($summary['message'] ?? '');
   $class   = match ($status) {
      'candidate' => 'success',
      'inventory' => 'warning',
      default     => 'secondary',
   };

   return "<span class='badge bg-{$class}'>" . $h($message) . "</span>";
};

$formatDate = static function ($value) use ($h): string {
   $value = trim((string)$value);
   return $value !== '' ? $h($value) : '-';
};

\Html::header('Cobertura SentinelOne', $_SERVER['PHP_SELF'], 'plugins', 'sentinelone');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";

echo "<div class='sentinelone-diagnostic'>";

// Hero
echo "<div class='sentinelone-diagnostic__hero'>";
echo "<div class='s1-hero__brand'>";
echo "<span class='s1-logo'><span class='ti ti-shield-check'></span></span>";
echo "<div>";
echo "<div class='sentinelone-dashboard__eyebrow'>SentinelOne</div>";
echo "<h2>" . __('Cobertura de Agentes', 'sentinelone') . "</h2>";
echo "<p>" . __('Agentes sem vinculo GLPI e computadores sem agente SentinelOne.', 'sentinelone') . "</p>";
echo "</div>";
echo "</div>";
echo "<div class='sentinelone-diagnostic__actions'>";
echo "<a class='btn btn-outline-secondary' href='" . $h($dashboardUrl) . "'><span class='ti ti-dashboard'></span>" . __('Dashboard', 'sentinelone') . "</a>";
echo "<a class='btn btn-outline-secondary' href='" . $h($agentUrl) . "'><span class='ti ti-devices-pc'></span>" . __('Agentes', 'sentinelone') . "</a>";
echo "</div>";
echo "</div>";

// Stats bar
$totalLinked      = (int)$unprotectedSummary['agents_linked'];
$totalAgents      = (int)$unlinkedSummary['agents_total'];
$totalUnlinked    = (int)$unlinkedSummary['agents_unlinked'];
$totalUnprotected = (int)$unprotectedSummary['unprotected_total'];
$totalComputers   = (int)$unprotectedSummary['computers_total'];

echo "<div class='sentinelone-diagnostic__stats'>";
echo "<div class='sentinelone-diagnostic__stat'><span>" . __('Agentes SentinelOne', 'sentinelone') . "</span><strong>" . $h($totalAgents) . "</strong></div>";
echo "<div class='sentinelone-diagnostic__stat'><span>" . __('Vinculados ao GLPI', 'sentinelone') . "</span><strong>" . $h($totalLinked) . "</strong></div>";
echo "<div class='sentinelone-diagnostic__stat'><span>" . __('Sem vinculo', 'sentinelone') . "</span><strong style='color:#b5179e'>" . $h($totalUnlinked) . "</strong></div>";
echo "<div class='sentinelone-diagnostic__stat'><span>" . __('Computadores GLPI', 'sentinelone') . "</span><strong>" . $h($totalComputers) . "</strong></div>";
echo "<div class='sentinelone-diagnostic__stat'><span>" . __('Sem agente S1', 'sentinelone') . "</span><strong style='color:#d6336c'>" . $h($totalUnprotected) . "</strong></div>";
echo "</div>";

// Tabs
$baseUrl = $rootDoc . '/plugins/sentinelone/front/coverage.php';
echo "<ul class='nav nav-tabs mb-3' style='margin-top:16px'>";
echo "<li class='nav-item'><a class='nav-link " . ($tab === 'unlinked' ? 'active' : '') . "' href='" . $h($baseUrl . '?tab=unlinked') . "'><span class='ti ti-stethoscope'></span>&nbsp;" . __('Agentes sem vinculo', 'sentinelone') . " <span class='badge bg-secondary ms-1'>" . $h($totalUnlinked) . "</span></a></li>";
echo "<li class='nav-item'><a class='nav-link " . ($tab === 'unprotected' ? 'active' : '') . "' href='" . $h($baseUrl . '?tab=unprotected') . "'><span class='ti ti-shield-off'></span>&nbsp;" . __('Computadores sem agente', 'sentinelone') . " <span class='badge bg-secondary ms-1'>" . $h($totalUnprotected) . "</span></a></li>";
echo "</ul>";

// --- Tab: Agentes sem vinculo ---
if ($tab === 'unlinked') {
   echo "<div class='alert alert-info'>" . sprintf(__('Mostrando ate %d agentes sem vinculo. O plugin tenta casar por serial, UUID, nome completo, nome curto e MAC durante a sincronizacao.', 'sentinelone'), $diagnostics['limit']) . "</div>";

   echo "<section class='sentinelone-diagnostic__panel'>";
   echo "<div class='sentinelone-diagnostic__panel-head'>";
   echo "<h3>" . __('Agentes SentinelOne sem computador associado', 'sentinelone') . "</h3>";
   echo "<div class='d-flex align-items-center gap-2'>";
   echo "<a class='btn btn-outline-secondary btn-sm' href='" . $h($baseUrl . '?tab=unlinked&export=csv') . "'><span class='ti ti-file-type-csv'></span> CSV</a>";
   if ($hasSyncRight) {
      echo "<form method='post' action='" . $h($syncUrl) . "' class='d-inline'>";
      echo "<input type='hidden' name='_glpi_csrf_token' value='" . $h(\Session::getNewCSRFToken()) . "'>";
      echo "<button class='btn btn-outline-success btn-sm' type='submit' name='action' value='relink' title='" . __('Tenta vincular todos os agentes sem link usando serial, UUID, nome e MAC', 'sentinelone') . "'>";
      echo "<span class='ti ti-link'></span> " . __('Re-vincular todos', 'sentinelone');
      echo "</button></form>";
   }
   echo "<form method='get' class='d-flex align-items-center gap-2'>";
   echo "<input type='hidden' name='tab' value='unlinked'>";
   echo "<label class='text-muted' for='sentinelone-limit-unlinked'>" . __('Limite', 'sentinelone') . "</label>";
   echo "<input id='sentinelone-limit-unlinked' class='form-control' type='number' min='10' max='200' name='limit_unlinked' value='" . $h($limitUnlinked) . "' style='width:110px'>";
   echo "<button class='btn btn-primary' type='submit'><span class='ti ti-refresh'></span>" . __('Atualizar', 'sentinelone') . "</button>";
   echo "</form>";
   echo "</div>";
   echo "</div>";
   $colCount = $hasSyncRight ? 5 : 4;
   echo "<div class='table-responsive'>";
   echo "<table class='table table-vcenter table-hover mb-0'>";
   echo "<thead><tr>";
   echo "<th>" . __('Endpoint', 'sentinelone') . "</th>";
   echo "<th>" . __('Identificadores', 'sentinelone') . "</th>";
   echo "<th>" . __('Diagnostico', 'sentinelone') . "</th>";
   echo "<th>" . __('Candidatos GLPI', 'sentinelone') . "</th>";
   if ($hasSyncRight) {
      echo "<th>" . __('Vincular manualmente', 'sentinelone') . "</th>";
   }
   echo "</tr></thead>";
   echo "<tbody>";

   foreach ($diagnostics['rows'] as $row) {
      $agent   = $row['agent'];
      $agentId = (int)($agent['id'] ?? 0);
      echo "<tr>";
      echo "<td><strong>" . $h($agent['computer_name'] ?? __('Endpoint sem nome', 'sentinelone')) . "</strong>";
      echo "<div class='text-muted'>" . $h(($agent['site_name'] ?? '-') . ' / ' . ($agent['group_name'] ?? '-')) . "</div></td>";
      echo "<td><div class='sentinelone-identifiers'>";
      echo "<span>" . __('Serial', 'sentinelone') . ": <code>" . $h($agent['serial'] ?? '-') . "</code></span>";
      echo "<span>" . __('UUID', 'sentinelone') . ": <code>" . $h($agent['uuid'] ?? '-') . "</code></span>";
      echo "<span>" . __('MAC', 'sentinelone') . ": <code>" . $h($agent['mac'] ?? '-') . "</code></span>";
      echo "<span>" . __('Ultimo contato', 'sentinelone') . ": <code>" . $h($agent['last_active_at'] ?? '-') . "</code></span>";
      echo "</div></td>";
      echo "<td>" . $statusBadge($row['summary']) . "</td>";
      echo "<td><div class='sentinelone-checks'>";
      foreach ($row['checks'] as $check) {
         if ($check['candidates'] === []) {
            continue;
         }
         echo "<div class='sentinelone-check'>";
         echo "<strong>" . $h($check['label']) . ": <code>" . $h($check['value'] !== '' ? $check['value'] : '-') . "</code></strong>";
         echo "<div class='sentinelone-candidates'>";
         foreach ($check['candidates'] as $candidate) {
            echo "<a class='badge bg-success text-white' href='" . $h($rootDoc . '/front/computer.form.php?id=' . (int)$candidate['id']) . "'>";
            echo "#" . $h($candidate['id']) . " " . $h($candidate['name']);
            echo "</a>";
         }
         echo "</div></div>";
      }
      echo "</div></td>";
      if ($hasSyncRight) {
         echo "<td>";
         echo "<form method='post' action='" . $h($syncUrl) . "' class='d-flex align-items-center gap-1'>";
         echo "<input type='hidden' name='_glpi_csrf_token' value='" . $h(\Session::getNewCSRFToken()) . "'>";
         echo "<input type='hidden' name='action' value='link_agent'>";
         echo "<input type='hidden' name='agent_id' value='" . $agentId . "'>";
         echo "<input type='number' name='computers_id' placeholder='ID' class='form-control form-control-sm' style='width:80px' min='1' required>";
         echo "<button type='submit' class='btn btn-sm btn-outline-primary' title='" . __('Vincular ao computador GLPI com esse ID', 'sentinelone') . "'><span class='ti ti-link'></span></button>";
         echo "</form>";
         echo "</td>";
      }
      echo "</tr>";
   }

   if ($diagnostics['rows'] === []) {
      echo "<tr><td colspan='" . $colCount . "' class='text-muted text-center p-4'>" . __('Nenhum agente sem vinculo encontrado.', 'sentinelone') . "</td></tr>";
   }

   echo "</tbody></table></div></section>";
}

// --- Tab: Computadores sem agente ---
if ($tab === 'unprotected') {
   if ((int)$unprotectedSummary['agents_total'] === 0) {
      echo "<div class='alert alert-warning'>" . __('Nenhum agente SentinelOne sincronizado ainda. Sincronize os agentes antes de usar este relatorio.', 'sentinelone') . "</div>";
   } else {
      echo "<div class='alert alert-info'>" . sprintf(__('Mostrando ate %d computadores ativos sem agente SentinelOne, nas entidades visiveis para voce.', 'sentinelone'), $report['limit']) . "</div>";
   }

   echo "<section class='sentinelone-diagnostic__panel'>";
   echo "<div class='sentinelone-diagnostic__panel-head'>";
   echo "<h3>" . __('Computadores desprotegidos', 'sentinelone') . "</h3>";
   echo "<div class='d-flex align-items-center gap-2'>";
   echo "<a class='btn btn-outline-secondary btn-sm' href='" . $h($baseUrl . '?tab=unprotected&export=csv') . "'><span class='ti ti-file-type-csv'></span> CSV</a>";
   echo "<form method='get' class='d-flex align-items-center gap-2'>";
   echo "<input type='hidden' name='tab' value='unprotected'>";
   echo "<label class='text-muted' for='sentinelone-limit-unprotected'>" . __('Limite', 'sentinelone') . "</label>";
   echo "<input id='sentinelone-limit-unprotected' class='form-control' type='number' min='10' max='500' name='limit_unprotected' value='" . $h($limitUnprotected) . "' style='width:110px'>";
   echo "<button class='btn btn-primary' type='submit'><span class='ti ti-refresh'></span>" . __('Atualizar', 'sentinelone') . "</button>";
   echo "</form>";
   echo "</div>";
   echo "</div>";
   echo "<div class='table-responsive'>";
   echo "<table class='table table-vcenter table-hover mb-0'>";
   echo "<thead><tr><th>" . __('Computador', 'sentinelone') . "</th><th>" . __('Serial', 'sentinelone') . "</th><th>" . __('Entidade', 'sentinelone') . "</th><th>" . __('Ultima atualizacao', 'sentinelone') . "</th><th></th></tr></thead>";
   echo "<tbody>";

   foreach ($report['rows'] as $row) {
      $computerId  = (int)($row['id'] ?? 0);
      $name        = trim((string)($row['name'] ?? '')) !== '' ? (string)$row['name'] : __('Computador', 'sentinelone') . ' #' . $computerId;
      $entityName  = \Dropdown::getDropdownName('glpi_entities', (int)($row['entities_id'] ?? 0));
      $computerUrl = $rootDoc . '/front/computer.form.php?id=' . $computerId;

      echo "<tr>";
      echo "<td><a href='" . $h($computerUrl) . "'>" . $h($name) . "</a></td>";
      echo "<td><code>" . $h(trim((string)($row['serial'] ?? '')) !== '' ? (string)$row['serial'] : '-') . "</code></td>";
      echo "<td>" . $h($entityName) . "</td>";
      echo "<td>" . $formatDate($row['date_mod'] ?? '') . "</td>";
      echo "<td><a class='btn btn-sm btn-outline-secondary' href='" . $h($computerUrl) . "'><span class='ti ti-external-link'></span></a></td>";
      echo "</tr>";
   }

   if ($report['rows'] === []) {
      echo "<tr><td colspan='5' class='text-muted text-center p-4'>" . __('Nenhum computador sem agente encontrado.', 'sentinelone') . "</td></tr>";
   }

   echo "</tbody></table></div></section>";
}

echo "</div>";

\Html::footer();

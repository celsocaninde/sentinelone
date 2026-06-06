<?php

use GlpiPlugin\Sentinelone\Log;
use GlpiPlugin\Sentinelone\Profile;

include('../../../inc/includes.php');

\Session::checkRight(Profile::RIGHT_READ, READ);

global $CFG_GLPI;

$h = static fn($value): string => htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$rootDoc     = (string)($CFG_GLPI['root_doc'] ?? '');
$dashboardUrl = $rootDoc . '/plugins/sentinelone/front/dashboard.php';
$selfUrl      = $rootDoc . '/plugins/sentinelone/front/logs.php';

$perPage   = 100;
$page      = max(1, (int)($_GET['page'] ?? 1));
$offset    = ($page - 1) * $perPage;
$filterAction = trim((string)($_GET['action'] ?? ''));
$filterStatus = trim((string)($_GET['status'] ?? ''));

$filters = [];
if ($filterAction !== '') {
   $filters['action'] = $filterAction;
}
if ($filterStatus !== '') {
   $filters['status'] = $filterStatus;
}

$total   = Log::countAll($filters);
$rows    = Log::getPaginated($perPage, $offset, $filters);
$actions = Log::getActions();
$pages   = max(1, (int)ceil($total / $perPage));

$statusClass = static function ($status): string {
   return match (strtolower(trim((string)$status))) {
      'ok', 'success', 'synced' => 'success',
      'error', 'failed'         => 'danger',
      'skipped', 'warning'      => 'warning',
      default                   => 'secondary',
   };
};

$buildPageUrl = static function (int $p) use ($selfUrl, $filterAction, $filterStatus): string {
   $params = ['page' => $p];
   if ($filterAction !== '') {
      $params['action'] = $filterAction;
   }
   if ($filterStatus !== '') {
      $params['status'] = $filterStatus;
   }
   return $selfUrl . '?' . http_build_query($params);
};

\Html::header('SentinelOne — Logs', $_SERVER['PHP_SELF'], 'plugins', 'sentinelone');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";

echo "<div class='sentinelone-dashboard'>";

// Hero
echo "<div class='sentinelone-dashboard__hero'>";
echo "<div class='s1-hero__brand'>";
echo "<span class='s1-logo'><span class='ti ti-list-details'></span></span>";
echo "<div>";
echo "<div class='sentinelone-dashboard__eyebrow'>SentinelOne</div>";
echo "<h2>" . __('Historico de Sincronizacoes', 'sentinelone') . "</h2>";
echo "<p>" . __('Registro completo de todas as execucoes das tarefas agendadas do plugin.', 'sentinelone') . "</p>";
echo "</div>";
echo "</div>";
echo "<div class='sentinelone-dashboard__actions'>";
echo "<a class='btn btn-outline-secondary' href='" . $h($dashboardUrl) . "'><span class='ti ti-dashboard'></span>" . __('Dashboard', 'sentinelone') . "</a>";
echo "</div>";
echo "</div>";

// Filters
echo "<form method='get' action='" . $h($selfUrl) . "' class='d-flex flex-wrap align-items-center gap-2 mb-3' style='background:#f8f9fa;padding:12px 16px;border-radius:8px;border:1px solid #e3e1ee'>";
echo "<label class='text-muted fw-semibold mb-0'>" . __('Filtros', 'sentinelone') . ":</label>";
echo "<select name='action' class='form-select' style='width:180px'>";
echo "<option value=''>" . __('Todas as acoes', 'sentinelone') . "</option>";
foreach ($actions as $act) {
   $sel = $filterAction === $act ? " selected" : '';
   echo "<option value='" . $h($act) . "'{$sel}>" . $h($act) . "</option>";
}
echo "</select>";
$statusOptions = ['ok' => 'OK', 'error' => 'Erro', 'skipped' => 'Ignorado', 'warning' => 'Aviso'];
echo "<select name='status' class='form-select' style='width:160px'>";
echo "<option value=''>" . __('Todos os status', 'sentinelone') . "</option>";
foreach ($statusOptions as $val => $label) {
   $sel = $filterStatus === $val ? " selected" : '';
   echo "<option value='" . $h($val) . "'{$sel}>" . $h($label) . "</option>";
}
echo "</select>";
echo "<button class='btn btn-primary' type='submit'><span class='ti ti-filter'></span> " . __('Filtrar', 'sentinelone') . "</button>";
if ($filterAction !== '' || $filterStatus !== '') {
   echo "<a class='btn btn-outline-secondary' href='" . $h($selfUrl) . "'><span class='ti ti-x'></span> " . __('Limpar', 'sentinelone') . "</a>";
}
echo "<span class='text-muted ms-auto'>" . $h($total) . " " . __('registros', 'sentinelone') . "</span>";
echo "</form>";

// Table
echo "<section class='sentinelone-panel sentinelone-panel--wide'>";
echo "<div class='table-responsive'>";
echo "<table class='table table-vcenter table-striped mb-0'>";
echo "<thead><tr>";
echo "<th>" . __('Data', 'sentinelone') . "</th>";
echo "<th>" . __('Acao', 'sentinelone') . "</th>";
echo "<th>" . __('Status', 'sentinelone') . "</th>";
echo "<th class='text-end'>" . __('Itens', 'sentinelone') . "</th>";
echo "<th>" . __('Mensagem', 'sentinelone') . "</th>";
echo "</tr></thead>";
echo "<tbody>";

if ($rows === []) {
   echo "<tr><td colspan='5'><div class='sentinelone-empty'>" . __('Nenhum log encontrado para os filtros selecionados.', 'sentinelone') . "</div></td></tr>";
} else {
   foreach ($rows as $row) {
      $status = (string)($row['status'] ?? '');
      $cls    = $statusClass($status);
      $count  = (int)($row['items_count'] ?? 0);
      echo "<tr>";
      echo "<td style='white-space:nowrap'>" . $h(trim((string)($row['date_creation'] ?? ''))) . "</td>";
      echo "<td><code>" . $h((string)($row['action'] ?? '')) . "</code></td>";
      echo "<td><span class='badge bg-" . $h($cls) . "'>" . $h($status) . "</span></td>";
      echo "<td class='text-end'>" . ($count > 0 ? $h((string)$count) : '<span class="text-muted">—</span>') . "</td>";
      echo "<td class='text-muted'>" . $h(trim((string)($row['message'] ?? ''))) . "</td>";
      echo "</tr>";
   }
}

echo "</tbody>";
echo "</table>";
echo "</div>";
echo "</section>";

// Pagination
if ($pages > 1) {
   echo "<nav class='d-flex justify-content-center mt-3'>";
   echo "<ul class='pagination'>";
   if ($page > 1) {
      echo "<li class='page-item'><a class='page-link' href='" . $h($buildPageUrl($page - 1)) . "'>&laquo;</a></li>";
   }
   $start = max(1, $page - 3);
   $end   = min($pages, $page + 3);
   for ($i = $start; $i <= $end; $i++) {
      $active = $i === $page ? " active" : '';
      echo "<li class='page-item{$active}'><a class='page-link' href='" . $h($buildPageUrl($i)) . "'>" . $h((string)$i) . "</a></li>";
   }
   if ($page < $pages) {
      echo "<li class='page-item'><a class='page-link' href='" . $h($buildPageUrl($page + 1)) . "'>&raquo;</a></li>";
   }
   echo "</ul></nav>";
}

echo "</div>";

\Html::footer();

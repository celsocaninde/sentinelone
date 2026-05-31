<?php

use GlpiPlugin\Sentinelone\Agent;
use GlpiPlugin\Sentinelone\Profile;

include('../../../inc/includes.php');

\Session::checkRight(Profile::RIGHT_READ, READ);

global $CFG_GLPI;

$h = static fn($value): string => htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$rootDoc = (string)($CFG_GLPI['root_doc'] ?? '');
$dashboardUrl = $rootDoc . '/plugins/sentinelone/front/dashboard.php';
$diagnosticUrl = $rootDoc . '/plugins/sentinelone/front/unlinked.php';
$limit = max(10, min(500, (int)($_GET['limit'] ?? 100)));
$report = Agent::getUnprotectedComputers($limit);
$summary = $report['summary'];

$formatDate = static function ($value) use ($h): string {
   $value = trim((string)$value);
   return $value !== '' ? $h($value) : '-';
};

\Html::header('Endpoints sem agente SentinelOne', $_SERVER['PHP_SELF'], 'plugins', 'sentinelone');

echo "<div class='sentinelone-diagnostic'>";
echo "<div class='sentinelone-diagnostic__hero'>";
echo "<div class='s1-hero__brand'>";
echo "<span class='s1-logo'><span class='ti ti-shield-off'></span></span>";
echo "<div>";
echo "<div class='sentinelone-dashboard__eyebrow'>SentinelOne</div>";
echo "<h2>Endpoints sem agente SentinelOne</h2>";
echo "<p>Computadores ativos no GLPI que nao possuem um agente SentinelOne vinculado.</p>";
echo "</div>";
echo "</div>";
echo "<div class='sentinelone-diagnostic__actions'>";
echo "<a class='btn btn-outline-secondary' href='" . $h($dashboardUrl) . "'><span class='ti ti-dashboard'></span>Dashboard</a>";
echo "<a class='btn btn-outline-secondary' href='" . $h($diagnosticUrl) . "'><span class='ti ti-stethoscope'></span>Agentes sem vinculo</a>";
echo "</div>";
echo "</div>";

$stats = [
   ['label' => 'Computadores GLPI', 'value' => $summary['computers_total']],
   ['label' => 'Com agente', 'value' => $summary['agents_linked']],
   ['label' => 'Sem agente', 'value' => $summary['unprotected_total']],
   ['label' => 'Agentes SentinelOne', 'value' => $summary['agents_total']],
];

echo "<div class='sentinelone-diagnostic__stats'>";
foreach ($stats as $stat) {
   echo "<div class='sentinelone-diagnostic__stat'>";
   echo "<span>" . $h($stat['label']) . "</span>";
   echo "<strong>" . $h($stat['value']) . "</strong>";
   echo "</div>";
}
echo "</div>";

if ((int)$summary['agents_total'] === 0) {
   echo "<div class='alert alert-warning'>Nenhum agente SentinelOne foi sincronizado ainda. Sincronize os agentes antes de usar este relatorio, senao todos os computadores aparecerao como sem agente.</div>";
} else {
   echo "<div class='alert alert-info'>Mostrando ate " . $h($report['limit']) . " computadores ativos sem agente SentinelOne, nas entidades visiveis para voce.</div>";
}

echo "<section class='sentinelone-diagnostic__panel'>";
echo "<div class='sentinelone-diagnostic__panel-head'>";
echo "<h3>Computadores desprotegidos</h3>";
echo "<form method='get' class='d-flex align-items-center gap-2'>";
echo "<label class='text-muted' for='sentinelone-limit'>Limite</label>";
echo "<input id='sentinelone-limit' class='form-control' type='number' min='10' max='500' name='limit' value='" . $h($report['limit']) . "' style='width: 110px'>";
echo "<button class='btn btn-primary' type='submit'><span class='ti ti-refresh'></span>Atualizar</button>";
echo "</form>";
echo "</div>";
echo "<div class='table-responsive'>";
echo "<table class='table table-vcenter table-hover mb-0'>";
echo "<thead><tr><th>Computador</th><th>Serial</th><th>Entidade</th><th>Ultima atualizacao</th><th></th></tr></thead>";
echo "<tbody>";

foreach ($report['rows'] as $row) {
   $computerId = (int)($row['id'] ?? 0);
   $name = trim((string)($row['name'] ?? '')) !== '' ? (string)$row['name'] : 'Computador #' . $computerId;
   $entityName = \Dropdown::getDropdownName('glpi_entities', (int)($row['entities_id'] ?? 0));
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
   echo "<tr><td colspan='5' class='text-muted text-center p-4'>Nenhum computador sem agente encontrado.</td></tr>";
}

echo "</tbody>";
echo "</table>";
echo "</div>";
echo "</section>";
echo "</div>";

\Html::footer();

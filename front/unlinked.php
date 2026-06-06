<?php

include('../../../inc/includes.php');

\Html::redirect(\Plugin::getWebDir('sentinelone') . '/front/coverage.php?tab=unlinked');
exit;

global $CFG_GLPI;

$h = static fn($value): string => htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$rootDoc = (string)($CFG_GLPI['root_doc'] ?? '');
$dashboardUrl = $rootDoc . '/plugins/sentinelone/front/dashboard.php';
$agentUrl = $rootDoc . '/plugins/sentinelone/front/agent.php';
$limit = max(10, min(200, (int)($_GET['limit'] ?? 80)));
$diagnostics = Agent::getUnlinkedDiagnostics($limit);
$summary = $diagnostics['summary'];

$statusBadge = static function (array $summary) use ($h): string {
   $status = (string)($summary['status'] ?? 'missing');
   $message = (string)($summary['message'] ?? '');
   $class = match ($status) {
      'candidate' => 'success',
      'inventory' => 'warning',
      default => 'secondary',
   };

   return "<span class='badge bg-{$class}'>" . $h($message) . "</span>";
};

\Html::header('Diagnostico SentinelOne', $_SERVER['PHP_SELF'], 'plugins', 'sentinelone');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";


echo "<div class='sentinelone-diagnostic'>";
echo "<div class='sentinelone-diagnostic__hero'>";
echo "<div class='s1-hero__brand'>";
echo "<span class='s1-logo'><span class='ti ti-stethoscope'></span></span>";
echo "<div>";
echo "<div class='sentinelone-dashboard__eyebrow'>SentinelOne</div>";
echo "<h2>Diagnostico de vinculo GLPI</h2>";
echo "<p>Agentes SentinelOne sem computador associado e possiveis candidatos no inventario GLPI.</p>";
echo "</div>";
echo "</div>";
echo "<div class='sentinelone-diagnostic__actions'>";
echo "<a class='btn btn-outline-secondary' href='" . $h($dashboardUrl) . "'><span class='ti ti-dashboard'></span>Dashboard</a>";
echo "<a class='btn btn-outline-secondary' href='" . $h($agentUrl) . "'><span class='ti ti-devices-pc'></span>Agentes</a>";
echo "</div>";
echo "</div>";

$stats = [
   ['label' => 'Agentes', 'value' => $summary['agents_total']],
   ['label' => 'Sem vinculo', 'value' => $summary['agents_unlinked']],
   ['label' => 'Computadores GLPI', 'value' => $summary['glpi_computers']],
   ['label' => 'Com nome', 'value' => $summary['agents_with_name']],
   ['label' => 'Com serial', 'value' => $summary['agents_with_serial']],
   ['label' => 'Com MAC', 'value' => $summary['agents_with_mac']],
];

echo "<div class='sentinelone-diagnostic__stats'>";
foreach ($stats as $stat) {
   echo "<div class='sentinelone-diagnostic__stat'>";
   echo "<span>" . $h($stat['label']) . "</span>";
   echo "<strong>" . $h($stat['value']) . "</strong>";
   echo "</div>";
}
echo "</div>";

echo "<div class='alert alert-info'>";
echo "Mostrando ate " . $h($diagnostics['limit']) . " agentes sem vinculo. O plugin tenta casar por serial, UUID, nome completo, nome curto e MAC durante a sincronizacao.";
echo "</div>";

echo "<section class='sentinelone-diagnostic__panel'>";
echo "<div class='sentinelone-diagnostic__panel-head'>";
echo "<h3>Amostra de agentes sem vinculo</h3>";
echo "<form method='get' class='d-flex align-items-center gap-2'>";
echo "<label class='text-muted' for='sentinelone-limit'>Limite</label>";
echo "<input id='sentinelone-limit' class='form-control' type='number' min='10' max='200' name='limit' value='" . $h($diagnostics['limit']) . "' style='width: 110px'>";
echo "<button class='btn btn-primary' type='submit'><span class='ti ti-refresh'></span>Atualizar</button>";
echo "</form>";
echo "</div>";
echo "<div class='table-responsive'>";
echo "<table class='table table-vcenter table-hover mb-0'>";
echo "<thead><tr><th>Endpoint</th><th>Identificadores</th><th>Diagnostico</th><th>Checagens</th></tr></thead>";
echo "<tbody>";

foreach ($diagnostics['rows'] as $row) {
   $agent = $row['agent'];
   echo "<tr>";
   echo "<td>";
   echo "<strong>" . $h($agent['computer_name'] ?? 'Endpoint sem nome') . "</strong>";
   echo "<div class='text-muted'>" . $h(($agent['site_name'] ?? '-') . ' / ' . ($agent['group_name'] ?? '-')) . "</div>";
   echo "</td>";
   echo "<td><div class='sentinelone-identifiers'>";
   echo "<span>Serial: <code>" . $h($agent['serial'] ?? '-') . "</code></span>";
   echo "<span>UUID: <code>" . $h($agent['uuid'] ?? '-') . "</code></span>";
   echo "<span>MAC: <code>" . $h($agent['mac'] ?? '-') . "</code></span>";
   echo "<span>Ultimo contato: <code>" . $h($agent['last_active_at'] ?? '-') . "</code></span>";
   echo "</div></td>";
   echo "<td>" . $statusBadge($row['summary']) . "</td>";
   echo "<td><div class='sentinelone-checks'>";
   foreach ($row['checks'] as $check) {
      echo "<div class='sentinelone-check'>";
      echo "<strong>" . $h($check['label']) . ": <code>" . $h($check['value'] !== '' ? $check['value'] : '-') . "</code></strong>";
      if ($check['candidates'] === []) {
         echo "<span>Nenhum candidato.</span>";
      } else {
         echo "<div class='sentinelone-candidates'>";
         foreach ($check['candidates'] as $candidate) {
            echo "<a class='badge bg-success text-white' href='" . $h($rootDoc . '/front/computer.form.php?id=' . (int)$candidate['id']) . "'>";
            echo "#" . $h($candidate['id']) . " " . $h($candidate['name']);
            echo "</a>";
         }
         echo "</div>";
      }
      echo "</div>";
   }
   echo "</div></td>";
   echo "</tr>";
}

if ($diagnostics['rows'] === []) {
   echo "<tr><td colspan='4' class='text-muted text-center p-4'>Nenhum agente sem vinculo encontrado.</td></tr>";
}

echo "</tbody>";
echo "</table>";
echo "</div>";
echo "</section>";
echo "</div>";

\Html::footer();

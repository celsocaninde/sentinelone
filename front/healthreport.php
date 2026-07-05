<?php

declare(strict_types=1);

use GlpiPlugin\Sentinelone\HealthReport;
use GlpiPlugin\Sentinelone\Profile;

include('../../../inc/includes.php');

\Session::checkRight(Profile::RIGHT_READ, READ);

global $CFG_GLPI;

$h = static fn($v): string => htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$rootDoc      = (string)($CFG_GLPI['root_doc'] ?? '');
$dashboardUrl = $rootDoc . '/plugins/sentinelone/front/dashboard.php';

$rows    = HealthReport::computeScores();
$summary = HealthReport::summary($rows);

$verdictBadge = static fn(string $v): string => match ($v) {
   HealthReport::VERDICT_HEALTHY  => 's1-badge--ok',
   HealthReport::VERDICT_WARNING  => 's1-badge--warning',
   default                        => 's1-badge--critical',
};
$scoreColor = static fn(float $s): string => $s >= 8 ? '#16a34a' : ($s >= 5 ? '#d97706' : '#dc2626');

$generatedBy = sprintf(
   __('Gerado em %1$s por %2$s', 'sentinelone'),
   date('d/m/Y H:i'),
   (string)($_SESSION['glpifriendlyname'] ?? $_SESSION['glpiname'] ?? '')
);

\Html::header(__('SentinelOne — Boletim de Saude da Frota', 'sentinelone'), $_SERVER['PHP_SELF'], 'plugins', 'sentinelone');
?>
<style>
@media print {
  .s1h-no-print { display: none !important; }
  .sentinelone-wrap { padding: 0 !important; }
  .s1h-print-header { display: block !important; }
  .s1h-table-card { box-shadow: none !important; border: none !important; }
  body { font-size: 12px; }
  tr { page-break-inside: avoid; }
  thead { display: table-header-group; }
}
.s1h-print-header { display: none; border-bottom: 3px solid #b5179e; padding-bottom: 10px; margin-bottom: 14px; }
.s1h-print-header h2 { margin: 0; font-size: 1.25rem; color: #111827; }
.s1h-print-header p { margin: 3px 0 0; font-size: 0.8rem; color: #475467; }
.s1h-print-kpis { display: flex; gap: 20px; margin-top: 8px; font-size: 0.88rem; font-weight: 600; flex-wrap: wrap; }

.s1h-hero { background: linear-gradient(120deg, #2d1f6e, #6a0dad 55%, #b5179e); border-radius: 16px; padding: 26px 30px; margin-bottom: 18px; display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; color: #fff; }
.s1h-hero-title { display: flex; align-items: center; gap: 16px; }
.s1h-hero-icon { width: 52px; height: 52px; border-radius: 14px; background: rgba(255,255,255,.14); display: flex; align-items: center; justify-content: center; font-size: 26px; }
.s1h-hero h1 { margin: 0; font-size: 1.45rem; color: #fff; }
.s1h-hero .s1h-kicker { font-size: 11px; font-weight: 800; letter-spacing: 2px; text-transform: uppercase; color: #e9d5ff; }
.s1h-hero p { margin: 2px 0 0; color: #ddd6fe; font-size: 0.85rem; }
.s1h-hero .btn-light { font-weight: 600; }

.s1h-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 14px; margin-bottom: 18px; }
.s1h-card { background: #fff; border: 1px solid #e4e9f0; border-left: 4px solid var(--s1h-color, #6a0dad); border-radius: 12px; padding: 16px 20px; box-shadow: 0 1px 2px rgba(16,24,40,.05); }
.s1h-card strong { display: block; font-size: 1.9rem; line-height: 1.1; color: var(--s1h-color, #1f2937); }
.s1h-card span { font-size: 0.8rem; color: #667085; font-weight: 600; }
.s1h-card--avg  { --s1h-color: #6a0dad; }
.s1h-card--ok   { --s1h-color: #16a34a; }
.s1h-card--warn { --s1h-color: #d97706; }
.s1h-card--crit { --s1h-color: #dc2626; }

.s1h-table-card { background: #fff; border: 1px solid #e4e9f0; border-radius: 12px; overflow: hidden; box-shadow: 0 1px 2px rgba(16,24,40,.05); }
.s1h-table-head { display: flex; align-items: center; justify-content: space-between; padding: 14px 20px; border-bottom: 1px solid #eef2f6; }
.s1h-table-head h2 { margin: 0; font-size: 1rem; color: #1f2937; }
.s1h-table-head p { margin: 2px 0 0; font-size: 0.78rem; color: #667085; }
.s1h-table { width: 100%; border-collapse: collapse; font-size: 0.86rem; }
.s1h-table th { background: #f8fafc; text-align: left; padding: 9px 14px; font-size: 0.72rem; text-transform: uppercase; color: #475467; border-bottom: 1px solid #eef2f6; }
.s1h-table td { padding: 9px 14px; border-bottom: 1px solid #f1f4f8; vertical-align: middle; }
.s1h-table tbody tr:last-child td { border-bottom: none; }
.s1h-score { font-weight: 800; font-size: 1rem; }
.s1h-scorebar { width: 90px; height: 6px; border-radius: 3px; background: #eef2f6; display: inline-block; vertical-align: middle; margin-left: 8px; }
.s1h-scorebar > div { height: 100%; border-radius: 3px; }
.s1h-factors { font-size: 0.78rem; color: #667085; }
</style>

<div class="sentinelone-wrap">

<div class="s1h-hero s1h-no-print">
   <div class="s1h-hero-title">
      <div class="s1h-hero-icon"><i class="ti ti-heart-rate-monitor"></i></div>
      <div>
         <span class="s1h-kicker">SentinelOne · Fleet Health</span>
         <h1><?= __('Boletim de Saude da Frota', 'sentinelone') ?></h1>
         <p><?= __('Nota 0-10 por endpoint: conectividade, versao, infeccoes, ameacas e CVEs em exploracao ativa.', 'sentinelone') ?></p>
      </div>
   </div>
   <div style="display:flex;gap:8px;flex-wrap:wrap">
      <a class="btn btn-sm btn-outline-light" href="<?= $h($dashboardUrl) ?>"><i class="ti ti-arrow-left"></i> <?= __('Dashboard', 'sentinelone') ?></a>
      <button type="button" class="btn btn-sm btn-light" onclick="window.print()"><i class="ti ti-printer"></i> <?= __('Exportar PDF', 'sentinelone') ?></button>
   </div>
</div>

<div class="s1h-cards s1h-no-print">
   <div class="s1h-card s1h-card--avg"><strong><?= number_format($summary['avg'], 1, ',', '.') ?></strong><span><?= __('Nota media da frota', 'sentinelone') ?></span></div>
   <div class="s1h-card s1h-card--ok"><strong><?= $summary['healthy'] ?></strong><span><?= __('Saudaveis (nota >= 8)', 'sentinelone') ?></span></div>
   <div class="s1h-card s1h-card--warn"><strong><?= $summary['warning'] ?></strong><span><?= __('Atencao (5 a 7,9)', 'sentinelone') ?></span></div>
   <div class="s1h-card s1h-card--crit"><strong><?= $summary['critical'] ?></strong><span><?= __('Criticos (nota < 5)', 'sentinelone') ?></span></div>
</div>

<div class="s1h-table-card">
   <div class="s1h-print-header">
      <h2><?= __('Boletim de Saude da Frota SentinelOne', 'sentinelone') ?></h2>
      <p><?= $h($generatedBy) ?></p>
      <div class="s1h-print-kpis">
         <span><?= __('Endpoints', 'sentinelone') ?>: <?= $summary['total'] ?></span>
         <span><?= __('Nota media', 'sentinelone') ?>: <?= number_format($summary['avg'], 1, ',', '.') ?></span>
         <span style="color:#16a34a"><?= __('Saudaveis', 'sentinelone') ?>: <?= $summary['healthy'] ?></span>
         <span style="color:#d97706"><?= __('Atencao', 'sentinelone') ?>: <?= $summary['warning'] ?></span>
         <span style="color:#dc2626"><?= __('Criticos', 'sentinelone') ?>: <?= $summary['critical'] ?></span>
      </div>
   </div>

   <div class="s1h-table-head s1h-no-print">
      <div>
         <h2><i class="ti ti-list-details"></i> <?= sprintf(__('Endpoints (%d) — pior nota primeiro', 'sentinelone'), $summary['total']) ?></h2>
         <p><?= $h($generatedBy) ?></p>
      </div>
   </div>

   <?php if ($rows === []): ?>
   <p style="padding:20px;color:#667085"><?= __('Nenhum agente sincronizado ainda.', 'sentinelone') ?></p>
   <?php else: ?>
   <div class="table-responsive">
   <table class="s1h-table">
      <thead>
         <tr>
            <th><?= __('Endpoint', 'sentinelone') ?></th>
            <th><?= __('Site', 'sentinelone') ?></th>
            <th><?= __('Nota', 'sentinelone') ?></th>
            <th><?= __('Veredito', 'sentinelone') ?></th>
            <th><?= __('Fatores de risco', 'sentinelone') ?></th>
            <th><?= __('Ultimo contato', 'sentinelone') ?></th>
         </tr>
      </thead>
      <tbody>
      <?php foreach ($rows as $row):
         $agent = $row['agent'];
         $color = $scoreColor($row['score']);
         $agentUrl = $rootDoc . '/plugins/sentinelone/front/agent.form.php?id=' . (int)$agent['id'];
      ?>
         <tr>
            <td>
               <a href="<?= $h($agentUrl) ?>" class="fw-semibold"><?= $h($agent['computer_name'] ?: $agent['sentinelone_id']) ?></a>
               <div style="font-size:0.74rem;color:#98a2b3"><?= $h($agent['os_name'] ?? '') ?></div>
            </td>
            <td><?= $h($agent['site_name'] ?? '—') ?></td>
            <td>
               <span class="s1h-score" style="color:<?= $color ?>"><?= number_format($row['score'], 1, ',', '.') ?></span>
               <span class="s1h-scorebar s1h-no-print"><div style="width:<?= (int)($row['score'] * 10) ?>%;background:<?= $color ?>"></div></span>
            </td>
            <td><span class="s1-badge <?= $verdictBadge($row['verdict']) ?>"><?= $h(HealthReport::verdictLabel($row['verdict'])) ?></span></td>
            <td class="s1h-factors"><?= $row['factors'] !== [] ? $h(implode(' · ', $row['factors'])) : '<span style="color:#16a34a">✓ ' . __('Sem fatores de risco', 'sentinelone') . '</span>' ?></td>
            <td style="font-size:0.8rem;color:#667085"><?= $agent['last_active_at'] ? \Html::convDateTime((string)$agent['last_active_at']) : '—' ?></td>
         </tr>
      <?php endforeach; ?>
      </tbody>
   </table>
   </div>
   <?php endif; ?>
</div>

</div>
<?php
\Html::footer();

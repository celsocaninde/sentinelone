<?php

use GlpiPlugin\Sentinelone\Cve;
use GlpiPlugin\Sentinelone\Profile;
use GlpiPlugin\Sentinelone\Sync;

include('../../../inc/includes.php');

\Session::checkRight(Profile::RIGHT_READ, READ);

global $CFG_GLPI;

$h = static fn($v): string => htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$rootDoc      = (string)($CFG_GLPI['root_doc'] ?? '');
$dashboardUrl = $rootDoc . '/plugins/sentinelone/front/dashboard.php';
$syncUrl      = $rootDoc . '/plugins/sentinelone/front/sync.form.php';
$hasSyncRight = Profile::hasSyncRight();

$stats   = Cve::getGlobalStats();
$topCves = Cve::getTopCves(15);
$topApps = Cve::getTopApplications(10);
$agents  = Cve::getAgentsWithMostCves(20);

$severityClass = static fn(string $s): string => match (strtoupper($s)) {
   'CRITICAL' => 's1-badge--critical',
   'HIGH'     => 's1-badge--high',
   'MEDIUM'   => 's1-badge--warning',
   'LOW'      => 's1-badge--muted',
   default    => 's1-badge--muted',
};

\Html::header(__('CVEs SentinelOne', 'sentinelone'), '', 'plugins', 'sentinelone');
?>

<div class="sentinelone-wrap">

   <!-- breadcrumb -->
   <div class="sentinelone-page-nav" style="display:flex;align-items:center;gap:8px;margin-bottom:16px;font-size:13px">
      <a href="<?= $h($dashboardUrl) ?>" class="btn btn-sm btn-secondary">
         <span class="ti ti-arrow-left"></span> <?= __('Dashboard', 'sentinelone') ?>
      </a>
      <span style="color:#9ca3af">/</span>
      <span><?= __('CVEs globais', 'sentinelone') ?></span>
      <div style="flex:1"></div>
      <?php if ($hasSyncRight): ?>
      <form method="post" action="<?= $h($syncUrl) ?>" style="display:inline">
         <input type="hidden" name="action" value="synccves">
         <input type="hidden" name="_glpi_csrf_token" value="<?= \Session::getNewCSRFToken() ?>">
         <button class="btn btn-sm btn-primary" type="submit">
            <span class="ti ti-refresh"></span> <?= __('Sincronizar CVEs agora', 'sentinelone') ?>
         </button>
      </form>
      <?php endif; ?>
   </div>

   <!-- hero / stat cards -->
   <div class="sentinelone-stats" style="margin-bottom:20px">
      <?php
      $sevOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
      $sevLabel = ['CRITICAL' => 'Críticos', 'HIGH' => 'Altos', 'MEDIUM' => 'Médios', 'LOW' => 'Baixos'];
      $bySev = $stats['by_severity'] ?? [];
      $total = (int)($stats['total'] ?? 0);
      ?>
      <div class="sentinelone-stat sentinelone-stat--accent">
         <span><?= __('CVEs totais', 'sentinelone') ?></span>
         <strong><?= $h($total) ?></strong>
         <small><?= __('endpoints afetados', 'sentinelone') ?></small>
      </div>
      <?php foreach ($sevOrder as $sev):
         $cnt = (int)($bySev[$sev] ?? 0);
         $mod = $cnt > 0 && in_array($sev, ['CRITICAL','HIGH'], true) ? ' sentinelone-stat--danger' : ($cnt > 0 ? ' sentinelone-stat--warning' : '');
      ?>
      <div class="sentinelone-stat<?= $mod ?>">
         <span><?= $h($sevLabel[$sev] ?? $sev) ?></span>
         <strong><?= $h($cnt) ?></strong>
         <small><?= $h($sev) ?></small>
      </div>
      <?php endforeach; ?>
   </div>

   <?php if ($total === 0): ?>
   <div class="alert alert-info">
      <span class="ti ti-info-circle"></span>
      <?= __('Nenhum CVE sincronizado ainda. Habilite "Sincronizar CVEs dos endpoints" na configuracao e execute a cron synccves.', 'sentinelone') ?>
   </div>
   <?php else: ?>

   <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px">

      <!-- Top CVEs -->
      <section class="sentinelone-panel">
         <div class="sentinelone-panel__head">
            <span class="ti ti-shield-exclamation"></span>
            <h3><?= __('Top CVEs', 'sentinelone') ?></h3>
            <span class="s1-badge s1-badge--muted"><?= count($topCves) ?></span>
         </div>
         <div class="sentinelone-panel__body" style="padding:0;overflow-x:auto">
            <table class="s1-cve-table">
               <thead>
                  <tr>
                     <th><?= __('CVE', 'sentinelone') ?></th>
                     <th><?= __('Severidade', 'sentinelone') ?></th>
                     <th>CVSS</th>
                     <th><?= __('Endpoints', 'sentinelone') ?></th>
                  </tr>
               </thead>
               <tbody>
                  <?php foreach ($topCves as $row): ?>
                  <tr>
                     <td><span class="s1-cve-id"><?= $h($row['cve_id']) ?></span></td>
                     <td><span class="s1-badge <?= $severityClass((string)$row['severity']) ?>"><?= $h($row['severity']) ?></span></td>
                     <td><?= $row['cvss_score'] !== null ? number_format((float)$row['cvss_score'], 1) : '—' ?></td>
                     <td><strong><?= $h($row['agents_count']) ?></strong></td>
                  </tr>
                  <?php endforeach; ?>
               </tbody>
            </table>
         </div>
      </section>

      <!-- Top aplicações -->
      <section class="sentinelone-panel">
         <div class="sentinelone-panel__head">
            <span class="ti ti-app-window"></span>
            <h3><?= __('Aplicacoes mais vulneraveis', 'sentinelone') ?></h3>
         </div>
         <div class="sentinelone-panel__body" style="padding:0;overflow-x:auto">
            <table class="s1-cve-table">
               <thead>
                  <tr>
                     <th><?= __('Aplicacao', 'sentinelone') ?></th>
                     <th><?= __('CVEs', 'sentinelone') ?></th>
                     <th><?= __('Endpoints', 'sentinelone') ?></th>
                  </tr>
               </thead>
               <tbody>
                  <?php foreach ($topApps as $row): ?>
                  <tr>
                     <td><?= $h($row['application_name']) ?></td>
                     <td>
                        <span class="s1-badge <?= in_array((int)$row['top_rank'], [1,2], true) ? 's1-badge--critical' : 's1-badge--warning' ?>">
                           <?= $h($row['cve_count']) ?>
                        </span>
                     </td>
                     <td><?= $h($row['agents_count']) ?></td>
                  </tr>
                  <?php endforeach; ?>
               </tbody>
            </table>
         </div>
      </section>

   </div>

   <!-- Endpoints com mais CVEs -->
   <section class="sentinelone-panel sentinelone-panel--wide" style="margin-bottom:20px">
      <div class="sentinelone-panel__head">
         <span class="ti ti-devices-pc"></span>
         <h3><?= __('Endpoints com mais CVEs', 'sentinelone') ?></h3>
         <span class="s1-badge s1-badge--muted"><?= count($agents) ?></span>
      </div>
      <div class="sentinelone-panel__body" style="padding:0;overflow-x:auto">
         <table class="table table-vcenter table-hover mb-0">
            <thead>
               <tr>
                  <th><?= __('Endpoint', 'sentinelone') ?></th>
                  <th class="text-end"><?= __('CVEs totais', 'sentinelone') ?></th>
                  <th class="text-end"><?= __('Criticos', 'sentinelone') ?></th>
                  <th></th>
               </tr>
            </thead>
            <tbody>
               <?php foreach ($agents as $row):
                  $agentUrl  = $rootDoc . '/plugins/sentinelone/front/agent.form.php?id=' . (int)$row['agent_id'];
                  $glpiUrl   = $row['computers_id'] ? $rootDoc . '/front/computer.form.php?id=' . (int)$row['computers_id'] : '';
                  $hasCrit   = (int)$row['critical_count'] > 0;
               ?>
               <tr <?= $hasCrit ? "style='background:rgba(220,53,69,.04)'" : '' ?>>
                  <td class="fw-semibold">
                     <a href="<?= $h($agentUrl) ?>"><?= $h($row['computer_name'] ?? '—') ?></a>
                     <?php if ($glpiUrl): ?>
                     <a href="<?= $h($glpiUrl) ?>" class="text-muted ms-1" title="Ver computador GLPI"><span class="ti ti-external-link" style="font-size:11px"></span></a>
                     <?php endif; ?>
                  </td>
                  <td class="text-end"><strong><?= $h($row['cve_count']) ?></strong></td>
                  <td class="text-end">
                     <?php if ($hasCrit): ?>
                     <span class="s1-badge s1-badge--critical"><?= $h($row['critical_count']) ?></span>
                     <?php else: ?>
                     <span class="text-muted">0</span>
                     <?php endif; ?>
                  </td>
                  <td>
                     <a href="<?= $h($agentUrl) ?>" class="btn btn-xs btn-outline-secondary">
                        <span class="ti ti-eye"></span>
                     </a>
                  </td>
               </tr>
               <?php endforeach; ?>
               <?php if ($agents === []): ?>
               <tr><td colspan="4" class="text-center text-muted"><?= __('Nenhum agente com CVEs sincronizados.', 'sentinelone') ?></td></tr>
               <?php endif; ?>
            </tbody>
         </table>
      </div>
   </section>

   <?php endif; ?>

</div>

<?php \Html::footer(); ?>

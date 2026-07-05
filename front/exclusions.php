<?php

use GlpiPlugin\Sentinelone\Exclusion;
use GlpiPlugin\Sentinelone\Profile;

include('../../../inc/includes.php');

\Session::checkRight(Profile::RIGHT_READ, READ);

global $CFG_GLPI;

$h = static fn($v): string => htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$rootDoc      = (string)($CFG_GLPI['root_doc'] ?? '');
$dashboardUrl = $rootDoc . '/plugins/sentinelone/front/dashboard.php';
$syncUrl      = $rootDoc . '/plugins/sentinelone/front/sync.form.php';
$hasSyncRight = Profile::hasSyncRight();

$type   = trim((string)($_GET['type'] ?? ''));
$search = trim((string)($_GET['search'] ?? ''));

$summary = Exclusion::summary();
$rows    = Exclusion::getAll($type, $search, 500);

\Html::header(__('Exclusoes — SentinelOne', 'sentinelone'), '', 'plugins', 'sentinelone');
?>

<div class="sentinelone-wrap">

   <div class="sentinelone-page-nav" style="display:flex;align-items:center;gap:8px;margin-bottom:16px;font-size:13px">
      <a href="<?= $h($dashboardUrl) ?>" class="btn btn-sm btn-secondary">
         <span class="ti ti-arrow-left"></span> <?= __('Dashboard', 'sentinelone') ?>
      </a>
      <span style="color:#9ca3af">/</span>
      <span><?= __('Auditoria de exclusoes', 'sentinelone') ?></span>
   </div>

   <div class="sentinelone-stats" style="margin-bottom:1rem">
      <div class="sentinelone-stat sentinelone-stat--accent">
         <span><?= __('Total de exclusoes', 'sentinelone') ?></span>
         <strong><?= $h($summary['total']) ?></strong>
         <small><?= __('Na console SentinelOne', 'sentinelone') ?></small>
      </div>
      <div class="sentinelone-stat<?= $summary['recent'] > 0 ? ' sentinelone-stat--danger' : '' ?>">
         <span><?= sprintf(__('Criadas nos ultimos %d dias', 'sentinelone'), Exclusion::RECENT_DAYS) ?></span>
         <strong><?= $h($summary['recent']) ?></strong>
         <small><?= __('Merecem revisao', 'sentinelone') ?></small>
      </div>
      <?php foreach (array_slice($summary['by_type'], 0, 2, true) as $t => $cnt): ?>
      <div class="sentinelone-stat">
         <span><?= $h(Exclusion::typeLabel((string)$t)) ?></span>
         <strong><?= $h($cnt) ?></strong>
         <small><?= __('exclusoes deste tipo', 'sentinelone') ?></small>
      </div>
      <?php endforeach; ?>
   </div>

   <section class="sentinelone-panel sentinelone-panel--wide">
      <div class="sentinelone-panel__head">
         <span class="ti ti-eye-off"></span>
         <h3><?= __('Exclusoes da console (allowlist)', 'sentinelone') ?></h3>
         <span class="s1-badge <?= $summary['recent'] > 0 ? 's1-badge--warning' : 's1-badge--ok' ?>">
            <?= sprintf(_n('%d exclusao', '%d exclusoes', $summary['total'], 'sentinelone'), $summary['total']) ?>
         </span>
         <div style="flex:1"></div>
         <?php if ($hasSyncRight): ?>
         <form method="post" action="<?= $h($syncUrl) ?>" style="display:inline">
            <input type="hidden" name="action" value="syncexclusions">
            <input type="hidden" name="_glpi_csrf_token" value="<?= \Session::getNewCSRFToken() ?>">
            <button class="btn btn-sm btn-secondary" type="submit">
               <span class="ti ti-refresh"></span> <?= __('Sincronizar agora', 'sentinelone') ?>
            </button>
         </form>
         <?php endif; ?>
      </div>

      <div class="sentinelone-panel__body" style="border-bottom:1px solid var(--s1-border)">
         <form method="get" class="d-flex flex-wrap gap-2">
            <input type="text" name="search" class="form-control form-control-sm" style="max-width:280px"
                   placeholder="<?= $h(__('Buscar por valor, autor ou escopo...', 'sentinelone')) ?>" value="<?= $h($search) ?>">
            <select name="type" class="form-select form-select-sm" style="max-width:220px">
               <option value=""><?= __('Todos os tipos', 'sentinelone') ?></option>
               <?php foreach (array_keys($summary['by_type']) as $t): ?>
               <option value="<?= $h($t) ?>" <?= $type === $t ? 'selected' : '' ?>><?= $h(Exclusion::typeLabel((string)$t)) ?></option>
               <?php endforeach; ?>
            </select>
            <button type="submit" class="btn btn-sm btn-secondary"><span class="ti ti-search"></span> <?= __('Filtrar', 'sentinelone') ?></button>
            <?php if ($type !== '' || $search !== ''): ?>
            <a class="btn btn-sm btn-outline-secondary" href="?"><?= __('Limpar', 'sentinelone') ?></a>
            <?php endif; ?>
         </form>
      </div>

      <?php if ($rows === []): ?>
      <div class="sentinelone-panel__body">
         <div class="alert alert-info" style="margin:0">
            <span class="ti ti-info-circle"></span>
            <?= $summary['total'] === 0
               ? __('Nenhuma exclusao sincronizada ainda. Ative "Sincronizar exclusoes da console (auditoria)" na configuracao e sincronize.', 'sentinelone')
               : __('Nenhuma exclusao encontrada para os filtros selecionados.', 'sentinelone') ?>
         </div>
      </div>
      <?php else: ?>
      <div class="sentinelone-panel__body" style="padding:0;overflow-x:auto">
         <table class="table table-vcenter table-hover mb-0">
            <thead>
               <tr>
                  <th><?= __('Tipo', 'sentinelone') ?></th>
                  <th><?= __('Valor', 'sentinelone') ?></th>
                  <th><?= __('Escopo', 'sentinelone') ?></th>
                  <th><?= __('Criado por', 'sentinelone') ?></th>
                  <th><?= __('OS', 'sentinelone') ?></th>
                  <th><?= __('Criada em', 'sentinelone') ?></th>
               </tr>
            </thead>
            <tbody>
               <?php foreach ($rows as $row):
                  $recent = Exclusion::isRecent((string)($row['s1_created_at'] ?? ''));
               ?>
               <tr<?= $recent ? " style='background:rgba(220,38,38,.05)'" : '' ?>>
                  <td><span class="s1-badge s1-badge--muted"><?= $h(Exclusion::typeLabel((string)($row['type'] ?? ''))) ?></span></td>
                  <td style="max-width:360px;word-break:break-all"><code style="font-size:.8rem"><?= $h($row['value'] ?? '—') ?></code></td>
                  <td><?= $h($row['scope_name'] ?? '—') ?></td>
                  <td><?= $h($row['created_by'] ?? '—') ?></td>
                  <td><?= $h($row['os_type'] ?? '—') ?></td>
                  <td>
                     <?= $row['s1_created_at'] ? $h(date('d/m/Y H:i', strtotime((string)$row['s1_created_at']))) : '—' ?>
                     <?php if ($recent): ?>
                     <span class="s1-badge s1-badge--critical" style="margin-left:4px;font-size:.62rem" title="<?= $h(sprintf(__('Criada nos ultimos %d dias', 'sentinelone'), Exclusion::RECENT_DAYS)) ?>">
                        <span class="ti ti-alert-triangle"></span> <?= __('recente', 'sentinelone') ?>
                     </span>
                     <?php endif; ?>
                  </td>
               </tr>
               <?php endforeach; ?>
            </tbody>
         </table>
      </div>
      <?php endif; ?>
   </section>

</div>

<?php \Html::footer(); ?>

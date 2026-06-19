<?php

use GlpiPlugin\Sentinelone\Profile;
use GlpiPlugin\Sentinelone\Threat;

include('../../../inc/includes.php');

\Session::checkRight(Profile::RIGHT_READ, READ);

global $CFG_GLPI;

$h = static fn($v): string => htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$rootDoc      = (string)($CFG_GLPI['root_doc'] ?? '');
$dashboardUrl = $rootDoc . '/plugins/sentinelone/front/dashboard.php';
$syncUrl      = $rootDoc . '/plugins/sentinelone/front/sync.form.php';
$threatForm   = $rootDoc . '/plugins/sentinelone/front/threat.form.php';
$hasSyncRight = Profile::hasSyncRight();

$ov    = Threat::getOverview(25);
$total = (int)$ov['total'];
$b     = $ov['buckets'];

\Html::header('Ameacas SentinelOne', $_SERVER['PHP_SELF'], 'plugins', 'sentinelone');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
?>

<div class="sentinelone-wrap sentinelone-dashboard">

   <!-- ░░ HERO ░░ -->
   <div class="sentinelone-cves__hero">
      <div class="s1-hero__brand">
         <span class="s1-logo"><span class="ti ti-bug"></span></span>
         <div>
            <span class="sentinelone-dashboard__eyebrow">SentinelOne · Threats</span>
            <h2><?= __('Ameaças & Detecções', 'sentinelone') ?></h2>
            <p>
               <?= sprintf(
                  __('%1$s ameaças · %2$s críticas · %3$s com ticket', 'sentinelone'),
                  '<strong>' . $h($total) . '</strong>',
                  '<strong>' . $h($b['Critica'] ?? 0) . '</strong>',
                  '<strong>' . $h($ov['tickets']) . '</strong>'
               ) ?>
            </p>
         </div>
      </div>
      <div class="sentinelone-cves__actions">
         <a href="<?= $h($dashboardUrl) ?>" class="btn btn-sm btn-ghost">
            <span class="ti ti-arrow-left"></span> <?= __('Dashboard', 'sentinelone') ?>
         </a>
         <?php if ($hasSyncRight): ?>
         <form method="post" action="<?= $h($syncUrl) ?>" style="display:inline">
            <input type="hidden" name="action" value="threats">
            <input type="hidden" name="_glpi_csrf_token" value="<?= \Session::getNewCSRFToken() ?>">
            <button class="btn btn-sm btn-light" type="submit">
               <span class="ti ti-refresh"></span> <?= __('Sincronizar Ameaças', 'sentinelone') ?>
            </button>
         </form>
         <?php endif; ?>
      </div>
   </div>

   <?php if ($total === 0): ?>
   <div class="sentinelone-empty" style="margin-top:1rem">
      <p style="font-size:1rem;font-weight:700;margin:0 0 .35rem">
         <span class="ti ti-shield-check"></span> <?= __('Nenhuma ameaça sincronizada', 'sentinelone') ?>
      </p>
      <p style="margin:0"><?= __('Rode a sincronização de ameaças ou aguarde a ação automática.', 'sentinelone') ?></p>
   </div>
   <?php else: ?>

   <!-- ░░ STAT CARDS ░░ -->
   <div class="sentinelone-stats" style="margin-bottom:1rem">
      <div class="sentinelone-stat sentinelone-stat--accent">
         <span><?= __('Total de ameaças', 'sentinelone') ?></span>
         <strong><?= $h($total) ?></strong>
         <small><?= sprintf(__('%s nos últimos 30 dias', 'sentinelone'), $h($ov['last30'])) ?></small>
      </div>
      <div class="sentinelone-stat<?= ($b['Critica'] ?? 0) > 0 ? ' sentinelone-stat--danger' : '' ?>">
         <span><?= __('Críticas', 'sentinelone') ?></span>
         <strong><?= $h($b['Critica'] ?? 0) ?></strong>
         <small><?= __('ação imediata', 'sentinelone') ?></small>
      </div>
      <div class="sentinelone-stat">
         <span><?= __('Suspeitas', 'sentinelone') ?></span>
         <strong><?= $h($b['Suspeita'] ?? 0) ?></strong>
         <small><?= __('em análise', 'sentinelone') ?></small>
      </div>
      <div class="sentinelone-stat sentinelone-stat--ok">
         <span><?= __('Com ticket', 'sentinelone') ?></span>
         <strong><?= $h($ov['tickets']) ?></strong>
         <small><?= sprintf(__('%s resolvidas', 'sentinelone'), $h($b['Resolvida'] ?? 0)) ?></small>
      </div>
   </div>

   <!-- ░░ DISTRIBUIÇÃO ░░ -->
   <?php
   $tOrder = [
      'Critica'    => ['Críticas', 'critical'],
      'Suspeita'   => ['Suspeitas', 'high'],
      'Ativa'      => ['Ativas', 'medium'],
      'Resolvida'  => ['Resolvidas', 'ok'],
      'Indefinida' => ['Indefinidas', 'low'],
   ];
   $sum = array_sum($b);
   ?>
   <section class="sentinelone-panel" style="margin-bottom:1rem">
      <div class="sentinelone-panel__head">
         <div class="sentinelone-panel__title">
            <span class="sentinelone-panel__icon"><span class="ti ti-chart-donut-3"></span></span>
            <div>
               <h3><?= __('Distribuição por estado', 'sentinelone') ?></h3>
               <p><?= __('Proporção das ameaças por nível de risco', 'sentinelone') ?></p>
            </div>
         </div>
      </div>
      <div class="sentinelone-panel__body">
         <div class="s1-sevbar">
            <?php foreach ($tOrder as $key => [$lbl, $seg]):
               $cnt = (int)($b[$key] ?? 0);
               if ($cnt === 0 || $sum === 0) { continue; }
               $pct = round($cnt / $sum * 100, 2);
            ?>
            <div class="s1-sevbar__seg s1-sevbar__seg--<?= $seg ?>" style="width:<?= $pct ?>%" title="<?= $h($lbl) ?>: <?= $cnt ?>"></div>
            <?php endforeach; ?>
         </div>
         <div class="s1-legend">
            <?php foreach ($tOrder as $key => [$lbl, $seg]): ?>
            <span class="s1-legend__item">
               <span class="s1-legend__dot s1-legend__dot--<?= $seg ?>"></span>
               <?= $h($lbl) ?> <strong><?= $h($b[$key] ?? 0) ?></strong>
            </span>
            <?php endforeach; ?>
         </div>
      </div>
   </section>

   <!-- ░░ AMEAÇAS RECENTES ░░ -->
   <section class="sentinelone-panel sentinelone-panel--wide" style="margin-bottom:1rem">
      <div class="sentinelone-panel__head">
         <div class="sentinelone-panel__title">
            <span class="sentinelone-panel__icon"><span class="ti ti-alert-triangle"></span></span>
            <div>
               <h3><?= __('Ameaças recentes', 'sentinelone') ?></h3>
               <p><?= __('Últimas detecções na frota', 'sentinelone') ?></p>
            </div>
         </div>
         <span class="s1-badge s1-badge--muted"><?= count($ov['recent']) ?></span>
      </div>
      <div class="sentinelone-panel__body" style="padding:0;overflow-x:auto">
         <table class="s1-cve-table">
            <thead>
               <tr>
                  <th><?= __('Ameaça', 'sentinelone') ?></th>
                  <th><?= __('Classificação', 'sentinelone') ?></th>
                  <th><?= __('Estado', 'sentinelone') ?></th>
                  <th><?= __('Endpoint', 'sentinelone') ?></th>
                  <th><?= __('Detectada', 'sentinelone') ?></th>
                  <th><?= __('Ticket', 'sentinelone') ?></th>
               </tr>
            </thead>
            <tbody>
               <?php foreach ($ov['recent'] as $row):
                  $tid      = (int)($row['id'] ?? 0);
                  $agentId  = (int)($row['plugin_sentinelone_agents_id'] ?? 0);
                  $agentUrl = $agentId > 0 ? $rootDoc . '/plugins/sentinelone/front/agent.form.php?id=' . $agentId : '';
                  $ticketId = (int)($row['tickets_id'] ?? 0);
               ?>
               <tr>
                  <td class="s1-rogues-host">
                     <a class="s1-cve-link" href="<?= $h($threatForm . '?id=' . $tid) ?>"><?= $h($row['threat_name'] ?: '—') ?></a>
                  </td>
                  <td><?= $h($row['classification'] ?: '—') ?></td>
                  <td><?= Threat::severityBadge($row) ?></td>
                  <td>
                     <?php if ($agentUrl): ?>
                        <a href="<?= $h($agentUrl) ?>"><?= $h($row['computer_name'] ?: '—') ?></a>
                     <?php else: ?>
                        <?= $h($row['computer_name'] ?: '—') ?>
                     <?php endif; ?>
                  </td>
                  <td class="s1-muted"><?= $row['detected_at'] ? date('d/m/Y H:i', strtotime((string)$row['detected_at'])) : '—' ?></td>
                  <td>
                     <?php if ($ticketId > 0): ?>
                        <a class="s1-cve-link" href="<?= $h($rootDoc . '/front/ticket.form.php?id=' . $ticketId) ?>">#<?= $ticketId ?></a>
                     <?php else: ?>
                        <span class="s1-muted">—</span>
                     <?php endif; ?>
                  </td>
               </tr>
               <?php endforeach; ?>
            </tbody>
         </table>
      </div>
   </section>

   <!-- ░░ BUSCA COMPLETA (GLPI) ░░ -->
   <section class="sentinelone-panel sentinelone-panel--wide">
      <div class="sentinelone-panel__head">
         <div class="sentinelone-panel__title">
            <span class="sentinelone-panel__icon"><span class="ti ti-list-search"></span></span>
            <div>
               <h3><?= __('Todas as ameaças', 'sentinelone') ?></h3>
               <p><?= __('Busca e filtros completos', 'sentinelone') ?></p>
            </div>
         </div>
      </div>
      <div class="sentinelone-panel__body">
         <?php \Search::show(Threat::class); ?>
      </div>
   </section>

   <?php endif; ?>

</div>

<?php \Html::footer(); ?>

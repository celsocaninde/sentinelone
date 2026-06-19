<?php

use GlpiPlugin\Sentinelone\Agent;
use GlpiPlugin\Sentinelone\Profile;

include('../../../inc/includes.php');

\Session::checkRight(Profile::RIGHT_READ, READ);

global $CFG_GLPI;

$h = static fn($v): string => htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$rootDoc      = (string)($CFG_GLPI['root_doc'] ?? '');
$dashboardUrl = $rootDoc . '/plugins/sentinelone/front/dashboard.php';
$coverageUrl  = $rootDoc . '/plugins/sentinelone/front/coverage.php';
$syncUrl      = $rootDoc . '/plugins/sentinelone/front/sync.form.php';
$agentForm    = $rootDoc . '/plugins/sentinelone/front/agent.form.php';
$hasSyncRight = Profile::hasSyncRight();

$ov      = Agent::getOverview(25);
$total   = (int)$ov['total'];
$onlinePct = $total > 0 ? round($ov['online'] / $total * 100) : 0;
$maxOs   = 0;
foreach ($ov['by_os'] as $o) { $maxOs = max($maxOs, (int)$o['count']); }

\Html::header('Agentes SentinelOne', $_SERVER['PHP_SELF'], 'plugins', 'sentinelone');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
?>

<div class="sentinelone-wrap sentinelone-dashboard">

   <!-- ░░ HERO ░░ -->
   <div class="sentinelone-cves__hero">
      <div class="s1-hero__brand">
         <span class="s1-logo"><span class="ti ti-devices-pc"></span></span>
         <div>
            <span class="sentinelone-dashboard__eyebrow">SentinelOne · Endpoints</span>
            <h2><?= __('Agentes', 'sentinelone') ?></h2>
            <p>
               <?= sprintf(
                  __('%1$s agentes · %2$s online · %3$s infectados', 'sentinelone'),
                  '<strong>' . $h($total) . '</strong>',
                  '<strong>' . $h($ov['online']) . '</strong>',
                  '<strong>' . $h($ov['infected']) . '</strong>'
               ) ?>
            </p>
         </div>
      </div>
      <div class="sentinelone-cves__actions">
         <a href="<?= $h($dashboardUrl) ?>" class="btn btn-sm btn-ghost">
            <span class="ti ti-arrow-left"></span> <?= __('Dashboard', 'sentinelone') ?>
         </a>
         <a href="<?= $h($coverageUrl) ?>" class="btn btn-sm btn-ghost">
            <span class="ti ti-shield-check"></span> <?= __('Cobertura', 'sentinelone') ?>
         </a>
         <?php if ($hasSyncRight): ?>
         <form method="post" action="<?= $h($syncUrl) ?>" style="display:inline">
            <input type="hidden" name="action" value="agents">
            <input type="hidden" name="_glpi_csrf_token" value="<?= \Session::getNewCSRFToken() ?>">
            <button class="btn btn-sm btn-light" type="submit">
               <span class="ti ti-refresh"></span> <?= __('Sincronizar Agentes', 'sentinelone') ?>
            </button>
         </form>
         <?php endif; ?>
      </div>
   </div>

   <?php if ($total === 0): ?>
   <div class="sentinelone-empty" style="margin-top:1rem">
      <p style="font-size:1rem;font-weight:700;margin:0 0 .35rem">
         <span class="ti ti-devices-off"></span> <?= __('Nenhum agente sincronizado', 'sentinelone') ?>
      </p>
      <p style="margin:0"><?= __('Rode a sincronização de agentes ou aguarde a ação automática.', 'sentinelone') ?></p>
   </div>
   <?php else: ?>

   <!-- ░░ STAT CARDS ░░ -->
   <div class="sentinelone-stats" style="margin-bottom:1rem">
      <div class="sentinelone-stat sentinelone-stat--accent">
         <span><?= __('Total de agentes', 'sentinelone') ?></span>
         <strong><?= $h($total) ?></strong>
         <small><?= sprintf(__('%s%% online', 'sentinelone'), $h($onlinePct)) ?></small>
      </div>
      <div class="sentinelone-stat sentinelone-stat--ok">
         <span><?= __('Online', 'sentinelone') ?></span>
         <strong><?= $h($ov['online']) ?></strong>
         <small><?= sprintf(__('%s offline', 'sentinelone'), $h($ov['offline'])) ?></small>
      </div>
      <div class="sentinelone-stat<?= ($ov['infected'] ?? 0) > 0 ? ' sentinelone-stat--danger' : '' ?>">
         <span><?= __('Infectados', 'sentinelone') ?></span>
         <strong><?= $h($ov['infected']) ?></strong>
         <small><?= __('prioridade alta', 'sentinelone') ?></small>
      </div>
      <a class="sentinelone-stat" href="<?= $h($coverageUrl) ?>">
         <span class="s1-stat-go"><span class="ti ti-arrow-right"></span></span>
         <span><?= __('Sem vínculo GLPI', 'sentinelone') ?></span>
         <strong><?= $h($ov['unlinked']) ?></strong>
         <small><?= __('ver cobertura', 'sentinelone') ?></small>
      </a>
   </div>

   <!-- ░░ COBERTURA ONLINE + SISTEMAS OPERACIONAIS ░░ -->
   <div style="display:grid;grid-template-columns:minmax(0,1fr) minmax(320px,.8fr);gap:1rem;margin-bottom:1rem">

      <section class="sentinelone-panel">
         <div class="sentinelone-panel__head">
            <div class="sentinelone-panel__title">
               <span class="sentinelone-panel__icon"><span class="ti ti-wifi"></span></span>
               <div>
                  <h3><?= __('Conectividade', 'sentinelone') ?></h3>
                  <p><?= __('Agentes com conexão recente à console', 'sentinelone') ?></p>
               </div>
            </div>
         </div>
         <div class="sentinelone-panel__body">
            <div class="sentinelone-coverage" style="border:0;padding:0;margin:0">
               <div class="sentinelone-coverage__head">
                  <strong><?= __('Online', 'sentinelone') ?></strong>
                  <span><?= sprintf(__('%1$s de %2$s · %3$s%%', 'sentinelone'), $h($ov['online']), $h($total), $h($onlinePct)) ?></span>
               </div>
               <div class="sentinelone-coverage__bar"><div class="sentinelone-coverage__fill" style="width:<?= $onlinePct ?>%"></div></div>
            </div>
            <div class="s1-legend" style="margin-top:1rem">
               <span class="s1-legend__item"><span class="s1-legend__dot s1-legend__dot--ok"></span><?= __('Online', 'sentinelone') ?> <strong><?= $h($ov['online']) ?></strong></span>
               <span class="s1-legend__item"><span class="s1-legend__dot s1-legend__dot--low"></span><?= __('Offline', 'sentinelone') ?> <strong><?= $h($ov['offline']) ?></strong></span>
               <span class="s1-legend__item"><span class="s1-legend__dot s1-legend__dot--high"></span><?= __('Infectados', 'sentinelone') ?> <strong><?= $h($ov['infected']) ?></strong></span>
               <span class="s1-legend__item"><span class="s1-legend__dot s1-legend__dot--critical"></span><?= __('Quarentena', 'sentinelone') ?> <strong><?= $h($ov['quarantine']) ?></strong></span>
            </div>
         </div>
      </section>

      <section class="sentinelone-panel">
         <div class="sentinelone-panel__head">
            <div class="sentinelone-panel__title">
               <span class="sentinelone-panel__icon"><span class="ti ti-device-desktop"></span></span>
               <div>
                  <h3><?= __('Sistemas operacionais', 'sentinelone') ?></h3>
                  <p><?= __('Distribuição da frota', 'sentinelone') ?></p>
               </div>
            </div>
         </div>
         <div class="sentinelone-panel__body" style="padding:0;overflow-x:auto">
            <table class="s1-cve-table">
               <tbody>
                  <?php foreach ($ov['by_os'] as $o):
                     $pct = $maxOs > 0 ? round((int)$o['count'] / $maxOs * 100) : 0;
                  ?>
                  <tr>
                     <td>
                        <div class="s1-app-cell">
                           <span class="s1-app-cell__name"><?= $h($o['os']) ?></span>
                           <div class="s1-meter"><div class="s1-meter__fill" style="width:<?= $pct ?>%"></div></div>
                        </div>
                     </td>
                     <td class="text-end" style="white-space:nowrap"><strong><?= $h($o['count']) ?></strong></td>
                  </tr>
                  <?php endforeach; ?>
                  <?php if ($ov['by_os'] === []): ?>
                  <tr><td class="text-center s1-muted"><?= __('Sem dados.', 'sentinelone') ?></td></tr>
                  <?php endif; ?>
               </tbody>
            </table>
         </div>
      </section>

   </div>

   <!-- ░░ AGENTES RECENTES ░░ -->
   <section class="sentinelone-panel sentinelone-panel--wide" style="margin-bottom:1rem">
      <div class="sentinelone-panel__head">
         <div class="sentinelone-panel__title">
            <span class="sentinelone-panel__icon"><span class="ti ti-clock-bolt"></span></span>
            <div>
               <h3><?= __('Atividade recente', 'sentinelone') ?></h3>
               <p><?= __('Agentes com contato mais recente', 'sentinelone') ?></p>
            </div>
         </div>
         <span class="s1-badge s1-badge--muted"><?= count($ov['recent']) ?></span>
      </div>
      <div class="sentinelone-panel__body" style="padding:0;overflow-x:auto">
         <table class="s1-cve-table">
            <thead>
               <tr>
                  <th><?= __('Endpoint', 'sentinelone') ?></th>
                  <th><?= __('Status', 'sentinelone') ?></th>
                  <th><?= __('SO', 'sentinelone') ?></th>
                  <th><?= __('Versão', 'sentinelone') ?></th>
                  <th><?= __('Site / Grupo', 'sentinelone') ?></th>
                  <th><?= __('Último contato', 'sentinelone') ?></th>
               </tr>
            </thead>
            <tbody>
               <?php foreach ($ov['recent'] as $row):
                  $aid = (int)($row['id'] ?? 0);
               ?>
               <tr>
                  <td class="s1-rogues-host">
                     <a class="s1-cve-link" href="<?= $h($agentForm . '?id=' . $aid) ?>"><?= $h($row['computer_name'] ?: '—') ?></a>
                  </td>
                  <td style="white-space:nowrap">
                     <?php if (!empty($row['is_online'])): ?>
                        <span class="s1-badge s1-badge--ok"><?= __('Online', 'sentinelone') ?></span>
                     <?php else: ?>
                        <span class="s1-badge s1-badge--muted"><?= __('Offline', 'sentinelone') ?></span>
                     <?php endif; ?>
                     <?php if (!empty($row['is_infected'])): ?>
                        <span class="s1-badge s1-badge--critical"><?= __('Infectado', 'sentinelone') ?></span>
                     <?php endif; ?>
                     <?php if (!empty($row['is_network_quarantine'])): ?>
                        <span class="s1-badge s1-badge--danger"><?= __('Quarentena', 'sentinelone') ?></span>
                     <?php endif; ?>
                  </td>
                  <td><?= $h($row['os_name'] ?: '—') ?></td>
                  <td class="s1-muted"><?= $h($row['agent_version'] ?: '—') ?></td>
                  <td class="s1-muted"><?= $h(trim((($row['site_name'] ?? '') ?: '—') . ' / ' . (($row['group_name'] ?? '') ?: '—'))) ?></td>
                  <td class="s1-muted"><?= $row['last_active_at'] ? date('d/m/Y H:i', strtotime((string)$row['last_active_at'])) : '—' ?></td>
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
               <h3><?= __('Todos os agentes', 'sentinelone') ?></h3>
               <p><?= __('Busca e filtros completos', 'sentinelone') ?></p>
            </div>
         </div>
      </div>
      <div class="sentinelone-panel__body">
         <?php \Search::show(Agent::class); ?>
      </div>
   </section>

   <?php endif; ?>

</div>

<?php \Html::footer(); ?>

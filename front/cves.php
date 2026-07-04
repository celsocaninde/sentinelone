<?php

use GlpiPlugin\Sentinelone\Cve;
use GlpiPlugin\Sentinelone\Enrichment;
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
$summary = Cve::getSummary();
$topCves = Cve::getTopCves(15);
$topApps = Cve::getTopApplications(10);
$agents  = Cve::getAgentsWithMostCves(20);

// Threat intel EPSS / CISA KEV (cron enrichcves)
$kevSummary = Enrichment::getKevSummary();
$intelDate  = Enrichment::lastRefresh();
$enrichMap  = Enrichment::forCves(array_column($topCves, 'cve_id'));

// Badge KEV ao lado do CVE id (☠ quando usado em campanhas de ransomware).
$kevBadge = static function (string $cveId) use ($enrichMap, $h): string {
   $e = $enrichMap[strtoupper($cveId)] ?? null;
   if ($e === null || empty($e['is_kev'])) {
      return '';
   }
   $title = !empty($e['kev_ransomware'])
      ? __('CISA KEV — exploração ativa E uso em campanhas de ransomware', 'sentinelone')
      : __('CISA KEV — exploração ativa confirmada', 'sentinelone');
   return " <span class='s1-badge s1-badge--critical' style='font-size:.62rem' title='" . $h($title) . "'>&#128293; KEV"
      . (!empty($e['kev_ransomware']) ? ' &#9760;' : '') . "</span>";
};

// Chip de EPSS (probabilidade de exploração em 30 dias).
$epssChip = static function (string $cveId) use ($enrichMap, $h): string {
   $e = $enrichMap[strtoupper($cveId)] ?? null;
   if ($e === null || $e['epss_score'] === null) {
      return '<span class="s1-muted">—</span>';
   }
   $pct   = (float)$e['epss_score'] * 100;
   $style = $pct >= 50 ? 'color:#b5179e;font-weight:700' : ($pct >= 10 ? 'font-weight:600' : '');
   return '<span style="' . $style . '">' . $h(number_format($pct, $pct >= 10 ? 0 : 1)) . '%</span>';
};

$total = (int)($summary['records'] ?? 0);

$severityClass = static fn(string $s): string => match (strtoupper($s)) {
   'CRITICAL' => 's1-badge--critical',
   'HIGH'     => 's1-badge--high',
   'MEDIUM'   => 's1-badge--warning',
   'LOW'      => 's1-badge--muted',
   default    => 's1-badge--muted',
};

// Chip de CVSS colorido pela severidade da linha.
$cvssChip = static function ($score, string $severity) use ($h): string {
   if ($score === null || $score === '') {
      return '<span class="s1-muted">—</span>';
   }
   $cls = match (strtoupper($severity)) {
      'CRITICAL' => 's1-cvss--critical',
      'HIGH'     => 's1-cvss--high',
      'MEDIUM'   => 's1-cvss--medium',
      default    => 's1-cvss--low',
   };
   return '<span class="s1-cvss ' . $cls . '">' . $h(number_format((float)$score, 1)) . '</span>';
};

\Html::header(__('CVEs SentinelOne', 'sentinelone'), '', 'plugins', 'sentinelone');
?>

<div class="sentinelone-wrap sentinelone-dashboard">

   <!-- ░░ HERO ░░ -->
   <div class="sentinelone-cves__hero">
      <div class="s1-hero__brand">
         <span class="s1-logo"><span class="ti ti-shield-checkered"></span></span>
         <div>
            <span class="sentinelone-dashboard__eyebrow">SentinelOne · Application Risk</span>
            <h2><?= __('CVEs & Vulnerabilidades', 'sentinelone') ?></h2>
            <p>
               <?= sprintf(
                  __('%1$s CVEs em %2$s endpoints · %3$s aplicações afetadas', 'sentinelone'),
                  '<strong>' . $h($summary['distinct']) . '</strong>',
                  '<strong>' . $h($summary['endpoints']) . '</strong>',
                  '<strong>' . $h($summary['apps']) . '</strong>'
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
            <input type="hidden" name="action" value="synccves">
            <input type="hidden" name="_glpi_csrf_token" value="<?= \Session::getNewCSRFToken() ?>">
            <button class="btn btn-sm btn-light" type="submit">
               <span class="ti ti-refresh"></span> <?= __('Sincronizar CVEs', 'sentinelone') ?>
            </button>
         </form>
         <?php endif; ?>
      </div>
   </div>

   <?php if ($total === 0): ?>
   <div class="sentinelone-empty" style="margin-top:1rem">
      <p style="font-size:1rem;font-weight:700;margin:0 0 .35rem">
         <span class="ti ti-shield-off"></span> <?= __('Nenhum CVE sincronizado ainda', 'sentinelone') ?>
      </p>
      <p style="margin:0">
         <?= __('Habilite "Sincronizar CVEs" na configuração e execute a sincronização. Os CVEs são derivados das aplicações com risco (Application Risk) de cada endpoint.', 'sentinelone') ?>
      </p>
   </div>
   <?php else: ?>

   <!-- ░░ STAT CARDS ░░ -->
   <div class="sentinelone-stats" style="margin-bottom:1rem">
      <a class="sentinelone-stat sentinelone-stat--accent" href="#s1-anchor-topcves">
         <span class="s1-stat-go"><span class="ti ti-arrow-down"></span></span>
         <span><?= __('Ocorrências de CVE', 'sentinelone') ?></span>
         <strong><?= $h($total) ?></strong>
         <small><?= sprintf(__('%s CVEs distintos', 'sentinelone'), $h($summary['distinct'])) ?></small>
      </a>
      <a class="sentinelone-stat<?= ($summary['critical_high'] ?? 0) > 0 ? ' sentinelone-stat--danger' : '' ?>" href="#s1-anchor-topcves">
         <span class="s1-stat-go"><span class="ti ti-arrow-down"></span></span>
         <span><?= __('Críticos + Altos', 'sentinelone') ?></span>
         <strong><?= $h($summary['critical_high']) ?></strong>
         <small><?= __('exigem atenção', 'sentinelone') ?></small>
      </a>
      <a class="sentinelone-stat" href="#s1-anchor-endpoints">
         <span class="s1-stat-go"><span class="ti ti-arrow-down"></span></span>
         <span><?= __('Endpoints afetados', 'sentinelone') ?></span>
         <strong><?= $h($summary['endpoints']) ?></strong>
         <small><?= __('com ao menos 1 CVE', 'sentinelone') ?></small>
      </a>
      <a class="sentinelone-stat" href="#s1-anchor-apps">
         <span class="s1-stat-go"><span class="ti ti-arrow-down"></span></span>
         <span><?= __('Aplicações vulneráveis', 'sentinelone') ?></span>
         <strong><?= $h($summary['apps']) ?></strong>
         <small><?= __('produtos distintos', 'sentinelone') ?></small>
      </a>
      <a class="sentinelone-stat<?= $kevSummary['cves'] > 0 ? ' sentinelone-stat--danger' : '' ?>" href="#s1-anchor-topcves"
         title="<?= $h(__('CVEs presentes no catálogo CISA KEV: exploração ativa confirmada no mundo real', 'sentinelone')) ?>">
         <span class="s1-stat-go"><span class="ti ti-arrow-down"></span></span>
         <span>&#128293; <?= __('Exposição KEV', 'sentinelone') ?></span>
         <strong><?= $h($kevSummary['cves']) ?></strong>
         <small><?php
            if ($kevSummary['cves'] > 0) {
               echo $h(sprintf(__('%1$s endpoints · %2$s c/ ransomware', 'sentinelone'), $kevSummary['endpoints'], $kevSummary['ransomware']));
            } elseif ($intelDate === null) {
               echo $h(__('ative a cron enrichcves', 'sentinelone'));
            } else {
               echo $h(__('nenhum CVE em exploração ativa', 'sentinelone'));
            }
         ?></small>
      </a>
   </div>

   <!-- ░░ DISTRIBUIÇÃO DE SEVERIDADE ░░ -->
   <?php
   $sevOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
   $sevLabel = ['CRITICAL' => 'Críticos', 'HIGH' => 'Altos', 'MEDIUM' => 'Médios', 'LOW' => 'Baixos'];
   $bySev    = $stats['by_severity'] ?? [];
   $sevTotal = array_sum(array_map(static fn($s) => (int)($bySev[$s] ?? 0), $sevOrder));
   ?>
   <section class="sentinelone-panel" style="margin-bottom:1rem">
      <div class="sentinelone-panel__head">
         <div class="sentinelone-panel__title">
            <span class="sentinelone-panel__icon"><span class="ti ti-chart-donut-3"></span></span>
            <div>
               <h3><?= __('Distribuição por severidade', 'sentinelone') ?></h3>
               <p><?= __('Proporção das ocorrências de CVE por nível de risco', 'sentinelone') ?></p>
            </div>
         </div>
      </div>
      <div class="sentinelone-panel__body">
         <div class="s1-sevbar">
            <?php foreach ($sevOrder as $sev):
               $cnt = (int)($bySev[$sev] ?? 0);
               if ($cnt === 0 || $sevTotal === 0) { continue; }
               $pct = round($cnt / $sevTotal * 100, 2);
            ?>
            <div class="s1-sevbar__seg s1-sevbar__seg--<?= strtolower($sev) ?>"
                 style="width:<?= $pct ?>%"
                 title="<?= $h($sevLabel[$sev]) ?>: <?= $cnt ?> (<?= $pct ?>%)"></div>
            <?php endforeach; ?>
         </div>
         <div class="s1-legend">
            <?php foreach ($sevOrder as $sev):
               $cnt = (int)($bySev[$sev] ?? 0);
            ?>
            <span class="s1-legend__item">
               <span class="s1-legend__dot s1-legend__dot--<?= strtolower($sev) ?>"></span>
               <?= $h($sevLabel[$sev]) ?> <strong><?= $h($cnt) ?></strong>
            </span>
            <?php endforeach; ?>
         </div>
      </div>
   </section>

   <!-- ░░ TOP CVEs  +  APPS VULNERÁVEIS ░░ -->
   <div id="s1-anchor-topcves" style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1rem">

      <section class="sentinelone-panel">
         <div class="sentinelone-panel__head">
            <div class="sentinelone-panel__title">
               <span class="sentinelone-panel__icon"><span class="ti ti-shield-exclamation"></span></span>
               <div>
                  <h3><?= __('Top CVEs', 'sentinelone') ?></h3>
                  <p><?= __('Maior severidade e alcance na frota', 'sentinelone') ?><?php if ($intelDate !== null): ?> · <?= $h(sprintf(__('intel EPSS/KEV de %s', 'sentinelone'), date('d/m/Y H:i', strtotime($intelDate)))) ?><?php endif; ?></p>
               </div>
            </div>
            <span class="s1-badge s1-badge--muted"><?= count($topCves) ?></span>
         </div>
         <div class="sentinelone-panel__body" style="padding:0;overflow-x:auto">
            <table class="s1-cve-table">
               <thead>
                  <tr>
                     <th><?= __('CVE', 'sentinelone') ?></th>
                     <th><?= __('Severidade', 'sentinelone') ?></th>
                     <th>CVSS</th>
                     <th title="<?= $h(__('Exploit Prediction Scoring System — probabilidade de exploração em 30 dias (FIRST.org)', 'sentinelone')) ?>">EPSS</th>
                     <th class="text-end"><?= __('Endpoints', 'sentinelone') ?></th>
                  </tr>
               </thead>
               <tbody>
                  <?php foreach ($topCves as $row):
                     $sev = (string)$row['severity'];
                     $cveLink = 'https://www.cve.org/CVERecord?id=' . rawurlencode((string)$row['cve_id']);
                  ?>
                  <tr>
                     <td>
                        <a class="s1-cve-link" href="<?= $h($cveLink) ?>" target="_blank" rel="noopener">
                           <?= $h($row['cve_id']) ?> <span class="ti ti-external-link" style="font-size:10px"></span>
                        </a><?= $kevBadge((string)$row['cve_id']) ?>
                     </td>
                     <td><span class="s1-badge <?= $severityClass($sev) ?>"><?= $h($sev) ?></span></td>
                     <td><?= $cvssChip($row['cvss_score'] ?? null, $sev) ?></td>
                     <td><?= $epssChip((string)$row['cve_id']) ?></td>
                     <td class="text-end"><strong><?= $h($row['agents_count']) ?></strong></td>
                  </tr>
                  <?php endforeach; ?>
                  <?php if ($topCves === []): ?>
                  <tr><td colspan="5" class="text-center s1-muted"><?= __('Sem dados.', 'sentinelone') ?></td></tr>
                  <?php endif; ?>
               </tbody>
            </table>
         </div>
      </section>

      <section class="sentinelone-panel" id="s1-anchor-apps">
         <div class="sentinelone-panel__head">
            <div class="sentinelone-panel__title">
               <span class="sentinelone-panel__icon"><span class="ti ti-app-window"></span></span>
               <div>
                  <h3><?= __('Aplicações mais vulneráveis', 'sentinelone') ?></h3>
                  <p><?= __('Produtos que concentram mais CVEs', 'sentinelone') ?></p>
               </div>
            </div>
         </div>
         <div class="sentinelone-panel__body" style="padding:0;overflow-x:auto">
            <table class="s1-cve-table">
               <thead>
                  <tr>
                     <th style="width:28px">#</th>
                     <th><?= __('Aplicação', 'sentinelone') ?></th>
                     <th class="text-end"><?= __('CVEs', 'sentinelone') ?></th>
                     <th class="text-end"><?= __('Endpoints', 'sentinelone') ?></th>
                  </tr>
               </thead>
               <tbody>
                  <?php
                  $maxApp = 0;
                  foreach ($topApps as $r) { $maxApp = max($maxApp, (int)$r['cve_count']); }
                  foreach ($topApps as $i => $row):
                     $cveCount = (int)$row['cve_count'];
                     $pct = $maxApp > 0 ? round($cveCount / $maxApp * 100) : 0;
                     $rank = $i + 1;
                  ?>
                  <tr>
                     <td><span class="s1-rank<?= $rank <= 3 ? ' s1-rank--top' : '' ?>"><?= $rank ?></span></td>
                     <td>
                        <div class="s1-app-cell">
                           <span class="s1-app-cell__name"><?= $h($row['application_name']) ?></span>
                           <div class="s1-meter"><div class="s1-meter__fill" style="width:<?= $pct ?>%"></div></div>
                        </div>
                     </td>
                     <td class="text-end">
                        <span class="s1-badge <?= (int)$row['top_rank'] <= 2 ? 's1-badge--critical' : 's1-badge--warning' ?>"><?= $h($cveCount) ?></span>
                     </td>
                     <td class="text-end"><?= $h($row['agents_count']) ?></td>
                  </tr>
                  <?php endforeach; ?>
                  <?php if ($topApps === []): ?>
                  <tr><td colspan="4" class="text-center s1-muted"><?= __('Sem dados.', 'sentinelone') ?></td></tr>
                  <?php endif; ?>
               </tbody>
            </table>
         </div>
      </section>

   </div>

   <!-- ░░ ENDPOINTS COM MAIS CVEs ░░ -->
   <section class="sentinelone-panel sentinelone-panel--wide" id="s1-anchor-endpoints" style="margin-bottom:1rem">
      <div class="sentinelone-panel__head">
         <div class="sentinelone-panel__title">
            <span class="sentinelone-panel__icon"><span class="ti ti-devices-pc"></span></span>
            <div>
               <h3><?= __('Endpoints com mais CVEs', 'sentinelone') ?></h3>
               <p><?= __('Priorize a remediação pelos ativos mais expostos', 'sentinelone') ?></p>
            </div>
         </div>
         <span class="s1-badge s1-badge--muted"><?= count($agents) ?></span>
      </div>
      <div class="sentinelone-panel__body" style="padding:0;overflow-x:auto">
         <table class="table table-vcenter table-hover mb-0">
            <thead>
               <tr>
                  <th><?= __('Endpoint', 'sentinelone') ?></th>
                  <th class="text-end"><?= __('CVEs totais', 'sentinelone') ?></th>
                  <th class="text-end"><?= __('Críticos', 'sentinelone') ?></th>
                  <th class="text-end"></th>
               </tr>
            </thead>
            <tbody>
               <?php foreach ($agents as $row):
                  $agentUrl  = $rootDoc . '/plugins/sentinelone/front/agent.form.php?id=' . (int)$row['agent_id'];
                  $glpiUrl   = $row['computers_id'] ? $rootDoc . '/front/computer.form.php?id=' . (int)$row['computers_id'] : '';
                  $hasCrit   = (int)$row['critical_count'] > 0;
               ?>
               <tr <?= $hasCrit ? "style='background:rgba(181,23,158,.04)'" : '' ?>>
                  <td class="fw-semibold">
                     <a href="<?= $h($agentUrl) ?>"><?= $h($row['computer_name'] ?? '—') ?></a>
                     <?php if ($glpiUrl): ?>
                     <a href="<?= $h($glpiUrl) ?>" class="text-muted ms-1" title="<?= $h(__('Ver computador GLPI', 'sentinelone')) ?>"><span class="ti ti-external-link" style="font-size:11px"></span></a>
                     <?php endif; ?>
                  </td>
                  <td class="text-end"><strong><?= $h($row['cve_count']) ?></strong></td>
                  <td class="text-end">
                     <?php if ($hasCrit): ?>
                     <span class="s1-badge s1-badge--critical"><?= $h($row['critical_count']) ?></span>
                     <?php else: ?>
                     <span class="s1-muted">0</span>
                     <?php endif; ?>
                  </td>
                  <td class="text-end">
                     <a href="<?= $h($agentUrl) ?>" class="btn btn-sm btn-outline-secondary">
                        <span class="ti ti-eye"></span> <?= __('Detalhes', 'sentinelone') ?>
                     </a>
                  </td>
               </tr>
               <?php endforeach; ?>
               <?php if ($agents === []): ?>
               <tr><td colspan="4" class="text-center s1-muted"><?= __('Nenhum endpoint com CVEs sincronizados.', 'sentinelone') ?></td></tr>
               <?php endif; ?>
            </tbody>
         </table>
      </div>
   </section>

   <?php endif; ?>

</div>

<?php \Html::footer(); ?>

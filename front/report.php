<?php

global $DB, $CFG_GLPI;

include('../../../inc/includes.php');

use GlpiPlugin\Sentinelone\Config as SentineloneConfig;
use GlpiPlugin\Sentinelone\Cve;
use GlpiPlugin\Sentinelone\Profile;
use GlpiPlugin\Sentinelone\RogueDevice;
use GlpiPlugin\Sentinelone\Sync;
use GlpiPlugin\Sentinelone\Threat;

if (!Plugin::isPluginActive('sentinelone')) {
   Html::displayErrorAndDie('Plugin SentinelOne não está ativo.');
}

Session::checkLoginUser();

$h = static fn($v): string => htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

$period = (int)($_GET['period'] ?? 30);
if (!in_array($period, [7, 30, 90], true)) {
   $period = 30;
}

$trendDays   = min($period, 30);
$periodLabel = date('d/m/Y', strtotime("-{$period} days")) . ' – ' . date('d/m/Y');

// ── Data ──────────────────────────────────────────────────────────────────────
$s         = Sync::stats();
$cveStats  = Cve::getGlobalStats();
$cvesBySev = $cveStats['by_severity'] ?? [];

$cutoff     = date('Y-m-d H:i:s', strtotime("-{$period} days"));
$newThreats = 0;
foreach ($DB->request([
   'COUNT' => 'cpt',
   'FROM'  => Threat::getTable(),
   'WHERE' => ['detected_at' => ['>=', $cutoff]],
]) as $r) {
   $newThreats = (int)($r['cpt'] ?? 0);
}

// Trend per day for the web view (up to 30 days)
$trend  = [];
$oldest = date('Y-m-d 00:00:00', strtotime('-' . ($trendDays - 1) . ' days'));
for ($i = $trendDays - 1; $i >= 0; $i--) {
   $trend[date('Y-m-d', strtotime("-{$i} days"))] = 0;
}
foreach ($DB->request([
   'SELECT' => ['detected_at'],
   'FROM'   => Threat::getTable(),
   'WHERE'  => ['NOT' => ['detected_at' => null], 'detected_at' => ['>=', $oldest]],
]) as $row) {
   $day = substr((string)($row['detected_at'] ?? ''), 0, 10);
   if (array_key_exists($day, $trend)) {
      $trend[$day]++;
   }
}

// ── Protection Index ──────────────────────────────────────────────────────────
$covered     = (int)($s['agents_total']          ?? 0);
$unprotected = (int)($s['computers_unprotected'] ?? 0);
$total       = $covered + $unprotected;
$pct         = $total > 0 ? (int)round($covered / $total * 100) : 0;
$penalty     = min(20, (int)($s['agents_infected'] ?? 0) * 3)
             + min(10, (int)($s['agents_outdated'] ?? 0) * 0.5)
             + min(5,  (int)($s['agents_offline']  ?? 0) * 0.1);
$idx         = max(0, min(100, (int)round($pct - $penalty)));

[$idxColor, $idxLabel] = match(true) {
   $idx >= 90 => ['#22c55e', 'Proteção Excelente'],
   $idx >= 75 => ['#3b82f6', 'Proteção Satisfatória'],
   $idx >= 60 => ['#f59e0b', 'Requer Atenção'],
   default    => ['#ef4444', 'Nível Crítico'],
};

// ── Numeric shorthands ────────────────────────────────────────────────────────
$agTotal    = (int)($s['agents_total']       ?? 0);
$agOnline   = (int)($s['agents_online']      ?? 0);
$agOffline  = (int)($s['agents_offline']     ?? 0);
$agInfected = (int)($s['agents_infected']    ?? 0);
$agOutdated = (int)($s['agents_outdated']    ?? 0);
$agQuar     = (int)($s['agents_quarantined'] ?? 0);
$agUnlinked = (int)($s['agents_unlinked']    ?? 0);
$thrTotal   = (int)($s['threats_total']      ?? 0);
$thrNoTck   = (int)($s['threats_no_ticket']  ?? 0);
$cveTotal   = (int)($cveStats['total']       ?? 0);
$cveCrit    = (int)($cvesBySev['CRITICAL']   ?? 0);
$cveHigh    = (int)($cvesBySev['HIGH']       ?? 0);
$cveMed     = (int)($cvesBySev['MEDIUM']     ?? 0);
$rogues     = $DB->tableExists(RogueDevice::getTable()) ? RogueDevice::countTotal() : 0;
$infected   = array_slice($s['attention_agents'] ?? [], 0, 8);
$genAt      = date('d/m/Y \à\s H:i');
$maxCount   = max(1, ...array_values($trend));
$dayNames   = ['Dom', 'Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb'];
$rootDoc    = (string)($CFG_GLPI['root_doc'] ?? '');

Html::header('SentinelOne – Relatório Executivo', '', 'plugins', 'sentinelone', 'report');
?>
<style>
/* ─── Reset / Base ─────────────────────────────────────────────────── */
.s1r { margin: -20px -20px 0; background: #f0eeff; min-height: calc(100vh - 60px);
       font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif; }

/* ─── Toolbar ──────────────────────────────────────────────────────── */
.s1r-toolbar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
               background: #fff; border-bottom: 1px solid #e5e7eb;
               padding: 10px 28px; position: sticky; top: 0; z-index: 100; }
.s1r-lbl { font-size: 12px; color: #9ca3af; font-weight: 500; }
.s1r-pill { padding: 5px 18px; border-radius: 20px; text-decoration: none;
            font-size: 12px; font-weight: 700; border: none; cursor: pointer; }
.s1r-pill.on  { background: #6b2cf5; color: #fff; }
.s1r-pill.off { background: #f3f0ff; color: #2d1f6e; }
.s1r-pill.off:hover { background: #ede9fb; }
.s1r-print { background: #2d1f6e; color: #fff; padding: 7px 22px; border: none;
             border-radius: 7px; cursor: pointer; font-size: 13px; font-weight: 700;
             margin-left: auto; letter-spacing: .3px; }
.s1r-print:hover { background: #3d2a8e; }

/* ─── Body ─────────────────────────────────────────────────────────── */
.s1r-body { max-width: 1320px; margin: 0 auto; padding: 24px 28px 32px; }

/* ─── Hero ─────────────────────────────────────────────────────────── */
.s1r-hero { border-radius: 16px; overflow: hidden; margin-bottom: 20px;
            background: linear-gradient(135deg,#1a1045 0%,#2d1f6e 55%,#4c1d95 100%);
            display: flex; align-items: center; gap: 0; }
.s1r-hero__left { flex: 1; padding: 36px 40px; color: #fff; }
.s1r-hero__logo { font-size: 48px; font-weight: 900; letter-spacing: -3px; line-height: 1; }
.s1r-hero__brand { font-size: 10px; letter-spacing: 6px; text-transform: uppercase;
                   color: #9d85e8; margin: 3px 0 16px; }
.s1r-hero__title { font-size: 26px; font-weight: 700; margin: 0 0 6px; }
.s1r-hero__period { font-size: 14px; color: #c4b8f5; }
.s1r-hero__right { display: flex; align-items: center; gap: 48px;
                   padding: 36px 48px 36px 0; }

/* Donut Gauge */
.s1r-gauge-wrap { display: flex; flex-direction: column; align-items: center; gap: 10px; }
.s1r-gauge { position: relative; width: 180px; height: 180px; flex-shrink: 0; }
.s1r-gauge__ring { width: 180px; height: 180px; border-radius: 50%;
                   background: conic-gradient(<?= $idxColor ?> <?= $idx ?>%, rgba(255,255,255,.12) 0%); }
.s1r-gauge__inner { position: absolute; inset: 22px; background: #1a1045;
                    border-radius: 50%; display: flex; flex-direction: column;
                    align-items: center; justify-content: center; }
.s1r-gauge__pct { font-size: 38px; font-weight: 900; color: <?= $idxColor ?>;
                  line-height: 1; letter-spacing: -1px; }
.s1r-gauge__sub { font-size: 9px; color: #c4b8f5; text-transform: uppercase;
                  letter-spacing: 2px; margin-top: 2px; }
.s1r-gauge__label { font-size: 14px; font-weight: 700; color: <?= $idxColor ?>; }
.s1r-gauge__desc  { font-size: 11px; color: #9d85e8; margin-top: 2px; }

.s1r-hero__stats { display: flex; flex-direction: column; gap: 20px; }
.s1r-hstat { display: flex; flex-direction: column; gap: 2px; }
.s1r-hstat__val { font-size: 32px; font-weight: 900; color: #fff; line-height: 1; }
.s1r-hstat__val.red { color: #fca5a5; }
.s1r-hstat__lbl { font-size: 10px; color: #9d85e8; text-transform: uppercase; letter-spacing: 1.5px; }

/* ─── KPI Grid ─────────────────────────────────────────────────────── */
.s1r-kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 20px; }
.s1r-kpi { background: #fff; border-radius: 12px; padding: 22px 24px;
           border-left: 4px solid transparent; }
.s1r-kpi--cov { border-color: #7c3aed; }
.s1r-kpi--thr { border-color: #ef4444; }
.s1r-kpi--risk{ border-color: #f59e0b; }
.s1r-kpi--cve { border-color: #22c55e; }
.s1r-kpi__eye { font-size: 10px; font-weight: 700; letter-spacing: 2.5px;
                text-transform: uppercase; margin-bottom: 10px; }
.s1r-kpi--cov .s1r-kpi__eye  { color: #7c3aed; }
.s1r-kpi--thr .s1r-kpi__eye  { color: #ef4444; }
.s1r-kpi--risk .s1r-kpi__eye { color: #d97706; }
.s1r-kpi--cve  .s1r-kpi__eye { color: #16a34a; }
.s1r-kpi__num { font-size: 44px; font-weight: 900; line-height: 1; margin-bottom: 4px; }
.s1r-kpi--cov  .s1r-kpi__num { color: #2d1f6e; }
.s1r-kpi--thr  .s1r-kpi__num { color: #dc2626; }
.s1r-kpi--risk .s1r-kpi__num { color: #92400e; }
.s1r-kpi--cve  .s1r-kpi__num { color: #166534; }
.s1r-kpi__num span { font-size: 18px; font-weight: 400; color: #9ca3af; }
.s1r-kpi__sub { font-size: 12px; color: #6b7280; line-height: 1.5; margin-top: 6px; }
.s1r-kpi__tag { display: inline-block; padding: 2px 9px; border-radius: 20px;
                font-size: 11px; font-weight: 700; margin-top: 6px; }
.s1r-tag-ok  { background: #dcfce7; color: #16a34a; }
.s1r-tag-bad { background: #fee2e2; color: #dc2626; }
.s1r-tag-warn{ background: #fef3c7; color: #d97706; }
.s1r-tag-neu { background: #f3f0ff; color: #7c3aed; }

/* ─── Chart ────────────────────────────────────────────────────────── */
.s1r-chart-card { background: #fff; border-radius: 12px; padding: 24px 26px; margin-bottom: 20px; }
.s1r-section-title { font-size: 11px; font-weight: 700; letter-spacing: 3.5px;
                     text-transform: uppercase; color: #9ca3af; margin-bottom: 18px; }
.s1r-bars { display: flex; align-items: flex-end; gap: 3px;
            height: 160px; background: #f8f6ff; border-radius: 10px;
            padding: 14px 12px 0; margin-bottom: 6px; }
.s1r-bar-col { flex: 1; display: flex; align-items: flex-end; height: 100%; }
.s1r-bar { width: 100%; border-radius: 4px 4px 0 0; min-height: 3px; transition: height .3s; }
.s1r-bar-labels { display: flex; gap: 3px; }
.s1r-bar-lbl { flex: 1; display: flex; flex-direction: column; align-items: center;
               font-size: 9px; gap: 1px; }
.s1r-bar-lbl span { color: #9ca3af; }
.s1r-bar-lbl strong { color: #2d1f6e; font-size: 10px; }

/* ─── Bottom Panels ────────────────────────────────────────────────── */
.s1r-grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px; }
.s1r-panel { background: #fff; border-radius: 12px; padding: 24px 26px; }
.s1r-panel--wide { grid-column: span 2; }
.s1r-row { display: flex; justify-content: space-between; align-items: center;
           padding: 10px 0; border-bottom: 1px solid #f5f3ff; font-size: 13px; }
.s1r-row:last-child { border-bottom: none; }
.s1r-row__lbl { color: #6b7280; display: flex; align-items: center; gap: 8px; }
.s1r-row__val { font-weight: 800; font-size: 16px; color: #2d1f6e; }
.s1r-row__val.red  { color: #dc2626; }
.s1r-row__val.warn { color: #d97706; }
.s1r-row__val.ok   { color: #16a34a; }
.s1r-dot { width: 9px; height: 9px; border-radius: 50%; flex-shrink: 0; }
.s1r-empty { padding: 20px; text-align: center; color: #22c55e;
             font-size: 13px; font-weight: 600; }

.s1r-threat-table { width: 100%; border-collapse: collapse; }
.s1r-threat-table th { font-size: 10px; text-transform: uppercase; letter-spacing: 1.5px;
                       color: #9ca3af; font-weight: 600; padding: 0 12px 8px 0;
                       border-bottom: 1px solid #f3f0ff; text-align: left; }
.s1r-threat-table td { padding: 9px 12px 9px 0; font-size: 13px; color: #374151;
                       border-bottom: 1px solid #f9f8ff; vertical-align: middle; }
.s1r-threat-table tr:last-child td { border-bottom: none; }
.s1r-badge { display: inline-block; padding: 2px 9px; border-radius: 20px;
             font-size: 11px; font-weight: 700; }
.s1r-badge-red  { background: #fee2e2; color: #dc2626; }
.s1r-badge-warn { background: #fef3c7; color: #b45309; }

/* ─── Footer ───────────────────────────────────────────────────────── */
.s1r-foot { background: #2d1f6e; border-radius: 12px; padding: 18px 28px;
            display: flex; justify-content: space-between; align-items: center; }
.s1r-foot__l { font-size: 12px; color: #c4b8f5; }
.s1r-foot__r { font-size: 12px; color: #7c6db5; }

/* ─── Print ────────────────────────────────────────────────────────── */
@media print {
   .s1r-toolbar, .glpi_header, .glpi_menu_container, .glpi_footer,
   #tab_menu, .breadcrumbs-container, nav, .sidebar { display: none !important; }
   .s1r { margin: 0 !important; background: #fff; }
   .s1r-body { padding: 12px; max-width: 100%; }
   .s1r-hero, .s1r-kpi, .s1r-chart-card, .s1r-panel, .s1r-foot { break-inside: avoid; }
   .s1r-hero { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
}
</style>

<div class="s1r">

  <!-- TOOLBAR -->
  <div class="s1r-toolbar">
    <span class="s1r-lbl">Período:</span>
    <?php foreach ([7 => '7 dias', 30 => '30 dias', 90 => '90 dias'] as $p => $lbl): ?>
    <a href="?period=<?= $p ?>" class="s1r-pill <?= $period === $p ? 'on' : 'off' ?>"><?= $lbl ?></a>
    <?php endforeach; ?>
    <button class="s1r-print" onclick="window.print()">&#8595;&nbsp; Exportar PDF</button>
  </div>

  <div class="s1r-body">

    <!-- HERO -->
    <div class="s1r-hero">
      <div class="s1r-hero__left">
        <div class="s1r-hero__logo">S1</div>
        <div class="s1r-hero__brand">SentinelOne</div>
        <div class="s1r-hero__title">Relatório Executivo de Segurança</div>
        <div class="s1r-hero__period">Período: <?= $h($periodLabel) ?></div>
      </div>
      <div class="s1r-hero__right">
        <div class="s1r-gauge-wrap">
          <div class="s1r-gauge">
            <div class="s1r-gauge__ring"></div>
            <div class="s1r-gauge__inner">
              <div class="s1r-gauge__pct"><?= $idx ?>%</div>
              <div class="s1r-gauge__sub">proteção</div>
            </div>
          </div>
          <div class="s1r-gauge__label"><?= $h($idxLabel) ?></div>
        </div>
        <div class="s1r-hero__stats">
          <div class="s1r-hstat">
            <div class="s1r-hstat__val"><?= $agTotal ?><span style="font-size:16px;font-weight:400;color:#9d85e8"> /<?= $total ?></span></div>
            <div class="s1r-hstat__lbl">endpoints cobertos</div>
          </div>
          <div class="s1r-hstat">
            <div class="s1r-hstat__val <?= $newThreats > 0 ? 'red' : '' ?>"><?= $newThreats ?></div>
            <div class="s1r-hstat__lbl">ameaças no período</div>
          </div>
          <div class="s1r-hstat">
            <div class="s1r-hstat__val <?= $agInfected > 0 ? 'red' : '' ?>"><?= $agInfected ?></div>
            <div class="s1r-hstat__lbl">endpoints em risco</div>
          </div>
        </div>
      </div>
    </div>

    <!-- KPI CARDS -->
    <div class="s1r-kpis">
      <div class="s1r-kpi s1r-kpi--cov">
        <div class="s1r-kpi__eye">Cobertura</div>
        <div class="s1r-kpi__num"><?= $pct ?><span>%</span></div>
        <div class="s1r-kpi__sub"><?= $covered ?> de <?= $total ?> dispositivos protegidos</div>
        <?php if ($unprotected > 0): ?>
        <span class="s1r-kpi__tag s1r-tag-warn"><?= $unprotected ?> sem agente</span>
        <?php else: ?>
        <span class="s1r-kpi__tag s1r-tag-ok">Cobertura total</span>
        <?php endif; ?>
      </div>
      <div class="s1r-kpi s1r-kpi--thr">
        <div class="s1r-kpi__eye">Ameaças Detectadas</div>
        <div class="s1r-kpi__num"><?= $newThreats ?><span> período</span></div>
        <div class="s1r-kpi__sub">Total acumulado: <?= $thrTotal ?></div>
        <?php if ($thrNoTck > 0): ?>
        <span class="s1r-kpi__tag s1r-tag-bad"><?= $thrNoTck ?> sem ticket</span>
        <?php else: ?>
        <span class="s1r-kpi__tag s1r-tag-ok">Todos com ticket</span>
        <?php endif; ?>
      </div>
      <div class="s1r-kpi s1r-kpi--risk">
        <div class="s1r-kpi__eye">Endpoints em Risco</div>
        <div class="s1r-kpi__num"><?= $agInfected ?><span> ativos</span></div>
        <div class="s1r-kpi__sub">Desatualizados: <?= $agOutdated ?> &nbsp;·&nbsp; Offline: <?= $agOffline ?></div>
        <?php if ($agQuar > 0): ?>
        <span class="s1r-kpi__tag s1r-tag-warn"><?= $agQuar ?> em quarentena</span>
        <?php elseif ($agInfected === 0): ?>
        <span class="s1r-kpi__tag s1r-tag-ok">Nenhum infectado</span>
        <?php endif; ?>
      </div>
      <div class="s1r-kpi s1r-kpi--cve">
        <div class="s1r-kpi__eye">Vulnerabilidades CVE</div>
        <div class="s1r-kpi__num"><?= $cveTotal ?><span> total</span></div>
        <div class="s1r-kpi__sub">Críticas: <?= $cveCrit ?> &nbsp;·&nbsp; Altas: <?= $cveHigh ?> &nbsp;·&nbsp; Médias: <?= $cveMed ?></div>
        <?php if ($cveCrit > 0): ?>
        <span class="s1r-kpi__tag s1r-tag-bad"><?= $cveCrit ?> críticas</span>
        <?php elseif ($cveTotal === 0): ?>
        <span class="s1r-kpi__tag s1r-tag-ok">Nenhuma CVE</span>
        <?php else: ?>
        <span class="s1r-kpi__tag s1r-tag-neu"><?= $cveHigh ?> altas</span>
        <?php endif; ?>
      </div>
    </div>

    <!-- TREND CHART -->
    <div class="s1r-chart-card">
      <div class="s1r-section-title">Tendência de Ameaças — últimos <?= $trendDays ?> dias</div>
      <div class="s1r-bars">
        <?php foreach ($trend as $date => $count):
          $barH = (int)max(3, round($count / $maxCount * 100));
          $today = date('Y-m-d');
          $bg = match(true) {
             $count === 0 => '#ddd6fc',
             $count <= 2  => '#a78bfa',
             $count <= 5  => '#7c3aed',
             default      => '#3d0fa0',
          };
          $outline = ($date === $today) ? 'outline:2px solid #6b2cf5;outline-offset:2px;' : '';
        ?>
        <div class="s1r-bar-col">
          <div class="s1r-bar" style="height:<?= $barH ?>%;background:<?= $bg ?>;<?= $outline ?>"></div>
        </div>
        <?php endforeach; ?>
      </div>
      <div class="s1r-bar-labels">
        <?php foreach ($trend as $date => $count):
          $lbl = $dayNames[(int)date('w', strtotime($date))];
        ?>
        <div class="s1r-bar-lbl"><span><?= $lbl ?></span><strong><?= $count ?></strong></div>
        <?php endforeach; ?>
      </div>
    </div>

    <!-- BOTTOM PANELS -->
    <div class="s1r-grid2">

      <!-- Devices requiring attention -->
      <div class="s1r-panel">
        <div class="s1r-section-title">Dispositivos Requerendo Atenção</div>
        <?php if (empty($infected)): ?>
        <div class="s1r-empty">&#10003; Nenhum dispositivo com ameaça ativa</div>
        <?php else: ?>
        <table class="s1r-threat-table">
          <thead><tr><th>Hostname</th><th>Status</th><th>Desde</th></tr></thead>
          <tbody>
          <?php foreach ($infected as $ag):
            $host = $h((string)($ag['computer_name'] ?? $ag['hostname'] ?? '—'));
            $since = substr((string)($ag['last_active_at'] ?? ''), 0, 10);
          ?>
          <tr>
            <td><span class="s1r-dot" style="background:#ef4444"></span><?= $host ?></td>
            <td><span class="s1r-badge s1r-badge-red">Ameaça ativa</span></td>
            <td style="color:#9ca3af;font-size:12px"><?= $since ?: '—' ?></td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
        <?php endif; ?>
      </div>

      <!-- Operational summary -->
      <div class="s1r-panel">
        <div class="s1r-section-title">Resumo Operacional</div>
        <div class="s1r-row">
          <div class="s1r-row__lbl"><span class="s1r-dot" style="background:#22c55e"></span>Agentes online</div>
          <div class="s1r-row__val ok"><?= $agOnline ?></div>
        </div>
        <div class="s1r-row">
          <div class="s1r-row__lbl"><span class="s1r-dot" style="background:#9ca3af"></span>Agentes offline</div>
          <div class="s1r-row__val <?= $agOffline > 0 ? 'warn' : '' ?>"><?= $agOffline ?></div>
        </div>
        <div class="s1r-row">
          <div class="s1r-row__lbl"><span class="s1r-dot" style="background:#f59e0b"></span>Desatualizados</div>
          <div class="s1r-row__val <?= $agOutdated > 0 ? 'warn' : 'ok' ?>"><?= $agOutdated ?></div>
        </div>
        <div class="s1r-row">
          <div class="s1r-row__lbl"><span class="s1r-dot" style="background:#6b7280"></span>Sem vínculo GLPI</div>
          <div class="s1r-row__val <?= $agUnlinked > 0 ? 'warn' : 'ok' ?>"><?= $agUnlinked ?></div>
        </div>
        <div class="s1r-row">
          <div class="s1r-row__lbl"><span class="s1r-dot" style="background:#8b5cf6"></span>Dispositivos Rogues</div>
          <div class="s1r-row__val <?= $rogues > 0 ? 'warn' : 'ok' ?>"><?= $rogues ?></div>
        </div>
        <div class="s1r-row">
          <div class="s1r-row__lbl"><span class="s1r-dot" style="background:#dc2626"></span>CVEs Críticas</div>
          <div class="s1r-row__val <?= $cveCrit > 0 ? 'red' : 'ok' ?>"><?= $cveCrit ?></div>
        </div>
        <div class="s1r-row">
          <div class="s1r-row__lbl"><span class="s1r-dot" style="background:#ef4444"></span>Ameaças sem ticket</div>
          <div class="s1r-row__val <?= $thrNoTck > 0 ? 'red' : 'ok' ?>"><?= $thrNoTck ?></div>
        </div>
      </div>

    </div>

    <!-- FOOTER -->
    <div class="s1r-foot">
      <div class="s1r-foot__l">Gerado automaticamente em <?= $h($genAt) ?> &bull; Plugin SentinelOne para GLPI</div>
      <div class="s1r-foot__r">Período: <?= $h($periodLabel) ?></div>
    </div>

  </div><!-- .s1r-body -->
</div><!-- .s1r -->
<?php
Html::footer();

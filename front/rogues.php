<?php

use GlpiPlugin\Sentinelone\Profile;
use GlpiPlugin\Sentinelone\RogueDevice;
use GlpiPlugin\Sentinelone\Sync;

include('../../../inc/includes.php');

\Session::checkRight(Profile::RIGHT_READ, READ);

global $CFG_GLPI;

$h = static fn($v): string => htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$rootDoc     = (string)($CFG_GLPI['root_doc'] ?? '');
$dashboardUrl = $rootDoc . '/plugins/sentinelone/front/dashboard.php';
$syncUrl      = $rootDoc . '/plugins/sentinelone/front/sync.form.php';
$hasSyncRight = Profile::hasSyncRight();

$limit  = max(10, min(1000, (int)($_GET['limit'] ?? 200)));
$offset = max(0, (int)($_GET['offset'] ?? 0));

// ── CSV export ────────────────────────────────────────────────────────────────
if (isset($_GET['export']) && $_GET['export'] === 'csv') {
   $rows = RogueDevice::getList(5000, 0);
   header('Content-Type: text/csv; charset=UTF-8');
   header('Content-Disposition: attachment; filename="sentinelone-rogues-' . date('Ymd-His') . '.csv"');
   header('Cache-Control: no-cache, no-store, must-revalidate');
   $out = fopen('php://output', 'w');
   fprintf($out, "\xEF\xBB\xBF");
   fputcsv($out, ['Hostname', 'IP', 'IP Externo', 'MAC', 'OS', 'Classificacao', 'Fabricante', 'Site', 'Agente Detector', 'Portas abertas', 'Primeira vez visto', 'Ultimo avistamento'], ';');
   foreach ($rows as $row) {
      fputcsv($out, [
         $row['hostname']             ?? '',
         $row['ip']                   ?? '',
         $row['external_ip']          ?? '',
         $row['mac']                  ?? '',
         $row['os']                   ?? '',
         $row['classification']       ?? '',
         $row['vendor']               ?? '',
         $row['site_name']            ?? '',
         $row['detecting_agent_name'] ?? '',
         RogueDevice::formatPorts((string)($row['open_ports'] ?? '')),
         $row['first_seen'] ?? '',
         $row['last_seen']  ?? '',
      ], ';');
   }
   fclose($out);
   exit;
}

$total = RogueDevice::countTotal();
$rows  = RogueDevice::getList($limit, $offset);

$classifBadge = static function (string $c) use ($h): string {
   $map = [
      'workstation'    => 's1-badge--muted',
      'server'         => 's1-badge--warning',
      'printer'        => 's1-badge--muted',
      'router'         => 's1-badge--warning',
      'switch'         => 's1-badge--muted',
      'firewall'       => 's1-badge--ok',
      'camera'         => 's1-badge--muted',
      'iot'            => 's1-badge--critical',
      'mobile'         => 's1-badge--muted',
      'unknown'        => 's1-badge--muted',
   ];
   $key   = strtolower($c);
   $class = $map[$key] ?? 's1-badge--muted';
   $label = $c !== '' ? $c : 'Unknown';
   return "<span class='s1-badge {$class}'>" . $h($label) . "</span>";
};

\Html::header(__('Dispositivos rogues — SentinelOne', 'sentinelone'), '', 'plugins', 'sentinelone');
?>

<div class="sentinelone-wrap">

   <!-- breadcrumb / nav -->
   <div class="sentinelone-page-nav" style="display:flex;align-items:center;gap:8px;margin-bottom:16px;font-size:13px">
      <a href="<?= $h($dashboardUrl) ?>" class="btn btn-sm btn-secondary">
         <span class="ti ti-arrow-left"></span> <?= __('Dashboard', 'sentinelone') ?>
      </a>
      <span style="color:#9ca3af">/</span>
      <span><?= __('Dispositivos rogues', 'sentinelone') ?></span>
   </div>

   <section class="sentinelone-panel sentinelone-panel--wide">
      <div class="sentinelone-panel__head">
         <span class="ti ti-ghost"></span>
         <h3><?= __('Dispositivos rogues detectados pelo Ranger', 'sentinelone') ?></h3>
         <span class="s1-badge <?= $total > 0 ? 's1-badge--warning' : 's1-badge--ok' ?>">
            <?= sprintf(_n('%d dispositivo', '%d dispositivos', $total, 'sentinelone'), $total) ?>
         </span>
         <div style="flex:1"></div>
         <?php if ($hasSyncRight): ?>
         <form method="post" action="<?= $h($syncUrl) ?>" style="display:inline">
            <input type="hidden" name="action" value="syncrogues">
            <input type="hidden" name="_glpi_csrf_token" value="<?= \Session::getNewCSRFToken() ?>">
            <button class="btn btn-sm btn-secondary" type="submit">
               <span class="ti ti-refresh"></span> <?= __('Sincronizar agora', 'sentinelone') ?>
            </button>
         </form>
         <?php endif; ?>
         <?php if ($total > 0): ?>
         <a class="btn btn-sm btn-secondary" href="?export=csv">
            <span class="ti ti-download"></span> CSV
         </a>
         <?php endif; ?>
      </div>

      <?php if ($total === 0): ?>
      <div class="sentinelone-panel__body">
         <div class="alert alert-info" style="margin:0">
            <span class="ti ti-info-circle"></span>
            <?= __('Nenhum dispositivo rogue encontrado. Verifique se o Ranger esta habilitado na console SentinelOne e se a sincronizacao ja foi executada.', 'sentinelone') ?>
         </div>
      </div>
      <?php else: ?>
      <div class="sentinelone-panel__body" style="padding:0;overflow-x:auto">
         <table class="s1-rogues-table">
            <thead>
               <tr>
                  <th><?= __('Hostname', 'sentinelone') ?></th>
                  <th><?= __('IP', 'sentinelone') ?></th>
                  <th><?= __('MAC', 'sentinelone') ?></th>
                  <th><?= __('OS', 'sentinelone') ?></th>
                  <th><?= __('Classificacao', 'sentinelone') ?></th>
                  <th><?= __('Fabricante', 'sentinelone') ?></th>
                  <th><?= __('Site', 'sentinelone') ?></th>
                  <th><?= __('Agente detector', 'sentinelone') ?></th>
                  <th><?= __('Portas', 'sentinelone') ?></th>
                  <th><?= __('Ultimo avistamento', 'sentinelone') ?></th>
               </tr>
            </thead>
            <tbody>
               <?php foreach ($rows as $row): ?>
               <tr>
                  <td class="s1-rogues-host">
                     <?= $row['hostname'] ? $h($row['hostname']) : '<span class="s1-muted">—</span>' ?>
                  </td>
                  <td>
                     <code class="s1-ip"><?= $h($row['ip'] ?? '—') ?></code>
                     <?php if (!empty($row['external_ip']) && $row['external_ip'] !== $row['ip']): ?>
                     <br><small class="s1-muted"><?= $h($row['external_ip']) ?></small>
                     <?php endif; ?>
                  </td>
                  <td><code class="s1-mac"><?= $h($row['mac'] ?? '—') ?></code></td>
                  <td><?= $h($row['os'] ?? '—') ?></td>
                  <td><?= $classifBadge((string)($row['classification'] ?? '')) ?></td>
                  <td><?= $h($row['vendor'] ?? '—') ?></td>
                  <td><?= $h($row['site_name'] ?? '—') ?></td>
                  <td class="s1-muted"><?= $h($row['detecting_agent_name'] ?? '—') ?></td>
                  <td class="s1-ports"><?= $h(RogueDevice::formatPorts((string)($row['open_ports'] ?? ''))) ?></td>
                  <td class="s1-muted">
                     <?= $row['last_seen']
                        ? date('d/m/Y H:i', strtotime((string)$row['last_seen']))
                        : '—' ?>
                  </td>
               </tr>
               <?php endforeach; ?>
            </tbody>
         </table>
      </div>

      <?php if ($total > $limit): ?>
      <div class="sentinelone-panel__body" style="padding:10px 16px;border-top:1px solid var(--s1-border);display:flex;gap:8px;align-items:center;font-size:12px;color:#6b7280">
         <span><?= sprintf(__('Exibindo %d de %d dispositivos', 'sentinelone'), count($rows), $total) ?></span>
         <?php if ($offset > 0): ?>
         <a class="btn btn-sm btn-secondary" href="?limit=<?= $limit ?>&offset=<?= max(0, $offset - $limit) ?>"><?= __('Anterior', 'sentinelone') ?></a>
         <?php endif; ?>
         <?php if ($offset + $limit < $total): ?>
         <a class="btn btn-sm btn-secondary" href="?limit=<?= $limit ?>&offset=<?= $offset + $limit ?>"><?= __('Proximo', 'sentinelone') ?></a>
         <?php endif; ?>
      </div>
      <?php endif; ?>
      <?php endif; ?>
   </section>

</div>

<?php \Html::footer(); ?>

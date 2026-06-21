<?php

use GlpiPlugin\Sentinelone\Diagnostics;
use GlpiPlugin\Sentinelone\FailedTicket;
use GlpiPlugin\Sentinelone\Profile;
use GlpiPlugin\Sentinelone\Sync;

include('../../../inc/includes.php');

\Session::checkRight(Profile::RIGHT_CONFIG, READ);

global $CFG_GLPI;

$h = static fn($v): string => htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$rootDoc = (string)($CFG_GLPI['root_doc'] ?? '');
$selfUrl = $rootDoc . '/plugins/sentinelone/front/diagnostics.php';

// O kernel do GLPI 11 valida o CSRF automaticamente no POST; nao chamar checkCSRF aqui.
$permResult = null;
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
   $action = (string)($_POST['action'] ?? '');

   if ($action === 'retry_now') {
      \Session::checkRight(Profile::RIGHT_CONFIG, UPDATE);
      $r = Sync::retryFailedTickets();
      if (($r['status'] ?? '') === 'locked') {
         \Session::addMessageAfterRedirect('Reprocessamento ja em andamento (lock ativo). Tente novamente em instantes.', false, WARNING);
      } else {
         \Session::addMessageAfterRedirect(sprintf('Fila reprocessada: %d resolvido(s), %d ainda pendente(s).', (int)($r['resolved'] ?? 0), (int)($r['failed'] ?? 0)));
      }
      \Html::redirect($selfUrl);
      exit;
   }

   if ($action === 'check_perms') {
      \Session::checkRight(Profile::RIGHT_CONFIG, UPDATE);
      $permResult = Sync::checkPermissions();
   }
}

$tables    = Diagnostics::tables();
$crons     = Diagnostics::crons();
$lastSyncs = Diagnostics::lastSyncs();
$locks     = Diagnostics::locks();
$pending   = Diagnostics::retryPending();

$csrf = \Session::getNewCSRFToken();

\Html::header('Diagnostico SentinelOne', $_SERVER['PHP_SELF'], 'plugins', 'sentinelone');
?>
<div class="page-body">
<div class="container-fluid mt-3">

<div class="d-flex align-items-center gap-2 mb-3">
   <a href="<?= $h($rootDoc . '/plugins/sentinelone/front/dashboard.php') ?>" class="btn btn-sm btn-outline-secondary">
      <span class="ti ti-arrow-left"></span> Voltar
   </a>
   <h2 class="mb-0 flex-grow-1"><span class="ti ti-stethoscope"></span> Auto-diagnostico</h2>
</div>

<div class="row g-3">

<!-- Permissoes do token -->
<div class="col-lg-6">
<div class="sentinelone-panel">
   <div class="sentinelone-panel__head"><h3>Permissoes do token</h3></div>
   <div class="sentinelone-panel__body">
      <p class="text-muted">Testa o acesso do token da API a cada modulo do SentinelOne. Util quando um sync nao traz dados (tipicamente 403 de Ranger ou Vulnerability Management).</p>
      <form method="post" action="<?= $h($selfUrl) ?>" class="mb-3">
         <input type="hidden" name="_glpi_csrf_token" value="<?= $h($csrf) ?>">
         <input type="hidden" name="action" value="check_perms">
         <button class="btn btn-sm btn-primary" type="submit"><span class="ti ti-plug-connected"></span> Testar permissoes agora</button>
      </form>
      <?php if ($permResult !== null): ?>
         <?php if (!($permResult['configured'] ?? false)): ?>
            <div class="alert alert-warning mb-0">Integracao nao configurada (base_url / token ausentes).</div>
         <?php else: ?>
            <div class="table-responsive">
            <table class="table table-sm table-vcenter mb-0">
            <thead><tr><th>Modulo</th><th>Status</th><th>Latencia</th></tr></thead>
            <tbody>
            <?php foreach ($permResult['modules'] as $m): ?>
               <tr>
                  <td><?= $h($m['name']) ?></td>
                  <td>
                     <?php if ($m['ok']): ?>
                        <span class="badge bg-success">OK</span>
                     <?php else: ?>
                        <span class="badge bg-danger"><?= $h($m['status']) ?></span>
                        <?php if (($m['detail'] ?? '') !== ''): ?>
                           <div class="small text-muted text-break"><?= $h(mb_substr((string)$m['detail'], 0, 160)) ?></div>
                        <?php endif; ?>
                     <?php endif; ?>
                  </td>
                  <td class="text-muted"><?= (int)$m['ms'] ?> ms</td>
               </tr>
            <?php endforeach; ?>
            </tbody>
            </table>
            </div>
         <?php endif; ?>
      <?php endif; ?>
   </div>
</div>
</div>

<!-- Fila de retry -->
<div class="col-lg-6">
<div class="sentinelone-panel">
   <div class="sentinelone-panel__head"><h3>Fila de retry (dead-letter)</h3></div>
   <div class="sentinelone-panel__body">
      <p class="mb-2">Tickets de ameaca que falharam ao ser criados ficam aqui para reprocessamento, em vez de abortar o sync.</p>
      <div class="d-flex align-items-center gap-3 mb-3">
         <span class="display-6 mb-0 <?= $pending > 0 ? 'text-danger' : 'text-success' ?>"><?= (int)$pending ?></span>
         <span class="text-muted">pendente(s)</span>
         <form method="post" action="<?= $h($selfUrl) ?>" class="ms-auto">
            <input type="hidden" name="_glpi_csrf_token" value="<?= $h($csrf) ?>">
            <input type="hidden" name="action" value="retry_now">
            <button class="btn btn-sm btn-outline-primary" type="submit" <?= $pending > 0 ? '' : 'disabled' ?>>
               <span class="ti ti-refresh"></span> Reprocessar agora
            </button>
         </form>
      </div>
      <?php $recent = FailedTicket::getRecent(8); ?>
      <?php if ($recent !== []): ?>
         <div class="table-responsive">
         <table class="table table-sm table-vcenter mb-0">
         <thead><tr><th>Ameaca</th><th>Tent.</th><th>Status</th><th>Erro</th></tr></thead>
         <tbody>
         <?php foreach ($recent as $f): ?>
            <tr>
               <td><?= $h($f['threat_name'] ?? '-') ?><div class="small text-muted"><?= $h($f['computer_name'] ?? '') ?></div></td>
               <td><?= (int)($f['attempts'] ?? 0) ?></td>
               <td>
                  <?php $st = (string)($f['status'] ?? ''); ?>
                  <span class="badge bg-<?= $st === 'resolved' ? 'success' : ($st === 'given_up' ? 'secondary' : 'warning') ?>"><?= $h($st) ?></span>
               </td>
               <td class="small text-muted text-break"><?= $h(mb_substr((string)($f['error'] ?? ''), 0, 120)) ?></td>
            </tr>
         <?php endforeach; ?>
         </tbody>
         </table>
         </div>
      <?php else: ?>
         <div class="alert alert-success mb-0">Nenhuma falha registrada.</div>
      <?php endif; ?>
   </div>
</div>
</div>

<!-- Crons -->
<div class="col-lg-7">
<div class="sentinelone-panel">
   <div class="sentinelone-panel__head"><h3>Tarefas de cron</h3></div>
   <div class="sentinelone-panel__body">
   <div class="table-responsive">
   <table class="table table-sm table-vcenter mb-0">
   <thead><tr><th>Tarefa</th><th>Estado</th><th>Ultima execucao</th><th>Saida</th></tr></thead>
   <tbody>
   <?php foreach ($crons as $c): ?>
      <tr>
         <td><?= $h($c['label']) ?><div class="small text-muted"><?= $h($c['name']) ?></div></td>
         <td>
            <?php
            $stateBadge = match ($c['state']) {
               1       => 'bg-success',
               2       => 'bg-warning',
               0       => 'bg-secondary',
               default => 'bg-danger',
            };
            ?>
            <span class="badge <?= $stateBadge ?>"><?= $h($c['state_label']) ?></span>
            <?php if ($c['state'] === 2): ?><span class="small text-warning d-block">verifique se nao esta travado</span><?php endif; ?>
         </td>
         <td class="text-muted"><?= $h($c['lastrun'] !== '' ? $c['lastrun'] : '-') ?></td>
         <td class="text-muted"><?= $h($c['lastcode'] !== '' ? $c['lastcode'] : '-') ?></td>
      </tr>
   <?php endforeach; ?>
   </tbody>
   </table>
   </div>
   <?php if ($locks !== []): ?>
      <div class="mt-2 small text-muted">
         Locks ativos:
         <?php
         $active = array_values(array_filter($locks, static fn($l) => $l['locked']));
         echo $active === [] ? '<span class="text-success">nenhum</span>' : $h(implode(', ', array_column($active, 'key')));
         ?>
      </div>
   <?php endif; ?>
   </div>
</div>
</div>

<!-- Tabelas + ultimo sync -->
<div class="col-lg-5">
<div class="sentinelone-panel mb-3">
   <div class="sentinelone-panel__head"><h3>Tabelas</h3></div>
   <div class="sentinelone-panel__body">
   <div class="table-responsive">
   <table class="table table-sm table-vcenter mb-0">
   <tbody>
   <?php foreach ($tables as $t): ?>
      <tr>
         <td><?= $h($t['name']) ?></td>
         <td class="text-end">
            <?php if ($t['exists']): ?>
               <span class="text-muted"><?= (int)$t['rows'] ?> linha(s)</span>
            <?php else: ?>
               <span class="badge bg-danger">ausente</span>
            <?php endif; ?>
         </td>
      </tr>
   <?php endforeach; ?>
   </tbody>
   </table>
   </div>
   </div>
</div>

<div class="sentinelone-panel">
   <div class="sentinelone-panel__head"><h3>Ultimo sync por tipo</h3></div>
   <div class="sentinelone-panel__body">
   <?php if ($lastSyncs === []): ?>
      <div class="text-muted">Sem registros de sync ainda.</div>
   <?php else: ?>
   <div class="table-responsive">
   <table class="table table-sm table-vcenter mb-0">
   <thead><tr><th>Acao</th><th>Ultimo OK</th><th>Ultimo erro</th></tr></thead>
   <tbody>
   <?php foreach ($lastSyncs as $s): ?>
      <tr>
         <td><?= $h($s['action']) ?></td>
         <td class="text-muted"><?= $h($s['last_ok'] !== '' ? $s['last_ok'] : '-') ?></td>
         <td>
            <?php if ($s['last_error'] !== ''): ?>
               <span class="text-danger" title="<?= $h($s['last_error_msg']) ?>"><?= $h($s['last_error']) ?></span>
            <?php else: ?>
               <span class="text-muted">-</span>
            <?php endif; ?>
         </td>
      </tr>
   <?php endforeach; ?>
   </tbody>
   </table>
   </div>
   <?php endif; ?>
   <p class="small text-muted mt-2 mb-0">Erros tambem sao espelhados em <code>files/_log/sentinelone.log</code>.</p>
   </div>
</div>
</div>

</div><!-- .row -->
</div><!-- .container-fluid -->
</div><!-- .page-body -->
<?php
\Html::footer();

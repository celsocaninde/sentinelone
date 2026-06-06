<?php

use GlpiPlugin\Sentinelone\Agent;
use GlpiPlugin\Sentinelone\Config as S1Config;
use GlpiPlugin\Sentinelone\Profile;
use GlpiPlugin\Sentinelone\Sync;
use GlpiPlugin\Sentinelone\Threat;

include('../../../inc/includes.php');

\Session::checkRight(Profile::RIGHT_READ, READ);

global $CFG_GLPI, $DB;

$id      = (int)($_GET['id'] ?? 0);
$rootDoc = (string)($CFG_GLPI['root_doc'] ?? '');
$syncUrl = $rootDoc . '/plugins/sentinelone/front/sync.form.php';
$listUrl = $rootDoc . '/plugins/sentinelone/front/agent.php';
$config  = S1Config::getConfig();

if ($id <= 0) {
   \Html::redirect($listUrl);
   exit;
}

$agent = null;
foreach ($DB->request(['FROM' => Agent::getTable(), 'WHERE' => ['id' => $id], 'LIMIT' => 1]) as $r) {
   $agent = $r;
}

if ($agent === null) {
   \Session::addMessageAfterRedirect('Agente nao encontrado.', false, ERROR);
   \Html::redirect($listUrl);
   exit;
}

$hasSyncRight = Profile::hasSyncRight();
$allowActions = $hasSyncRight && (string)($config['allow_remote_actions'] ?? '0') === '1';

$h = static fn($v): string => htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

$isOnline  = (int)($agent['is_online'] ?? 0) === 1;
$isQ       = (int)($agent['is_network_quarantine'] ?? 0) === 1;
$infected  = (int)($agent['is_infected'] ?? 0) === 1;

// Ameacas recentes
$threats = [];
$s1AgentId = (string)($agent['sentinelone_id'] ?? '');
if ($s1AgentId !== '') {
   foreach ($DB->request([
      'FROM'  => Threat::getTable(),
      'WHERE' => ['sentinelone_agent_id' => $s1AgentId],
      'ORDER' => ['detected_at DESC'],
      'LIMIT' => 10,
   ]) as $r) {
      $threats[] = $r;
   }
}

// Atividades recentes
$activities = [];
if ($s1AgentId !== '') {
   foreach ($DB->request([
      'FROM'  => 'glpi_plugin_sentinelone_activities',
      'WHERE' => ['sentinelone_agent_id' => $s1AgentId],
      'ORDER' => ['occurred_at DESC'],
      'LIMIT' => 15,
   ]) as $r) {
      $activities[] = $r;
   }
}

// Software instalado
$software = [];
$computerId = (int)($agent['computers_id'] ?? 0);
if ($computerId > 0 && $DB->tableExists('glpi_computers_softwareversions')) {
   foreach ($DB->request([
      'SELECT' => ['sv.id', 's.name', 'sv.name AS version', 's.manufacturers_id'],
      'FROM'   => ['glpi_computers_softwareversions' => 'csv'],
      'LEFT JOIN' => [
         'glpi_softwareversions AS sv' => ['ON' => ['csv' => 'softwareversions_id', 'sv' => 'id']],
         'glpi_softwares AS s'         => ['ON' => ['sv'  => 'softwares_id',        's'  => 'id']],
      ],
      'WHERE'  => ['csv.computers_id' => $computerId, 'csv.is_deleted' => 0],
      'ORDER'  => ['s.name ASC'],
      'LIMIT'  => 100,
   ]) as $r) {
      $software[] = $r;
   }
}

$consoleUrl = S1Config::consoleEndpointUrl($config, $s1AgentId);

\Html::header('Agente SentinelOne', $_SERVER['PHP_SELF'], 'plugins', 'sentinelone');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
?>
<div class="page-body">
<div class="container-fluid mt-3">

<div class="d-flex align-items-center gap-2 mb-3">
   <a href="<?= $h($listUrl) ?>" class="btn btn-sm btn-outline-secondary">
      <span class="ti ti-arrow-left"></span> Voltar
   </a>
   <h2 class="mb-0 flex-grow-1"><?= $h($agent['computer_name'] ?? 'Agente') ?></h2>
   <div class="d-flex gap-1">
      <?php if ($infected): ?><span class="s1-badge s1-badge--critical">infectado</span><?php endif; ?>
      <?php if ($isQ): ?><span class="s1-badge s1-badge--critical">quarentena</span><?php endif; ?>
      <span class="s1-badge <?= $isOnline ? 's1-badge--ok' : 's1-badge--muted' ?>">
         <?= $isOnline ? 'online' : 'offline' ?>
      </span>
   </div>
</div>

<div class="row g-3">

<!-- Info -->
<div class="col-lg-5">
<div class="sentinelone-panel">
   <div class="sentinelone-panel__head"><h3>Informacoes do agente</h3></div>
   <div class="sentinelone-panel__body">
   <table class="table table-sm mb-0">
   <tbody>
      <tr><th>Sistema operacional</th><td><?= $h($agent['os_name'] ?? '-') ?></td></tr>
      <tr><th>Versao do agente</th><td><?= $h($agent['agent_version'] ?? '-') ?></td></tr>
      <tr><th>IP</th><td><?= $h($agent['ip'] ?? '-') ?></td></tr>
      <tr><th>MAC</th><td><?= $h($agent['mac'] ?? '-') ?></td></tr>
      <tr><th>Serial</th><td><?= $h($agent['serial'] ?? '-') ?></td></tr>
      <tr><th>UUID</th><td><small><?= $h($agent['uuid'] ?? '-') ?></small></td></tr>
      <tr><th>Site</th><td><?= $h($agent['site_name'] ?? '-') ?></td></tr>
      <tr><th>Grupo</th><td><?= $h($agent['group_name'] ?? '-') ?></td></tr>
      <tr><th>Ultimo contato</th><td><?= $h($agent['last_active_at'] ?? '-') ?></td></tr>
      <?php if ($computerId > 0): ?>
      <tr><th>Computador GLPI</th><td>
         <a href="<?= $h($rootDoc . '/front/computer.form.php?id=' . $computerId) ?>">
            #<?= $computerId ?> <span class="ti ti-external-link"></span>
         </a>
      </td></tr>
      <?php endif; ?>
      <?php if ($consoleUrl !== ''): ?>
      <tr><th>Console S1</th><td>
         <a href="<?= $h($consoleUrl) ?>" target="_blank" rel="noopener">
            Abrir <span class="ti ti-external-link"></span>
         </a>
      </td></tr>
      <?php endif; ?>
   </tbody>
   </table>
   </div>
</div>
</div>

<!-- Acoes -->
<div class="col-lg-7">
<div class="sentinelone-panel">
   <div class="sentinelone-panel__head"><h3>Acoes remotas</h3></div>
   <div class="sentinelone-panel__body">
   <?php if (!$allowActions): ?>
   <div class="alert alert-warning mb-0">
      <?php if (!$hasSyncRight): ?>
      Sem permissao para executar acoes.
      <?php else: ?>
      Acoes remotas desabilitadas. Ative em <a href="<?= $h($rootDoc . '/plugins/sentinelone/front/config.form.php') ?>">configuracoes</a>.
      <?php endif; ?>
   </div>
   <?php else: ?>
   <div class="d-flex flex-wrap gap-2">

   <form method="post" action="<?= $h($syncUrl) ?>">
      <input type="hidden" name="_glpi_csrf_token" value="<?= $h(\Session::getNewCSRFToken()) ?>">
      <input type="hidden" name="action" value="scan_agent">
      <input type="hidden" name="agent_id" value="<?= $id ?>">
      <button class="btn btn-sm btn-primary" type="submit">
         <span class="ti ti-search"></span> Iniciar Scan
      </button>
   </form>

   <form method="post" action="<?= $h($syncUrl) ?>">
      <input type="hidden" name="_glpi_csrf_token" value="<?= $h(\Session::getNewCSRFToken()) ?>">
      <input type="hidden" name="action" value="update_agent">
      <input type="hidden" name="agent_id" value="<?= $id ?>">
      <button class="btn btn-sm btn-outline-primary" type="submit"
         onclick="return confirm('Atualizar o agente SentinelOne para a versao mais recente?')">
         <span class="ti ti-arrow-up-circle"></span> Atualizar Agente
      </button>
   </form>

   <form method="post" action="<?= $h($syncUrl) ?>">
      <input type="hidden" name="_glpi_csrf_token" value="<?= $h(\Session::getNewCSRFToken()) ?>">
      <input type="hidden" name="action" value="restart_agent">
      <input type="hidden" name="agent_id" value="<?= $id ?>">
      <button class="btn btn-sm btn-outline-warning" type="submit"
         onclick="return confirm('Reiniciar o servico do agente SentinelOne neste endpoint?')">
         <span class="ti ti-refresh"></span> Restart Agente
      </button>
   </form>

   <?php if ($isQ): ?>
   <form method="post" action="<?= $h($syncUrl) ?>">
      <input type="hidden" name="_glpi_csrf_token" value="<?= $h(\Session::getNewCSRFToken()) ?>">
      <input type="hidden" name="action" value="unquarantine_agent">
      <input type="hidden" name="agent_id" value="<?= $id ?>">
      <button class="btn btn-sm btn-outline-success" type="submit">
         <span class="ti ti-network"></span> Reintegrar Rede
      </button>
   </form>
   <?php else: ?>
   <form method="post" action="<?= $h($syncUrl) ?>">
      <input type="hidden" name="_glpi_csrf_token" value="<?= $h(\Session::getNewCSRFToken()) ?>">
      <input type="hidden" name="action" value="quarantine_agent">
      <input type="hidden" name="agent_id" value="<?= $id ?>">
      <button class="btn btn-sm btn-outline-danger" type="submit"
         onclick="return confirm('Isolar este endpoint da rede? Ele perdera conectividade exceto com a console SentinelOne.')">
         <span class="ti ti-network-off"></span> Isolar da Rede
      </button>
   </form>
   <?php endif; ?>

   </div>
   <?php endif; ?>
   </div>
</div>
</div>

<!-- Ameacas -->
<div class="col-12">
<div class="sentinelone-panel">
   <div class="sentinelone-panel__head">
      <h3>Ameacas recentes</h3>
      <a href="<?= $h($rootDoc . '/plugins/sentinelone/front/threat.php') ?>">Ver todas</a>
   </div>
   <?php if ($threats === []): ?>
   <div class="sentinelone-panel__body">
      <div class="sentinelone-empty">Nenhuma ameaca registrada para este endpoint.</div>
   </div>
   <?php else: ?>
   <div class="table-responsive">
   <table class="table table-vcenter table-hover mb-0">
   <thead><tr>
      <th>Ameaca</th><th>Classificacao</th><th>Status</th>
      <th>Severidade</th><th>Detectada em</th><th>Ticket</th>
   </tr></thead>
   <tbody>
   <?php foreach ($threats as $t): ?>
   <?php [$sl, $sc] = Threat::severity($t); ?>
   <tr>
      <td>
         <a href="<?= $h($rootDoc . '/plugins/sentinelone/front/threat.form.php?id=' . (int)$t['id']) ?>">
            <?= $h($t['threat_name'] ?? '-') ?>
         </a>
      </td>
      <td><?= $h($t['classification'] ?? '-') ?></td>
      <td><?= $h($t['status'] ?? '-') ?></td>
      <td><span class="s1-badge <?= $h($sc) ?>"><?= $h($sl) ?></span></td>
      <td><?= $h($t['detected_at'] ?? '-') ?></td>
      <td>
         <?php if (!empty($t['tickets_id'])): ?>
         <a href="<?= $h($rootDoc . '/front/ticket.form.php?id=' . (int)$t['tickets_id']) ?>">#<?= (int)$t['tickets_id'] ?></a>
         <?php else: ?>-<?php endif; ?>
      </td>
   </tr>
   <?php endforeach; ?>
   </tbody>
   </table>
   </div>
   <?php endif; ?>
</div>
</div>

<!-- Atividades -->
<?php if ($activities !== []): ?>
<div class="col-lg-6">
<div class="sentinelone-panel">
   <div class="sentinelone-panel__head"><h3>Atividades recentes</h3></div>
   <div class="table-responsive">
   <table class="table table-sm table-vcenter mb-0">
   <thead><tr><th>Tipo</th><th>Descricao</th><th>Data</th></tr></thead>
   <tbody>
   <?php foreach ($activities as $a): ?>
   <tr>
      <td><small><?= $h($a['activity_type'] ?? '-') ?></small></td>
      <td><small><?= $h(mb_strimwidth((string)($a['description'] ?? ''), 0, 120, '...')) ?></small></td>
      <td><small><?= $h($a['occurred_at'] ?? '-') ?></small></td>
   </tr>
   <?php endforeach; ?>
   </tbody>
   </table>
   </div>
</div>
</div>
<?php endif; ?>

<!-- Software -->
<?php if ($software !== []): ?>
<div class="col-lg-6">
<div class="sentinelone-panel">
   <div class="sentinelone-panel__head"><h3>Software instalado (<?= count($software) ?>)</h3></div>
   <div class="table-responsive" style="max-height:360px;overflow-y:auto">
   <table class="table table-sm table-vcenter mb-0">
   <thead><tr><th>Nome</th><th>Versao</th></tr></thead>
   <tbody>
   <?php foreach ($software as $sw): ?>
   <tr>
      <td><?= $h($sw['name'] ?? '-') ?></td>
      <td><small><?= $h($sw['version'] ?? '-') ?></small></td>
   </tr>
   <?php endforeach; ?>
   </tbody>
   </table>
   </div>
</div>
</div>
<?php endif; ?>

</div><!-- .row -->
</div><!-- .container-fluid -->
</div><!-- .page-body -->
<?php
\Html::footer();

<?php

use GlpiPlugin\Sentinelone\Agent;
use GlpiPlugin\Sentinelone\Config as S1Config;
use GlpiPlugin\Sentinelone\Cve;
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
   \Session::addMessageAfterRedirect('Agente não encontrado.', false, ERROR);
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

$agentVersion    = trim((string)($agent['agent_version'] ?? ''));
$minVersion      = trim((string)($config['min_agent_version'] ?? ''));
$versionOutdated = $minVersion !== '' && $agentVersion !== '' && version_compare($agentVersion, $minVersion, '<');

$subtitleParts = array_values(array_filter([(string)($agent['os_name'] ?? ''), (string)($agent['site_name'] ?? '')]));

\Html::header('Agente SentinelOne', $_SERVER['PHP_SELF'], 'plugins', 'sentinelone');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
?>
<div class="page-body">
<div class="container-fluid mt-3">

<div class="d-flex align-items-center mb-3">
   <a href="<?= $h($listUrl) ?>" class="btn btn-sm btn-outline-secondary">
      <span class="ti ti-arrow-left"></span> Voltar
   </a>
</div>

<div class="s1-asset-card mb-3">
   <div class="s1-asset-card__head">
      <span class="s1-logo s1-logo--solid"><span class="ti ti-shield-half-filled"></span></span>
      <div>
         <h3><?= $h($agent['computer_name'] ?: ($agent['sentinelone_id'] ?? 'Agente')) ?></h3>
         <?php if ($subtitleParts !== []): ?>
         <small><?= $h(implode(' · ', $subtitleParts)) ?></small>
         <?php endif; ?>
      </div>
      <div class="s1-asset-card__spacer"></div>
      <?php if ($infected): ?><span class="s1-badge s1-badge--critical"><span class="ti ti-bug"></span> infectado</span><?php endif; ?>
      <?php if ($isQ): ?><span class="s1-badge s1-badge--critical"><span class="ti ti-network-off"></span> quarentena</span><?php endif; ?>
      <?php if ($versionOutdated): ?>
      <span class="s1-badge s1-badge--warning" title="Versao minima configurada: <?= $h($minVersion) ?>">&#9888; desatualizado</span>
      <?php endif; ?>
      <span class="s1-badge <?= $isOnline ? 's1-badge--ok' : 's1-badge--muted' ?>">
         <span class="ti <?= $isOnline ? 'ti-plug-connected' : 'ti-plug-connected-x' ?>"></span> <?= $isOnline ? 'online' : 'offline' ?>
      </span>
      <?php if ($consoleUrl !== ''): ?>
      <a class="btn btn-sm btn-light" href="<?= $h($consoleUrl) ?>" target="_blank" rel="noopener">
         <span class="ti ti-external-link"></span> Console
      </a>
      <?php endif; ?>
   </div>
   <div class="s1-asset-card__body">
   <div class="s1-kv">
      <div class="s1-kv__item"><span>Sistema operacional</span><strong><?= $h($agent['os_name'] ?? '-') ?></strong></div>
      <div class="s1-kv__item"><span>Versao do agente</span><strong><?= $h($agentVersion !== '' ? $agentVersion : '-') ?></strong></div>
      <div class="s1-kv__item"><span>IP</span><strong><?= $h($agent['ip'] ?? '-') ?></strong></div>
      <div class="s1-kv__item"><span>MAC</span><strong><?= $h($agent['mac'] ?? '-') ?></strong></div>
      <div class="s1-kv__item"><span>Serial</span><strong><?= $h($agent['serial'] ?? '-') ?></strong></div>
      <div class="s1-kv__item"><span>UUID</span><strong style="font-size:.82rem"><?= $h($agent['uuid'] ?? '-') ?></strong></div>
      <div class="s1-kv__item"><span>Site</span><strong><?= $h($agent['site_name'] ?? '-') ?></strong></div>
      <div class="s1-kv__item"><span>Grupo</span><strong><?= $h($agent['group_name'] ?? '-') ?></strong></div>
      <div class="s1-kv__item"><span>Ultimo contato</span><strong><?= $h($agent['last_active_at'] ?? '-') ?></strong></div>
      <?php if ($computerId > 0): ?>
      <div class="s1-kv__item">
         <span>Computador GLPI</span>
         <strong><a href="<?= $h($rootDoc . '/front/computer.form.php?id=' . $computerId) ?>">#<?= $computerId ?> <span class="ti ti-external-link" style="font-size:.8rem"></span></a></strong>
      </div>
      <?php endif; ?>
   </div>
   </div>
</div>

<div class="row g-3">

<!-- Acoes -->
<div class="col-12">
<div class="sentinelone-panel">
   <div class="sentinelone-panel__head">
      <div class="sentinelone-panel__title">
         <span class="sentinelone-panel__icon"><span class="ti ti-adjustments-bolt"></span></span>
         <div>
            <h3>Acoes remotas</h3>
            <p>Comandos enviados direto ao agente na console SentinelOne</p>
         </div>
      </div>
   </div>
   <div class="sentinelone-panel__body">
   <?php if (!$allowActions): ?>
   <div class="alert alert-warning mb-0 d-flex align-items-center gap-2">
      <span class="ti ti-lock"></span>
      <?php if (!$hasSyncRight): ?>
      Sem permissão para executar ações.
      <?php else: ?>
      Ações remotas desabilitadas. Ative em <a href="<?= $h($rootDoc . '/plugins/sentinelone/front/config.form.php') ?>">configurações</a>.
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
         onclick="return confirm('Reiniciar o serviço do agente SentinelOne neste endpoint?')">
         <span class="ti ti-refresh"></span> Reiniciar Agente
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
         onclick="return confirm('Isolar este endpoint da rede? Ele perderá conectividade exceto com a console SentinelOne.')">
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
      <div class="sentinelone-panel__title">
         <span class="sentinelone-panel__icon"><span class="ti ti-shield-search"></span></span>
         <div>
            <h3>Ameaças recentes</h3>
            <p>Últimas 10 detecções sincronizadas para este endpoint</p>
         </div>
      </div>
      <a href="<?= $h($rootDoc . '/plugins/sentinelone/front/threat.php') ?>">Ver todas</a>
   </div>
   <?php if ($threats === []): ?>
   <div class="sentinelone-panel__body">
      <div class="sentinelone-empty">Nenhuma ameaça registrada para este endpoint.</div>
   </div>
   <?php else: ?>
   <div class="table-responsive">
   <table class="table table-vcenter table-hover mb-0">
   <thead><tr>
      <th>Ameaça</th><th>Classificação</th><th>Status</th>
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

<?php Cve::showForAgent($id); ?>

</div><!-- .container-fluid -->
</div><!-- .page-body -->
<?php
\Html::footer();

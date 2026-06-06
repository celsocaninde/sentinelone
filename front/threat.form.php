<?php

use GlpiPlugin\Sentinelone\Config as S1Config;
use GlpiPlugin\Sentinelone\Profile;
use GlpiPlugin\Sentinelone\Sync;
use GlpiPlugin\Sentinelone\Threat;

include('../../../inc/includes.php');

\Session::checkRight(Profile::RIGHT_READ, READ);

global $CFG_GLPI, $DB;

$id       = (int)($_GET['id'] ?? 0);
$rootDoc  = (string)($CFG_GLPI['root_doc'] ?? '');
$syncUrl  = $rootDoc . '/plugins/sentinelone/front/sync.form.php';
$listUrl  = $rootDoc . '/plugins/sentinelone/front/threat.php';
$config   = S1Config::getConfig();

if ($id <= 0) {
   \Html::redirect($listUrl);
   exit;
}

$row = null;
foreach ($DB->request(['FROM' => Threat::getTable(), 'WHERE' => ['id' => $id], 'LIMIT' => 1]) as $r) {
   $row = $r;
}

if ($row === null) {
   \Session::addMessageAfterRedirect('Ameaca nao encontrada.', false, ERROR);
   \Html::redirect($listUrl);
   exit;
}

$hasSyncRight = Profile::hasSyncRight();
$allowActions = $hasSyncRight && (string)($config['allow_remote_actions'] ?? '0') === '1';

$h = static fn($v): string => htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

$raw = [];
if (!empty($row['raw_json'])) {
   $raw = json_decode((string)$row['raw_json'], true) ?: [];
}

// Extrai indicadores MITRE do raw_json
$indicators = $raw['indicators'] ?? [];
$mitreTechniques = [];
foreach ($indicators as $ind) {
   foreach ($ind['techniques'] ?? [] as $t) {
      $techId = (string)($t['id'] ?? '');
      if ($techId !== '' && !isset($mitreTechniques[$techId])) {
         $mitreTechniques[$techId] = [
            'id'       => $techId,
            'name'     => (string)($t['name'] ?? $techId),
            'link'     => (string)($t['link'] ?? ''),
            'category' => (string)($ind['category'] ?? ''),
         ];
      }
   }
}

$sha256 = trim((string)($row['hash_sha256'] ?? ''));
$sha1   = trim((string)($row['hash_sha1'] ?? ''));

[$sevLabel, $sevClass] = Threat::severity($row);

\Html::header('Ameaca SentinelOne', $_SERVER['PHP_SELF'], 'plugins', 'sentinelone');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
?>
<div class="page-body">
<div class="container-fluid mt-3">

<div class="d-flex align-items-center gap-2 mb-3">
   <a href="<?= $h($listUrl) ?>" class="btn btn-sm btn-outline-secondary">
      <span class="ti ti-arrow-left"></span> Voltar
   </a>
   <h2 class="mb-0 flex-grow-1"><?= $h($row['threat_name'] ?? 'Ameaca') ?></h2>
   <span class="s1-badge <?= $h($sevClass) ?>"><?= $h($sevLabel) ?></span>
</div>

<div class="row g-3">

<!-- Info principal -->
<div class="col-lg-6">
<div class="sentinelone-panel">
   <div class="sentinelone-panel__head"><h3>Detalhes da ameaca</h3></div>
   <div class="sentinelone-panel__body">
   <table class="table table-sm mb-0">
   <tbody>
      <tr><th>Endpoint</th><td><?= $h($row['computer_name'] ?? '-') ?></td></tr>
      <tr><th>Classificacao</th><td><?= $h($row['classification'] ?? '-') ?></td></tr>
      <tr><th>Status</th><td><?= $h($row['status'] ?? '-') ?></td></tr>
      <tr><th>Confianca</th><td><?= $h($row['confidence_level'] ?? '-') ?></td></tr>
      <tr><th>Veredito do analista</th><td><?= $h($row['analyst_verdict'] ?? '-') ?></td></tr>
      <tr><th>Severidade</th><td><?= $h($row['severity'] ?? '-') ?></td></tr>
      <tr><th>Caminho do arquivo</th><td class="text-break"><?= $h($row['file_path'] ?? '-') ?></td></tr>
      <tr><th>Detectada em</th><td><?= $h($row['detected_at'] ?? '-') ?></td></tr>
      <tr><th>Resolvida em</th><td><?= $h($row['resolved_at'] ?? '-') ?></td></tr>
      <?php if ($sha1 !== ''): ?>
      <tr><th>SHA-1</th><td><code class="text-break"><?= $h($sha1) ?></code></td></tr>
      <?php endif; ?>
      <?php if ($sha256 !== ''): ?>
      <tr>
         <th>SHA-256</th>
         <td>
            <code class="text-break"><?= $h($sha256) ?></code>
            <div class="mt-1 d-flex gap-1 flex-wrap">
               <a href="https://www.virustotal.com/gui/file/<?= $h($sha256) ?>" target="_blank" rel="noopener" class="btn btn-xs btn-outline-danger">
                  <span class="ti ti-virus"></span> VirusTotal
               </a>
               <a href="https://app.any.run/tasks#filehash=<?= $h($sha256) ?>" target="_blank" rel="noopener" class="btn btn-xs btn-outline-warning">
                  <span class="ti ti-flask"></span> Any.run
               </a>
            </div>
         </td>
      </tr>
      <?php endif; ?>
      <?php
      $consoleUrl = S1Config::consoleThreatUrl($config, (string)($row['sentinelone_threat_id'] ?? ''));
      if ($consoleUrl !== ''):
      ?>
      <tr>
         <th>Console S1</th>
         <td><a href="<?= $h($consoleUrl) ?>" target="_blank" rel="noopener">
            Abrir na console <span class="ti ti-external-link"></span>
         </a></td>
      </tr>
      <?php endif; ?>
      <?php if (!empty($row['tickets_id'])): ?>
      <tr>
         <th>Ticket GLPI</th>
         <td><a href="<?= $h($rootDoc . '/front/ticket.form.php?id=' . (int)$row['tickets_id']) ?>">
            Ticket #<?= (int)$row['tickets_id'] ?>
         </a></td>
      </tr>
      <?php endif; ?>
   </tbody>
   </table>
   </div>
</div>
</div>

<!-- Ações -->
<div class="col-lg-6">
<div class="sentinelone-panel">
   <div class="sentinelone-panel__head"><h3>Acoes</h3></div>
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

   <!-- Mitigar -->
   <form method="post" action="<?= $h($syncUrl) ?>" class="d-inline">
      <input type="hidden" name="_glpi_csrf_token" value="<?= $h(\Session::getNewCSRFToken()) ?>">
      <input type="hidden" name="action" value="mitigate_threat">
      <input type="hidden" name="threat_id" value="<?= $id ?>">
      <button class="btn btn-sm btn-danger" type="submit"
         onclick="return confirm('Mitigar esta ameaca? O processo sera encerrado e o arquivo colocado em quarentena.')">
         <span class="ti ti-shield-x"></span> Mitigar
      </button>
   </form>

   <!-- Rollback -->
   <form method="post" action="<?= $h($syncUrl) ?>" class="d-inline">
      <input type="hidden" name="_glpi_csrf_token" value="<?= $h(\Session::getNewCSRFToken()) ?>">
      <input type="hidden" name="action" value="rollback_threat">
      <input type="hidden" name="threat_id" value="<?= $id ?>">
      <button class="btn btn-sm btn-warning" type="submit"
         onclick="return confirm('Executar rollback? As mudancas feitas pelo malware serao desfeitas.')">
         <span class="ti ti-rotate-clockwise-2"></span> Rollback
      </button>
   </form>

   <!-- Veredito: False Positive -->
   <form method="post" action="<?= $h($syncUrl) ?>" class="d-inline">
      <input type="hidden" name="_glpi_csrf_token" value="<?= $h(\Session::getNewCSRFToken()) ?>">
      <input type="hidden" name="action" value="set_verdict">
      <input type="hidden" name="threat_id" value="<?= $id ?>">
      <input type="hidden" name="verdict" value="false_positive">
      <button class="btn btn-sm btn-outline-success" type="submit">
         <span class="ti ti-check"></span> Falso Positivo
      </button>
   </form>

   <!-- Veredito: True Positive -->
   <form method="post" action="<?= $h($syncUrl) ?>" class="d-inline">
      <input type="hidden" name="_glpi_csrf_token" value="<?= $h(\Session::getNewCSRFToken()) ?>">
      <input type="hidden" name="action" value="set_verdict">
      <input type="hidden" name="threat_id" value="<?= $id ?>">
      <input type="hidden" name="verdict" value="true_positive">
      <button class="btn btn-sm btn-outline-danger" type="submit">
         <span class="ti ti-alert-triangle"></span> Verdadeiro Positivo
      </button>
   </form>

   </div>
   <?php endif; ?>

   </div>
</div>
</div>

<!-- MITRE ATT&CK -->
<?php if ($mitreTechniques !== []): ?>
<div class="col-12">
<div class="sentinelone-panel">
   <div class="sentinelone-panel__head"><h3>MITRE ATT&amp;CK</h3></div>
   <div class="sentinelone-panel__body">
   <div class="table-responsive">
   <table class="table table-sm table-vcenter mb-0">
   <thead><tr><th>Tecnica</th><th>ID</th><th>Categoria</th><th>Link</th></tr></thead>
   <tbody>
   <?php foreach ($mitreTechniques as $t): ?>
   <tr>
      <td><?= $h($t['name']) ?></td>
      <td><code><?= $h($t['id']) ?></code></td>
      <td><?= $h($t['category']) ?></td>
      <td>
         <?php if ($t['link'] !== ''): ?>
         <a href="<?= $h($t['link']) ?>" target="_blank" rel="noopener">
            <span class="ti ti-external-link"></span> ATT&amp;CK
         </a>
         <?php else: ?>
         <a href="https://attack.mitre.org/techniques/<?= $h($t['id']) ?>/" target="_blank" rel="noopener">
            <span class="ti ti-external-link"></span> ATT&amp;CK
         </a>
         <?php endif; ?>
      </td>
   </tr>
   <?php endforeach; ?>
   </tbody>
   </table>
   </div>
   </div>
</div>
</div>
<?php endif; ?>

</div><!-- .row -->
</div><!-- .container-fluid -->
</div><!-- .page-body -->
<?php
\Html::footer();

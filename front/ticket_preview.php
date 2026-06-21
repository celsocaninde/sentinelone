<?php

use GlpiPlugin\Sentinelone\Profile;
use GlpiPlugin\Sentinelone\TicketManager;

include('../../../inc/includes.php');

\Session::checkRight(Profile::RIGHT_CONFIG, READ);

global $CFG_GLPI;

$rootDoc = (string)($CFG_GLPI['root_doc'] ?? '');
$samples = TicketManager::previewSamples();

\Html::header('Pre-visualizacao do ticket SentinelOne', $_SERVER['PHP_SELF'], 'plugins', 'sentinelone');
?>
<div class="page-body">
<div class="container-fluid mt-3">

<div class="d-flex align-items-center gap-2 mb-3">
   <a href="<?= htmlspecialchars($rootDoc . '/plugins/sentinelone/front/config.form.php', ENT_QUOTES) ?>" class="btn btn-sm btn-outline-secondary">
      <span class="ti ti-arrow-left"></span> Voltar a configuracao
   </a>
   <h2 class="mb-0"><span class="ti ti-eye"></span> Pre-visualizacao do ticket (dados de exemplo)</h2>
</div>

<p class="text-muted">Exemplo de como o ticket e a nota forense interna sao renderizados. Os dados sao ficticios; nenhum ticket e criado.</p>

<div class="row g-3">
   <div class="col-xl-6">
      <h3 class="h5">Corpo do ticket <span class="badge bg-success">publico</span></h3>
      <?= $samples['ticket'] ?>
   </div>
   <div class="col-xl-6">
      <h3 class="h5">Nota forense <span class="badge bg-danger">privada / so tecnicos</span></h3>
      <?= $samples['details'] ?>
   </div>
</div>

</div>
</div>
<?php
\Html::footer();

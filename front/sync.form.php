<?php

use GlpiPlugin\Sentinelone\Profile;
use GlpiPlugin\Sentinelone\Sync;

include('../../../inc/includes.php');

\Session::checkRight(Profile::RIGHT_SYNC, UPDATE);

global $CFG_GLPI;

$dashboardUrl = (string)($CFG_GLPI['root_doc'] ?? '') . '/plugins/sentinelone/front/dashboard.php';
$action = (string)($_POST['action'] ?? '');

try {
   if ($action === 'agents') {
      $result = Sync::syncAgents();
      \Session::addMessageAfterRedirect('Agentes sincronizados: ' . $result['processed'] . '.');
   } elseif ($action === 'threats') {
      $result = Sync::syncThreats();
      \Session::addMessageAfterRedirect('Ameacas sincronizadas: ' . $result['processed'] . '. Tickets criados: ' . $result['tickets'] . '.');
   } elseif ($action === 'all') {
      $agents = Sync::syncAgents();
      $threats = Sync::syncThreats();
      \Session::addMessageAfterRedirect(
         'Sincronizacao concluida. Agentes: ' . $agents['processed'] . '. Ameacas: ' . $threats['processed'] . '. Tickets criados: ' . $threats['tickets'] . '.'
      );
   } else {
      \Session::addMessageAfterRedirect('Acao de sincronizacao invalida.', false, ERROR);
   }
} catch (\Throwable $error) {
   \Session::addMessageAfterRedirect(
      'Erro ao sincronizar SentinelOne: ' . $error->getMessage(),
      false,
      ERROR
   );
}

\Html::redirect($dashboardUrl);

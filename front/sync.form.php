<?php

use GlpiPlugin\Sentinelone\Profile;
use GlpiPlugin\Sentinelone\Sync;

include('../../../inc/includes.php');

\Session::checkRight(Profile::RIGHT_SYNC, UPDATE);

global $CFG_GLPI;

$rootDoc      = (string)($CFG_GLPI['root_doc'] ?? '');
$dashboardUrl = $rootDoc . '/plugins/sentinelone/front/dashboard.php';
$coverageUrl  = $rootDoc . '/plugins/sentinelone/front/coverage.php?tab=unlinked';
$roguesUrl    = $rootDoc . '/plugins/sentinelone/front/rogues.php';
$exclusionsUrl = $rootDoc . '/plugins/sentinelone/front/exclusions.php';
$action       = (string)($_POST['action'] ?? '');

try {
   if ($action === 'agents') {
      $result = Sync::syncAgents();
      \Session::addMessageAfterRedirect('Agentes sincronizados: ' . $result['processed'] . '.');
   } elseif ($action === 'threats') {
      $result = Sync::syncThreats();
      \Session::addMessageAfterRedirect('Ameacas sincronizadas: ' . $result['processed'] . '. Tickets criados: ' . $result['tickets'] . '.');
   } elseif ($action === 'activities') {
      $result = Sync::syncActivities();
      \Session::addMessageAfterRedirect('Atividades sincronizadas: ' . $result['processed'] . '.');
   } elseif ($action === 'groups') {
      $result = Sync::syncGroups();
      \Session::addMessageAfterRedirect('Grupos sincronizados: ' . $result['processed'] . '.');
   } elseif ($action === 'mitigate_threat') {
      $threatId = (int)($_POST['threat_id'] ?? 0);
      $url      = $rootDoc . '/plugins/sentinelone/front/threat.form.php?id=' . $threatId;
      if (Sync::mitigateThreat($threatId)) {
         \Session::addMessageAfterRedirect('Ameaca mitigada com sucesso.');
      } else {
         \Session::addMessageAfterRedirect('Falha ao mitigar ameaca. Verifique permissoes e configuracao.', false, ERROR);
      }
      \Html::redirect($url);
      exit;
   } elseif ($action === 'rollback_threat') {
      $threatId = (int)($_POST['threat_id'] ?? 0);
      $url      = $rootDoc . '/plugins/sentinelone/front/threat.form.php?id=' . $threatId;
      if (Sync::rollbackThreat($threatId)) {
         \Session::addMessageAfterRedirect('Rollback executado com sucesso.');
      } else {
         \Session::addMessageAfterRedirect('Falha ao executar rollback.', false, ERROR);
      }
      \Html::redirect($url);
      exit;
   } elseif ($action === 'set_verdict') {
      $threatId = (int)($_POST['threat_id'] ?? 0);
      $verdict  = (string)($_POST['verdict'] ?? '');
      $url      = $rootDoc . '/plugins/sentinelone/front/threat.form.php?id=' . $threatId;
      if (Sync::setThreatVerdict($threatId, $verdict)) {
         \Session::addMessageAfterRedirect('Veredito atualizado: ' . $verdict . '.');
      } else {
         \Session::addMessageAfterRedirect('Falha ao atualizar veredito.', false, ERROR);
      }
      \Html::redirect($url);
      exit;
   } elseif ($action === 'scan_agent') {
      $agentId = (int)($_POST['agent_id'] ?? 0);
      $url     = $rootDoc . '/plugins/sentinelone/front/agent.form.php?id=' . $agentId;
      if (Sync::scanAgent($agentId)) {
         \Session::addMessageAfterRedirect('Scan iniciado no agente.');
      } else {
         \Session::addMessageAfterRedirect('Falha ao iniciar scan.', false, ERROR);
      }
      \Html::redirect($url);
      exit;
   } elseif ($action === 'update_agent') {
      $agentId = (int)($_POST['agent_id'] ?? 0);
      $url     = $rootDoc . '/plugins/sentinelone/front/agent.form.php?id=' . $agentId;
      if (Sync::updateAgent($agentId)) {
         \Session::addMessageAfterRedirect('Atualizacao do agente enfileirada.');
      } else {
         \Session::addMessageAfterRedirect('Falha ao enfileirar atualizacao do agente.', false, ERROR);
      }
      \Html::redirect($url);
      exit;
   } elseif ($action === 'restart_agent') {
      $agentId = (int)($_POST['agent_id'] ?? 0);
      $url     = $rootDoc . '/plugins/sentinelone/front/agent.form.php?id=' . $agentId;
      if (Sync::restartAgent($agentId)) {
         \Session::addMessageAfterRedirect('Restart do agente enfileirado.');
      } else {
         \Session::addMessageAfterRedirect('Falha ao reiniciar agente.', false, ERROR);
      }
      \Html::redirect($url);
      exit;
   } elseif ($action === 'quarantine_agent') {
      $agentId = (int)($_POST['agent_id'] ?? 0);
      if (Sync::quarantineAgent($agentId)) {
         \Session::addMessageAfterRedirect('Agente isolado da rede com sucesso.');
      } else {
         \Session::addMessageAfterRedirect('Falha ao isolar agente. Verifique permissoes e configuracao.', false, ERROR);
      }
   } elseif ($action === 'unquarantine_agent') {
      $agentId = (int)($_POST['agent_id'] ?? 0);
      if (Sync::unquarantineAgent($agentId)) {
         \Session::addMessageAfterRedirect('Agente reintegrado a rede com sucesso.');
      } else {
         \Session::addMessageAfterRedirect('Falha ao reintegrar agente.', false, ERROR);
      }
   } elseif ($action === 'all') {
      $agents     = Sync::syncAgents();
      $threats    = Sync::syncThreats();
      $activities = Sync::syncActivities();
      $grps       = Sync::syncGroups();
      \Session::addMessageAfterRedirect(
         'Sincronizacao concluida. Agentes: ' . $agents['processed'] . '. Ameacas: ' . $threats['processed'] . '. Tickets criados: ' . $threats['tickets'] . '. Atividades: ' . $activities['processed'] . '. Grupos: ' . $grps['processed'] . '.'
      );
   } elseif ($action === 'relink') {
      $result = Sync::relinkAgents();
      \Session::addMessageAfterRedirect(
         'Re-vinculacao concluida: ' . $result['linked'] . ' de ' . $result['total'] . ' agentes desvinculados foram linkados ao GLPI.'
      );
      \Html::redirect($coverageUrl);
      exit;
   } elseif ($action === 'syncrogues') {
      $result = Sync::syncRogues();
      $status = $result['status'] ?? 'ok';
      if ($status === 'disabled') {
         \Session::addMessageAfterRedirect('Sincronizacao de rogues esta desativada. Ative "Sincronizar dispositivos rogues (Ranger)" na configuracao do plugin.', false, WARNING);
      } elseif ($status === 'not_configured') {
         \Session::addMessageAfterRedirect('Integracao SentinelOne nao configurada.', false, WARNING);
      } elseif ($status === 'forbidden') {
         \Session::addMessageAfterRedirect('Acesso negado pelo SentinelOne (403): o token nao tem permissao para o Ranger. Verifique se o Ranger esta licenciado e se o papel do service-user inclui o escopo de Network Discovery.', false, ERROR);
      } elseif ($status === 'error') {
         \Session::addMessageAfterRedirect('Falha ao sincronizar rogues: ' . ($result['error'] ?? 'erro desconhecido'), false, ERROR);
      } else {
         \Session::addMessageAfterRedirect('Dispositivos rogues sincronizados: ' . $result['total'] . '.');
      }
      \Html::redirect($roguesUrl);
      exit;
   } elseif ($action === 'syncexclusions') {
      $result = Sync::syncExclusions();
      $status = $result['status'] ?? 'ok';
      if ($status === 'disabled') {
         \Session::addMessageAfterRedirect('Sincronizacao de exclusoes esta desativada. Ative "Sincronizar exclusoes da console (auditoria)" na configuracao do plugin.', false, WARNING);
      } elseif ($status === 'not_configured') {
         \Session::addMessageAfterRedirect('Integracao SentinelOne nao configurada.', false, WARNING);
      } elseif ($status === 'forbidden') {
         \Session::addMessageAfterRedirect('Acesso negado pelo SentinelOne (403): o token nao tem permissao para consultar exclusoes.', false, ERROR);
      } elseif ($status === 'error') {
         \Session::addMessageAfterRedirect('Falha ao sincronizar exclusoes: ' . ($result['error'] ?? 'erro desconhecido'), false, ERROR);
      } else {
         \Session::addMessageAfterRedirect('Exclusoes sincronizadas: ' . $result['total'] . '.');
      }
      \Html::redirect($exclusionsUrl);
      exit;
   } elseif ($action === 'synccves') {
      $result = Sync::syncCves(true);
      $status = $result['status'] ?? 'ok';
      if ($status === 'forbidden') {
         \Session::addMessageAfterRedirect('Acesso negado pelo SentinelOne (403): o token nao tem permissao para Application Risk / Vulnerability Management.', false, ERROR);
      } elseif ($status === 'not_configured') {
         \Session::addMessageAfterRedirect('Integracao SentinelOne nao configurada.', false, WARNING);
      } elseif ($result['processed'] === 0) {
         \Session::addMessageAfterRedirect('Nenhum agente com UUID encontrado para sincronizar CVEs.', false, WARNING);
      } else {
         \Session::addMessageAfterRedirect('CVEs sincronizados: ' . $result['cves'] . ' em ' . $result['processed'] . ' agentes.');
      }
      \Html::redirect($rootDoc . '/plugins/sentinelone/front/cves.php');
      exit;
   } elseif ($action === 'link_agent') {
      $agentId     = (int)($_POST['agent_id'] ?? 0);
      $computersId = (int)($_POST['computers_id'] ?? 0);
      if (Sync::linkAgent($agentId, $computersId)) {
         \Session::addMessageAfterRedirect('Agente vinculado ao computador #' . $computersId . ' com sucesso.');
      } else {
         \Session::addMessageAfterRedirect('Falha ao vincular. Verifique se o ID do computador existe.', false, ERROR);
      }
      \Html::redirect($coverageUrl);
      exit;
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

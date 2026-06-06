<?php

use GlpiPlugin\Sentinelone\ApiClient;
use GlpiPlugin\Sentinelone\Config;
use GlpiPlugin\Sentinelone\Notifier;
use GlpiPlugin\Sentinelone\Profile;

include('../../../inc/includes.php');

\Session::checkRight(Profile::RIGHT_CONFIG, READ);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
   \Session::checkRight(Profile::RIGHT_CONFIG, UPDATE);

   $isAjaxTest      = isset($_POST['ajax_test']);
   $isTest          = isset($_POST['test']) || $isAjaxTest;
   $isTestEmail     = isset($_POST['test_email']) || isset($_POST['ajax_test_email']);
   $startedAt = microtime(true);
   $sendJson = static function(array $payload): void {
      header('Content-Type: application/json; charset=UTF-8');
      echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
      exit;
   };

   try {
      if ($isTestEmail) {
         $config = Config::buildConfigFromInput($_POST);
         $result = Notifier::sendTestEmail($config);
         $sendJson($result);
      } elseif ($isTest) {
         $config = Config::buildConfigFromInput($_POST);
         $response = ApiClient::fromConfig($config)->testConnection();
         $durationMs = max(1, (int)round((microtime(true) - $startedAt) * 1000));
         $status = (int)($response['_http_status'] ?? 0);

         $payload = [
            'ok'          => true,
            'duration_ms' => $durationMs,
            'status'      => $status,
            'message'     => 'Conexao OK em ' . $durationMs . ' ms.',
         ];

         if ($isAjaxTest) {
            $sendJson($payload);
         }

         Config::setConnectionTestFlash($payload);
      } else {
         Config::saveFromInput($_POST);
         \Session::addMessageAfterRedirect('Configuracao SentinelOne salva com sucesso.');
      }
   } catch (\Throwable $error) {
      if ($isTest) {
         $durationMs = max(1, (int)round((microtime(true) - $startedAt) * 1000));
         $payload = [
            'ok'          => false,
            'duration_ms' => $durationMs,
            'status'      => 0,
            'message'     => 'Falha ao testar em ' . $durationMs . ' ms: ' . $error->getMessage(),
         ];

         if ($isAjaxTest) {
            $sendJson($payload);
         }

         Config::setConnectionTestFlash($payload);
      } else {
         \Session::addMessageAfterRedirect(
            'Erro na configuracao SentinelOne: ' . $error->getMessage(),
            false,
            ERROR
         );
      }
   }

   \Html::redirect(Config::getPluginFormUrl());
}

\Html::header('SentinelOne', $_SERVER['PHP_SELF'], 'config', 'plugins');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
Config::showForm();
\Html::footer();

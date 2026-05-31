<?php

namespace GlpiPlugin\Sentinelone;

use Symfony\Component\Mime\Address;

class Notifier
{
   public static function alertCriticalThreat(array $threat, array $config): void
   {
      if ((string)($config['alert_on_critical_threat'] ?? '0') !== '1') {
         return;
      }

      $recipients = Config::alertEmails($config);
      if ($recipients === []) {
         return;
      }

      $computer = trim((string)($threat['computer_name'] ?? ''));
      $subject = '[SentinelOne] Ameaca critica em ' . ($computer !== '' ? $computer : 'endpoint');

      $lines = [
         'Uma ameaca critica foi detectada pelo SentinelOne.',
         '',
         'Endpoint: ' . self::v($threat['computer_name'] ?? null),
         'Ameaca: ' . self::v($threat['threat_name'] ?? null),
         'Classificacao: ' . self::v($threat['classification'] ?? null),
         'Status: ' . self::v($threat['status'] ?? null),
         'Confianca: ' . self::v($threat['confidence_level'] ?? null),
         'Veredito do analista: ' . self::v($threat['analyst_verdict'] ?? null),
         'Detectada em: ' . self::v($threat['detected_at'] ?? null),
         'Threat ID: ' . self::v($threat['sentinelone_threat_id'] ?? null),
      ];

      $url = Config::consoleThreatUrl($config, (string)($threat['sentinelone_threat_id'] ?? ''));
      if ($url !== '') {
         $lines[] = '';
         $lines[] = 'Abrir na console: ' . $url;
      }

      self::send($recipients, $subject, implode("\n", $lines));
   }

   /**
    * @param string[] $issues
    */
   public static function alertAgentIssue(array $agent, array $issues, array $config): void
   {
      if ((string)($config['alert_on_agent_issue'] ?? '0') !== '1' || $issues === []) {
         return;
      }

      $recipients = Config::alertEmails($config);
      if ($recipients === []) {
         return;
      }

      $computer = trim((string)($agent['computer_name'] ?? ''));
      $subject = '[SentinelOne] Problema no agente ' . ($computer !== '' ? $computer : 'endpoint');

      $lines = [
         'O agente SentinelOne apresenta o(s) seguinte(s) problema(s):',
         '',
         '- ' . implode("\n- ", $issues),
         '',
         'Endpoint: ' . self::v($agent['computer_name'] ?? null),
         'Site: ' . self::v($agent['site_name'] ?? null),
         'Grupo: ' . self::v($agent['group_name'] ?? null),
         'Versao do agente: ' . self::v($agent['agent_version'] ?? null),
         'Ultimo contato: ' . self::v($agent['last_active_at'] ?? null),
      ];

      $url = Config::consoleEndpointUrl($config, (string)($agent['sentinelone_id'] ?? ''));
      if ($url !== '') {
         $lines[] = '';
         $lines[] = 'Abrir na console: ' . $url;
      }

      self::send($recipients, $subject, implode("\n", $lines));
   }

   /**
    * @param string[] $recipients
    */
   public static function send(array $recipients, string $subject, string $body): bool
   {
      global $CFG_GLPI;

      if ($recipients === [] || !class_exists(\GLPIMailer::class)) {
         return false;
      }

      $fromEmail = trim((string)($CFG_GLPI['admin_email'] ?? ''));
      $fromName = trim((string)($CFG_GLPI['admin_email_name'] ?? ''));

      if ($fromEmail === '') {
         Log::record('alert', 'skipped', 'admin_email do GLPI nao configurado; alerta nao enviado.');
         return false;
      }

      try {
         $mailer = new \GLPIMailer();
         $email = $mailer->getEmail();
         $email->from(new Address($fromEmail, $fromName !== '' ? $fromName : $fromEmail));
         foreach ($recipients as $to) {
            $email->addTo($to);
         }
         $email->subject($subject);
         $email->text($body);

         if ($mailer->send()) {
            Log::record('alert', 'ok', 'Alerta enviado: ' . $subject, count($recipients));
            return true;
         }

         Log::record('alert', 'error', 'Falha ao enviar alerta: ' . (string)$mailer->getError());
         return false;
      } catch (\Throwable $error) {
         Log::record('alert', 'error', 'Excecao ao enviar alerta: ' . $error->getMessage());
         return false;
      }
   }

   private static function v($value): string
   {
      $value = trim((string)$value);
      return $value !== '' ? $value : '-';
   }
}

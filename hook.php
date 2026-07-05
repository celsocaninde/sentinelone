<?php

use GlpiPlugin\Sentinelone\Config as SentineloneConfig;
use GlpiPlugin\Sentinelone\Profile;
use GlpiPlugin\Sentinelone\Sync;

function plugin_sentinelone_install(): bool
{
   global $DB;

   $migration = new Migration(PLUGIN_SENTINELONE_VERSION);
   $charset = DBConnection::getDefaultCharset();
   $collation = DBConnection::getDefaultCollation();

   $tables = [
      'glpi_plugin_sentinelone_configs' => "
         CREATE TABLE `glpi_plugin_sentinelone_configs` (
            `id` int unsigned NOT NULL AUTO_INCREMENT,
            `name` varchar(255) NOT NULL,
            `console_url` varchar(255) DEFAULT NULL,
            `api_token` text DEFAULT NULL,
            `is_active` tinyint NOT NULL DEFAULT 1,
            `readonly_mode` tinyint NOT NULL DEFAULT 1,
            `create_tickets` tinyint NOT NULL DEFAULT 0,
            `allow_remote_actions` tinyint NOT NULL DEFAULT 0,
            `entities_id` int unsigned NOT NULL DEFAULT 0,
            `date_creation` timestamp NULL DEFAULT NULL,
            `date_mod` timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`)
         ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}",
      'glpi_plugin_sentinelone_agents' => "
         CREATE TABLE `glpi_plugin_sentinelone_agents` (
            `id` int unsigned NOT NULL AUTO_INCREMENT,
            `sentinelone_id` varchar(255) NOT NULL,
            `computers_id` int unsigned DEFAULT NULL,
            `entities_id` int unsigned NOT NULL DEFAULT 0,
            `computer_name` varchar(255) DEFAULT NULL,
            `serial` varchar(255) DEFAULT NULL,
            `uuid` varchar(255) DEFAULT NULL,
            `mac` varchar(255) DEFAULT NULL,
            `ip` varchar(255) DEFAULT NULL,
            `os_name` varchar(255) DEFAULT NULL,
            `agent_version` varchar(255) DEFAULT NULL,
            `site_name` varchar(255) DEFAULT NULL,
            `group_name` varchar(255) DEFAULT NULL,
            `is_online` tinyint NOT NULL DEFAULT 0,
            `is_infected` tinyint NOT NULL DEFAULT 0,
            `last_active_at` timestamp NULL DEFAULT NULL,
            `tickets_id` int unsigned DEFAULT NULL,
            `raw_json` longtext DEFAULT NULL,
            `date_creation` timestamp NULL DEFAULT NULL,
            `date_mod` timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            UNIQUE KEY `uniq_sentinelone_agent` (`sentinelone_id`),
            KEY `idx_computers_id` (`computers_id`),
            KEY `idx_computer_name` (`computer_name`)
         ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}",
      'glpi_plugin_sentinelone_threats' => "
         CREATE TABLE `glpi_plugin_sentinelone_threats` (
            `id` int unsigned NOT NULL AUTO_INCREMENT,
            `sentinelone_threat_id` varchar(255) NOT NULL,
            `sentinelone_agent_id` varchar(255) DEFAULT NULL,
            `plugin_sentinelone_agents_id` int unsigned DEFAULT NULL,
            `tickets_id` int unsigned DEFAULT NULL,
            `entities_id` int unsigned NOT NULL DEFAULT 0,
            `computer_name` varchar(255) DEFAULT NULL,
            `threat_name` varchar(255) DEFAULT NULL,
            `classification` varchar(255) DEFAULT NULL,
            `status` varchar(255) DEFAULT NULL,
            `confidence_level` varchar(50) DEFAULT NULL,
            `analyst_verdict` varchar(50) DEFAULT NULL,
            `severity` varchar(50) DEFAULT NULL,
            `file_path` text DEFAULT NULL,
            `hash_sha1` varchar(255) DEFAULT NULL,
            `hash_sha256` varchar(255) DEFAULT NULL,
            `detected_at` timestamp NULL DEFAULT NULL,
            `resolved_at` timestamp NULL DEFAULT NULL,
            `raw_json` longtext DEFAULT NULL,
            `date_creation` timestamp NULL DEFAULT NULL,
            `date_mod` timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            UNIQUE KEY `uniq_sentinelone_threat` (`sentinelone_threat_id`),
            KEY `idx_tickets_id` (`tickets_id`),
            KEY `idx_agent_id` (`sentinelone_agent_id`)
         ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}",
      'glpi_plugin_sentinelone_activities' => "
         CREATE TABLE `glpi_plugin_sentinelone_activities` (
            `id` int unsigned NOT NULL AUTO_INCREMENT,
            `sentinelone_activity_id` varchar(255) NOT NULL,
            `sentinelone_agent_id` varchar(255) DEFAULT NULL,
            `plugin_sentinelone_agents_id` int unsigned DEFAULT NULL,
            `activity_type` varchar(255) DEFAULT NULL,
            `description` text DEFAULT NULL,
            `occurred_at` timestamp NULL DEFAULT NULL,
            `date_creation` timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            UNIQUE KEY `uniq_sentinelone_activity` (`sentinelone_activity_id`),
            KEY `idx_agent_id` (`sentinelone_agent_id`),
            KEY `idx_occurred_at` (`occurred_at`)
         ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}",
      'glpi_plugin_sentinelone_logs' => "
         CREATE TABLE `glpi_plugin_sentinelone_logs` (
            `id` int unsigned NOT NULL AUTO_INCREMENT,
            `action` varchar(255) NOT NULL,
            `status` varchar(50) NOT NULL,
            `message` text DEFAULT NULL,
            `items_count` int unsigned NOT NULL DEFAULT 0,
            `date_creation` timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            KEY `idx_action` (`action`),
            KEY `idx_status` (`status`)
         ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}",
      'glpi_plugin_sentinelone_groups' => "
         CREATE TABLE `glpi_plugin_sentinelone_groups` (
            `id` int unsigned NOT NULL AUTO_INCREMENT,
            `sentinelone_id` varchar(255) NOT NULL,
            `name` varchar(255) DEFAULT NULL,
            `type` varchar(64) DEFAULT NULL,
            `policy_mode` varchar(64) NOT NULL DEFAULT 'unknown',
            `agent_count` int unsigned NOT NULL DEFAULT 0,
            `site_name` varchar(255) DEFAULT NULL,
            `site_id` varchar(255) DEFAULT NULL,
            `date_creation` timestamp NULL DEFAULT NULL,
            `date_mod` timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            UNIQUE KEY `uniq_sentinelone_group` (`sentinelone_id`),
            KEY `idx_policy_mode` (`policy_mode`)
         ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}",
      'glpi_plugin_sentinelone_rogue_devices' => "
         CREATE TABLE `glpi_plugin_sentinelone_rogue_devices` (
            `id` int unsigned NOT NULL AUTO_INCREMENT,
            `sentinelone_id` varchar(255) NOT NULL,
            `hostname` varchar(255) DEFAULT NULL,
            `ip` varchar(128) DEFAULT NULL,
            `external_ip` varchar(128) DEFAULT NULL,
            `mac` varchar(64) DEFAULT NULL,
            `os` varchar(255) DEFAULT NULL,
            `classification` varchar(128) DEFAULT NULL,
            `vendor` varchar(255) DEFAULT NULL,
            `site_name` varchar(255) DEFAULT NULL,
            `detecting_agent_name` varchar(255) DEFAULT NULL,
            `open_ports` text DEFAULT NULL,
            `first_seen` timestamp NULL DEFAULT NULL,
            `last_seen` timestamp NULL DEFAULT NULL,
            `date_creation` timestamp NULL DEFAULT NULL,
            `date_mod` timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            UNIQUE KEY `uniq_rogue_id` (`sentinelone_id`),
            KEY `idx_ip` (`ip`),
            KEY `idx_last_seen` (`last_seen`)
         ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}",
      'glpi_plugin_sentinelone_cves' => "
         CREATE TABLE `glpi_plugin_sentinelone_cves` (
            `id` int unsigned NOT NULL AUTO_INCREMENT,
            `plugin_sentinelone_agents_id` int unsigned NOT NULL DEFAULT 0,
            `cve_id` varchar(64) NOT NULL,
            `severity` varchar(32) NOT NULL DEFAULT 'UNKNOWN',
            `severity_rank` tinyint unsigned NOT NULL DEFAULT 5,
            `cvss_score` decimal(4,1) DEFAULT NULL,
            `application_name` varchar(255) DEFAULT NULL,
            `application_version` varchar(128) DEFAULT NULL,
            `description` text DEFAULT NULL,
            `cve_link` varchar(512) DEFAULT NULL,
            `published_date` timestamp NULL DEFAULT NULL,
            `date_creation` timestamp NULL DEFAULT NULL,
            `date_mod` timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            KEY `idx_agent` (`plugin_sentinelone_agents_id`),
            KEY `idx_severity_rank` (`severity_rank`),
            KEY `idx_cve_id` (`cve_id`)
         ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}",
      'glpi_plugin_sentinelone_failedtickets' => "
         CREATE TABLE `glpi_plugin_sentinelone_failedtickets` (
            `id` int unsigned NOT NULL AUTO_INCREMENT,
            `sentinelone_threat_id` varchar(255) DEFAULT NULL,
            `threat_name` varchar(255) DEFAULT NULL,
            `computer_name` varchar(255) DEFAULT NULL,
            `payload` longtext DEFAULT NULL,
            `agent_payload` longtext DEFAULT NULL,
            `error` text DEFAULT NULL,
            `attempts` int unsigned NOT NULL DEFAULT 0,
            `status` varchar(20) NOT NULL DEFAULT 'pending',
            `last_attempt_at` timestamp NULL DEFAULT NULL,
            `date_creation` timestamp NULL DEFAULT NULL,
            `date_mod` timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            KEY `idx_status` (`status`),
            KEY `idx_threat` (`sentinelone_threat_id`)
         ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}",
   ];

   foreach ($tables as $table => $sql) {
      if (!$DB->tableExists($table)) {
         $DB->doQueryOrDie($sql, "Error creating {$table}");
      }
   }

   // Migracoes para instalacoes existentes (colunas adicionadas apos a v0.1).
   $threatsTable = 'glpi_plugin_sentinelone_threats';
   foreach (['confidence_level', 'analyst_verdict', 'severity'] as $newField) {
      if ($DB->tableExists($threatsTable) && !$DB->fieldExists($threatsTable, $newField)) {
         $migration->addField($threatsTable, $newField, 'string', ['value' => null]);
      }
   }

   if ($DB->tableExists($threatsTable) && !$DB->fieldExists($threatsTable, 'synced_note_ids')) {
      $migration->addField($threatsTable, 'synced_note_ids', 'text', ['value' => null]);
   }

   $agentsTable = 'glpi_plugin_sentinelone_agents';
   if ($DB->tableExists($agentsTable) && !$DB->fieldExists($agentsTable, 'tickets_id')) {
      $DB->doQuery("ALTER TABLE `{$agentsTable}` ADD COLUMN `tickets_id` int unsigned DEFAULT NULL");
   } elseif ($DB->tableExists($agentsTable) && $DB->fieldExists($agentsTable, 'tickets_id')) {
      $col = $DB->request(['SELECT' => ['COLUMN_TYPE'], 'FROM' => 'information_schema.COLUMNS',
         'WHERE' => ['TABLE_SCHEMA' => $DB->dbdefault, 'TABLE_NAME' => $agentsTable, 'COLUMN_NAME' => 'tickets_id']])->current();
      if ($col && strpos((string)($col['COLUMN_TYPE'] ?? ''), 'unsigned') === false) {
         $DB->doQuery("ALTER TABLE `{$agentsTable}` MODIFY COLUMN `tickets_id` int unsigned DEFAULT NULL");
      }
   }
   if ($DB->tableExists($agentsTable) && !$DB->fieldExists($agentsTable, 'is_network_quarantine')) {
      $migration->addField($agentsTable, 'is_network_quarantine', 'bool', ['value' => 0]);
   }

   SentineloneConfig::installDefaults();

   // Insere novos campos de configuracao para instalacoes existentes.
   $existingConfig = \Config::getConfigurationValues(SentineloneConfig::CONTEXT, ['sync_activities', 'site_entity_map', 'ticket_group_id', 'sync_software', 'sync_software_limit', 'sync_cves', 'sync_cves_limit', 'sync_rogues', 'sync_incremental', 'report_recipients', 'sync_date_from', 'agent_inactive_days', 'log_retention_days']);
   $newConfigDefaults = [];
   if (!isset($existingConfig['sync_activities'])) {
      $newConfigDefaults['sync_activities'] = '0';
   }
   if (!isset($existingConfig['site_entity_map'])) {
      $newConfigDefaults['site_entity_map'] = '';
   }
   if (!isset($existingConfig['ticket_group_id'])) {
      $newConfigDefaults['ticket_group_id'] = '0';
   }
   if (!isset($existingConfig['sync_software'])) {
      $newConfigDefaults['sync_software'] = '0';
   }
   if (!isset($existingConfig['sync_software_limit'])) {
      $newConfigDefaults['sync_software_limit'] = '30';
   }
   if (!isset($existingConfig['sync_groups'])) {
      $newConfigDefaults['sync_groups'] = '1';
   }
   if (!isset($existingConfig['alert_on_agent_offline'])) {
      $newConfigDefaults['alert_on_agent_offline'] = '0';
   }
   if (!isset($existingConfig['offline_alert_hours'])) {
      $newConfigDefaults['offline_alert_hours'] = '24';
   }
   if (!isset($existingConfig['sync_cves'])) {
      $newConfigDefaults['sync_cves'] = '0';
   }
   if (!isset($existingConfig['sync_cves_limit'])) {
      $newConfigDefaults['sync_cves_limit'] = '30';
   }
   if (!isset($existingConfig['sync_rogues'])) {
      $newConfigDefaults['sync_rogues'] = '0';
   }
   if (!isset($existingConfig['sync_incremental'])) {
      $newConfigDefaults['sync_incremental'] = '0';
   }
   if (!isset($existingConfig['report_recipients'])) {
      $newConfigDefaults['report_recipients'] = '';
   }
   if (!isset($existingConfig['sync_date_from'])) {
      $newConfigDefaults['sync_date_from'] = '';
   }
   if (!isset($existingConfig['agent_inactive_days'])) {
      $newConfigDefaults['agent_inactive_days'] = '0';
   }
   if (!isset($existingConfig['log_retention_days'])) {
      $newConfigDefaults['log_retention_days'] = '90';
   }
   if ($newConfigDefaults !== []) {
      \Config::setConfigurationValues(SentineloneConfig::CONTEXT, $newConfigDefaults);
   }
   Profile::ensureProfileRights();

   // mode: execucao automatica via CLI (cron do sistema).
   // allowmode: INTERNAL | EXTERNAL para que o botao "Executar" (modo web/GLPI)
   // tambem fique disponivel para acionamento manual a partir da interface.
   CronTask::register(Sync::class, 'syncagents', HOUR_TIMESTAMP, [
      'mode'      => CronTask::MODE_EXTERNAL,
      'allowmode' => CronTask::MODE_INTERNAL | CronTask::MODE_EXTERNAL,
      'state'     => CronTask::STATE_DISABLE,
   ]);

   CronTask::register(Sync::class, 'syncsoftware', HOUR_TIMESTAMP * 24, [
      'mode'      => CronTask::MODE_EXTERNAL,
      'allowmode' => CronTask::MODE_INTERNAL | CronTask::MODE_EXTERNAL,
      'state'     => CronTask::STATE_DISABLE,
   ]);

   CronTask::register(Sync::class, 'syncactivities', HOUR_TIMESTAMP * 4, [
      'mode'      => CronTask::MODE_EXTERNAL,
      'allowmode' => CronTask::MODE_INTERNAL | CronTask::MODE_EXTERNAL,
      'state'     => CronTask::STATE_DISABLE,
   ]);

   CronTask::register(Sync::class, 'syncthreats', HOUR_TIMESTAMP, [
      'mode'      => CronTask::MODE_EXTERNAL,
      'allowmode' => CronTask::MODE_INTERNAL | CronTask::MODE_EXTERNAL,
      'state'     => CronTask::STATE_DISABLE,
   ]);

   CronTask::register(Sync::class, 'syncgroups', HOUR_TIMESTAMP * 6, [
      'mode'      => CronTask::MODE_EXTERNAL,
      'allowmode' => CronTask::MODE_INTERNAL | CronTask::MODE_EXTERNAL,
      'state'     => CronTask::STATE_DISABLE,
   ]);

   CronTask::register(Sync::class, 'alertoffline', HOUR_TIMESTAMP * 4, [
      'mode'      => CronTask::MODE_EXTERNAL,
      'allowmode' => CronTask::MODE_INTERNAL | CronTask::MODE_EXTERNAL,
      'state'     => CronTask::STATE_DISABLE,
   ]);

   CronTask::register(Sync::class, 'synccves', HOUR_TIMESTAMP * 24, [
      'mode'      => CronTask::MODE_EXTERNAL,
      'allowmode' => CronTask::MODE_INTERNAL | CronTask::MODE_EXTERNAL,
      'state'     => CronTask::STATE_DISABLE,
   ]);

   CronTask::register(Sync::class, 'syncrogues', HOUR_TIMESTAMP * 4, [
      'mode'      => CronTask::MODE_EXTERNAL,
      'allowmode' => CronTask::MODE_INTERNAL | CronTask::MODE_EXTERNAL,
      'state'     => CronTask::STATE_DISABLE,
   ]);

   CronTask::register(Sync::class, 'reportweekly', HOUR_TIMESTAMP * 24 * 7, [
      'mode'      => CronTask::MODE_EXTERNAL,
      'allowmode' => CronTask::MODE_INTERNAL | CronTask::MODE_EXTERNAL,
      'state'     => CronTask::STATE_DISABLE,
   ]);

   CronTask::register(Sync::class, 'purgelogs', HOUR_TIMESTAMP * 24, [
      'mode'      => CronTask::MODE_EXTERNAL,
      'allowmode' => CronTask::MODE_INTERNAL | CronTask::MODE_EXTERNAL,
      'state'     => CronTask::STATE_DISABLE,
   ]);

   CronTask::register(Sync::class, 'retryfailedtickets', HOUR_TIMESTAMP, [
      'mode'      => CronTask::MODE_EXTERNAL,
      'allowmode' => CronTask::MODE_INTERNAL | CronTask::MODE_EXTERNAL,
      'state'     => CronTask::STATE_DISABLE,
   ]);

   CronTask::register(Sync::class, 'enrichcves', HOUR_TIMESTAMP * 24, [
      'mode'      => CronTask::MODE_EXTERNAL,
      'allowmode' => CronTask::MODE_INTERNAL | CronTask::MODE_EXTERNAL,
      'state'     => CronTask::STATE_DISABLE,
   ]);

   \GlpiPlugin\Sentinelone\Enrichment::ensureTable();

   // CronTask::register() nao atualiza linhas ja existentes. Para instalacoes
   // anteriores (allowmode = EXTERNAL apenas, sem o botao "Executar"), corrige
   // o allowmode das tasks ja registradas de forma idempotente.
   $DB->update(
      'glpi_crontasks',
      ['allowmode' => CronTask::MODE_INTERNAL | CronTask::MODE_EXTERNAL],
      [
         'itemtype' => Sync::class,
         'name'     => ['syncagents', 'syncthreats', 'syncactivities', 'syncsoftware', 'syncgroups', 'alertoffline', 'synccves', 'syncrogues', 'reportweekly', 'purgelogs', 'retryfailedtickets', 'enrichcves'],
      ]
   );

   $migration->executeMigration();

   return true;
}

function plugin_sentinelone_uninstall(): bool
{
   global $DB;

   $tables = [
      'glpi_plugin_sentinelone_logs',
      'glpi_plugin_sentinelone_activities',
      'glpi_plugin_sentinelone_threats',
      'glpi_plugin_sentinelone_cves',
      'glpi_plugin_sentinelone_cve_enrichment',
      'glpi_plugin_sentinelone_kev_tickets',
      'glpi_plugin_sentinelone_rogue_devices',
      'glpi_plugin_sentinelone_failedtickets',
      'glpi_plugin_sentinelone_agents',
      'glpi_plugin_sentinelone_groups',
      'glpi_plugin_sentinelone_configs',
   ];

   foreach ($tables as $table) {
      if ($DB->tableExists($table)) {
         $DB->doQueryOrDie("DROP TABLE `{$table}`", "Error dropping {$table}");
      }
   }

   $config = new \Config();
   $config->deleteByCriteria(['context' => SentineloneConfig::CONTEXT]);

   $cron = new CronTask();
   $cron->deleteByCriteria(['itemtype' => Sync::class]);

   $rights = array_column(Profile::getAllRights(), 'field');
   if ($rights !== []) {
      ProfileRight::deleteProfileRights($rights);
   }

   return true;
}

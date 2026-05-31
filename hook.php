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

   $agentsTable = 'glpi_plugin_sentinelone_agents';
   if ($DB->tableExists($agentsTable) && !$DB->fieldExists($agentsTable, 'tickets_id')) {
      $migration->addField($agentsTable, 'tickets_id', 'integer', ['value' => null]);
   }

   SentineloneConfig::installDefaults();
   Profile::ensureProfileRights();

   CronTask::register(Sync::class, 'syncagents', HOUR_TIMESTAMP, [
      'mode'      => CronTask::MODE_EXTERNAL,
      'allowmode' => CronTask::MODE_EXTERNAL,
      'state'     => CronTask::STATE_DISABLE,
   ]);

   CronTask::register(Sync::class, 'syncthreats', HOUR_TIMESTAMP, [
      'mode'      => CronTask::MODE_EXTERNAL,
      'allowmode' => CronTask::MODE_EXTERNAL,
      'state'     => CronTask::STATE_DISABLE,
   ]);

   $migration->executeMigration();

   return true;
}

function plugin_sentinelone_uninstall(): bool
{
   global $DB;

   $tables = [
      'glpi_plugin_sentinelone_logs',
      'glpi_plugin_sentinelone_threats',
      'glpi_plugin_sentinelone_agents',
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

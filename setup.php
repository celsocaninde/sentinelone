<?php

use Glpi\Plugin\Hooks;
use GlpiPlugin\Sentinelone\Activity;
use GlpiPlugin\Sentinelone\Agent;
use GlpiPlugin\Sentinelone\Config as SentineloneConfig;
use GlpiPlugin\Sentinelone\Cve;
use GlpiPlugin\Sentinelone\Dashboard as SentineloneDashboard;
use GlpiPlugin\Sentinelone\RogueDevice;
use GlpiPlugin\Sentinelone\Profile as SentineloneProfile;
use GlpiPlugin\Sentinelone\Threat;

define('PLUGIN_SENTINELONE_VERSION', '1.4.0');
define('PLUGIN_SENTINELONE_MIN_GLPI_VERSION', '11.0.0');
define('PLUGIN_SENTINELONE_MAX_GLPI_VERSION', '11.0.99');

function plugin_init_sentinelone(): void
{
   global $PLUGIN_HOOKS;

   Plugin::loadLang('sentinelone');

   SentineloneProfile::syncCurrentProfileRights();

   $PLUGIN_HOOKS['csrf_compliant']['sentinelone'] = true;
   $PLUGIN_HOOKS['config_page']['sentinelone'] = 'front/config.form.php';
   $PLUGIN_HOOKS[Hooks::ADD_CSS]['sentinelone'] = ['css/sentinelone.css'];
   $PLUGIN_HOOKS[Hooks::DASHBOARD_CARDS]['sentinelone'] = [SentineloneDashboard::class, 'getCards'];

   Plugin::registerClass(SentineloneProfile::class, [
      'addtabon' => [\Profile::class],
   ]);

   Plugin::registerClass(SentineloneConfig::class, [
      'addtabon' => \Config::class,
   ]);

   Plugin::registerClass(Agent::class, [
      'addtabon' => \Computer::class,
   ]);

   Plugin::registerClass(Threat::class);
   Plugin::registerClass(Activity::class);
   Plugin::registerClass(Cve::class);
   Plugin::registerClass(RogueDevice::class);

   $PLUGIN_HOOKS[Hooks::MENU_TOADD]['sentinelone'] = [
      'plugins' => Agent::class,
   ];
}

function plugin_version_sentinelone(): array
{
   return [
      'name'           => 'SentinelOne',
      'version'        => PLUGIN_SENTINELONE_VERSION,
      'author'         => 'Celso / Codex / Claude',
      'license'        => 'GPLv3+',
      'homepage'       => '',
      'requirements'   => [
         'glpi' => [
            'min' => PLUGIN_SENTINELONE_MIN_GLPI_VERSION,
            'max' => PLUGIN_SENTINELONE_MAX_GLPI_VERSION,
         ],
         'php' => [
            'min' => '8.2',
         ],
      ],
   ];
}

function plugin_sentinelone_check_prerequisites(): bool
{
   if (version_compare(GLPI_VERSION, PLUGIN_SENTINELONE_MIN_GLPI_VERSION, 'lt')
      || version_compare(GLPI_VERSION, PLUGIN_SENTINELONE_MAX_GLPI_VERSION, 'gt')) {
      echo sprintf(
         'This plugin requires GLPI >= %s and <= %s.',
         PLUGIN_SENTINELONE_MIN_GLPI_VERSION,
         PLUGIN_SENTINELONE_MAX_GLPI_VERSION
      );
      return false;
   }

   if (version_compare(PHP_VERSION, '8.2.0', 'lt')) {
      echo 'This plugin requires PHP >= 8.2.';
      return false;
   }

   return true;
}

function plugin_sentinelone_check_config(bool $verbose = false): bool
{
   return true;
}

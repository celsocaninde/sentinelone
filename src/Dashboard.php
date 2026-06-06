<?php

namespace GlpiPlugin\Sentinelone;

use GlpiPlugin\Sentinelone\Group;
use GlpiPlugin\Sentinelone\Sync;

/**
 * Cards de KPI do SentinelOne para o dashboard nativo do GLPI.
 *
 * Sao registrados via hook `dashboard_cards` e ficam disponiveis na galeria
 * de widgets ("Adicionar um widget") de qualquer dashboard, ao lado dos cards
 * nativos. Cada card usa o widget `bigNumber` do core.
 */
class Dashboard
{
   /** Grupo exibido na galeria de widgets. */
   private const GROUP = 'SentinelOne';

   /**
    * Callback do hook `dashboard_cards`. Recebe (e devolve) o acumulado de
    * cards coletado dos demais plugins.
    *
    * @param array|null $cards
    * @return array
    */
   public static function getCards($cards = null): array
   {
      if (!is_array($cards)) {
         $cards = [];
      }

      $defs = [
         'plugin_sentinelone_agents_total'          => 'cardAgentsTotal',
         'plugin_sentinelone_agents_online'         => 'cardAgentsOnline',
         'plugin_sentinelone_agents_infected'       => 'cardAgentsInfected',
         'plugin_sentinelone_agents_quarantined'    => 'cardAgentsQuarantined',
         'plugin_sentinelone_agents_outdated'       => 'cardAgentsOutdated',
         'plugin_sentinelone_threats_total'         => 'cardThreatsTotal',
         'plugin_sentinelone_threats_no_ticket'     => 'cardThreatsNoTicket',
         'plugin_sentinelone_computers_unprotected' => 'cardComputersUnprotected',
         'plugin_sentinelone_groups_risky'          => 'cardGroupsRisky',
         'plugin_sentinelone_rogue_devices'         => 'cardRogueDevices',
      ];

      $labels = [
         'plugin_sentinelone_agents_total'          => 'SentinelOne - Agentes',
         'plugin_sentinelone_agents_online'         => 'SentinelOne - Agentes online',
         'plugin_sentinelone_agents_infected'       => 'SentinelOne - Endpoints infectados',
         'plugin_sentinelone_agents_quarantined'    => 'SentinelOne - Em quarentena',
         'plugin_sentinelone_agents_outdated'       => 'SentinelOne - Agentes desatualizados',
         'plugin_sentinelone_threats_total'         => 'SentinelOne - Ameacas',
         'plugin_sentinelone_threats_no_ticket'     => 'SentinelOne - Ameacas sem ticket',
         'plugin_sentinelone_computers_unprotected' => 'SentinelOne - Computadores sem agente',
         'plugin_sentinelone_groups_risky'          => 'SentinelOne - Grupos sem protecao plena',
         'plugin_sentinelone_rogue_devices'         => 'SentinelOne - Dispositivos rogues',
      ];

      foreach ($defs as $key => $method) {
         $cards[$key] = [
            'widgettype' => ['bigNumber'],
            'group'      => self::GROUP,
            'label'      => $labels[$key],
            'provider'   => self::class . '::' . $method,
         ];
      }

      return $cards;
   }

   public static function cardAgentsTotal(array $params = []): array
   {
      return self::bigNumber(
         self::count(Agent::getTable()),
         'Agentes SentinelOne',
         'ti ti-devices-pc',
         self::frontUrl('agent.php')
      );
   }

   public static function cardAgentsOnline(array $params = []): array
   {
      return self::bigNumber(
         self::count(Agent::getTable(), ['is_online' => 1]),
         'Agentes online',
         'ti ti-plug-connected',
         self::frontUrl('agent.php')
      );
   }

   public static function cardAgentsInfected(array $params = []): array
   {
      return self::bigNumber(
         self::count(Agent::getTable(), ['is_infected' => 1]),
         'Endpoints infectados',
         'ti ti-bug',
         self::frontUrl('agent.php')
      );
   }

   public static function cardThreatsTotal(array $params = []): array
   {
      return self::bigNumber(
         self::count(Threat::getTable()),
         'Ameacas SentinelOne',
         'ti ti-shield-search',
         self::frontUrl('threat.php')
      );
   }

   public static function cardThreatsNoTicket(array $params = []): array
   {
      return self::bigNumber(
         self::count(Threat::getTable(), ['tickets_id' => null]),
         'Ameacas sem ticket',
         'ti ti-ticket-off',
         self::frontUrl('threat.php')
      );
   }

   public static function cardAgentsQuarantined(array $params = []): array
   {
      return self::bigNumber(
         self::count(Agent::getTable(), ['is_network_quarantine' => 1]),
         'Em quarentena',
         'ti ti-network-off',
         self::frontUrl('agent.php')
      );
   }

   public static function cardAgentsOutdated(array $params = []): array
   {
      return self::bigNumber(
         Sync::countOutdatedAgentsPublic(),
         'Agentes desatualizados',
         'ti ti-arrow-big-down',
         self::frontUrl('agent.php')
      );
   }

   public static function cardGroupsRisky(array $params = []): array
   {
      global $DB;

      $value = 0;
      if (Profile::hasReadRight() && $DB->tableExists(Group::getTable())) {
         $r1 = $DB->request(['COUNT' => 'cpt', 'FROM' => Group::getTable(), 'WHERE' => ['policy_mode' => 'detect']])->current();
         $r2 = $DB->request(['COUNT' => 'cpt', 'FROM' => Group::getTable(), 'WHERE' => ['policy_mode' => 'none']])->current();
         $value = (int)($r1['cpt'] ?? 0) + (int)($r2['cpt'] ?? 0);
      }

      return self::bigNumber(
         $value,
         'Grupos sem protecao plena',
         'ti ti-alert-triangle',
         self::frontUrl('dashboard.php')
      );
   }

   public static function cardComputersUnprotected(array $params = []): array
   {
      $value = Profile::hasReadRight() ? Agent::countUnprotectedComputers() : 0;

      return [
         'number' => $value,
         'label'  => 'Computadores sem agente',
         'icon'   => 'ti ti-shield-off',
         'url'    => self::frontUrl('unprotected.php'),
      ];
   }

   public static function cardRogueDevices(array $params = []): array
   {
      $value = Profile::hasReadRight() ? RogueDevice::countTotal() : 0;

      return self::bigNumber(
         $value,
         'Dispositivos rogues (Ranger)',
         'ti ti-ghost',
         self::frontUrl('rogues.php')
      );
   }

   /**
    * Monta o payload do widget bigNumber a partir de uma contagem simples.
    */
   private static function bigNumber(int $number, string $label, string $icon, string $url): array
   {
      return [
         'number' => $number,
         'label'  => $label,
         'icon'   => $icon,
         'url'    => $url,
      ];
   }

   /**
    * Conta linhas respeitando o direito de leitura do plugin (evita vazar
    * numeros para perfis sem acesso ao SentinelOne).
    */
   private static function count(string $table, array $where = []): int
   {
      global $DB;

      if (!Profile::hasReadRight() || !$DB->tableExists($table)) {
         return 0;
      }

      $criteria = [
         'COUNT' => 'cpt',
         'FROM'  => $table,
      ];

      if ($where !== []) {
         $criteria['WHERE'] = $where;
      }

      $row = $DB->request($criteria)->current();

      return (int)($row['cpt'] ?? 0);
   }

   private static function frontUrl(string $file): string
   {
      global $CFG_GLPI;

      $rootDoc = (string)($CFG_GLPI['root_doc'] ?? '');

      return $rootDoc . '/plugins/sentinelone/front/' . ltrim($file, '/');
   }
}

<?php

namespace GlpiPlugin\Sentinelone;

class Profile extends \Profile
{
   public const RIGHT_READ = 'plugin_sentinelone_read';
   public const RIGHT_SYNC = 'plugin_sentinelone_sync';
   public const RIGHT_CONFIG = 'plugin_sentinelone_config';

   public static function getAllRights(): array
   {
      return [
         [
            'label'  => 'SentinelOne - Visualizacao',
            'field'  => self::RIGHT_READ,
            'rights' => [READ],
         ],
         [
            'label'  => 'SentinelOne - Sincronizacao',
            'field'  => self::RIGHT_SYNC,
            'rights' => [READ, UPDATE],
         ],
         [
            'label'  => 'SentinelOne - Configuracao',
            'field'  => self::RIGHT_CONFIG,
            'rights' => [READ, UPDATE],
         ],
      ];
   }

   public static function ensureProfileRights(): void
   {
      global $DB;

      $rights = self::getAllRights();
      $fields = array_column($rights, 'field');

      if ($fields === [] || !$DB->tableExists('glpi_profilerights')) {
         return;
      }

      $profiles = [];
      foreach ($DB->request([
         'SELECT' => ['id', 'name'],
         'FROM'   => 'glpi_profiles',
      ]) as $row) {
         $profiles[(int)$row['id']] = (string)$row['name'];
      }

      $existing = [];
      foreach ($DB->request([
         'SELECT' => ['id', 'profiles_id', 'name', 'rights'],
         'FROM'   => 'glpi_profilerights',
         'WHERE'  => ['name' => $fields],
      ]) as $row) {
         $existing[(int)$row['profiles_id'] . '|' . (string)$row['name']] = [
            'id'     => (int)$row['id'],
            'rights' => (int)$row['rights'],
         ];
      }

      foreach ($profiles as $profileId => $profileName) {
         foreach ($rights as $right) {
            $field = (string)$right['field'];
            $defaultRights = self::getDefaultRightsForProfile($profileName, $right);
            $key = $profileId . '|' . $field;

            if (isset($existing[$key])) {
               if ($defaultRights > 0 && (int)$existing[$key]['rights'] === 0) {
                  $DB->update('glpi_profilerights', [
                     'rights' => $defaultRights,
                  ], [
                     'id' => (int)$existing[$key]['id'],
                  ]);
               }
               continue;
            }

            $DB->insert('glpi_profilerights', [
               'profiles_id' => $profileId,
               'name'        => $field,
               'rights'      => $defaultRights,
            ]);
         }
      }
   }

   public static function syncCurrentProfileRights(): void
   {
      global $DB;

      if (
         !isset($DB)
         || !isset($_SESSION['glpiactiveprofile'])
         || !is_array($_SESSION['glpiactiveprofile'])
      ) {
         return;
      }

      $profileId = (int)($_SESSION['glpiactiveprofile']['id'] ?? 0);
      if ($profileId <= 0 || !$DB->tableExists('glpi_profilerights')) {
         return;
      }

      foreach (self::getCurrentRightsForProfile($profileId) as $field => $rights) {
         $_SESSION['glpiactiveprofile'][$field] = $rights;
      }
   }

   public static function getCurrentRightsForProfile(int $profileId): array
   {
      global $DB;

      $result = [];
      $fields = array_column(self::getAllRights(), 'field');

      if ($profileId <= 0 || $fields === [] || !$DB->tableExists('glpi_profilerights')) {
         return $result;
      }

      foreach ($DB->request([
         'SELECT' => ['name', 'rights'],
         'FROM'   => 'glpi_profilerights',
         'WHERE'  => [
            'profiles_id' => $profileId,
            'name'        => $fields,
         ],
      ]) as $row) {
         $result[(string)$row['name']] = (int)$row['rights'];
      }

      return $result;
   }

   public static function saveRightsForProfile(int $profileId, array $submittedRights): void
   {
      global $DB;

      if ($profileId <= 0 || !$DB->tableExists('glpi_profilerights')) {
         return;
      }

      foreach (self::getAllRights() as $right) {
         $field = (string)$right['field'];
         $selected = isset($submittedRights[$field]) && is_array($submittedRights[$field])
            ? array_map('intval', $submittedRights[$field])
            : [];

         $mask = 0;
         foreach ($right['rights'] as $value) {
            $value = (int)$value;
            if (in_array($value, $selected, true)) {
               $mask |= $value;
            }
         }

         $existing = $DB->request([
            'SELECT' => ['id'],
            'FROM'   => 'glpi_profilerights',
            'WHERE'  => [
               'profiles_id' => $profileId,
               'name'        => $field,
            ],
            'LIMIT' => 1,
         ])->current();

         if ($existing) {
            $DB->update('glpi_profilerights', [
               'rights' => $mask,
            ], [
               'id' => (int)$existing['id'],
            ]);
         } else {
            $DB->insert('glpi_profilerights', [
               'profiles_id' => $profileId,
               'name'        => $field,
               'rights'      => $mask,
            ]);
         }
      }
   }

   public static function hasReadRight(): bool
   {
      return \Session::haveRight(self::RIGHT_READ, READ)
         || \Session::haveRight(self::RIGHT_CONFIG, READ);
   }

   public static function hasSyncRight(): bool
   {
      return \Session::haveRight(self::RIGHT_SYNC, UPDATE)
         || \Session::haveRight(self::RIGHT_CONFIG, UPDATE);
   }

   public static function hasConfigReadRight(): bool
   {
      return \Session::haveRight(self::RIGHT_CONFIG, READ);
   }

   public static function hasConfigUpdateRight(): bool
   {
      return \Session::haveRight(self::RIGHT_CONFIG, UPDATE);
   }

   public static function getIcon(): string
   {
      return 'ti ti-shield-lock';
   }

   public function getTabNameForItem(\CommonGLPI $item, $withtemplate = 0): string
   {
      if ($item instanceof \Profile) {
         return self::createTabEntry('SentinelOne', 0, null, self::getIcon());
      }

      return '';
   }

   public static function displayTabContentForItem(\CommonGLPI $item, $tabnum = 1, $withtemplate = 0): bool
   {
      global $CFG_GLPI;

      if (!$item instanceof \Profile) {
         return true;
      }

      $profileId = (int)$item->getID();
      $currentRights = self::getCurrentRightsForProfile($profileId);
      $canEdit = \Session::haveRight('profile', UPDATE);
      $formUrl = ($CFG_GLPI['root_doc'] ?? '') . '/plugins/sentinelone/front/profile.rights.php';

      $icons = [
         self::RIGHT_READ   => 'ti-eye',
         self::RIGHT_SYNC   => 'ti-refresh',
         self::RIGHT_CONFIG => 'ti-settings',
      ];
      $permLabels = [READ => 'Ler', UPDATE => 'Atualizar'];

      echo "<div class='sentinelone-rights'>";
      echo "<div class='sentinelone-rights__head'>";
      echo "<span class='s1-logo s1-logo--solid'><span class='ti ti-shield-lock'></span></span>";
      echo "<div>";
      echo "<h3>Permissoes SentinelOne</h3>";
      echo "<p>Defina o que este perfil pode ver e alterar no plugin.</p>";
      echo "</div>";
      echo "</div>";

      echo "<form method='post' action='" . self::h($formUrl) . "'>";
      echo \Html::hidden('profiles_id', ['value' => $profileId]);

      echo "<div class='sentinelone-rights__list'>";
      foreach (self::getAllRights() as $right) {
         $field = (string)$right['field'];
         $mask = (int)($currentRights[$field] ?? 0);
         $icon = $icons[$field] ?? 'ti-shield';

         echo "<div class='sentinelone-right'>";
         echo "<div class='sentinelone-right__info'>";
         echo "<span class='sentinelone-right__icon ti " . self::h($icon) . "'></span>";
         echo "<div class='sentinelone-right__text'>";
         echo "<strong>" . self::h((string)$right['label']) . "</strong>";
         echo "<code>" . self::h($field) . "</code>";
         echo "</div>";
         echo "</div>";

         echo "<div class='sentinelone-right__perms'>";
         foreach ([READ, UPDATE] as $permission) {
            $label = $permLabels[$permission];
            if (in_array($permission, $right['rights'], true)) {
               $checked = ($mask & $permission) === $permission;
               echo "<label class='s1-switch" . ($canEdit ? '' : ' is-disabled') . "'>";
               echo "<input type='checkbox' name='plugin_sentinelone_rights[" . self::h($field) . "][]' value='" . (int)$permission . "'"
                  . ($checked ? ' checked' : '')
                  . ($canEdit ? '' : ' disabled')
                  . ">";
               echo "<span class='s1-switch__slider'></span>";
               echo "<span class='s1-switch__text'>" . self::h($label) . "</span>";
               echo "</label>";
            } else {
               echo "<span class='s1-switch s1-switch--na'><span class='ti ti-minus'></span>" . self::h($label) . "</span>";
            }
         }
         echo "</div>";

         echo "</div>";
      }
      echo "</div>";

      if ($canEdit) {
         echo "<div class='sentinelone-rights__footer'>";
         echo "<button class='btn btn-primary' type='submit' name='save_sentinelone_rights' value='1'><span class='ti ti-device-floppy'></span>Salvar permissoes</button>";
         echo "</div>";
      }

      \Html::closeForm();
      echo "</div>";

      return true;
   }

   private static function getDefaultRightsForProfile(string $profileName, array $right): int
   {
      if (
         strcasecmp($profileName, 'Super-Admin') !== 0
         && strcasecmp($profileName, 'Admin') !== 0
      ) {
         return 0;
      }

      $mask = 0;
      foreach ((array)$right['rights'] as $permission) {
         $mask |= (int)$permission;
      }

      return $mask;
   }

   private static function h(string $value): string
   {
      return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
   }
}

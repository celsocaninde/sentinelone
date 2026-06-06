<?php

namespace GlpiPlugin\Sentinelone;

class Group extends \CommonDBTM
{
   public static $rightname = 'plugin_sentinelone_read';

   public static function getTypeName($nb = 0): string
   {
      return $nb > 1 ? 'Grupos SentinelOne' : 'Grupo SentinelOne';
   }

   public static function getTable($classname = null): string
   {
      return 'glpi_plugin_sentinelone_groups';
   }

   public static function getModeLabel(string $mode): string
   {
      return match (strtolower($mode)) {
         'protect' => 'Protect',
         'detect'  => 'Detect',
         'none'    => 'Desativado',
         default   => ucfirst($mode) !== '' ? ucfirst($mode) : 'Desconhecido',
      };
   }

   public static function getModeBadge(string $mode): string
   {
      $cls = match (strtolower($mode)) {
         'protect' => 'success',
         'detect'  => 'warning',
         'none'    => 'danger',
         default   => 'secondary',
      };
      $label = htmlspecialchars(self::getModeLabel($mode), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
      return "<span class='badge bg-{$cls}'>{$label}</span>";
   }

   public static function isRisky(string $mode): bool
   {
      return in_array(strtolower($mode), ['detect', 'none', 'unknown', ''], true);
   }
}

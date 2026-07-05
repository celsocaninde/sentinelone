<?php
/**
 * Harness de verificacao do plugin SentinelOne — exercita os caminhos das
 * features contra o banco vivo, sem tocar a API. Rodar no container fpm:
 *   docker exec glpi-nginx-glpi-fpm-1 php /var/www/glpi/plugins/sentinelone/tools/verify.php
 */

use Glpi\Kernel\Kernel;

require '/var/www/glpi/vendor/autoload.php';
$kernel = new Kernel();
$kernel->boot();

Plugin::load('sentinelone');

// CLI nao tem sessao logada; concede o direito de leitura do plugin para os
// providers com gate de permissao devolverem dados reais.
$_SESSION['glpiactiveprofile']['plugin_sentinelone_read'] = READ;

$pass = 0;
$fail = 0;
function check(string $name, bool $ok, string $extra = ''): void
{
   global $pass, $fail;
   echo ($ok ? 'PASS' : 'FAIL') . " — {$name}" . ($extra !== '' ? " ({$extra})" : '') . "\n";
   $ok ? $pass++ : $fail++;
}

global $DB;

// 1) Classes principais autoloadam
foreach (['Agent', 'Threat', 'Cve', 'Enrichment', 'HealthReport', 'KevTicket', 'TicketManager', 'Sync', 'Config', 'Dashboard'] as $class) {
   check("classe {$class} carrega", class_exists('GlpiPlugin\\Sentinelone\\' . $class));
}

// 2) Tabelas
foreach ([
   'glpi_plugin_sentinelone_agents',
   'glpi_plugin_sentinelone_threats',
   'glpi_plugin_sentinelone_cves',
   'glpi_plugin_sentinelone_cve_enrichment',
] as $table) {
   check("tabela {$table}", $DB->tableExists($table));
}

// 3) Config: chaves novas presentes
$config = GlpiPlugin\Sentinelone\Config::getConfig();
check('config kev_auto_ticket existe', array_key_exists('kev_auto_ticket', $config), (string)$config['kev_auto_ticket']);

// 4) Enrichment: resumo KEV com o formato esperado
$kev = GlpiPlugin\Sentinelone\Enrichment::getKevSummary();
check('getKevSummary devolve as 4 chaves', count(array_intersect_key($kev, array_flip(['cves', 'occurrences', 'endpoints', 'ransomware']))) === 4);
check('getKevSummary valores >= 0', min($kev) >= 0, json_encode($kev));

// 5) HealthReport: notas coerentes
$rows = GlpiPlugin\Sentinelone\HealthReport::computeScores();
check('computeScores devolve a frota inteira', count($rows) > 0, count($rows) . ' agentes');
$sane = true;
$sorted = true;
$prev = -1;
foreach ($rows as $row) {
   if ($row['score'] < 0 || $row['score'] > 10) {
      $sane = false;
   }
   if ($row['score'] < $prev) {
      $sorted = false;
   }
   $prev = $row['score'];
}
check('notas dentro de [0,10]', $sane);
check('ordenado do pior para o melhor', $sorted);
$summary = GlpiPlugin\Sentinelone\HealthReport::summary($rows);
check('summary soma bate com o total', $summary['healthy'] + $summary['warning'] + $summary['critical'] === $summary['total'], json_encode($summary));
check('veredito coerente com a nota', GlpiPlugin\Sentinelone\HealthReport::verdictFor(9.0) === 'healthy'
   && GlpiPlugin\Sentinelone\HealthReport::verdictFor(6.0) === 'warning'
   && GlpiPlugin\Sentinelone\HealthReport::verdictFor(2.0) === 'critical');

// 6) KevTicket: tabela de controle + desligado nao cria nada
GlpiPlugin\Sentinelone\KevTicket::ensureTable();
check('tabela kev_tickets criada', $DB->tableExists('glpi_plugin_sentinelone_kev_tickets'));
$offConfig = array_merge($config, ['kev_auto_ticket' => '0']);
[$t, $p] = GlpiPlugin\Sentinelone\KevTicket::processNewFindings($offConfig);
check('processNewFindings com toggle OFF nao cria ticket', $t === 0 && $p === 0);

// 7) Cards nativos do dashboard GLPI
$cards = GlpiPlugin\Sentinelone\Dashboard::getCards([]);
check('dashboard_cards devolve 12 cards', count($cards) === 12, (string)count($cards));

// 8) Crons registradas
$cronRow = $DB->request([
   'COUNT' => 'cpt',
   'FROM'  => 'glpi_crontasks',
   'WHERE' => ['itemtype' => GlpiPlugin\Sentinelone\Sync::class],
])->current();
check('12 crons registradas', (int)($cronRow['cpt'] ?? 0) === 12, (string)($cronRow['cpt'] ?? 0));

// 9) Locales compilados
foreach (['pt_BR', 'en_US'] as $locale) {
   check("locale {$locale}.mo existe", is_file(__DIR__ . "/../locales/{$locale}.mo"));
}

echo "\nRESULT: {$pass} passed, {$fail} failed\n";
exit($fail > 0 ? 1 : 0);

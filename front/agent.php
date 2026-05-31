<?php

use GlpiPlugin\Sentinelone\Agent;
use GlpiPlugin\Sentinelone\Profile;

include('../../../inc/includes.php');

\Session::checkRight(Profile::RIGHT_READ, READ);

\Html::header('Agentes SentinelOne', $_SERVER['PHP_SELF'], 'plugins', 'sentinelone');
\Search::show(Agent::class);
\Html::footer();

<?php

use GlpiPlugin\Sentinelone\Profile;
use GlpiPlugin\Sentinelone\Threat;

include('../../../inc/includes.php');

\Session::checkRight(Profile::RIGHT_READ, READ);

\Html::header('Ameacas SentinelOne', $_SERVER['PHP_SELF'], 'plugins', 'sentinelone');
\Search::show(Threat::class);
\Html::footer();

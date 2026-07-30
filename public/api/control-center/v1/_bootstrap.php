<?php

declare(strict_types=1);

use Vp3\Http\PublicResponseGuard;

$container = require dirname(__DIR__, 4) . '/bootstrap.php';
PublicResponseGuard::enable();

return $container;

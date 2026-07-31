<?php

declare(strict_types=1);

use Vp3\Http\BrowserRequestIntegrity;
use Vp3\Http\ControlCenterEndpoint;
use Vp3\Http\PublicResponseGuard;

$container = require dirname(__DIR__, 4) . '/bootstrap.php';
$requestIntegrity = new BrowserRequestIntegrity(
    (string) $container['config']['app']['base_url'],
    (string) $container['config']['app']['env']
);
ControlCenterEndpoint::configureRequestIntegrity($requestIntegrity);
PublicResponseGuard::enable();

return $container;

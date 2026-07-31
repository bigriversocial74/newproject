<?php

declare(strict_types=1);

use Vp3\HomeServers\HomeServerControlPlaneService;
use Vp3\Http\BrowserRequestIntegrity;
use Vp3\Http\HomeServerEndpoint;

$container = require dirname(__DIR__, 4) . '/bootstrap.php';
$requestIntegrity = new BrowserRequestIntegrity(
    (string) $container['config']['app']['base_url'],
    (string) $container['config']['app']['env']
);
HomeServerEndpoint::configureRequestIntegrity($requestIntegrity);
$container['homeserver_control_plane'] = new HomeServerControlPlaneService(
    $container['database'],
    $container['homeservers'],
    max(120, (int) (getenv('VP3_HOMESERVER_INSTALLER_GRANT_TTL_SECONDS') ?: 600)),
    max(300, (int) (getenv('VP3_HOMESERVER_TRANSFER_TTL_SECONDS') ?: 1800))
);

return $container;

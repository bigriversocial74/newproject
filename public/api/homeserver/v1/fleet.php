<?php

declare(strict_types=1);

use Vp3\HomeServers\HomeServerFleetQueryService;
use Vp3\Http\HomeServerEndpoint;
use Vp3\Http\JsonResponse;

$container = require __DIR__ . '/_bootstrap.php';
HomeServerEndpoint::requireBrowserMethod('POST');

try {
    $payload = HomeServerEndpoint::payload();
    $account = HomeServerEndpoint::accountContext($container, $payload);
    $fleet = new HomeServerFleetQueryService($container['database']);
    JsonResponse::send(['data' => $fleet->snapshot($account['account_id'])]);
} catch (Throwable $exception) {
    HomeServerEndpoint::sendException($exception);
}

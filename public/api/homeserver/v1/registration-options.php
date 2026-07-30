<?php

declare(strict_types=1);

use Vp3\HomeServers\HomeServerRegistrationOptionsService;
use Vp3\Http\HomeServerEndpoint;
use Vp3\Http\JsonResponse;

$container = require __DIR__ . '/_bootstrap.php';
HomeServerEndpoint::requireMethod('POST');

try {
    $payload = HomeServerEndpoint::payload();
    $account = HomeServerEndpoint::accountContext($container, $payload);
    $options = new HomeServerRegistrationOptionsService($container['database']);
    JsonResponse::send(['data' => [
        'account_id' => $account['account_id'],
        'licenses' => $options->eligibleLicenses($account['account_id']),
    ]]);
} catch (Throwable $exception) {
    HomeServerEndpoint::sendException($exception);
}

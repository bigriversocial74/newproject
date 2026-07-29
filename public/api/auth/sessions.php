<?php

declare(strict_types=1);

use Vp3\Http\AuthEndpoint;
use Vp3\Http\JsonResponse;

$container = require dirname(__DIR__, 3) . '/bootstrap.php';
AuthEndpoint::requireMethod('GET');

try {
    $current = $container['authentication_context']->requireCurrent(AuthEndpoint::ip(), AuthEndpoint::userAgent());
    JsonResponse::send(['data' => ['sessions' => $container['database_sessions']->listForUser(
        $current['user']['id'],
        $current['session']['public_id']
    )]]);
} catch (Throwable $exception) {
    AuthEndpoint::sendException($exception);
}

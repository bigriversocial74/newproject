<?php

declare(strict_types=1);

use Vp3\Http\AuthEndpoint;
use Vp3\Http\JsonResponse;

$container = require dirname(__DIR__, 3) . '/bootstrap.php';
AuthEndpoint::requireMethod('GET');

try {
    $current = $container['authentication_context']->requireCurrent(AuthEndpoint::ip(), AuthEndpoint::userAgent());
    JsonResponse::send(['data' => [
        'user' => $current['user'],
        'session' => $current['session'],
        'csrf_token' => $container['session']->csrfToken(),
    ]]);
} catch (Throwable $exception) {
    AuthEndpoint::sendException($exception);
}

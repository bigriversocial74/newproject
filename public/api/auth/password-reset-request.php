<?php

declare(strict_types=1);

use Vp3\Http\JsonResponse;

$container = require dirname(__DIR__, 3) . '/bootstrap.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    JsonResponse::send(['error' => ['code' => 'method_not_allowed', 'message' => 'POST required.']], 405);
}

try {
    $payload = json_decode((string) file_get_contents('php://input'), true, 16, JSON_THROW_ON_ERROR);
    $token = $container['account_security']->createPasswordReset((string) ($payload['email'] ?? ''));
    $response = ['data' => ['status' => 'accepted']];
    if ($token !== null && ($container['config']['app']['env'] ?? 'production') !== 'production') {
        $response['data']['reset_token'] = $token;
    }
    JsonResponse::send($response, 202);
} catch (JsonException) {
    JsonResponse::send(['error' => ['code' => 'invalid_json', 'message' => 'The request body is not valid JSON.']], 400);
}

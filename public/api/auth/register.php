<?php

declare(strict_types=1);

use Vp3\Http\JsonResponse;

$container = require dirname(__DIR__, 3) . '/bootstrap.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    JsonResponse::send(['error' => ['code' => 'method_not_allowed', 'message' => 'POST required.']], 405);
}

try {
    $payload = json_decode((string) file_get_contents('php://input'), true, 32, JSON_THROW_ON_ERROR);
    if (!is_array($payload)) {
        throw new RuntimeException('Invalid request body.');
    }

    $result = $container['auth']->register(
        (string) ($payload['email'] ?? ''),
        (string) ($payload['password'] ?? ''),
        (string) ($payload['display_name'] ?? '')
    );

    $response = [
        'data' => [
            'account_id' => $result['account_id'],
            'user_id' => $result['user_id'],
            'status' => 'pending_verification',
        ],
    ];

    if (($container['config']['app']['env'] ?? 'production') !== 'production') {
        $response['data']['verification_token'] = $result['verification_token'];
    }

    JsonResponse::send($response, 201);
} catch (JsonException $exception) {
    JsonResponse::send(['error' => ['code' => 'invalid_json', 'message' => 'The request body is not valid JSON.']], 400);
} catch (Throwable $exception) {
    JsonResponse::send(['error' => ['code' => 'registration_failed', 'message' => $exception->getMessage()]], 422);
}

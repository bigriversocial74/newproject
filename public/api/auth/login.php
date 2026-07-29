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

    $user = $container['auth']->authenticate(
        (string) ($payload['email'] ?? ''),
        (string) ($payload['password'] ?? '')
    );

    if ($user === null) {
        JsonResponse::send(['error' => ['code' => 'invalid_credentials', 'message' => 'The email or password is incorrect.']], 401);
    }

    $container['session']->regenerate();
    $container['session']->put('auth_user', [
        'id' => $user['id'],
        'public_id' => $user['public_id'],
        'email' => $user['email'],
        'display_name' => $user['display_name'],
        'authenticated_at' => time(),
    ]);

    JsonResponse::send(['data' => ['user' => $user]]);
} catch (JsonException $exception) {
    JsonResponse::send(['error' => ['code' => 'invalid_json', 'message' => 'The request body is not valid JSON.']], 400);
} catch (Throwable $exception) {
    JsonResponse::send(['error' => ['code' => 'login_failed', 'message' => 'Unable to sign in.']], 500);
}

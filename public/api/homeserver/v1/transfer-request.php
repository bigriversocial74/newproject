<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\Http\HomeServerEndpoint;
use Vp3\Http\JsonResponse;

$container = require __DIR__ . '/_bootstrap.php';
HomeServerEndpoint::requireMethod('POST');
try {
    $payload = HomeServerEndpoint::payload();
    $account = HomeServerEndpoint::accountContext($container, $payload);
    $targetPublicId = trim((string) ($payload['target_account_public_id'] ?? ''));
    if (!preg_match('/^[A-Za-z0-9._:-]{3,64}$/', $targetPublicId)) {
        throw new AuthPublicException('target_account_identity_invalid', 'A valid destination VP3 account identity is required.', 422);
    }
    $targetQuery = $container['database']->pdo()->prepare(
        "SELECT id FROM accounts WHERE public_id=:public AND status='active' LIMIT 1"
    );
    $targetQuery->execute(['public' => $targetPublicId]);
    $targetAccountId = (int) $targetQuery->fetchColumn();
    if ($targetAccountId < 1) {
        throw new AuthPublicException('target_account_not_found', 'The destination VP3 account was not found or is inactive.', 404);
    }
    $result = $container['homeserver_control_plane']->requestTransfer(
        $account['account_id'],
        (string) ($payload['device_public_id'] ?? ''),
        $targetAccountId,
        HomeServerEndpoint::requestId($payload)
    );
    $result['target_account_public_id'] = $targetPublicId;
    JsonResponse::send(['data' => $result], 201);
} catch (Throwable $exception) {
    HomeServerEndpoint::sendException($exception);
}

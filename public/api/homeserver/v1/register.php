<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\HomeServers\HomeServerLicenseIdentityResolver;
use Vp3\Http\HomeServerEndpoint;
use Vp3\Http\JsonResponse;

$container = require __DIR__ . '/_bootstrap.php';
HomeServerEndpoint::requireBrowserMethod('POST');
try {
    $payload = HomeServerEndpoint::payload();
    $account = HomeServerEndpoint::accountContext($container, $payload);
    if (array_key_exists('license_id', $payload)) {
        throw new AuthPublicException(
            'license_public_identity_required',
            'Use the public HomeServer license identity for registration.',
            400
        );
    }
    $licensePublicId = trim((string) ($payload['license_public_id'] ?? ''));
    $licenseId = (new HomeServerLicenseIdentityResolver($container['database']))
        ->resolveEligible($account['account_id'], $licensePublicId);
    $result = $container['homeserver_control_plane']->registerDevice(
        $account['account_id'],
        $licenseId,
        (string) ($payload['device_fingerprint'] ?? ''),
        HomeServerEndpoint::requestId($payload),
        HomeServerEndpoint::idempotencyKey($payload)
    );
    unset($result['device_id']);
    $result['account_public_id'] = $account['account_public_id'];
    $result['license_public_id'] = $licensePublicId;
    JsonResponse::send(['data' => $result], 201);
} catch (Throwable $exception) {
    HomeServerEndpoint::sendException($exception);
}

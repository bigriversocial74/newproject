<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\HomeServers\HomeServerLicenseIdentityResolver;
use Vp3\Http\HomeServerEndpoint;
use Vp3\Http\JsonResponse;

$container = require __DIR__ . '/_bootstrap.php';
HomeServerEndpoint::requireMethod('POST');
try {
    $payload = HomeServerEndpoint::payload();
    $account = HomeServerEndpoint::accountContext($container, $payload);
    if (array_key_exists('target_license_id', $payload)) {
        throw new AuthPublicException(
            'license_public_identity_required',
            'Use the public HomeServer license identity for transfer acceptance.',
            400
        );
    }
    $licensePublicId = trim((string) ($payload['target_license_public_id'] ?? ''));
    $licenseId = (new HomeServerLicenseIdentityResolver($container['database']))
        ->resolveEligible($account['account_id'], $licensePublicId);
    $result = $container['homeserver_control_plane']->acceptTransfer(
        $account['account_id'],
        (string) ($payload['transfer_code'] ?? ''),
        $licenseId,
        HomeServerEndpoint::requestId($payload)
    );
    unset($result['license_id']);
    $result['account_public_id'] = $account['account_public_id'];
    $result['license_public_id'] = $licensePublicId;
    JsonResponse::send(['data' => $result]);
} catch (Throwable $exception) {
    HomeServerEndpoint::sendException($exception);
}

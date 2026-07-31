<?php

declare(strict_types=1);

use Vp3\Http\ControlCenterEndpoint;
use Vp3\Http\JsonResponse;
use Vp3\Security\SecurityAuditExportService;
use Vp3\Security\SecurityAuditQueryService;

$container = require __DIR__ . '/_bootstrap.php';
ControlCenterEndpoint::requireMethod('POST');

try {
    $payload = ControlCenterEndpoint::payload();
    $account = ControlCenterEndpoint::accountContextForRoles(
        $container,
        $payload,
        ['customer_owner', 'customer_admin']
    );

    $format = isset($payload['format']) ? (string) $payload['format'] : 'csv';
    $filters = isset($payload['filters']) && is_array($payload['filters'])
        ? $payload['filters']
        : [];

    $query = new SecurityAuditQueryService($container['database']);
    $export = new SecurityAuditExportService($container['database'], $query);
    $result = $export->build(
        $account['account_id'],
        (int) $account['user']['id'],
        $account['role'],
        $format,
        $filters
    );

    JsonResponse::send(['data' => [
        'public_id' => $result['public_id'],
        'format' => $result['format'],
        'row_count' => $result['row_count'],
        'content_hash' => $result['content_hash'],
        'expires_at' => $result['expires_at'],
        'content_base64' => base64_encode($result['content']),
    ]]);
} catch (Throwable $exception) {
    ControlCenterEndpoint::sendException($exception);
}

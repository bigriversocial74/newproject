<?php

declare(strict_types=1);

use Vp3\Deployment\PlatformOperatorGrantService;

$root = dirname(__DIR__);
$container = require $root . '/bootstrap.php';
$options = [];
foreach (array_slice($argv, 1) as $argument) {
    if (str_starts_with($argument, '--') && str_contains($argument, '=')) {
        [$key, $value] = explode('=', substr($argument, 2), 2);
        $options[strtolower(trim($key))] = trim($value);
    }
}
$respond = static function (array $document, int $exit = 0): never {
    fwrite(STDOUT, json_encode($document, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    exit($exit);
};
try {
    $action = strtolower((string) ($options['action'] ?? getenv('VP3_PLATFORM_OPERATOR_ACTION') ?: 'grant'));
    if (!in_array($action, ['grant', 'revoke'], true)) {
        throw new RuntimeException('Use --action=grant or --action=revoke.');
    }
    $requiredConfirmation = $action === 'grant' ? 'GRANT_PLATFORM_OPERATOR' : 'REVOKE_PLATFORM_OPERATOR';
    if (!hash_equals($requiredConfirmation, (string) ($options['confirm'] ?? getenv('VP3_PLATFORM_OPERATOR_CONFIRM') ?: ''))) {
        throw new RuntimeException('Explicit --confirm=' . $requiredConfirmation . ' acknowledgement is required.');
    }
    $account = (string) ($options['account'] ?? getenv('VP3_PLATFORM_OPERATOR_ACCOUNT_PUBLIC_ID') ?: '');
    $owner = (string) ($options['owner'] ?? getenv('VP3_PLATFORM_OPERATOR_OWNER_PUBLIC_ID') ?: '');
    $requestId = (string) ($options['request-id'] ?? getenv('VP3_PLATFORM_OPERATOR_REQUEST_ID') ?: '');
    $service = new PlatformOperatorGrantService($container['database']);
    $data = $action === 'grant'
        ? $service->grant($account, $owner, $requestId)
        : $service->revoke($account, $owner, $requestId);
    $respond(['ok' => true, 'data' => $data]);
} catch (Throwable $exception) {
    $respond([
        'ok' => false,
        'error' => [
            'code' => 'platform_operator_access_change_failed',
            'message' => 'The platform operator access change did not complete.',
        ],
    ], 1);
}

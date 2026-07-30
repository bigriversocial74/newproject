<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};
$read = static function (string $path) use ($root): string {
    $content = file_get_contents($root . '/' . $path);
    if (!is_string($content)) {
        throw new RuntimeException('Unable to read ' . $path);
    }
    return $content;
};

$required = [
    'public/infrastructure.php',
    'public/api/control-center/v1/infrastructure-overview.php',
    'public/api/control-center/v1/infrastructure-action.php',
    'public/assets/infrastructure-control-center.js',
    'public/assets/infrastructure-control-center.css',
    'src/Infrastructure/InfrastructureControlCenterQueryService.php',
    'src/Infrastructure/InfrastructureControlCenterActionService.php',
    'tests/phase20_infrastructure_control_center_database_integration.php',
    '.github/workflows/phase20-infrastructure-control-center.yml',
];
foreach ($required as $path) {
    $assert(is_file($root . '/' . $path), 'Missing Phase 20 file: ' . $path);
}

$page = $read('public/infrastructure.php');
$overview = $read('public/api/control-center/v1/infrastructure-overview.php');
$action = $read('public/api/control-center/v1/infrastructure-action.php');
$query = $read('src/Infrastructure/InfrastructureControlCenterQueryService.php');
$actions = $read('src/Infrastructure/InfrastructureControlCenterActionService.php');
$nav = $read('src/ControlCenter/ControlCenterPage.php');
$js = $read('public/assets/infrastructure-control-center.js');

$assert(str_contains($page, "['customer_owner', 'customer_admin']"), 'Infrastructure page is not owner/admin-only.');
$assert(str_contains($overview, 'accountContextForRoles'), 'Infrastructure overview does not enforce role-aware account context.');
$assert(str_contains($action, 'ControlCenterEndpoint::requestId'), 'Infrastructure mutations do not require bounded request IDs.');
$assert(str_contains($action, 'ControlCenterEndpoint::idempotencyKey'), 'Infrastructure queue mutations do not require idempotency keys.');
$assert(str_contains($actions, 'LIMIT 1 FOR UPDATE'), 'Infrastructure actions do not lock membership and resource state.');
$assert(str_contains($actions, 'hash_equals($storedRole, $role)'), 'Infrastructure actions trust a stale caller role.');
$assert(str_contains($actions, "\$confirmation !== 'TEARDOWN'"), 'Infrastructure teardown lacks exact confirmation.');
$assert(str_contains($actions, 'provider_operation_steps'), 'Infrastructure queueing does not create durable operation stages.');
$assert(str_contains($actions, 'credentials_ciphertext'), 'Provider credentials are not encrypted into the production schema.');
$assert(str_contains($actions, 'infrastructure_permission_denied'), 'Denied infrastructure actions do not use a stable public code.');
$assert(str_contains($nav, "'infrastructure' => ['/infrastructure.php', 'Infrastructure']"), 'Control Center navigation omits Infrastructure.');
$assert(str_contains($js, "credentials: 'same-origin'"), 'Infrastructure browser API calls are not same-origin credentialed.');
$assert(!str_contains($js, 'localStorage') && !str_contains($js, 'sessionStorage'), 'Infrastructure UI persists sensitive state in browser storage.');
$assert(!preg_match('/<script(?![^>]*src=)/i', $page), 'Infrastructure page contains inline JavaScript.');

$forbiddenOutput = [
    'credentials_ciphertext', 'credentials_nonce', 'credentials_tag', 'encryption_key_id',
    'provider_reference_ciphertext', 'provider_reference_nonce', 'provider_reference_tag',
    'record_value_hash', 'service_plan_hash', 'endpoint_hash', 'domains_hash',
    'lease_token', 'locked_by', 'last_error_code', 'last_error_message',
    'receipt_hash', 'metadata_json',
];
foreach ($forbiddenOutput as $key) {
    $assert(
        !preg_match("/['\"]" . preg_quote($key, '/') . "['\"]\s*=>/", $query),
        'Infrastructure query exposes forbidden key ' . $key . '.'
    );
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 20 Infrastructure Control Center contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 20 Infrastructure Control Center contract passed.\n");

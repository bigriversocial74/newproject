<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$required = [
    'src/Operations/OperationsControlCenterQueryService.php',
    'src/Operations/OperationsControlCenterActionService.php',
    'src/ControlCenter/ControlCenterPage.php',
    'public/operations.php',
    'public/api/control-center/v1/operations-overview.php',
    'public/api/control-center/v1/operations-action.php',
    'public/assets/operations-control-center.js',
    'public/assets/operations-control-center.css',
    'tests/phase18_operations_control_center_database_integration.php',
    '.github/workflows/phase18-operations-control-center.yml',
];
foreach ($required as $path) {
    if (!is_file($root . '/' . $path)) {
        $failures[] = 'Missing Phase 18 file: ' . $path;
    }
}

$read = static fn (string $path): string => (string) @file_get_contents($root . '/' . $path);
$bootstrap = $read('bootstrap.php');
$shell = $read('src/ControlCenter/ControlCenterPage.php');
$query = $read('src/Operations/OperationsControlCenterQueryService.php');
$actions = $read('src/Operations/OperationsControlCenterActionService.php');
$page = $read('public/operations.php');
$overviewEndpoint = $read('public/api/control-center/v1/operations-overview.php');
$actionEndpoint = $read('public/api/control-center/v1/operations-action.php');
$client = $read('public/assets/operations-control-center.js');
$installer = $read('database/vp3-single-install.sql');
$workflow = $read('.github/workflows/phase18-operations-control-center.yml');

$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

$assert(str_contains($bootstrap, 'OperationsControlCenterQueryService')
    && str_contains($bootstrap, 'OperationsControlCenterActionService')
    && str_contains($bootstrap, "'operations_control_center_query'")
    && str_contains($bootstrap, "'operations_control_center_actions'"),
    'Phase 18 services are not wired into bootstrap.');
$assert(str_contains($shell, "'operations' => ['/operations.php', 'Operations']")
    && str_contains($shell, "$" . "role === 'support_member'")
    && str_contains($shell, 'operations-control-center.css'),
    'Role-aware Operations navigation or stylesheet loading is incomplete.');
$assert(str_contains($page, "['customer_owner', 'customer_admin', 'support_member']")
    && str_contains($page, "'operations'")
    && str_contains($page, '/assets/operations-control-center.js'),
    'Operations page role or shell contract is incomplete.');
$assert(!str_contains($page, '<script>') && !str_contains($page, '<style') && !str_contains($page, ' style='),
    'Operations page violates the external script/style CSP contract.');

foreach ([$overviewEndpoint, $actionEndpoint] as $endpoint) {
    $assert(str_contains($endpoint, "requireMethod('POST')")
        && str_contains($endpoint, 'accountContextForRoles')
        && str_contains($endpoint, "['customer_owner', 'customer_admin', 'support_member']"),
        'Operations API is missing POST, CSRF/session, or role-aware account boundaries.');
}
$assert(str_contains($actionEndpoint, 'ControlCenterEndpoint::requestId')
    && str_contains($actionEndpoint, 'incident_public_id')
    && str_contains($actionEndpoint, 'channel_public_id'),
    'Operations actions do not require request identity or public resource IDs.');

$assert(str_contains($query, "WHERE account_scope=:account")
    && str_contains($query, 'i.account_scope=:account')
    && str_contains($query, 'c.account_scope=:channel_account'),
    'Operations snapshot is missing account isolation.');
foreach (['destination_ciphertext', 'destination_nonce', 'destination_tag', 'encryption_key_id', 'last_error_hash', 'payload_hash', 'response_hash', 'locked_by', 'lease_token'] as $forbidden) {
    $assert(!str_contains($query, $forbidden), 'Operations browser query exposes protected operational data: ' . $forbidden);
}
$assert(str_contains($query, "'can_acknowledge' => true")
    && str_contains($query, "'can_resolve' => $" . "canManage")
    && str_contains($query, "'can_manage_channels' => $" . "canManage"),
    'Operations permissions are not role-aware.');
$assert(str_contains($query, "substr(hash('sha256'") && str_contains($query, "'source_reference'"),
    'Operations snapshot does not replace raw internal source IDs with bounded references.');

$assert(str_contains($actions, "LIMIT 1 FOR UPDATE")
    && str_contains($actions, 'hash_equals($storedRole, $actorRole)')
    && str_contains($actions, 'customer_owner')
    && str_contains($actions, 'customer_admin')
    && str_contains($actions, 'support_member'),
    'Operations mutations do not revalidate the active actor role transactionally.');
$assert(str_contains($actions, "preg_match('/^OPS-INC-[A-F0-9]{20}$/")
    && str_contains($actions, "preg_match('/^OPS-CHANNEL-[A-F0-9]{20}$/"),
    'Operations mutations do not use bounded public resource identifiers.');
$assert(str_contains($actions, "$" . "this->cipher->encrypt")
    && str_contains($actions, "json_encode(['email' => $" . "email]")
    && str_contains($actions, "'operations-channel|'"),
    'Notification destinations are not encrypted using the retained context contract.');
$assert(str_contains($actions, 'operational_request_receipts')
    && str_contains($actions, 'appendIncidentEvent')
    && str_contains($actions, '$this->audit->appendWithPdo')
    && str_contains($actions, '$this->notifications->queueWithPdo'),
    'Operations mutations are missing replay receipts, incident evidence, audit evidence, or notification delivery.');
$assert(str_contains($actions, 'summary_hash') && !str_contains($actions, 'resolution_summary='),
    'Incident resolution text can be persisted instead of evidence-hashed.');

foreach (['localStorage', 'sessionStorage', '.innerHTML', 'eval(', 'destination_ciphertext', 'destination_nonce', 'destination_tag'] as $forbidden) {
    $assert(!str_contains($client, $forbidden), 'Operations client contains forbidden behavior or protected data: ' . $forbidden);
}
$assert(str_contains($client, 'textContent')
    && str_contains($client, 'X-Request-ID')
    && str_contains($client, "credentials: 'same-origin'"),
    'Operations client is missing safe rendering, request identity, or same-origin credentials.');

$phase10 = strpos($installer, '20260729_phase10_operations_readiness.sql');
$phase17 = strpos($installer, '20260730_phase17_account_team_security.sql');
$assert($phase10 !== false && $phase17 !== false && $phase10 < $phase17,
    'Cumulative installer does not retain the certified operations schema before Phase 17.');
$assert(str_contains($workflow, "php: ['8.2', '8.3']")
    && str_contains($workflow, 'mysql:8.0')
    && str_contains($workflow, 'mariadb:10.11')
    && substr_count($workflow, 'vp3-single-install.sql') >= 4,
    'Phase 18 workflow does not certify PHP 8.2/8.3 and repeated MySQL/MariaDB imports.');

if ($failures !== []) {
    fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL);
    exit(1);
}

echo "Phase 18 operations control center contract passed.\n";

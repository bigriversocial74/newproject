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
    'src/Lifecycle/DomainPodLifecycleQueryService.php',
    'src/Lifecycle/DomainPodLifecycleActionService.php',
    'src/Lifecycle/PodRollbackLifecycleService.php',
    'tests/phase21_nested_transaction_database_integration.php',
    'tests/phase21_domain_pod_lifecycle_database_integration.php',
    'tests/phase21_failed_pod_rollback_database_integration.php',
    '.github/workflows/phase21-domain-pod-lifecycle.yml',
];
foreach ($required as $path) {
    $assert(is_file($root . '/' . $path), 'Missing Phase 21 file: ' . $path);
}

$database = $read('src/Database.php');
$query = $read('src/Lifecycle/DomainPodLifecycleQueryService.php');
$actions = $read('src/Lifecycle/DomainPodLifecycleActionService.php');
$rollback = $read('src/Lifecycle/PodRollbackLifecycleService.php');
$overview = $read('public/api/control-center/v1/overview.php');
$domainApi = $read('public/api/control-center/v1/domain-action.php');
$podApi = $read('public/api/control-center/v1/pod-action.php');
$dashboard = $read('public/dashboard.php');
$domainsPage = $read('public/domains.php');
$podsPage = $read('public/pods.php');
$browser = $read('public/assets/control-center.js');

$assert(str_contains($database, 'SAVEPOINT vp3_nested_') || str_contains($database, "'SAVEPOINT ' . \$savepoint"), 'Database wrapper lacks nested savepoints.');
$assert(str_contains($database, 'ROLLBACK TO SAVEPOINT'), 'Nested transaction failures do not roll back to a savepoint.');
$assert(str_contains($database, 'RELEASE SAVEPOINT'), 'Nested savepoints are not released.');
$assert(str_contains($actions, 'LIMIT 1 FOR UPDATE'), 'Lifecycle mutations do not lock membership and resources.');
$assert(str_contains($actions, 'hash_equals($storedRole, $role)'), 'Lifecycle mutations trust stale caller roles.');
$assert(str_contains($actions, 'lifecycle_permission_denied'), 'Lifecycle authorization lacks a stable public denial code.');
$assert(str_contains($actions, "\$confirmation !== 'RELEASE'"), 'Domain release lacks exact confirmation.');
$assert(str_contains($rollback, "\$confirmation !== 'ROLLBACK'"), 'POD rollback lacks exact confirmation.');
$assert(str_contains($rollback, 'ACTIVE_JOB_STATUSES'), 'POD rollback lacks active-job serialization.');
$assert(str_contains($rollback, "status='canceled'"), 'Failed POD work is not atomically replaced before rollback.');
$assert(str_contains($actions, 'domain_request_receipts') || str_contains($actions, 'registerAndActivate'), 'Certified Domain idempotency logic is not retained.');
$assert(str_contains($actions, '$this->pods->enqueue('), 'Certified POD provisioning service is not retained.');
$assert(str_contains($overview, 'accountContextForRoles'), 'Lifecycle overview uses generic membership context.');
$assert(str_contains($domainApi, 'accountContextForRoles'), 'Domain API uses generic membership context.');
$assert(str_contains($podApi, 'accountContextForRoles'), 'POD API uses generic membership context.');
$assert(str_contains($podApi, 'PodRollbackLifecycleService'), 'Active rollback endpoint bypasses failed-job replacement.');
foreach ([$dashboard, $domainsPage, $podsPage] as $page) {
    $assert(str_contains($page, "resolveForRoles(\$container, ['customer_owner', 'customer_admin'])"), 'Lifecycle page is not owner/admin-only.');
}
$assert(str_contains($browser, 'subscription_public_id'), 'Domain registration does not use a public subscription identity.');
$assert(!str_contains($browser, 'subscription_id: Number('), 'Browser still sends numeric subscription IDs.');
$assert(str_contains($browser, 'requires_attention'), 'POD UI does not use the customer-safe worker attention signal.');
$assert(!str_contains($browser, 'last_error_code'), 'POD UI exposes raw worker error codes.');
$assert(str_contains($browser, 'credentials: "same-origin"'), 'Lifecycle browser requests are not same-origin credentialed.');
$assert(!str_contains($browser, 'localStorage') && !str_contains($browser, 'sessionStorage'), 'Lifecycle UI persists sensitive state in browser storage.');

$forbiddenQueryKeys = [
    "'id' =>", "'source_id' =>", "'last_error_code' =>", "'last_error_message' =>",
    "'hosting_reference' =>", "'database_reference' =>", "'installation_fingerprint' =>",
    "'locked_by' =>", "'lease_token' =>", "'metadata_json' =>",
];
foreach ($forbiddenQueryKeys as $needle) {
    $assert(!str_contains($query, $needle), 'Lifecycle query exposes forbidden output mapping ' . $needle . '.');
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 21 Domain/POD lifecycle contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 21 Domain/POD lifecycle contract passed.\n");

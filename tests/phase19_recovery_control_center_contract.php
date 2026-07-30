<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) $failures[] = $message;
};
$read = static function (string $path) use ($root): string {
    $content = file_get_contents($root . '/' . $path);
    if (!is_string($content)) throw new RuntimeException('Unable to read ' . $path);
    return $content;
};

$required = [
    'public/recovery.php',
    'public/api/control-center/v1/recovery-overview.php',
    'public/api/control-center/v1/recovery-action.php',
    'public/assets/recovery-control-center.js',
    'public/assets/recovery-control-center.css',
    'src/Recovery/RecoveryControlCenterQueryService.php',
    'src/Recovery/RecoveryControlCenterActionService.php',
    '.github/workflows/phase19-recovery-control-center.yml',
];
foreach ($required as $path) $assert(is_file($root . '/' . $path), 'Missing Phase 19 file: ' . $path);

$page = $read('public/recovery.php');
$overview = $read('public/api/control-center/v1/recovery-overview.php');
$action = $read('public/api/control-center/v1/recovery-action.php');
$query = $read('src/Recovery/RecoveryControlCenterQueryService.php');
$actions = $read('src/Recovery/RecoveryControlCenterActionService.php');
$nav = $read('src/ControlCenter/ControlCenterPage.php');
$js = $read('public/assets/recovery-control-center.js');

$assert(str_contains($page, "['customer_owner', 'customer_admin']"), 'Recovery page is not owner/admin-only.');
$assert(str_contains($overview, 'accountContextForRoles'), 'Recovery overview does not use role-aware account context.');
$assert(str_contains($action, 'ControlCenterEndpoint::requestId'), 'Recovery mutations do not require request IDs.');
$assert(str_contains($action, 'ControlCenterEndpoint::idempotencyKey'), 'Destructive recovery queues do not require idempotency keys.');
$assert(str_contains($actions, 'LIMIT 1 FOR UPDATE'), 'Recovery action service does not lock role/resource state.');
$assert(str_contains($actions, 'hash_equals($stored,$role)'), 'Recovery action service trusts stale caller roles.');
$assert(str_contains($actions, '$confirm !== \'RESTORE\''), 'Verified restore lacks exact confirmation.');
$assert(str_contains($actions, 'manifest_signature'), 'Update queue does not require signed releases.');
$assert(str_contains($actions, 'SoftwareUpdateService::STAGES'), 'Update queue does not create the certified update stages.');
$assert(str_contains($nav, "'recovery' => ['/recovery.php', 'Recovery & Updates']"), 'Control Center navigation omits Recovery & Updates.');
$assert(str_contains($js, "credentials: 'same-origin'"), 'Recovery browser API calls are not same-origin credentialed.');
$assert(!str_contains($js, 'localStorage') && !str_contains($js, 'sessionStorage'), 'Recovery UI persists sensitive state in browser storage.');
$assert(!preg_match('/<script(?![^>]*src=)/i', $page), 'Recovery page contains inline JavaScript.');

$forbiddenOutput = [
    'provider_reference_ciphertext', 'provider_reference_nonce', 'provider_reference_tag', 'encryption_key_id',
    'pre_update_backup_reference', 'pre_update_backup_hash', 'lease_token', 'locked_by', 'last_error_message',
    'snapshot_hash', 'receipt_hash', 'metadata_json',
];
foreach ($forbiddenOutput as $key) {
    $assert(!preg_match("/['\"]" . preg_quote($key, '/') . "['\"]\s*=>/", $query), 'Recovery query exposes forbidden key ' . $key . '.');
}

$assert(str_contains($actions, "'public' =>") || str_contains($actions, "'public'=>"), 'Recovery service does not bind explicit native PDO parameters.');

if ($failures !== []) {
    fwrite(STDERR, "Phase 19 Recovery Control Center contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
echo "Phase 19 Recovery Control Center contract passed.\n";

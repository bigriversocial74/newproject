<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

$builder = $root . '/tools/build-single-install.php';
$command = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($builder);
$output = [];
$status = 0;
exec($command . ' 2>&1', $output, $status);
$assert($status === 0, 'The standalone SQL installer builder failed: ' . implode("\n", $output));

$installer = (string) file_get_contents($root . '/database/vp3-single-install.sql');
$manifest = (string) file_get_contents($root . '/database/single-install-manifest.txt');
$migration = (string) file_get_contents($root . '/database/migrations/20260730_phase30_security_audit_hardening.sql');
$service = (string) file_get_contents($root . '/src/Security/SecurityAuditService.php');
$authAudit = (string) file_get_contents($root . '/src/Auth/AuthAuditService.php');

$assert($installer !== '', 'The cumulative installer was not generated.');
$assert(preg_match('/^\s*SOURCE\s+/mi', $installer) !== 1, 'The cumulative installer still depends on SOURCE directives.');
$assert(str_contains($installer, '-- VP3 cumulative standalone database installer'), 'The cumulative installer lacks the standalone-file identity header.');
$assert(str_contains($installer, 'SET FOREIGN_KEY_CHECKS = 0;') && str_contains($installer, 'SET FOREIGN_KEY_CHECKS = 1;'), 'The cumulative installer does not bracket its full import safely.');
$assert(str_contains($installer, 'CREATE TABLE IF NOT EXISTS security_audit_events'), 'The cumulative installer omits the Phase 30 security audit ledger.');
$assert(str_contains($installer, 'CREATE TABLE IF NOT EXISTS security_reauthentication_challenges'), 'The cumulative installer omits sensitive-action reauthentication state.');
$assert(str_contains($installer, 'CREATE TABLE IF NOT EXISTS security_rate_limit_buckets'), 'The cumulative installer omits security rate-limit state.');

$manifestEntries = array_values(array_filter(array_map('trim', explode("\n", $manifest)), static fn (string $line): bool => $line !== '' && !str_starts_with($line, '#')));
$assert(count($manifestEntries) >= 22, 'The cumulative installer manifest does not retain the full historical migration order.');
foreach ($manifestEntries as $entry) {
    $assert(str_contains($installer, '-- BEGIN ' . $entry), 'The generated installer omits manifest entry ' . $entry . '.');
}
$assert(end($manifestEntries) === 'migrations/20260730_phase30_security_audit_hardening.sql', 'Phase 30 is not the final migration in the cumulative installer manifest.');

$requiredTables = [
    'security_audit_heads',
    'security_audit_events',
    'security_audit_retention_policies',
    'security_audit_exports',
    'security_reauthentication_challenges',
    'security_rate_limit_buckets',
];
foreach ($requiredTables as $table) {
    $assert(str_contains($migration, 'CREATE TABLE IF NOT EXISTS ' . $table), 'Phase 30 migration omits ' . $table . '.');
}
$assert(str_contains($migration, 'UNIQUE KEY uq_security_audit_scope_sequence'), 'The audit ledger does not enforce per-account sequence uniqueness.');
$assert(str_contains($migration, 'UNIQUE KEY uq_security_audit_chain_hash'), 'The audit ledger does not enforce chain-hash uniqueness.');
$assert(str_contains($migration, 'event_retention_days SMALLINT UNSIGNED NOT NULL DEFAULT 2555'), 'The default seven-year audit retention contract is missing.');

$assert(str_contains($service, 'SELECT last_sequence,last_chain_hash') && str_contains($service, 'FOR UPDATE'), 'Security audit writes do not serialize on the account chain head.');
$assert(str_contains($service, 'previous_chain_hash') && str_contains($service, 'chain_hash'), 'Security audit writes do not retain the hash-chain boundary.');
$assert(str_contains($service, 'verifyScope'), 'The security audit ledger has no tamper-verification method.');
$assert(str_contains($service, 'BLOCKED_METADATA_KEYS'), 'The security audit service has no explicit secret-redaction catalog.');
$assert(str_contains($service, "'authorization'") && str_contains($service, "'cookie'") && str_contains($service, "'private_key'"), 'Required sensitive metadata classes are not redacted.');
$assert(str_contains($service, 'JSON_PRESERVE_ZERO_FRACTION') && str_contains($service, 'ksort($value, SORT_STRING)'), 'Audit hashing is not based on deterministic canonical JSON.');
$assert(str_contains($service, 'hashClientValue($ipAddress)') && str_contains($service, 'hashClientValue($userAgent)'), 'Client network and user-agent data are not privacy hashed.');

$assert(str_contains($authAudit, 'new SecurityAuditService($database)'), 'Authentication auditing is not connected to the Phase 30 ledger.');
$assert(substr_count($authAudit, '$this->securityAudit->record(') >= 2, 'Authentication and session events are not both bridged into the Phase 30 ledger.');
$assert(str_contains($authAudit, '$this->database->transaction('), 'Legacy and Phase 30 authentication audit writes are not atomic.');
$assert(str_contains($authAudit, "eventType: 'session.' . \$eventType"), 'Session lifecycle events do not use the Phase 30 session namespace.');
$assert(str_contains($authAudit, "str_starts_with(\$normalized, 'auth.mfa.')"), 'MFA events are not classified into the dedicated MFA category.');

if ($failures !== []) {
    fwrite(STDERR, "Phase 30 security audit hardening contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

fwrite(STDOUT, "Phase 30 security audit hardening and standalone installer contract passed.\n");
require __DIR__ . '/phase30_security_runtime_contract.php';

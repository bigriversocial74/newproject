<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

$query = (string) file_get_contents($root . '/src/Security/SecurityAuditQueryService.php');
$export = (string) file_get_contents($root . '/src/Security/SecurityAuditExportService.php');
$reauth = (string) file_get_contents($root . '/src/Security/SecurityReauthenticationService.php');
$rateLimit = (string) file_get_contents($root . '/src/Security/SecurityRateLimitService.php');
$migration = (string) file_get_contents($root . '/database/migrations/20260730_phase30_security_audit_hardening.sql');
$legacyPhase29 = (string) file_get_contents($root . '/.github/workflows/phase29-browser-request-integrity.yml');
$overviewEndpoint = (string) file_get_contents($root . '/public/api/control-center/v1/security-audit-overview.php');
$exportEndpoint = (string) file_get_contents($root . '/public/api/control-center/v1/security-audit-export.php');

$builder = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($root . '/tools/build-single-install.php');
$firstOutput = [];
$firstStatus = 0;
exec($builder . ' 2>&1', $firstOutput, $firstStatus);
$firstInstaller = (string) file_get_contents($root . '/database/vp3-single-install.sql');
$secondOutput = [];
$secondStatus = 0;
exec($builder . ' 2>&1', $secondOutput, $secondStatus);
$secondInstaller = (string) file_get_contents($root . '/database/vp3-single-install.sql');
$assert($firstStatus === 0 && $secondStatus === 0, 'The standalone installer did not build successfully twice.');
$assert($firstInstaller !== '' && hash_equals(hash('sha256', $firstInstaller), hash('sha256', $secondInstaller)), 'The standalone installer is not byte-for-byte reproducible.');
$assert($firstInstaller === $secondInstaller, 'Repeated standalone installer builds produced different bytes.');
$assert(preg_match('/^-- Ordered migration source SHA-256: [a-f0-9]{64}$/m', $secondInstaller) === 1, 'The standalone installer lacks a deterministic source identity.');

$assert(str_contains($query, "'customer_owner'") && str_contains($query, "'customer_admin'"), 'Full account audit access omits customer owner or admin roles.');
$assert(str_contains($query, 'category=:visible_category OR actor_id=:visible_actor'), 'Billing audit visibility is not restricted to billing events or the current actor.');
$assert(str_contains($query, 'actor_id=:visible_actor'), 'Support audit visibility is not restricted to the current actor.');
$assert(str_contains($query, 'verifyScope($accountId)'), 'The security dashboard does not report ledger integrity.');
$assert(str_contains($query, 'min($limit, 500)'), 'Security audit queries do not enforce a bounded result limit.');

$assert(str_contains($export, "in_array(\$format, ['csv', 'jsonl'], true)"), 'Protected audit export does not constrain output formats.');
$assert(str_contains($export, "status=\\'ready\\'") && str_contains($export, 'content_hash'), 'Audit export receipts do not certify completed content.');
$assert(str_contains($export, 'security.audit.exported'), 'Audit exports do not generate their own security event.');
$assert(!str_contains($migration, 'content LONGTEXT'), 'Audit export content is persisted in the database instead of returned transiently.');

$assert(str_contains($migration, "'consumed'"), 'Sensitive-action reauthentication has no consumed state.');
$assert(str_contains($migration, 'consumed_at DATETIME NULL'), 'Sensitive-action reauthentication has no consumption timestamp.');
$assert(str_contains($reauth, "status=\\'satisfied\\'") && str_contains($reauth, "status=\\'consumed\\'"), 'Reauthentication does not enforce satisfy-then-consume sequencing.');
$assert(str_contains($reauth, 'already used'), 'Reauthentication reuse does not fail closed.');
$assert(str_contains($reauth, "hash('sha256', \$challenge)"), 'Raw reauthentication challenges are persisted.');

$assert(str_contains($rateLimit, 'FOR UPDATE'), 'Rate-limit bucket mutation is not serialized.');
$assert(str_contains($rateLimit, 'blocked_until') && str_contains($rateLimit, 'retry_after'), 'Rate-limit enforcement does not persist and return blocking state.');
$assert(str_contains($rateLimit, "hash('sha256', \$scopeType . '|' . \$actionType . '|' . \$scopeKey)"), 'Rate-limit scope keys are not privacy hashed.');

foreach ([$overviewEndpoint, $exportEndpoint] as $endpoint) {
    $assert(str_contains($endpoint, "ControlCenterEndpoint::requireMethod('POST')"), 'A Phase 30 endpoint bypasses the browser request-integrity boundary.');
    $assert(str_contains($endpoint, 'ControlCenterEndpoint::accountContextForRoles('), 'A Phase 30 endpoint bypasses account-role authorization.');
}
$assert(str_contains($exportEndpoint, "['customer_owner', 'customer_admin']"), 'Security audit export is not restricted to account owners and admins.');

$assert(str_contains($legacyPhase29, 'workflow_dispatch:'), 'The superseded Phase 29 workflow is not manual-only.');
$assert(!str_contains($legacyPhase29, "on:\n  pull_request:"), 'The superseded Phase 29 workflow still fans out on pull requests.');

if ($failures !== []) {
    fwrite(STDERR, "Phase 30 security runtime contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

fwrite(STDOUT, "Phase 30 security query, export, reauthentication, rate-limit and deterministic-installer contract passed.\n");

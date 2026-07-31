<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

$page = (string) file_get_contents($root . '/public/security-center.php');
$script = (string) file_get_contents($root . '/public/assets/security-center.js');
$style = (string) file_get_contents($root . '/public/assets/security-center.css');
$endpoint = (string) file_get_contents($root . '/public/api/control-center/v1/security-center-overview.php');
$service = (string) file_get_contents($root . '/src/Security/SecurityCenterQueryService.php');
$navigation = (string) file_get_contents($root . '/src/ControlCenter/ControlCenterPage.php');
$manifest = (string) file_get_contents($root . '/database/single-install-manifest.txt');
$installer = (string) file_get_contents($root . '/database/vp3-single-install.sql');

$assert(str_contains($page, "['customer_owner', 'customer_admin']"), 'The Security Center page is not restricted to owners and administrators.');
$assert(str_contains($page, "'security-center'"), 'The Security Center page does not use its dedicated Control Center identity.');
$assert(str_contains($page, 'Tamper-Evident Security Evidence'), 'The Security Center omits the audit-evidence surface.');
$assert(str_contains($page, 'Active Security &amp; Operational Incidents') || str_contains($page, 'Active Security & Operational Incidents'), 'The Security Center omits incident visibility.');
$assert(str_contains($navigation, "'security-center' => ['/security-center.php', 'Security Center']"), 'Owner and administrator navigation omits the Security Center.');
$assert(str_contains($navigation, '/assets/security-center.css'), 'The shared shell does not load Security Center styles.');

$assert(str_contains($endpoint, "ControlCenterEndpoint::requireMethod('POST')"), 'The Security Center endpoint bypasses the browser request-integrity boundary.');
$assert(str_contains($endpoint, 'ControlCenterEndpoint::accountContextForRoles('), 'The Security Center endpoint bypasses account-role resolution.');
$assert(str_contains($endpoint, "['customer_owner', 'customer_admin']"), 'The Security Center endpoint is not owner/admin-only.');
$assert(str_contains($endpoint, 'SecurityCenterQueryService'), 'The Security Center endpoint bypasses the unified query service.');

$assert(str_contains($service, 'SecurityAuditQueryService'), 'The Security Center does not use the Phase 30 audit ledger query boundary.');
$assert(str_contains($service, 'OperationsControlCenterQueryService'), 'The Security Center does not use the certified incident query boundary.');
$assert(str_contains($service, 'assertCurrentMembership'), 'The Security Center does not revalidate the current account role.');
$assert(str_contains($service, 'hash_equals($storedRole, $role)'), 'The Security Center stale-role check is not constant-time.');
$assert(str_contains($service, 'if (!(bool) $audit[\'chain_valid\'])'), 'Audit-chain failure does not force critical posture.');
$assert(str_contains($service, "return 100;"), 'Audit-chain failure does not force the maximum risk score.');
$assert(str_contains($service, 'activeSessionSummary'), 'The Security Center omits account-wide active-session exposure.');

$assert(str_contains($script, "credentials: 'same-origin'"), 'The Security Center browser client does not use same-origin credentials.');
$assert(str_contains($script, 'account_public_id: accountPublicId'), 'The Security Center browser client does not use the public account identity.');
$assert(str_contains($script, 'csrf_token: csrfToken'), 'The Security Center browser client omits CSRF evidence.');
$assert(!str_contains($script, 'localStorage') && !str_contains($script, 'sessionStorage'), 'The Security Center persists account or evidence state in browser storage.');
$assert(!str_contains($script, '.innerHTML'), 'The Security Center renders server data through innerHTML.');
$assert(str_contains($script, '/api/control-center/v1/security-audit-export.php'), 'The Security Center omits the protected Phase 30 export boundary.');
$assert(str_contains($style, '.security-posture'), 'The Security Center stylesheet omits posture presentation.');

$assert(str_contains($manifest, 'migrations/20260730_phase30_security_audit_hardening.sql'), 'Phase 31 lost its certified Phase 30 database prerequisite.');
$assert(!preg_match('/^migrations\/.*phase31.*\.sql$/mi', $manifest), 'Phase 31 unexpectedly introduced a database migration.');
$assert(preg_match('/^\s*SOURCE\s+/mi', $installer) !== 1, 'The standalone SQL installer regressed to SOURCE directives.');

if ($failures !== []) {
    fwrite(STDERR, "Phase 31 Security Center contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

fwrite(STDOUT, "Phase 31 Security Center read surface contract passed.\n");

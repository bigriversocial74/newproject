<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/Auth/PasswordPolicy.php';

use Vp3\Auth\PasswordPolicy;

$failures = [];
$root = dirname(__DIR__);
$policy = new PasswordPolicy(12);

try {
    $policy->assertValid('StrongPass123');
} catch (Throwable $exception) {
    $failures[] = 'Valid password was rejected: ' . $exception->getMessage();
}

foreach (['short1A', 'alllowercase123', 'ALLUPPERCASE123', 'NoNumbersHere'] as $invalid) {
    try {
        $policy->assertValid($invalid);
        $failures[] = 'Invalid password was accepted: ' . $invalid;
    } catch (InvalidArgumentException) {
        // Expected.
    }
}

$baseSql = file_get_contents($root . '/database/migrations/20260728_phase2_auth_accounts.sql');
foreach (['accounts', 'users', 'account_users', 'email_verification_tokens', 'password_reset_tokens', 'auth_sessions', 'audit_events'] as $table) {
    if (!is_string($baseSql) || !str_contains($baseSql, 'CREATE TABLE IF NOT EXISTS ' . $table)) {
        $failures[] = 'Missing required table definition: ' . $table;
    }
}

$qualitySql = file_get_contents($root . '/database/migrations/20260729_phase2_auth_accounts_quality.sql');
foreach (['account_contacts', 'security_events', 'idempotency_keys'] as $table) {
    if (!is_string($qualitySql) || !str_contains($qualitySql, 'CREATE TABLE IF NOT EXISTS ' . $table)) {
        $failures[] = 'Missing quality table definition: ' . $table;
    }
}

$completionSql = file_get_contents($root . '/database/migrations/20260729_phase2_auth_accounts_completion.sql');
foreach (['customer_owner', 'vp3_super_admin', 'auth_role_permissions', 'auth_session_events'] as $contract) {
    if (!is_string($completionSql) || !str_contains($completionSql, $contract)) {
        $failures[] = 'Missing completion contract: ' . $contract;
    }
}

$installer = file_get_contents($root . '/database/phase2-auth-accounts-single-install.sql');
foreach (['20260728_phase2_auth_accounts.sql', '20260729_phase2_auth_accounts_quality.sql', '20260729_phase2_auth_accounts_completion.sql'] as $migration) {
    if (!is_string($installer) || !str_contains($installer, $migration)) {
        $failures[] = 'Cumulative installer is missing: ' . $migration;
    }
}

foreach ([
    'src/Auth/AccountSecurityService.php',
    'public/api/auth/verify-email.php',
    'public/api/auth/password-reset-request.php',
    'public/api/auth/password-reset-complete.php',
] as $path) {
    if (!is_file($root . '/' . $path)) {
        $failures[] = 'Missing Phase 2 implementation file: ' . $path;
    }
}

if ($failures !== []) {
    fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL);
    exit(1);
}

echo "Phase 2 authentication and account tests passed.\n";

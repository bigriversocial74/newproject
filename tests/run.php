<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/Auth/PasswordPolicy.php';

use Vp3\Auth\PasswordPolicy;

$failures = [];
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

$sql = file_get_contents(dirname(__DIR__) . '/database/migrations/20260728_phase2_auth_accounts.sql');
foreach (['accounts', 'users', 'account_users', 'email_verification_tokens', 'password_reset_tokens', 'auth_sessions', 'audit_events'] as $table) {
    if (!is_string($sql) || !str_contains($sql, 'CREATE TABLE IF NOT EXISTS ' . $table)) {
        $failures[] = 'Missing required table definition: ' . $table;
    }
}

if ($failures !== []) {
    fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL);
    exit(1);
}

echo "Phase 2 authentication and account tests passed.\n";

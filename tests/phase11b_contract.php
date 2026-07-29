<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];

$requiredFiles = [
    'database/migrations/20260729_phase11b_identity_authentication_completion.sql',
    'database/migrations/20260729_phase11b_identity_authentication_integrity.sql',
    'src/Auth/AuthPublicException.php',
    'src/Auth/AuthAuditService.php',
    'src/Auth/DatabaseSessionService.php',
    'src/Auth/AuthenticationContext.php',
    'src/Auth/PasswordChangeService.php',
    'src/Auth/Mail/MailAdapter.php',
    'src/Auth/Mail/NullMailAdapter.php',
    'src/Auth/Mail/SmtpMailAdapter.php',
    'src/Auth/Mail/MailAdapterFactory.php',
    'src/Http/AuthEndpoint.php',
    'public/api/auth/logout.php',
    'public/api/auth/logout-all.php',
    'public/api/auth/logout-others.php',
    'public/api/auth/current.php',
    'public/api/auth/sessions.php',
    'public/api/auth/revoke-session.php',
    'public/api/auth/rotate-session.php',
    'public/api/auth/resend-verification.php',
    'public/api/auth/change-password.php',
    'tests/phase11b_database_integration.php',
    'docs/vp3-platform-backend/06-PHASE-11B-IDENTITY-AUTHENTICATION.md',
];
foreach ($requiredFiles as $path) {
    if (!is_file($root . '/' . $path)) {
        $failures[] = 'Missing Phase 11B file: ' . $path;
    }
}

$migration = file_get_contents($root . '/database/migrations/20260729_phase11b_identity_authentication_completion.sql');
foreach (['inactivity_expires_at','absolute_expires_at','rotated_from_public_id','revocation_reason','invalidated_at','metadata_json','idx_auth_sessions_active_user'] as $contract) {
    if (!is_string($migration) || !str_contains($migration, $contract)) {
        $failures[] = 'Phase 11B migration is missing: ' . $contract;
    }
}
$integrity = file_get_contents($root . '/database/migrations/20260729_phase11b_identity_authentication_integrity.sql');
foreach (['MODIFY inactivity_expires_at DATETIME NOT NULL','MODIFY absolute_expires_at DATETIME NOT NULL','fk_auth_sessions_revoked_by_user','idx_email_verification_request','idx_password_reset_request'] as $contract) {
    if (!is_string($integrity) || !str_contains($integrity, $contract)) {
        $failures[] = 'Phase 11B integrity contract is missing: ' . $contract;
    }
}

$installer = file_get_contents($root . '/database/vp3-single-install.sql');
foreach (['20260729_phase11b_identity_authentication_completion.sql','20260729_phase11b_identity_authentication_integrity.sql'] as $migrationName) {
    if (!is_string($installer) || !str_contains($installer, $migrationName)) {
        $failures[] = 'Cumulative installer does not include: ' . $migrationName;
    }
}
$phase2Installer = file_get_contents($root . '/database/phase2-auth-accounts-single-install.sql');
foreach (['20260729_phase11b_identity_authentication_completion.sql','20260729_phase11b_identity_authentication_integrity.sql'] as $migrationName) {
    if (!is_string($phase2Installer) || !str_contains($phase2Installer, $migrationName)) {
        $failures[] = 'Retained identity installer does not include: ' . $migrationName;
    }
}

$config = file_get_contents($root . '/config/config-example.php');
foreach (['session_inactivity_ttl_seconds','session_absolute_ttl_seconds',"'mail' =>",'smtp_host','smtp_encryption','sender_email'] as $contract) {
    if (!is_string($config) || !str_contains($config, $contract)) {
        $failures[] = 'Authentication configuration is missing: ' . $contract;
    }
}

$authService = file_get_contents($root . '/src/Auth/AuthService.php');
foreach (['login_attempt_limit','login_attempt_window_seconds','verification_ttl_seconds',"=== 'active'",'PDOException','verification_delivery_failed','mail_delivery_failed'] as $contract) {
    if (!is_string($authService) || !str_contains($authService, $contract)) {
        $failures[] = 'AuthService contract is missing: ' . $contract;
    }
}
if (is_string($authService) && (str_contains($authService, "modify('+24 hours')") || str_contains($authService, '>= 10'))) {
    $failures[] = 'AuthService retains hardcoded authentication limits.';
}

$sessionService = file_get_contents($root . '/src/Auth/DatabaseSessionService.php');
foreach (['hashToken($token)','inactivity_expires_at','absolute_expires_at','binding_mismatch','revoked_at IS NULL','rowCount() !== 1','auth.logout','auth.logout_all','auth.logout_others'] as $contract) {
    if (!is_string($sessionService) || !str_contains($sessionService, $contract)) {
        $failures[] = 'Database session contract is missing: ' . $contract;
    }
}
if (is_string($sessionService) && str_contains($sessionService, "'session_hash' => \$token")) {
    $failures[] = 'Database session service stores a plaintext session token.';
}

$passwordChange = file_get_contents($root . '/src/Auth/PasswordChangeService.php');
foreach (['password_verify','password_change','currentSessionPublicId','auth.password_changed','auth.session.revoked'] as $contract) {
    if (!is_string($passwordChange) || !str_contains($passwordChange, $contract)) {
        $failures[] = 'Password-change revocation contract is missing: ' . $contract;
    }
}

$accountSecurity = file_get_contents($root . '/src/Auth/AccountSecurityService.php');
foreach (['invalidated_at','password_reset.completed','mail_delivery_failed','auth.session.revoked'] as $contract) {
    if (!is_string($accountSecurity) || !str_contains($accountSecurity, $contract)) {
        $failures[] = 'Account security contract is missing: ' . $contract;
    }
}

$smtp = file_get_contents($root . '/src/Auth/Mail/SmtpMailAdapter.php');
foreach (['verify_peer','verify_peer_name','allow_self_signed','STARTTLS','assertSafeHeader',"['tls', 'ssl']"] as $contract) {
    if (!is_string($smtp) || !str_contains($smtp, $contract)) {
        $failures[] = 'SMTP security contract is missing: ' . $contract;
    }
}

foreach (['public/api/auth/logout.php','public/api/auth/logout-all.php','public/api/auth/logout-others.php','public/api/auth/revoke-session.php','public/api/auth/rotate-session.php','public/api/auth/change-password.php'] as $path) {
    $source = file_get_contents($root . '/' . $path);
    if (!is_string($source) || !str_contains($source, 'assertCsrf')) {
        $failures[] = 'Cookie-authenticated mutation lacks CSRF enforcement: ' . $path;
    }
}

foreach (glob($root . '/public/api/auth/*.php') ?: [] as $path) {
    $source = file_get_contents($path);
    if (is_string($source) && str_contains($source, 'getMessage()')) {
        $failures[] = 'Authentication endpoint leaks internal exception messages: ' . basename($path);
    }
}

$registration = file_get_contents($root . '/public/api/auth/register.php');
$resetRequest = file_get_contents($root . '/public/api/auth/password-reset-request.php');
if (is_string($registration) && str_contains($registration, 'verification_token')) {
    $failures[] = 'Registration endpoint exposes the verification token.';
}
if (is_string($resetRequest) && str_contains($resetRequest, 'reset_token')) {
    $failures[] = 'Password reset request endpoint exposes the reset token.';
}

if ($failures !== []) {
    fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL);
    exit(1);
}

echo "Phase 11B static contract certification passed.\n";

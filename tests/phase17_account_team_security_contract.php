<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$required = [
    'database/migrations/20260730_phase17_account_team_security.sql',
    'src/Auth/AuthRuntimeConfigurationValidator.php',
    'src/Auth/AuthSecretCipher.php',
    'src/Auth/MfaService.php',
    'src/Auth/TeamSecurityService.php',
    'src/ControlCenter/AccountSecurityQueryService.php',
    'public/account-security.php',
    'public/team-invite.php',
    'public/api/auth/mfa-complete.php',
    'public/api/control-center/v1/account-security-overview.php',
    'public/api/control-center/v1/mfa-action.php',
    'public/api/control-center/v1/profile-action.php',
    'public/api/control-center/v1/team-action.php',
    'public/assets/account-security.js',
    'public/assets/account-security.css',
];
foreach ($required as $path) {
    if (!is_file($root . '/' . $path)) {
        $failures[] = 'Missing Phase 17 file: ' . $path;
    }
}
$read = static fn (string $path): string => (string) @file_get_contents($root . '/' . $path);
$installer = $read('database/vp3-single-install.sql');
$migration = $read('database/migrations/20260730_phase17_account_team_security.sql');
$cipher = $read('src/Auth/AuthSecretCipher.php');
$runtime = $read('src/Auth/AuthRuntimeConfigurationValidator.php');
$auth = $read('src/Auth/AuthService.php');
$mfa = $read('src/Auth/MfaService.php');
$team = $read('src/Auth/TeamSecurityService.php');
$query = $read('src/ControlCenter/AccountSecurityQueryService.php');
$login = $read('public/api/auth/login.php');
$pageContext = $read('src/ControlCenter/AccountPageContext.php');
$apiContext = $read('src/Http/ControlCenterEndpoint.php');
$shell = $read('src/ControlCenter/ControlCenterPage.php');
$page = $read('public/account-security.php');
$invitePage = $read('public/team-invite.php');
$client = $read('public/assets/account-security.js');
$databaseTest = $read('tests/phase17_account_team_security_database_integration.php');

$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

$phase15 = strpos($installer, '20260730_phase15_federated_settings.sql');
$phase17 = strpos($installer, '20260730_phase17_account_team_security.sql');
$assert($phase15 !== false && $phase17 !== false && $phase15 < $phase17, 'Cumulative installer does not retain Phase 15 before Phase 17.');
foreach (['account_invitations', 'auth_mfa_methods', 'auth_mfa_recovery_codes', 'auth_mfa_challenges', 'account_security_receipts'] as $table) {
    $assert(str_contains($migration, 'CREATE TABLE IF NOT EXISTS ' . $table), 'Phase 17 migration is missing ' . $table . '.');
}
foreach (['customer_owner','customer_admin','billing_manager','support_member'] as $role) {
    $assert(str_contains($migration . $pageContext . $apiContext, $role), 'Current customer role is missing: ' . $role);
}
$assert(str_contains($pageContext, 'function resolveForRoles'), 'Role-aware page context is missing.');
$assert(str_contains($apiContext, 'function accountContextForRoles'), 'Role-aware API context is missing.');
$assert(str_contains($shell, "'billing_manager'") && str_contains($shell, "'support_member'"), 'Role-aware Control Center navigation is incomplete.');

foreach (['aes-256-gcm', 'random_bytes(12)', '$context, 16', 'strlen($key) !== 32'] as $needle) {
    $assert(str_contains($cipher, $needle), 'MFA secret encryption boundary is missing: ' . $needle);
}
$assert(str_contains($runtime, "environment !== 'production'") && str_contains($runtime, 'exactly 32 bytes in production'), 'Production authentication-key validation is incomplete.');
$assert(!str_contains($migration, 'secret_plaintext') && !str_contains($migration, 'recovery_code VARCHAR'), 'MFA secrets or recovery codes can be stored in plaintext.');
$assert(str_contains($mfa, '$this->cipher->encrypt($secret, $context)'), 'MFA enrollment does not encrypt the TOTP secret.');
$assert(str_contains($mfa, 'last_used_counter') && str_contains($mfa, '$counter <= $minimumExclusive'), 'TOTP replay protection is missing.');
$assert(str_contains($mfa, 'used_at IS NULL LIMIT 1 FOR UPDATE') && str_contains($mfa, 'SET used_at=:used_at') && str_contains($mfa, 'rowCount() === 1'), 'Recovery codes are not consumed atomically.');
$assert(str_contains($mfa, "hash_equals((string) \$row['ip_hash']") && str_contains($mfa, "hash_equals((string) \$row['user_agent_hash']"), 'MFA challenge binding is incomplete.');
$assert(str_contains($mfa, 'attempt_count=:attempt_count') && str_contains($mfa, 'mfa_challenge_locked') && str_contains($mfa, "'attempt_limit'"), 'MFA attempt locking is missing.');
$assert(str_contains($mfa, "return ['denied' => \$locked ? 'attempt_limit' : 'invalid_code']") && str_contains($mfa, "mfa.challenge_completed', 'denied'"), 'Denied MFA evidence is not committed before rejection.');
$assert(str_contains($login, 'true') && str_contains($login, 'mfa_required') && strpos($login, "database_sessions']->create") > strpos($login, 'requiresMfa'), 'Login can create an authenticated session before MFA completes.');
$assert(str_contains($auth, 'last_login_at=:last_login_at') && str_contains($auth, 'updated_at=:updated_at'), 'Login completion reuses a native PDO named parameter.');

$assert(str_contains($team, "hash('sha256', \$token)"), 'Invitation tokens are not stored as hashes.');
$assert(str_contains($team, 'invited_email_normalized') && str_contains($team, 'email_normalized') && str_contains($team, 'hash_equals'), 'Invitation acceptance is not bound to the canonical invited email.');
$assert(str_contains($team, "status='expired'") && str_contains($query, "THEN 'expired'"), 'Expired invitations are not represented explicitly.');
$assert(str_contains($team, "return ['denied' => 'email_mismatch']") && str_contains($team, "team.invitation_accepted', 'denied'"), 'Invitation denial evidence is not committed before rejection.');
$assert(str_contains($team, 'assertAnotherOwner') && str_contains($team, 'team_final_owner_required'), 'Final-owner protection is missing.');
$assert(str_contains($team, 'private function assertActor') && str_contains($team, "status='active' LIMIT 1 FOR UPDATE"), 'Team mutations do not revalidate the active actor membership.');
$assert(str_contains($team, "UPDATE auth_sessions") && str_contains($team, "'membership_' . \$status") && str_contains($team, 'revocation_reason=:reason'), 'Membership suspension/removal does not revoke sessions safely.');
$assert(str_contains($query, '$canManageTeam') && str_contains($query, 'AND au.user_id=:current_user'), 'Non-manager team data is not isolated to the current user.');

$assert(str_contains($client, 'inviteButton.disabled = !snapshot.can_manage_team'), 'Invite button is not enabled from the authorized overview state.');
foreach (['localStorage', 'sessionStorage', '.innerHTML', 'eval('] as $forbidden) {
    $assert(!str_contains($client, $forbidden), 'Account Security client contains forbidden browser behavior: ' . $forbidden);
}
$assert(!str_contains($page, '<script>') && !str_contains($page, '<style') && !str_contains($page, ' style='), 'Account Security page violates the external script/style CSP contract.');
$assert(str_contains($invitePage, "form-action 'self'") && str_contains($invitePage, 'assertCsrf'), 'Invitation acceptance page is missing CSP or CSRF enforcement.');
$assert(str_contains($page, 'resolveForRoles') && str_contains($page, "'support_member'"), 'Account Security page does not admit all current customer roles.');
$assert(str_contains($databaseTest, 'PDO::ATTR_EMULATE_PREPARES => false'), 'Phase 17 database certification does not use native PDO prepares.');
$assert(!is_file($root . '/.github/workflows/phase17-test-correction.yml'), 'Temporary self-modifying Phase 17 workflow remains in the branch.');

if ($failures !== []) {
    fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL);
    exit(1);
}
echo "Phase 17 account, team and security contract passed.\n";

<?php

declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    $prefix = 'Vp3\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $path = dirname(__DIR__) . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($path)) {
        require $path;
    }
});

use Vp3\Auth\AccountSecurityService;
use Vp3\Auth\AuthAuditService;
use Vp3\Auth\AuthPublicException;
use Vp3\Auth\AuthService;
use Vp3\Auth\DatabaseSessionService;
use Vp3\Auth\Mail\NullMailAdapter;
use Vp3\Auth\PasswordChangeService;
use Vp3\Auth\PasswordPolicy;
use Vp3\Database;

$dsn = getenv('VP3_TEST_DSN') ?: '';
$username = getenv('VP3_TEST_DB_USER') ?: 'root';
$password = getenv('VP3_TEST_DB_PASSWORD') ?: '';
if ($dsn === '') {
    fwrite(STDERR, "VP3_TEST_DSN is required.\n");
    exit(1);
}

$failures = [];
$database = new Database([
    'dsn' => $dsn,
    'username' => $username,
    'password' => $password,
    'options' => [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ],
]);
$pdo = $database->pdo();
$policy = new PasswordPolicy(12);
$mail = new NullMailAdapter();
$audit = new AuthAuditService($database);
$config = [
    'verification_ttl_seconds' => 600,
    'password_reset_ttl_seconds' => 600,
    'login_attempt_limit' => 5,
    'login_attempt_window_seconds' => 3600,
    'base_url' => 'https://vp3.example.test',
];
$auth = new AuthService($database, $policy, $mail, $config, $audit);
$security = new AccountSecurityService($database, $policy, $mail, $config, $audit);
$sessions = new DatabaseSessionService($database, 300, 900, $audit);
$passwordChanges = new PasswordChangeService($database, $policy, $audit);

$expectAuthCode = static function (callable $callback, string $code) use (&$failures): void {
    try {
        $callback();
        $failures[] = 'Expected authentication error was not raised: ' . $code;
    } catch (AuthPublicException $exception) {
        if ($exception->publicCode() !== $code) {
            $failures[] = 'Expected ' . $code . ', received ' . $exception->publicCode() . '.';
        }
    }
};

try {
    $suffix = bin2hex(random_bytes(6));
    $email = 'phase11b-' . $suffix . '@example.test';
    $registered = $auth->register($email, 'StrongPass123', 'Phase 11B Owner', '127.0.0.10', 'vp3-phase11b');
    $verificationMessage = $mail->lastMessage();
    if ($verificationMessage === null || !str_contains($verificationMessage['text_body'], '/verify-email?token=')) {
        $failures[] = 'Verification email was not delivered through the test adapter.';
    }

    $expectAuthCode(static fn () => $auth->authenticate($email, 'StrongPass123', '127.0.0.10', 'vp3-phase11b'), 'email_verification_required');
    if (!$security->verifyEmail($registered['verification_token'])) {
        $failures[] = 'Verification token did not activate the account.';
    }
    if ($security->verifyEmail($registered['verification_token'])) {
        $failures[] = 'Verification token replay was accepted.';
    }

    $user = $auth->authenticate($email, 'StrongPass123', '127.0.0.10', 'vp3-phase11b');
    if ($user === null || $user['id'] !== $registered['user_id']) {
        $failures[] = 'Verified user could not authenticate.';
    }

    $sessionOne = $sessions->create($registered['user_id'], '127.0.0.10', 'vp3-phase11b');
    $storedSession = $pdo->prepare('SELECT session_hash FROM auth_sessions WHERE session_public_id = :public_id');
    $storedSession->execute(['public_id' => $sessionOne['public_id']]);
    $storedHash = (string) $storedSession->fetchColumn();
    if ($storedHash === $sessionOne['token'] || $storedHash !== hash('sha256', $sessionOne['token'])) {
        $failures[] = 'Application session token was not stored exclusively as a hash.';
    }
    $validated = $sessions->validate($sessionOne['token'], '127.0.0.10', 'vp3-phase11b');
    if ($validated['user']['id'] !== $registered['user_id']) {
        $failures[] = 'Valid database session was not accepted.';
    }

    $rotated = $sessions->rotate($sessionOne['token'], '127.0.0.10', 'vp3-phase11b');
    $expectAuthCode(static fn () => $sessions->validate($sessionOne['token'], '127.0.0.10', 'vp3-phase11b'), 'invalid_session');
    $expectAuthCode(static fn () => $sessions->rotate($sessionOne['token'], '127.0.0.10', 'vp3-phase11b'), 'invalid_session');
    $sessions->validate($rotated['token'], '127.0.0.10', 'vp3-phase11b');

    $bindingSession = $sessions->create($registered['user_id'], '127.0.0.11', 'binding-agent');
    $expectAuthCode(static fn () => $sessions->validate($bindingSession['token'], '127.0.0.12', 'binding-agent'), 'invalid_session');

    $inactivitySession = $sessions->create($registered['user_id'], '127.0.0.13', 'expiry-agent');
    $pdo->prepare('UPDATE auth_sessions SET inactivity_expires_at = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 SECOND) WHERE session_public_id = :public_id')
        ->execute(['public_id' => $inactivitySession['public_id']]);
    $expectAuthCode(static fn () => $sessions->validate($inactivitySession['token'], '127.0.0.13', 'expiry-agent'), 'invalid_session');

    $absoluteSession = $sessions->create($registered['user_id'], '127.0.0.14', 'absolute-agent');
    $pdo->prepare('UPDATE auth_sessions SET absolute_expires_at = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 SECOND) WHERE session_public_id = :public_id')
        ->execute(['public_id' => $absoluteSession['public_id']]);
    $expectAuthCode(static fn () => $sessions->validate($absoluteSession['token'], '127.0.0.14', 'absolute-agent'), 'invalid_session');

    $current = $sessions->create($registered['user_id'], '127.0.0.15', 'logout-agent');
    $other = $sessions->create($registered['user_id'], '127.0.0.16', 'logout-agent-2');
    if (!$sessions->revokeCurrent($current['token'], '127.0.0.15', 'logout-agent')) {
        $failures[] = 'Current logout did not revoke the current session.';
    }
    $sessions->validate($other['token'], '127.0.0.16', 'logout-agent-2');

    $selected = $sessions->create($registered['user_id'], '127.0.0.18', 'selected-agent');
    if (!$sessions->revokeSelected($registered['user_id'], $selected['public_id'], '127.0.0.16', 'logout-agent-2')) {
        $failures[] = 'Selected-device revocation failed.';
    }
    $expectAuthCode(static fn () => $sessions->validate($selected['token'], '127.0.0.18', 'selected-agent'), 'invalid_session');

    $logoutOthersA = $sessions->create($registered['user_id'], '127.0.0.19', 'logout-others-a');
    $logoutOthersB = $sessions->create($registered['user_id'], '127.0.0.20', 'logout-others-b');
    $revokedOthers = $sessions->revokeAllForUser(
        $registered['user_id'],
        'logout_others',
        $logoutOthersA['public_id'],
        '127.0.0.19',
        'logout-others-a'
    );
    if ($revokedOthers < 1) {
        $failures[] = 'Logout-others did not revoke any alternate sessions.';
    }
    $sessions->validate($logoutOthersA['token'], '127.0.0.19', 'logout-others-a');
    $expectAuthCode(static fn () => $sessions->validate($logoutOthersB['token'], '127.0.0.20', 'logout-others-b'), 'invalid_session');
    if ($sessions->revokeAllForUser($registered['user_id'], 'logout_all', null, '127.0.0.19', 'logout-others-a') < 1) {
        $failures[] = 'Logout-all did not revoke the remaining session.';
    }
    $expectAuthCode(static fn () => $sessions->validate($logoutOthersA['token'], '127.0.0.19', 'logout-others-a'), 'invalid_session');

    $secondEmail = 'phase11b-other-' . $suffix . '@example.test';
    $second = $auth->register($secondEmail, 'StrongPass123', 'Other User');
    $security->verifyEmail($second['verification_token']);
    $secondSession = $sessions->create($second['user_id'], '127.0.0.21', 'other-agent');
    if ($sessions->revokeSelected($registered['user_id'], $secondSession['public_id'], '127.0.0.15', 'logout-agent')) {
        $failures[] = 'Cross-user selected-session revocation was allowed.';
    }
    $sessions->validate($secondSession['token'], '127.0.0.21', 'other-agent');

    $pendingEmail = 'phase11b-pending-' . $suffix . '@example.test';
    $pending = $auth->register($pendingEmail, 'StrongPass123', 'Pending User');
    $resentToken = $security->resendVerification($pendingEmail);
    if (!is_string($resentToken) || $resentToken === '') {
        $failures[] = 'Verification resend did not issue a replacement token.';
    } else {
        if ($security->verifyEmail($pending['verification_token'])) {
            $failures[] = 'Verification resend did not invalidate the prior token.';
        }
        if (!$security->verifyEmail($resentToken)) {
            $failures[] = 'Replacement verification token was not accepted.';
        }
    }

    $expiredEmail = 'phase11b-expired-' . $suffix . '@example.test';
    $expired = $auth->register($expiredEmail, 'StrongPass123', 'Expired User');
    $pdo->prepare('UPDATE email_verification_tokens SET expires_at = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 SECOND) WHERE token_hash = :hash')
        ->execute(['hash' => hash('sha256', $expired['verification_token'])]);
    if ($security->verifyEmail($expired['verification_token'])) {
        $failures[] = 'Expired verification token was accepted.';
    }

    if ($security->requestPasswordReset('missing-' . $suffix . '@example.test') !== null) {
        $failures[] = 'Unknown account unexpectedly received a reset token.';
    }
    $resetToken = $security->requestPasswordReset($email);
    if (!is_string($resetToken) || $resetToken === '') {
        $failures[] = 'Password reset token was not delivered.';
    } else {
        $resetMessage = $mail->lastMessage();
        if ($resetMessage === null || !str_contains($resetMessage['text_body'], '/reset-password?token=')) {
            $failures[] = 'Password reset email was not delivered through the test adapter.';
        }
        $preResetOne = $sessions->create($registered['user_id'], '127.0.0.22', 'reset-agent-1');
        $preResetTwo = $sessions->create($registered['user_id'], '127.0.0.23', 'reset-agent-2');
        if (!$security->resetPassword($resetToken, 'ChangedPass456')) {
            $failures[] = 'Password reset did not complete.';
        }
        if ($security->resetPassword($resetToken, 'ChangedPass789')) {
            $failures[] = 'Password reset token replay was accepted.';
        }
        $expectAuthCode(static fn () => $sessions->validate($preResetOne['token'], '127.0.0.22', 'reset-agent-1'), 'invalid_session');
        $expectAuthCode(static fn () => $sessions->validate($preResetTwo['token'], '127.0.0.23', 'reset-agent-2'), 'invalid_session');
        if ($auth->authenticate($email, 'StrongPass123', '127.0.0.24', 'vp3-phase11b') !== null) {
            $failures[] = 'Old password remained valid after password reset.';
        }
        if ($auth->authenticate($email, 'ChangedPass456', '127.0.0.25', 'vp3-phase11b') === null) {
            $failures[] = 'New password was rejected after password reset.';
        }
    }

    $expiredReset = $security->requestPasswordReset($email);
    if (is_string($expiredReset)) {
        $pdo->prepare('UPDATE password_reset_tokens SET expires_at = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 SECOND) WHERE token_hash = :hash')
            ->execute(['hash' => hash('sha256', $expiredReset)]);
        if ($security->resetPassword($expiredReset, 'ExpiredPass789')) {
            $failures[] = 'Expired password-reset token was accepted.';
        }
    } else {
        $failures[] = 'Unable to create password-reset expiry fixture.';
    }

    $changeCurrent = $sessions->create($registered['user_id'], '127.0.0.26', 'change-agent-current');
    $changeOther = $sessions->create($registered['user_id'], '127.0.0.27', 'change-agent-other');
    $expectAuthCode(static fn () => $passwordChanges->change(
        $registered['user_id'],
        'WrongCurrent123',
        'FinalPass789',
        $changeCurrent['public_id'],
        '127.0.0.26',
        'change-agent-current'
    ), 'current_password_invalid');
    $changeResult = $passwordChanges->change(
        $registered['user_id'],
        'ChangedPass456',
        'FinalPass789',
        $changeCurrent['public_id'],
        '127.0.0.26',
        'change-agent-current'
    );
    if ($changeResult['revoked_sessions'] < 1) {
        $failures[] = 'Password change did not revoke alternate sessions.';
    }
    $sessions->validate($changeCurrent['token'], '127.0.0.26', 'change-agent-current');
    $expectAuthCode(static fn () => $sessions->validate($changeOther['token'], '127.0.0.27', 'change-agent-other'), 'invalid_session');
    if ($auth->authenticate($email, 'ChangedPass456', '127.0.0.28', 'vp3-phase11b') !== null) {
        $failures[] = 'Previous password remained valid after authenticated password change.';
    }
    if ($auth->authenticate($email, 'FinalPass789', '127.0.0.29', 'vp3-phase11b') === null) {
        $failures[] = 'Changed password was rejected.';
    }

    $duplicateRejected = false;
    try {
        $auth->register($email, 'StrongPass123', 'Duplicate Owner');
    } catch (AuthPublicException $exception) {
        $duplicateRejected = $exception->publicCode() === 'registration_unavailable';
    }
    if (!$duplicateRejected) {
        $failures[] = 'Duplicate-email database race path was not mapped safely.';
    }

    $throttleEmail = 'phase11b-throttle-' . $suffix . '@example.test';
    $throttleIp = '198.51.100.' . random_int(1, 200);
    for ($attempt = 0; $attempt < 5; $attempt++) {
        $auth->authenticate($throttleEmail, 'WrongPass123', $throttleIp, 'throttle-agent');
    }
    $expectAuthCode(static fn () => $auth->authenticate($throttleEmail, 'WrongPass123', $throttleIp, 'throttle-agent'), 'login_throttled');

    $plaintextNeedles = array_filter([
        $registered['verification_token'],
        $sessionOne['token'],
        $rotated['token'],
        $resetToken ?? null,
        $expiredReset ?? null,
    ], 'is_string');
    foreach ($plaintextNeedles as $needle) {
        $auditLeak = $pdo->prepare('SELECT COUNT(*) FROM audit_events WHERE metadata_json LIKE :needle');
        $auditLeak->execute(['needle' => '%' . $needle . '%']);
        if ((int) $auditLeak->fetchColumn() > 0) {
            $failures[] = 'Plaintext token leaked into audit metadata.';
            break;
        }
        foreach (['email_verification_tokens', 'password_reset_tokens', 'auth_sessions'] as $table) {
            $column = $table === 'auth_sessions' ? 'session_hash' : 'token_hash';
            $plaintext = $pdo->prepare("SELECT COUNT(*) FROM {$table} WHERE {$column} = :plaintext");
            $plaintext->execute(['plaintext' => $needle]);
            if ((int) $plaintext->fetchColumn() > 0) {
                $failures[] = 'Plaintext token was stored in ' . $table . '.';
                break 2;
            }
        }
    }

    foreach ([
        'auth.registration',
        'auth.verification.requested',
        'auth.email_verified',
        'auth.login.success',
        'auth.login.failure',
        'auth.login.throttled',
        'auth.session.created',
        'auth.session.rotated',
        'auth.session.revoked',
        'auth.session.rejected',
        'auth.password_reset.requested',
        'auth.password_reset.completed',
        'auth.password_changed',
        'auth.logout',
        'auth.logout_all',
        'auth.logout_others',
    ] as $eventType) {
        $event = $pdo->prepare('SELECT COUNT(*) FROM audit_events WHERE event_type = :event_type');
        $event->execute(['event_type' => $eventType]);
        if ((int) $event->fetchColumn() < 1) {
            $failures[] = 'Missing durable authentication audit event: ' . $eventType;
        }
    }
} catch (Throwable $exception) {
    $failures[] = get_class($exception) . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL);
    exit(1);
}

echo "Phase 11B database integration certification passed.\n";

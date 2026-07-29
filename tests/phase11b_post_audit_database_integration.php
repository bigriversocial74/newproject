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
use Vp3\Auth\AuthService;
use Vp3\Auth\DatabaseSessionService;
use Vp3\Auth\Mail\NullMailAdapter;
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
$policy = new PasswordPolicy(12);
$mail = new NullMailAdapter();
$audit = new AuthAuditService($database);
$config = [
    'verification_ttl_seconds' => 600,
    'password_reset_ttl_seconds' => 600,
    'login_attempt_limit' => 8,
    'login_attempt_window_seconds' => 900,
    'base_url' => 'https://vp3.example.test',
];
$auth = new AuthService($database, $policy, $mail, $config, $audit);
$security = new AccountSecurityService($database, $policy, $mail, $config, $audit);
$sessions = new DatabaseSessionService($database, 300, 900, $audit);

try {
    $suffix = bin2hex(random_bytes(6));
    $email = 'phase11b-audit-' . $suffix . '@example.test';
    $registered = $auth->register($email, 'StrongPass123', 'Post Audit User');
    if (!$security->verifyEmail($registered['verification_token'])) {
        $failures[] = 'Unable to activate post-audit reset fixture.';
    }

    $resetOne = $security->requestPasswordReset($email);
    $resetTwo = $security->requestPasswordReset($email);
    if (!is_string($resetOne) || !is_string($resetTwo) || $resetOne === $resetTwo) {
        $failures[] = 'Password-reset replacement tokens were not issued independently.';
    } else {
        if ($security->resetPassword($resetOne, 'RejectedPass456')) {
            $failures[] = 'A replaced password-reset token remained usable.';
        }
        if (!$security->resetPassword($resetTwo, 'ChangedPass456')) {
            $failures[] = 'The latest password-reset token was rejected.';
        }
    }

    $pendingEmail = 'phase11b-audit-pending-' . $suffix . '@example.test';
    $pending = $auth->register($pendingEmail, 'StrongPass123', 'Post Audit Pending');
    $verificationTwo = $security->resendVerification($pendingEmail);
    $verificationThree = $security->resendVerification($pendingEmail);
    if (!is_string($verificationTwo) || !is_string($verificationThree)) {
        $failures[] = 'Verification replacement tokens were not delivered.';
    } else {
        if ($security->verifyEmail($pending['verification_token'])) {
            $failures[] = 'Original verification token survived replacement.';
        }
        if ($security->verifyEmail($verificationTwo)) {
            $failures[] = 'Intermediate verification token survived replacement.';
        }
        if (!$security->verifyEmail($verificationThree)) {
            $failures[] = 'Latest verification token was rejected.';
        }
    }

    $session = $sessions->create($registered['user_id'], '203.0.113.40', 'post-audit-agent');
    $rotated = $sessions->rotate($session['token'], '203.0.113.40', 'post-audit-agent');
    if (!hash_equals($session['absolute_expires_at'], $rotated['absolute_expires_at'])) {
        $failures[] = 'Session rotation extended the absolute session lifetime.';
    }
    $sessions->validate($rotated['token'], '203.0.113.40', 'post-audit-agent');
    $listed = $sessions->listForUser($registered['user_id'], $rotated['public_id']);
    $currentFound = false;
    foreach ($listed as $listedSession) {
        if ($listedSession['public_id'] === $rotated['public_id'] && $listedSession['current'] === true) {
            $currentFound = true;
            break;
        }
    }
    if (!$currentFound) {
        $failures[] = 'Active-session listing did not identify the current rotated session.';
    }
} catch (Throwable $exception) {
    $failures[] = get_class($exception) . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL);
    exit(1);
}

echo "Phase 11B post-audit database certification passed.\n";

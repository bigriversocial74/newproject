<?php

declare(strict_types=1);

use PDO;
use Throwable;
use Vp3\Auth\AccountSecurityService;
use Vp3\Auth\AuthService;
use Vp3\Auth\PasswordPolicy;
use Vp3\Database;

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
$auth = new AuthService($database, $policy);
$security = new AccountSecurityService($database, $policy);

try {
    $email = 'phase2-' . bin2hex(random_bytes(5)) . '@example.test';
    $registered = $auth->register($email, 'StrongPass123', 'Phase Two Owner');

    $membership = $pdo->prepare(
        'SELECT au.role, au.status, a.status AS account_status, u.status AS user_status
         FROM account_users au
         JOIN accounts a ON a.id = au.account_id
         JOIN users u ON u.id = au.user_id
         WHERE au.account_id = :account_id AND au.user_id = :user_id'
    );
    $membership->execute([
        'account_id' => $registered['account_id'],
        'user_id' => $registered['user_id'],
    ]);
    $row = $membership->fetch();
    if (!$row || $row['role'] !== 'customer_owner' || $row['account_status'] !== 'pending_verification') {
        $failures[] = 'Registration did not create the required owner membership and pending account state.';
    }

    if (!$security->verifyEmail($registered['verification_token'])) {
        $failures[] = 'Email verification failed.';
    }
    if ($security->verifyEmail($registered['verification_token'])) {
        $failures[] = 'Email verification token was reusable.';
    }

    $user = $auth->authenticate($email, 'StrongPass123', '127.0.0.1', 'vp3-ci');
    if ($user === null || $user['id'] !== $registered['user_id']) {
        $failures[] = 'Verified user could not authenticate.';
    }

    $now = new DateTimeImmutable('now');
    $pdo->prepare(
        'INSERT INTO auth_sessions
         (user_id, session_public_id, session_hash, ip_hash, user_agent_hash, last_seen_at, expires_at, created_at)
         VALUES (:user_id, :public_id, :hash, :ip_hash, :ua_hash, :last_seen, :expires_at, :created_at)'
    )->execute([
        'user_id' => $registered['user_id'],
        'public_id' => 'SES-' . strtoupper(bin2hex(random_bytes(8))),
        'hash' => hash('sha256', random_bytes(32)),
        'ip_hash' => hash('sha256', '127.0.0.1'),
        'ua_hash' => hash('sha256', 'vp3-ci'),
        'last_seen' => $now->format('Y-m-d H:i:s'),
        'expires_at' => $now->modify('+1 hour')->format('Y-m-d H:i:s'),
        'created_at' => $now->format('Y-m-d H:i:s'),
    ]);

    $resetToken = $security->createPasswordReset($email);
    if (!is_string($resetToken) || $resetToken === '') {
        $failures[] = 'Password reset token was not issued.';
    } elseif (!$security->resetPassword($resetToken, 'ChangedPass456')) {
        $failures[] = 'Password reset failed.';
    }

    if (is_string($resetToken) && $security->resetPassword($resetToken, 'ChangedPass789')) {
        $failures[] = 'Password reset token was reusable.';
    }
    if ($auth->authenticate($email, 'StrongPass123', '127.0.0.2', 'vp3-ci') !== null) {
        $failures[] = 'Old password remained valid after reset.';
    }
    if ($auth->authenticate($email, 'ChangedPass456', '127.0.0.3', 'vp3-ci') === null) {
        $failures[] = 'New password was not accepted after reset.';
    }

    $session = $pdo->prepare('SELECT revoked_at FROM auth_sessions WHERE user_id = :user_id ORDER BY id DESC LIMIT 1');
    $session->execute(['user_id' => $registered['user_id']]);
    if (!$session->fetchColumn()) {
        $failures[] = 'Password reset did not revoke active sessions.';
    }

    $invalidOwnershipRejected = false;
    try {
        $pdo->prepare(
            'INSERT INTO account_users (account_id, user_id, role, status, created_at, updated_at)
             VALUES (:account_id, :user_id, :role, :status, :created_at, :updated_at)'
        )->execute([
            'account_id' => 999999999,
            'user_id' => $registered['user_id'],
            'role' => 'customer_admin',
            'status' => 'active',
            'created_at' => $now->format('Y-m-d H:i:s'),
            'updated_at' => $now->format('Y-m-d H:i:s'),
        ]);
    } catch (Throwable) {
        $invalidOwnershipRejected = true;
    }
    if (!$invalidOwnershipRejected) {
        $failures[] = 'Foreign-key ownership boundary did not reject an invalid account membership.';
    }

    foreach (['customer_owner','customer_admin','billing_manager','support_member','vp3_support','vp3_operations','vp3_admin','vp3_super_admin'] as $role) {
        $allowed = $pdo->prepare('SELECT COUNT(*) FROM role_permissions WHERE role = :role');
        $allowed->execute(['role' => $role]);
        if ((int) $allowed->fetchColumn() < 1) {
            $failures[] = 'Missing permission seed for role: ' . $role;
        }
    }
} catch (Throwable $exception) {
    $failures[] = get_class($exception) . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL);
    exit(1);
}

echo "Phase 2 database integration certification passed.\n";

<?php

declare(strict_types=1);

use Vp3\Auth\AuthAuditService;
use Vp3\Auth\AuthService;
use Vp3\Auth\DatabaseSessionService;
use Vp3\Auth\Mail\NullMailAdapter;
use Vp3\Auth\PasswordPolicy;
use Vp3\Database;
use Vp3\Http\PublicResponseGuard;

$root = dirname(__DIR__);
$autoload = $root . '/vendor/autoload.php';
if (is_file($autoload)) {
    require $autoload;
} else {
    spl_autoload_register(static function (string $class) use ($root): void {
        $prefix = 'Vp3\\';
        if (!str_starts_with($class, $prefix)) return;
        $path = $root . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($path)) require $path;
    });
}

$dsn = getenv('VP3_TEST_DSN') ?: '';
if ($dsn === '') { fwrite(STDERR, "VP3_TEST_DSN is required.\n"); exit(1); }
$database = new Database([
    'dsn' => $dsn,
    'username' => getenv('VP3_TEST_DB_USER') ?: 'root',
    'password' => getenv('VP3_TEST_DB_PASSWORD') ?: '',
    'options' => [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false],
]);
$pdo = $database->pdo();
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void { if (!$condition) $failures[] = $message; };

try {
    $token = strtoupper(bin2hex(random_bytes(5)));
    $email = strtolower('phase27-' . $token . '@example.test');
    $audit = new AuthAuditService($database);
    $mail = new NullMailAdapter();
    $auth = new AuthService($database, new PasswordPolicy(12), $mail, [
        'verification_ttl_seconds' => 3600,
        'login_attempt_limit' => 8,
        'login_attempt_window_seconds' => 900,
        'base_url' => 'https://vp3.example.test',
    ], $audit);
    $registered = $auth->register($email, 'Phase27-Strong-Password!42', 'Phase 27 User', '127.0.0.27', 'Phase27-Test-Agent');
    $assert(($registered['account_id'] ?? 0) > 0 && ($registered['user_id'] ?? 0) > 0, 'Server-side registration did not retain internal identities for service use.');

    $identity = $pdo->prepare(
        "SELECT a.public_id AS account_public_id,u.public_id AS user_public_id
         FROM accounts a
         JOIN users u ON u.id=?
         JOIN account_users au ON au.account_id=a.id AND au.user_id=u.id AND au.status='active'
         WHERE a.id=? LIMIT 1"
    );
    $identity->execute([(int) $registered['user_id'], (int) $registered['account_id']]);
    $public = $identity->fetch();
    $assert(is_array($public) && str_starts_with((string) $public['account_public_id'], 'VP3-'), 'Registration public account identity is unavailable.');
    $assert(is_array($public) && str_starts_with((string) $public['user_public_id'], 'USR-'), 'Registration public user identity is unavailable.');

    $verifiedAt = gmdate('Y-m-d H:i:s');
    $pdo->prepare("UPDATE users SET status='active',email_verified_at=?,updated_at=? WHERE id=?")
        ->execute([$verifiedAt, $verifiedAt, (int) $registered['user_id']]);
    $pdo->prepare("UPDATE accounts SET status='active',updated_at=? WHERE id=?")
        ->execute([$verifiedAt, (int) $registered['account_id']]);

    $sessions = new DatabaseSessionService($database, 1800, 86400, $audit);
    $created = $sessions->create((int) $registered['user_id'], '127.0.0.27', 'Phase27-Test-Agent');
    $rawCurrent = $sessions->validate((string) $created['token'], '127.0.0.27', 'Phase27-Test-Agent', false);
    $assert(isset($rawCurrent['user']['id']), 'Raw authentication context did not exercise the internal user ID.');
    $assert(isset($rawCurrent['user']['public_id'], $rawCurrent['session']['public_id']), 'Raw authentication context omitted public identities.');

    $safeCurrent = PublicResponseGuard::sanitize(['data' => [
        'user' => $rawCurrent['user'],
        'session' => $rawCurrent['session'],
        'csrf_token' => 'phase27-csrf-token',
    ]]);
    PublicResponseGuard::assertSafe($safeCurrent);
    $assert(!isset($safeCurrent['data']['user']['id']), 'Sanitized authentication context retained the internal user ID.');
    $assert(($safeCurrent['data']['user']['public_id'] ?? null) === $public['user_public_id'], 'Sanitized context lost the public user identity.');
    $assert(($safeCurrent['data']['session']['public_id'] ?? null) === $created['public_id'], 'Sanitized context lost the public session identity.');
    $assert(($safeCurrent['data']['csrf_token'] ?? null) === 'phase27-csrf-token', 'Sanitized context lost the CSRF token.');

    $safeRegistration = PublicResponseGuard::sanitize(['data' => [
        'account_public_id' => (string) $public['account_public_id'],
        'user_public_id' => (string) $public['user_public_id'],
        'account_id' => (int) $registered['account_id'],
        'user_id' => (int) $registered['user_id'],
        'status' => 'pending_verification',
    ]]);
    PublicResponseGuard::assertSafe($safeRegistration);
    $assert(!isset($safeRegistration['data']['account_id'], $safeRegistration['data']['user_id']), 'Registration response retained internal identities.');
    $assert(($safeRegistration['data']['account_public_id'] ?? null) === $public['account_public_id'], 'Registration lost the public account identity.');
    $assert(($safeRegistration['data']['user_public_id'] ?? null) === $public['user_public_id'], 'Registration lost the public user identity.');
    $assert(count($mail->messages()) === 1, 'Registration did not retain verification delivery behavior.');
    $native = $pdo->getAttribute(PDO::ATTR_EMULATE_PREPARES);
    $assert($native === false || $native === 0, 'Phase 27 database proof did not use native PDO prepares.');
} catch (Throwable $exception) {
    $failures[] = $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 27 public authentication response database failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 27 public authentication response database certification passed.\n");

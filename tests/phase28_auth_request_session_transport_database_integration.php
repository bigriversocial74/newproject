<?php

declare(strict_types=1);

use Vp3\Auth\AuthAuditService;
use Vp3\Auth\AuthPublicException;
use Vp3\Auth\AuthService;
use Vp3\Auth\DatabaseSessionService;
use Vp3\Auth\Mail\NullMailAdapter;
use Vp3\Auth\PasswordPolicy;
use Vp3\Database;
use Vp3\Http\AuthRequestIntegrity;
use Vp3\Http\SessionManager;

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
$session = null;

try {
    $token = strtoupper(bin2hex(random_bytes(5)));
    $email = strtolower('phase28-' . $token . '@example.test');
    $audit = new AuthAuditService($database);
    $mail = new NullMailAdapter();
    $auth = new AuthService($database, new PasswordPolicy(12), $mail, [
        'verification_ttl_seconds' => 3600,
        'login_attempt_limit' => 8,
        'login_attempt_window_seconds' => 900,
        'base_url' => 'https://vp3.example.test',
    ], $audit);
    $registered = $auth->register($email, 'Phase28-Strong-Password!42', 'Phase 28 User', '127.0.0.28', 'Phase28-Test-Agent');
    $verifiedAt = gmdate('Y-m-d H:i:s');
    $pdo->prepare("UPDATE users SET status='active',email_verified_at=?,updated_at=? WHERE id=?")
        ->execute([$verifiedAt, $verifiedAt, (int) $registered['user_id']]);
    $pdo->prepare("UPDATE accounts SET status='active',updated_at=? WHERE id=?")
        ->execute([$verifiedAt, (int) $registered['account_id']]);

    $databaseSessions = new DatabaseSessionService($database, 1800, 86400, $audit);
    $created = $databaseSessions->create((int) $registered['user_id'], '127.0.0.28', 'Phase28-Test-Agent');
    $session = new SessionManager(['name' => '__Host-vp3_phase28_' . $token, 'secure' => true]);
    $session->start();
    $session->setApplicationToken((string) $created['token']);
    $assert(hash_equals((string) $created['token'], $session->applicationToken()), 'Hardened PHP session did not retain the opaque application token.');
    $validated = $databaseSessions->validate($session->applicationToken(), '127.0.0.28', 'Phase28-Test-Agent', false);
    $assert(($validated['session']['public_id'] ?? null) === $created['public_id'], 'Database session validation changed under hardened cookie transport.');

    $parameters = session_get_cookie_params();
    $assert(($parameters['path'] ?? null) === '/', 'Runtime session cookie path is not root-scoped.');
    $assert(($parameters['secure'] ?? null) === true, 'Runtime session cookie is not Secure.');
    $assert(($parameters['httponly'] ?? null) === true, 'Runtime session cookie is not HttpOnly.');
    $assert(($parameters['samesite'] ?? null) === 'Lax', 'Runtime session cookie SameSite is not Lax.');
    $assert(($parameters['domain'] ?? '') === '', 'Runtime session cookie acquired a Domain scope.');

    $guard = new AuthRequestIntegrity('https://vp3.example.test', 'production');
    $guard->assertTrusted([
        'HTTP_HOST' => 'vp3.example.test',
        'HTTP_ORIGIN' => 'https://vp3.example.test',
        'HTTP_SEC_FETCH_SITE' => 'same-origin',
    ]);
    try {
        $guard->assertTrusted([
            'HTTP_HOST' => 'vp3.example.test',
            'HTTP_ORIGIN' => 'https://attacker.example.test',
            'HTTP_SEC_FETCH_SITE' => 'cross-site',
        ]);
        $failures[] = 'Database-backed authentication transport accepted a cross-origin request.';
    } catch (AuthPublicException $exception) {
        $assert($exception->publicCode() === 'untrusted_request_origin', 'Cross-origin rejection lost its stable public code.');
    }

    $assert(count($mail->messages()) === 1, 'Registration verification delivery changed during Phase 28 integration proof.');
    $native = $pdo->getAttribute(PDO::ATTR_EMULATE_PREPARES);
    $assert($native === false || $native === 0, 'Phase 28 database proof did not use native PDO prepares.');
} catch (Throwable $exception) {
    $failures[] = $exception::class . ': ' . $exception->getMessage();
} finally {
    if ($session instanceof SessionManager && session_status() === PHP_SESSION_ACTIVE) {
        $session->destroy();
    }
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 28 authentication request/session transport database failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 28 authentication request/session transport database certification passed.\n");

<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\ControlCenter\ControlCenterUrl;
use Vp3\ControlCenter\PublicAccountIdentityResolver;
use Vp3\Database;

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
$publicFailure = static function (callable $work, string $code): bool {
    try { $work(); } catch (AuthPublicException $exception) { return $exception->publicCode() === $code; }
    return false;
};

try {
    $token = strtoupper(bin2hex(random_bytes(5)));
    $now = gmdate('Y-m-d H:i:s');
    $passwordHash = password_hash('Phase26-Strong-Password!42', PASSWORD_DEFAULT);
    if (!is_string($passwordHash)) throw new RuntimeException('Unable to create Phase 26 password fixture.');

    $email = strtolower('phase26-' . $token . '@example.test');
    $userPublic = 'USR26-' . $token;
    $pdo->prepare("INSERT INTO users (public_id,email,email_normalized,password_hash,display_name,status,email_verified_at,created_at,updated_at) VALUES (?,?,?,?,?,'active',?,?,?)")
        ->execute([$userPublic, $email, $email, $passwordHash, 'Phase 26 Owner', $now, $now, $now]);
    $userId = (int) $pdo->lastInsertId();

    $createAccount = static function (string $suffix) use ($pdo, $token, $now): array {
        $public = 'ACC26-' . $token . '-' . $suffix;
        $pdo->prepare("INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at) VALUES (?,'organization','active',?,?,?)")
            ->execute([$public, 'Phase 26 ' . $suffix, $now, $now]);
        return ['id' => (int) $pdo->lastInsertId(), 'public_id' => $public];
    };
    $owned = $createAccount('OWNED');
    $other = $createAccount('OTHER');
    $pdo->prepare("INSERT INTO account_users (account_id,user_id,role,status,created_at,updated_at) VALUES (?,?,'customer_owner','active',?,?)")
        ->execute([$owned['id'], $userId, $now, $now]);

    $resolver = new PublicAccountIdentityResolver($database);
    $resolved = $resolver->resolve($userId, $owned['public_id'], ['customer_owner', 'customer_admin', 'billing_manager']);
    $assert($resolved['account_id'] === $owned['id'], 'Public account resolver returned the wrong internal account.');
    $assert($resolved['account_public_id'] === $owned['public_id'], 'Public account resolver lost the public identity.');

    $success = ControlCenterUrl::absolute('https://vp3.example.test', '/billing.php', $resolved['account_public_id'], ['checkout' => 'success']);
    $parts = parse_url($success);
    parse_str((string) ($parts['query'] ?? ''), $query);
    $assert(($parts['scheme'] ?? null) === 'https' && ($parts['host'] ?? null) === 'vp3.example.test', 'Generated return URL is not exact HTTPS same-origin.');
    $assert(($query['account'] ?? null) === $owned['public_id'], 'Generated return URL lost the public account identity.');
    $assert(!array_key_exists('account_id', $query), 'Generated return URL exposed an internal account ID.');
    $assert(!str_contains($success, (string) $owned['id']), 'Generated return URL contains the numeric account ID.');
    $assert($publicFailure(fn () => $resolver->resolve($userId, $other['public_id'], ['customer_owner']), 'account_membership_required'), 'Cross-account public identity was accepted.');
    $native = $pdo->getAttribute(PDO::ATTR_EMULATE_PREPARES);
    $assert($native === false || $native === 0, 'Phase 26 database proof did not use native PDO prepares.');
} catch (Throwable $exception) {
    $failures[] = $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 26 public navigation database failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

fwrite(STDOUT, "Phase 26 public navigation database certification passed.\n");

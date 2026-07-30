<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\Database;
use Vp3\Infrastructure\InfrastructureControlCenterActionService;
use Vp3\Infrastructure\ProviderSecretCipher;

$root = dirname(__DIR__);
$autoload = $root . '/vendor/autoload.php';
if (is_file($autoload)) {
    require $autoload;
} else {
    spl_autoload_register(static function (string $class) use ($root): void {
        $prefix = 'Vp3\\';
        if (!str_starts_with($class, $prefix)) {
            return;
        }
        $path = $root . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($path)) {
            require $path;
        }
    });
}

$dsn = getenv('VP3_TEST_DSN') ?: '';
if ($dsn === '') {
    fwrite(STDERR, "VP3_TEST_DSN is required.\n");
    exit(1);
}
$database = new Database([
    'dsn' => $dsn,
    'username' => getenv('VP3_TEST_DB_USER') ?: 'root',
    'password' => getenv('VP3_TEST_DB_PASSWORD') ?: '',
    'options' => [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ],
]);
$pdo = $database->pdo();
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

try {
    $suffix = strtoupper(bin2hex(random_bytes(6)));
    $now = gmdate('Y-m-d H:i:s');
    $requestId = 'REQ-P20-STALE-' . $suffix;
    $passwordHash = password_hash('Phase20-Stale-Role!42', PASSWORD_DEFAULT);
    if (!is_string($passwordHash)) {
        throw new RuntimeException('Unable to hash the stale-role test password.');
    }

    $pdo->prepare(
        "INSERT INTO accounts
         (public_id,account_type,status,display_name,created_at,updated_at)
         VALUES (:public,'organization','active',:name,:created,:updated)"
    )->execute([
        'public' => 'VP3-P20-STALE-' . $suffix,
        'name' => 'Phase 20 Stale Role',
        'created' => $now,
        'updated' => $now,
    ]);
    $accountId = (int) $pdo->lastInsertId();

    $email = strtolower('phase20-stale-' . $suffix . '@example.test');
    $pdo->prepare(
        "INSERT INTO users
         (public_id,email,email_normalized,password_hash,display_name,status,email_verified_at,created_at,updated_at)
         VALUES (:public,:email,:normalized,:password,:name,'active',:verified,:created,:updated)"
    )->execute([
        'public' => 'USER-P20-STALE-' . $suffix,
        'email' => $email,
        'normalized' => $email,
        'password' => $passwordHash,
        'name' => 'Phase 20 Stale Role Owner',
        'verified' => $now,
        'created' => $now,
        'updated' => $now,
    ]);
    $userId = (int) $pdo->lastInsertId();

    $pdo->prepare(
        "INSERT INTO account_users
         (account_id,user_id,role,status,created_at,updated_at)
         VALUES (:account,:user,'customer_owner','active',:created,:updated)"
    )->execute([
        'account' => $accountId,
        'user' => $userId,
        'created' => $now,
        'updated' => $now,
    ]);

    $service = new InfrastructureControlCenterActionService(
        $database,
        new ProviderSecretCipher(base64_encode(random_bytes(32)), 'phase20-stale-role-key')
    );

    $denied = false;
    try {
        $service->saveConnection(
            $accountId,
            $userId,
            'customer_admin',
            'dns',
            'stale-role-dns',
            'Stale Role DNS',
            ['token' => 'must-not-be-stored'],
            $requestId
        );
    } catch (AuthPublicException $exception) {
        $denied = $exception->publicCode() === 'infrastructure_permission_denied';
    }
    $assert($denied, 'A stale caller role was accepted for a provider credential mutation.');

    $connectionCount = $pdo->prepare(
        'SELECT COUNT(*) FROM provider_connections WHERE account_id=:account'
    );
    $connectionCount->execute(['account' => $accountId]);
    $assert((int) $connectionCount->fetchColumn() === 0, 'A stale-role denial persisted provider credentials.');

    $receipt = $pdo->prepare(
        "SELECT COUNT(*)
         FROM provider_receipts
         WHERE account_id=:account AND request_id=:request AND result='denied'"
    );
    $receipt->execute(['account' => $accountId, 'request' => $requestId]);
    $assert((int) $receipt->fetchColumn() === 1, 'A stale-role denial did not persist one provider receipt.');

    $audit = $pdo->prepare(
        "SELECT COUNT(*)
         FROM audit_events
         WHERE account_id=:account AND actor_id=:actor AND request_id=:request AND result='denied'"
    );
    $audit->execute([
        'account' => $accountId,
        'actor' => $userId,
        'request' => $requestId,
    ]);
    $assert((int) $audit->fetchColumn() === 1, 'A stale-role denial did not persist one audit event.');
} catch (Throwable $exception) {
    $failures[] = 'Unhandled Phase 20 stale-role integration exception: ' . $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 20 stale-role database failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 20 stale-role database certification passed.\n");

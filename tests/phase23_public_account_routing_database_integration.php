<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
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
    'options' => [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ],
]);
$pdo = $database->pdo();
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void { if (!$condition) $failures[] = $message; };
$publicFailure = static function (callable $work, string $code, int $status): bool {
    try { $work(); } catch (AuthPublicException $exception) {
        return $exception->publicCode() === $code && $exception->httpStatus() === $status;
    }
    return false;
};

try {
    $token = strtoupper(bin2hex(random_bytes(5)));
    $now = gmdate('Y-m-d H:i:s');
    $createUser = static function (string $suffix) use ($pdo, $token, $now): int {
        $email = 'p23-' . strtolower($token . '-' . $suffix) . '@example.test';
        $pdo->prepare("INSERT INTO users (public_id,email,email_normalized,password_hash,display_name,status,email_verified_at,created_at,updated_at) VALUES (?,?,?,?,?,'active',?,?,?)")
            ->execute(["USR23-{$token}-{$suffix}", $email, $email, password_hash('Phase23!Testing123', PASSWORD_DEFAULT), 'Phase 23 ' . $suffix, $now, $now, $now]);
        return (int) $pdo->lastInsertId();
    };
    $createAccount = static function (string $suffix, string $status = 'active') use ($pdo, $token, $now): array {
        $public = "ACC23-{$token}-{$suffix}";
        $pdo->prepare("INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at) VALUES (?,'organization',?,?,?,?)")
            ->execute([$public, $status, 'Phase 23 ' . $suffix, $now, $now]);
        return ['id' => (int) $pdo->lastInsertId(), 'public_id' => $public];
    };
    $membership = static function (int $accountId, int $userId, string $role, string $status = 'active') use ($pdo, $now): void {
        $pdo->prepare('INSERT INTO account_users (account_id,user_id,role,status,created_at,updated_at) VALUES (?,?,?,?,?,?)')
            ->execute([$accountId, $userId, $role, $status, $now, $now]);
    };

    $owner = $createUser('OWNER');
    $outsider = $createUser('OUTSIDER');
    $billing = $createUser('BILLING');
    $support = $createUser('SUPPORT');
    $first = $createAccount('ALPHA');
    $second = $createAccount('BETA');
    $inactive = $createAccount('INACTIVE', 'suspended');
    $membership($first['id'], $owner, 'customer_owner');
    $membership($second['id'], $owner, 'customer_admin');
    $membership($inactive['id'], $owner, 'customer_owner');
    $membership($first['id'], $billing, 'billing_manager');
    $membership($first['id'], $support, 'support_member');
    $membership($second['id'], $outsider, 'customer_owner', 'suspended');

    $resolver = new PublicAccountIdentityResolver($database);
    $ownerAccounts = $resolver->memberships($owner, ['customer_owner', 'customer_admin']);
    $assert(count($ownerAccounts) === 2, 'Resolver did not exclude the inactive account.');
    $assert(!array_key_exists('credential_hash', $ownerAccounts[0]), 'Resolver exposed unrelated private data.');

    $default = $resolver->resolve($owner, null, ['customer_owner', 'customer_admin']);
    $assert($default['account_id'] > 0 && str_starts_with($default['account_public_id'], 'ACC23-'), 'Default authorized account resolution failed.');
    $assert((string) $default['account_id'] !== $default['account_public_id'], 'Resolver confused internal and public account identities.');

    $selected = $resolver->resolve($owner, $second['public_id'], ['customer_owner', 'customer_admin']);
    $assert($selected['account_id'] === $second['id'], 'Exact public account selection resolved the wrong internal account.');
    $assert($selected['account_public_id'] === $second['public_id'] && $selected['role'] === 'customer_admin', 'Exact public account selection lost public identity or role.');

    $billingResolved = $resolver->resolve($billing, $first['public_id'], ['billing_manager']);
    $assert($billingResolved['role'] === 'billing_manager', 'Role-specific public account resolution failed.');
    $supportResolved = $resolver->resolve($support, $first['public_id'], ['support_member']);
    $assert($supportResolved['role'] === 'support_member', 'Support public account resolution failed.');

    $assert($publicFailure(fn () => $resolver->resolve($billing, $first['public_id'], ['customer_owner', 'customer_admin']), 'account_membership_required', 403), 'Billing manager crossed the owner/admin boundary.');
    $assert($publicFailure(fn () => $resolver->resolve($outsider, $second['public_id'], ['customer_owner']), 'account_membership_required', 403), 'Suspended membership was accepted.');
    $assert($publicFailure(fn () => $resolver->resolve($owner, $inactive['public_id'], ['customer_owner']), 'account_membership_required', 403), 'Inactive account was accepted.');
    $assert($publicFailure(fn () => $resolver->resolve($owner, 'ACC23-NOT-OWNED', ['customer_owner', 'customer_admin']), 'account_membership_required', 403), 'Cross-account public identity was silently replaced by a default.');
    $assert($publicFailure(fn () => $resolver->resolve($owner, 'bad account id', ['customer_owner']), 'account_identity_invalid', 400), 'Malformed public identity was accepted.');
    $assert($publicFailure(fn () => $resolver->resolve($owner, $first['public_id'], ['root']), 'account_role_invalid', 500), 'Invalid role policy was accepted.');

    $native = $pdo->getAttribute(PDO::ATTR_EMULATE_PREPARES);
    $assert($native === false || $native === 0, 'Phase 23 database proof did not use native PDO prepares.');
} catch (Throwable $exception) {
    $failures[] = $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 23 public account routing database failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 23 public account routing database certification passed.\n");

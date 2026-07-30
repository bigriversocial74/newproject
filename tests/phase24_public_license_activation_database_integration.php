<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\Database;
use Vp3\HomeServers\HomeServerLicenseIdentityResolver;

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
$publicFailure = static function (callable $work, string $code): bool {
    try { $work(); } catch (AuthPublicException $exception) { return $exception->publicCode() === $code; }
    return false;
};

try {
    $token = strtoupper(bin2hex(random_bytes(5)));
    $now = gmdate('Y-m-d H:i:s');
    $ends = gmdate('Y-m-d H:i:s', time() + 2592000);
    $planId = (int) $pdo->query("SELECT id FROM plans WHERE code='standard' LIMIT 1")->fetchColumn();
    if ($planId < 1) throw new RuntimeException('VP3 Standard plan seed is missing.');

    $createAccount = static function (string $suffix) use ($pdo, $token, $now, $ends, $planId): array {
        $accountPublic = "ACC24-{$token}-{$suffix}";
        $pdo->prepare("INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at) VALUES (?,'organization','active',?,?,?)")
            ->execute([$accountPublic, 'Phase 24 ' . $suffix, $now, $now]);
        $accountId = (int) $pdo->lastInsertId();
        $pdo->prepare("INSERT INTO subscriptions (public_id,account_id,plan_id,status,starts_at,current_period_starts_at,current_period_ends_at,created_at,updated_at) VALUES (?,?,?,'active',?,?,?,?,?)")
            ->execute(["SUB24-{$token}-{$suffix}", $accountId, $planId, $now, $now, $ends, $now, $now]);
        $subscriptionId = (int) $pdo->lastInsertId();
        $label = strtolower("p24-{$token}-{$suffix}");
        $pdo->prepare("INSERT INTO domain_registrations (public_id,account_id,subscription_id,label,hostname,status,routing_status,ssl_status,registered_at,created_at,updated_at) VALUES (?,?,?,?,?,'active','active','active',?,?,?)")
            ->execute(["DOM24-{$token}-{$suffix}", $accountId, $subscriptionId, $label, $label . '.vp3.me', $now, $now, $now]);
        $domainId = (int) $pdo->lastInsertId();
        $pdo->prepare("INSERT INTO entitlement_bundles (public_id,account_id,subscription_id,domain_registration_id,plan_id,snapshot_hash,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)")
            ->execute(["BND24-{$token}-{$suffix}", $accountId, $subscriptionId, $domainId, $planId, hash('sha256', $token . $suffix), $now, $now]);
        return ['account' => $accountId, 'subscription' => $subscriptionId, 'domain' => $domainId, 'bundle' => (int) $pdo->lastInsertId()];
    };
    $createLicense = static function (array $account, string $suffix, string $product, string $status = 'active') use ($pdo, $token, $now): array {
        $public = "LIC24-{$token}-{$suffix}";
        $pdo->prepare("INSERT INTO licenses (public_id,account_id,subscription_id,domain_registration_id,entitlement_bundle_id,product_type,status,starts_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)")
            ->execute([$public, $account['account'], $account['subscription'], $account['domain'], $account['bundle'], $product, $status, $now, $now, $now]);
        return ['id' => (int) $pdo->lastInsertId(), 'public_id' => $public];
    };
    $occupy = static function (array $account, array $license, string $suffix) use ($pdo, $token, $now): void {
        $pdo->prepare("INSERT INTO homeserver_devices (public_id,account_id,subscription_id,domain_registration_id,license_id,device_fingerprint,credential_hash,status,pairing_status,software_version,mcp_version,update_channel,frontend_limit,paired_frontend_count,last_heartbeat_at,paired_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,'online','paired','24.0.0','1.0.0','stable',4,1,?,?,?,?)")
            ->execute(["HS24-{$token}-{$suffix}", $account['account'], $account['subscription'], $account['domain'], $license['id'], hash('sha256', 'fingerprint-' . $token . $suffix), hash('sha256', 'credential-' . $token . $suffix), $now, $now, $now, $now]);
    };

    $primary = $createAccount('PRIMARY');
    $other = $createAccount('OTHER');
    $eligible = $createLicense($primary, 'ELIGIBLE', 'homeserver');
    $occupied = $createLicense($primary, 'OCCUPIED', 'homeserver');
    $wrongProduct = $createLicense($primary, 'POD', 'pod');
    $expired = $createLicense($primary, 'EXPIRED', 'homeserver', 'expired');
    $otherEligible = $createLicense($other, 'OTHER', 'homeserver');
    $occupy($primary, $occupied, 'OCCUPIED');

    $resolver = new HomeServerLicenseIdentityResolver($database);
    $options = $resolver->eligibleLicenses($primary['account']);
    $assert(count($options) === 1, 'Eligible license list did not exclude occupied, expired, or wrong-product licenses.');
    $assert(($options[0]['license_public_id'] ?? null) === $eligible['public_id'], 'Eligible license list returned the wrong public identity.');
    $assert(!array_key_exists('license_id', $options[0]), 'Eligible license list exposed an internal license ID.');
    $assert(isset($options[0]['domain_public_id'], $options[0]['subscription_public_id'], $options[0]['hostname']), 'Eligible license list omitted customer-safe context.');

    $resolved = $resolver->resolveEligible($primary['account'], $eligible['public_id']);
    $assert($resolved === $eligible['id'], 'Public license identity resolved the wrong internal license.');
    $assert($publicFailure(fn () => $resolver->resolveEligible($primary['account'], $otherEligible['public_id']), 'license_not_eligible'), 'Cross-account license was accepted.');
    $assert($publicFailure(fn () => $resolver->resolveEligible($primary['account'], $occupied['public_id']), 'license_not_eligible'), 'Occupied license was accepted.');
    $assert($publicFailure(fn () => $resolver->resolveEligible($primary['account'], $wrongProduct['public_id']), 'license_not_eligible'), 'Wrong-product license was accepted.');
    $assert($publicFailure(fn () => $resolver->resolveEligible($primary['account'], $expired['public_id']), 'license_not_eligible'), 'Expired license was accepted.');
    $assert($publicFailure(fn () => $resolver->resolveEligible($primary['account'], 'bad license id'), 'license_identity_invalid'), 'Malformed license identity was accepted.');
    $assert($publicFailure(fn () => $resolver->eligibleLicenses(0), 'license_account_invalid'), 'Invalid account was accepted.');
    $native = $pdo->getAttribute(PDO::ATTR_EMULATE_PREPARES);
    $assert($native === false || $native === 0, 'Phase 24 database proof did not use native PDO prepares.');
} catch (Throwable $exception) {
    $failures[] = $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 24 public license activation database failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 24 public license activation database certification passed.\n");

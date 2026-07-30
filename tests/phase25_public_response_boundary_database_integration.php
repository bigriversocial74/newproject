<?php

declare(strict_types=1);

use Vp3\Auth\AuthAuditService;
use Vp3\Auth\AuthSecretCipher;
use Vp3\Auth\MfaService;
use Vp3\ControlCenter\AccountBillingQueryService;
use Vp3\ControlCenter\AccountControlCenterQueryService;
use Vp3\ControlCenter\AccountSecurityQueryService;
use Vp3\Database;
use Vp3\HomeServers\HomeServerFleetQueryService;
use Vp3\Http\PublicResponseGuard;

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
    $token = strtoupper(bin2hex(random_bytes(5)));
    $now = gmdate('Y-m-d H:i:s');
    $ends = gmdate('Y-m-d H:i:s', time() + 2592000);
    $accountPublic = 'ACC25-' . $token;
    $userPublic = 'USR25-' . $token;
    $subscriptionPublic = 'SUB25-' . $token;
    $domainPublic = 'DOM25-' . $token;
    $podLicensePublic = 'PODLIC25-' . $token;
    $homeServerLicensePublic = 'HSL25-' . $token;
    $devicePublic = 'HS25-' . $token;
    $label = strtolower('p25-' . $token);
    $passwordHash = password_hash('Phase25-Strong-Password!42', PASSWORD_DEFAULT);
    if (!is_string($passwordHash)) {
        throw new RuntimeException('Unable to create the Phase 25 password fixture.');
    }

    $planId = (int) $pdo->query("SELECT id FROM plans WHERE code='standard' LIMIT 1")->fetchColumn();
    if ($planId < 1) {
        throw new RuntimeException('VP3 Standard plan seed is missing.');
    }

    $pdo->prepare("INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at) VALUES (?,'organization','active',?,?,?)")
        ->execute([$accountPublic, 'Phase 25 Public Boundary', $now, $now]);
    $accountId = (int) $pdo->lastInsertId();

    $email = strtolower('owner-' . $token . '@example.test');
    $pdo->prepare("INSERT INTO users (public_id,email,email_normalized,password_hash,display_name,status,email_verified_at,created_at,updated_at) VALUES (?,?,?,?,?,'active',?,?,?)")
        ->execute([$userPublic, $email, $email, $passwordHash, 'Phase 25 Owner', $now, $now, $now]);
    $userId = (int) $pdo->lastInsertId();
    $pdo->prepare("INSERT INTO account_users (account_id,user_id,role,status,created_at,updated_at) VALUES (?,?,'customer_owner','active',?,?)")
        ->execute([$accountId, $userId, $now, $now]);

    $pdo->prepare("INSERT INTO subscriptions (public_id,account_id,plan_id,status,starts_at,current_period_starts_at,current_period_ends_at,created_at,updated_at) VALUES (?,?,?,'active',?,?,?,?,?)")
        ->execute([$subscriptionPublic, $accountId, $planId, $now, $now, $ends, $now, $now]);
    $subscriptionId = (int) $pdo->lastInsertId();

    $pdo->prepare("INSERT INTO domain_registrations (public_id,account_id,subscription_id,label,hostname,status,routing_status,ssl_status,registered_at,created_at,updated_at) VALUES (?,?,?,?,?,'active','active','active',?,?,?)")
        ->execute([$domainPublic, $accountId, $subscriptionId, $label, $label . '.vp3.me', $now, $now, $now]);
    $domainId = (int) $pdo->lastInsertId();

    $bundlePublic = 'BND25-' . $token;
    $pdo->prepare("INSERT INTO entitlement_bundles (public_id,account_id,subscription_id,domain_registration_id,plan_id,snapshot_hash,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)")
        ->execute([$bundlePublic, $accountId, $subscriptionId, $domainId, $planId, hash('sha256', $token), $now, $now]);
    $bundleId = (int) $pdo->lastInsertId();

    $licenseInsert = $pdo->prepare("INSERT INTO licenses (public_id,account_id,subscription_id,domain_registration_id,entitlement_bundle_id,product_type,status,starts_at,created_at,updated_at) VALUES (?,?,?,?,?,?,'active',?,?,?)");
    $licenseInsert->execute([$podLicensePublic, $accountId, $subscriptionId, $domainId, $bundleId, 'pod', $now, $now, $now]);
    $licenseInsert->execute([$homeServerLicensePublic, $accountId, $subscriptionId, $domainId, $bundleId, 'homeserver', $now, $now, $now]);
    $homeServerLicenseId = (int) $pdo->lastInsertId();

    $pdo->prepare("INSERT INTO homeserver_devices (public_id,account_id,subscription_id,domain_registration_id,license_id,device_fingerprint,credential_hash,status,pairing_status,software_version,mcp_version,update_channel,frontend_limit,paired_frontend_count,last_heartbeat_at,paired_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,'online','paired','25.0.0','1.0.0','stable',4,1,?,?,?,?)")
        ->execute([$devicePublic, $accountId, $subscriptionId, $domainId, $homeServerLicenseId, hash('sha256', 'fingerprint-' . $token), hash('sha256', 'credential-' . $token), $now, $now, $now, $now]);

    $rawDashboard = (new AccountControlCenterQueryService($database))->snapshot($accountId);
    $rawBilling = (new AccountBillingQueryService($database))->snapshot($accountId);
    $audit = new AuthAuditService($database);
    $cipher = new AuthSecretCipher(base64_encode(random_bytes(32)), 'phase25-test-key');
    $mfa = new MfaService($database, $cipher, $audit, 300, 8);
    $rawSecurity = (new AccountSecurityQueryService($database, $mfa))->snapshot($accountId, $userId, 'customer_owner', 'SESSION-P25-' . $token);
    $rawFleet = (new HomeServerFleetQueryService($database))->snapshot($accountId);

    $assert(isset($rawDashboard['account']['id'], $rawDashboard['subscriptions'][0]['id']), 'Dashboard fixture did not exercise internal identifiers.');
    $assert(isset($rawBilling['account']['id']), 'Billing fixture did not exercise an internal account identifier.');
    $assert(isset($rawSecurity['account']['id']), 'Security fixture did not exercise an internal account identifier.');
    $assert(isset($rawFleet['account_id'], $rawFleet['devices'][0]['license_id'], $rawFleet['devices'][0]['domain_registration_id']), 'Fleet fixture did not exercise internal relationship identifiers.');

    $safeDashboard = PublicResponseGuard::sanitize(['data' => $rawDashboard]);
    $safeBilling = PublicResponseGuard::sanitize(['data' => $rawBilling]);
    $safeSecurity = PublicResponseGuard::sanitize(['data' => $rawSecurity]);
    $safeFleet = PublicResponseGuard::sanitize(['data' => $rawFleet]);
    foreach ([$safeDashboard, $safeBilling, $safeSecurity, $safeFleet] as $safeResponse) {
        PublicResponseGuard::assertSafe($safeResponse);
    }

    $assert(($safeDashboard['data']['account']['public_id'] ?? null) === $accountPublic, 'Dashboard lost the public account identity.');
    $assert(($safeDashboard['data']['subscriptions'][0]['public_id'] ?? null) === $subscriptionPublic, 'Dashboard lost the public subscription identity.');
    $assert(($safeDashboard['data']['domains'][0]['public_id'] ?? null) === $domainPublic, 'Dashboard lost the public Domain identity.');
    $assert(($safeBilling['data']['account']['public_id'] ?? null) === $accountPublic, 'Billing lost the public account identity.');
    $assert(($safeSecurity['data']['account']['public_id'] ?? null) === $accountPublic, 'Security lost the public account identity.');
    $assert(($safeFleet['data']['devices'][0]['device_public_id'] ?? null) === $devicePublic, 'Fleet lost the public device identity.');
    $assert(($safeFleet['data']['devices'][0]['license_public_id'] ?? null) === $homeServerLicensePublic, 'Fleet lost the public license identity.');
    $native = $pdo->getAttribute(PDO::ATTR_EMULATE_PREPARES);
    $assert($native === false || $native === 0, 'Phase 25 database proof did not use native PDO prepares.');
} catch (Throwable $exception) {
    $failures[] = $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 25 public response boundary database failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

fwrite(STDOUT, "Phase 25 public response boundary database certification passed.\n");

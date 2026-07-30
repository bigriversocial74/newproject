<?php

declare(strict_types=1);

use Vp3\Database;
use Vp3\Settings\FederatedSettingsService;

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
if ($dsn === '') {
    fwrite(STDERR, "VP3_TEST_DSN is required.\n");
    exit(1);
}
$database = new Database([
    'dsn' => $dsn,
    'username' => getenv('VP3_TEST_DB_USER') ?: 'root',
    'password' => getenv('VP3_TEST_DB_PASSWORD') ?: '',
    'options' => [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => true],
]);
$pdo = $database->pdo();
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) $failures[] = $message;
};

try {
    $token = strtolower(bin2hex(random_bytes(6)));
    $now = gmdate('Y-m-d H:i:s');
    $planId = (int) $pdo->query("SELECT id FROM plans WHERE code='standard' LIMIT 1")->fetchColumn();
    if ($planId < 1) throw new RuntimeException('VP3 Standard plan seed is missing.');

    $createAccount = static function (string $suffix) use ($pdo, $token, $now, $planId): array {
        $email = "phase15-{$token}-{$suffix}@example.test";
        $pdo->prepare("INSERT INTO users (public_id,email,email_normalized,password_hash,display_name,status,email_verified_at,created_at,updated_at) VALUES (:public,:email,:email,:password,:name,'active',:now,:now,:now)")
            ->execute(['public' => 'USR-P15-' . strtoupper($token . '-' . $suffix), 'email' => $email, 'password' => password_hash('Phase15!Testing123', PASSWORD_DEFAULT), 'name' => 'Phase 15 ' . $suffix, 'now' => $now]);
        $userId = (int) $pdo->lastInsertId();
        $pdo->prepare("INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at) VALUES (:public,'individual','active',:name,:now,:now)")
            ->execute(['public' => 'VP3-P15-' . strtoupper($token . '-' . $suffix), 'name' => 'Phase 15 ' . $suffix, 'now' => $now]);
        $accountId = (int) $pdo->lastInsertId();
        $pdo->prepare("INSERT INTO account_users (account_id,user_id,role,status,created_at,updated_at) VALUES (:account,:user,'owner','active',:now,:now)")
            ->execute(['account' => $accountId, 'user' => $userId, 'now' => $now]);
        $pdo->prepare("INSERT INTO subscriptions (public_id,account_id,plan_id,status,starts_at,current_period_starts_at,current_period_ends_at,created_at,updated_at) VALUES (:public,:account,:plan,'active',:now,:now,:ends,:now,:now)")
            ->execute(['public' => 'SUB-P15-' . strtoupper($token . '-' . $suffix), 'account' => $accountId, 'plan' => $planId, 'now' => $now, 'ends' => gmdate('Y-m-d H:i:s', time() + 2592000)]);
        $subscriptionId = (int) $pdo->lastInsertId();
        $label = 'phase15-' . $token . '-' . $suffix;
        $pdo->prepare("INSERT INTO domain_registrations (public_id,account_id,subscription_id,label,hostname,status,routing_status,ssl_status,registered_at,created_at,updated_at) VALUES (:public,:account,:subscription,:label,:hostname,'active','active','active',:now,:now,:now)")
            ->execute(['public' => 'DOM-P15-' . strtoupper($token . '-' . $suffix), 'account' => $accountId, 'subscription' => $subscriptionId, 'label' => $label, 'hostname' => $label . '.vp3.me', 'now' => $now]);
        $domainId = (int) $pdo->lastInsertId();
        $pdo->prepare("INSERT INTO entitlement_bundles (public_id,account_id,subscription_id,domain_registration_id,plan_id,snapshot_hash,created_at,updated_at) VALUES (:public,:account,:subscription,:domain,:plan,:hash,:now,:now)")
            ->execute(['public' => 'BUNDLE-P15-' . strtoupper($token . '-' . $suffix), 'account' => $accountId, 'subscription' => $subscriptionId, 'domain' => $domainId, 'plan' => $planId, 'hash' => hash('sha256', $suffix . $token), 'now' => $now]);
        $bundleId = (int) $pdo->lastInsertId();
        $pdo->prepare("INSERT INTO licenses (public_id,account_id,subscription_id,domain_registration_id,entitlement_bundle_id,product_type,status,starts_at,created_at,updated_at) VALUES (:public,:account,:subscription,:domain,:bundle,'homeserver','active',:now,:now,:now)")
            ->execute(['public' => 'HSL-P15-' . strtoupper($token . '-' . $suffix), 'account' => $accountId, 'subscription' => $subscriptionId, 'domain' => $domainId, 'bundle' => $bundleId, 'now' => $now]);
        return ['user' => $userId, 'account' => $accountId, 'subscription' => $subscriptionId, 'domain' => $domainId, 'license' => (int) $pdo->lastInsertId()];
    };

    $primary = $createAccount('primary');
    $other = $createAccount('other');
    $credential = 'phase15-device-credential-' . $token;
    $devicePublic = 'HS-P15-' . strtoupper($token);
    $pdo->prepare("INSERT INTO homeserver_devices (public_id,account_id,subscription_id,domain_registration_id,license_id,device_fingerprint,credential_hash,status,pairing_status,software_version,mcp_version,update_channel,frontend_limit,paired_frontend_count,last_heartbeat_at,paired_at,created_at,updated_at) VALUES (:public,:account,:subscription,:domain,:license,:fingerprint,:credential,'online','paired','15.0.0','1.0.0','stable',2,0,:now,:now,:now,:now)")
        ->execute(['public' => $devicePublic, 'account' => $primary['account'], 'subscription' => $primary['subscription'], 'domain' => $primary['domain'], 'license' => $primary['license'], 'fingerprint' => hash('sha256', 'device-' . $token), 'credential' => hash('sha256', $credential), 'now' => $now]);

    $service = new FederatedSettingsService($database);
    $initial = $service->snapshotForAccount($primary['account']);
    $assert($initial['schema'] === 'vp3.federated-settings.v1', 'Snapshot schema is incorrect.');
    $assert(count($initial['settings']) >= 10, 'Federated catalog is incomplete.');
    $assert($initial['max_revision'] === 0, 'Default snapshot should have revision zero.');

    $updated = $service->updateFromBrowser($primary['account'], $primary['user'], 'appearance.theme', 'dark', 0);
    $theme = array_values(array_filter($updated['settings'], static fn (array $setting): bool => $setting['setting_key'] === 'appearance.theme'))[0] ?? null;
    $assert(is_array($theme) && $theme['value'] === 'dark' && $theme['revision'] === 1, 'VP3 shared setting update failed.');

    $staleRejected = false;
    try {
        $service->updateFromBrowser($primary['account'], $primary['user'], 'appearance.theme', 'light', 0);
    } catch (RuntimeException $exception) {
        $staleRejected = str_contains(strtolower($exception->getMessage()), 'changed');
    }
    $assert($staleRejected, 'Stale browser revision was not rejected.');

    $sync = $service->synchronizeDevice($devicePublic, $credential, 'REQ-P15-' . strtoupper($token), 1, [
        ['setting_key' => 'updates.install_window', 'value' => '03:00-04:00', 'expected_revision' => 0],
        ['setting_key' => 'appearance.theme', 'value' => 'light', 'expected_revision' => 1],
        ['setting_key' => 'updates.channel', 'value' => 'beta', 'expected_revision' => 0],
    ]);
    $assert(count($sync['applied']) === 2, 'Device sync did not apply the permitted settings.');
    $assert(count($sync['conflicts']) === 1 && $sync['conflicts'][0]['reason'] === 'vp3_authority', 'Device sync did not reject the VP3-owned setting.');
    $deviceWindow = array_values(array_filter($sync['settings'], static fn (array $setting): bool => $setting['setting_key'] === 'updates.install_window'))[0] ?? null;
    $assert(is_array($deviceWindow) && $deviceWindow['value'] === '03:00-04:00', 'Device-owned setting was not persisted at device scope.');

    $replay = $service->synchronizeDevice($devicePublic, $credential, 'REQ-P15-' . strtoupper($token), 1, []);
    $assert($replay['replayed'] === true, 'Device sync request replay was not detected.');

    $accountSnapshot = $service->snapshotForAccount($primary['account']);
    $accountWindow = array_values(array_filter($accountSnapshot['settings'], static fn (array $setting): bool => $setting['setting_key'] === 'updates.install_window'))[0] ?? null;
    $assert(is_array($accountWindow) && $accountWindow['value'] === '02:00-05:00', 'Device-owned override leaked into the account snapshot.');

    $isolated = false;
    try {
        $service->snapshotForAccount($other['account'], $devicePublic);
    } catch (RuntimeException) {
        $isolated = true;
    }
    $assert($isolated, 'Cross-account device settings access was not denied.');
    $encoded = json_encode($sync, JSON_THROW_ON_ERROR);
    foreach (['credential_hash','device_fingerprint','password_hash','private_key'] as $forbidden) {
        $assert(!str_contains($encoded, $forbidden), "Snapshot exposed {$forbidden}.");
    }
} catch (Throwable $exception) {
    $failures[] = $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, implode("\n", $failures) . "\n");
    exit(1);
}
echo "Phase 15 federated settings database integration passed.\n";

<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\Database;
use Vp3\HomeServers\HomeServerLeaseSigner;
use Vp3\Settings\FederatedSettingsControlCenterService;
use Vp3\Settings\FederatedSettingsControlCenterSigner;
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
    'options' => [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ],
]);
$pdo = $database->pdo();
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) $failures[] = $message;
};
$setting = static function (array $snapshot, string $key): ?array {
    foreach ((array) ($snapshot['settings'] ?? []) as $row) {
        if (($row['setting_key'] ?? null) === $key) return $row;
    }
    return null;
};
$publicException = static function (callable $work, string $expectedCode): bool {
    try {
        $work();
    } catch (AuthPublicException $exception) {
        return $exception->publicCode() === $expectedCode;
    }
    return false;
};
$decodeDocument = static function (string $document): array {
    $value = strtr($document, '-_', '+/');
    $padding = strlen($value) % 4;
    if ($padding > 0) $value .= str_repeat('=', 4 - $padding);
    $decoded = base64_decode($value, true);
    return is_string($decoded) ? json_decode($decoded, true, 32, JSON_THROW_ON_ERROR) : [];
};

try {
    $token = strtoupper(bin2hex(random_bytes(4)));
    $now = gmdate('Y-m-d H:i:s');
    $planId = (int) $pdo->query("SELECT id FROM plans WHERE code='standard' LIMIT 1")->fetchColumn();
    if ($planId < 1) throw new RuntimeException('VP3 Standard plan seed is missing.');

    $createAccount = static function (string $suffix, string $role = 'customer_owner') use ($pdo, $token, $now, $planId): array {
        $lower = strtolower($suffix);
        $email = "p22-{$token}-{$lower}@example.test";
        $userPublic = "USR22-{$token}-{$suffix}";
        $accountPublic = "ACC22-{$token}-{$suffix}";
        $pdo->prepare("INSERT INTO users (public_id,email,email_normalized,password_hash,display_name,status,email_verified_at,created_at,updated_at) VALUES (:public,:email,:email,:password,:name,'active',:now,:now,:now)")
            ->execute(['public' => $userPublic, 'email' => $email, 'password' => password_hash('Phase22!Testing123', PASSWORD_DEFAULT), 'name' => 'Phase 22 ' . $suffix, 'now' => $now]);
        $userId = (int) $pdo->lastInsertId();
        $pdo->prepare("INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at) VALUES (:public,'organization','active',:name,:now,:now)")
            ->execute(['public' => $accountPublic, 'name' => 'Phase 22 ' . $suffix, 'now' => $now]);
        $accountId = (int) $pdo->lastInsertId();
        $pdo->prepare("INSERT INTO account_users (account_id,user_id,role,status,created_at,updated_at) VALUES (:account,:user,:role,'active',:now,:now)")
            ->execute(['account' => $accountId, 'user' => $userId, 'role' => $role, 'now' => $now]);
        $pdo->prepare("INSERT INTO subscriptions (public_id,account_id,plan_id,status,starts_at,current_period_starts_at,current_period_ends_at,created_at,updated_at) VALUES (:public,:account,:plan,'active',:now,:now,:ends,:now,:now)")
            ->execute(['public' => "SUB22-{$token}-{$suffix}", 'account' => $accountId, 'plan' => $planId, 'now' => $now, 'ends' => gmdate('Y-m-d H:i:s', time() + 2592000)]);
        $subscriptionId = (int) $pdo->lastInsertId();
        $label = strtolower("p22-{$token}-{$suffix}");
        $pdo->prepare("INSERT INTO domain_registrations (public_id,account_id,subscription_id,label,hostname,status,routing_status,ssl_status,registered_at,created_at,updated_at) VALUES (:public,:account,:subscription,:label,:hostname,'active','active','active',:now,:now,:now)")
            ->execute(['public' => "DOM22-{$token}-{$suffix}", 'account' => $accountId, 'subscription' => $subscriptionId, 'label' => $label, 'hostname' => $label . '.vp3.me', 'now' => $now]);
        $domainId = (int) $pdo->lastInsertId();
        $pdo->prepare("INSERT INTO entitlement_bundles (public_id,account_id,subscription_id,domain_registration_id,plan_id,snapshot_hash,created_at,updated_at) VALUES (:public,:account,:subscription,:domain,:plan,:hash,:now,:now)")
            ->execute(['public' => "BND22-{$token}-{$suffix}", 'account' => $accountId, 'subscription' => $subscriptionId, 'domain' => $domainId, 'plan' => $planId, 'hash' => hash('sha256', $token . $suffix), 'now' => $now]);
        $bundleId = (int) $pdo->lastInsertId();
        $pdo->prepare("INSERT INTO licenses (public_id,account_id,subscription_id,domain_registration_id,entitlement_bundle_id,product_type,status,starts_at,created_at,updated_at) VALUES (:public,:account,:subscription,:domain,:bundle,'homeserver','active',:now,:now,:now)")
            ->execute(['public' => "HSL22-{$token}-{$suffix}", 'account' => $accountId, 'subscription' => $subscriptionId, 'domain' => $domainId, 'bundle' => $bundleId, 'now' => $now]);
        return [
            'user' => $userId,
            'account' => $accountId,
            'account_public' => $accountPublic,
            'subscription' => $subscriptionId,
            'domain' => $domainId,
            'license' => (int) $pdo->lastInsertId(),
            'role' => $role,
        ];
    };
    $addMember = static function (int $accountId, string $suffix, string $role) use ($pdo, $token, $now): int {
        $email = 'p22-' . strtolower($token . '-' . $suffix) . '@example.test';
        $pdo->prepare("INSERT INTO users (public_id,email,email_normalized,password_hash,display_name,status,email_verified_at,created_at,updated_at) VALUES (:public,:email,:email,:password,:name,'active',:now,:now,:now)")
            ->execute(['public' => "USR22-{$token}-{$suffix}", 'email' => $email, 'password' => password_hash('Phase22!Testing123', PASSWORD_DEFAULT), 'name' => 'Phase 22 ' . $suffix, 'now' => $now]);
        $userId = (int) $pdo->lastInsertId();
        $pdo->prepare("INSERT INTO account_users (account_id,user_id,role,status,created_at,updated_at) VALUES (:account,:user,:role,'active',:now,:now)")
            ->execute(['account' => $accountId, 'user' => $userId, 'role' => $role, 'now' => $now]);
        return $userId;
    };
    $createDevice = static function (array $account, string $suffix) use ($pdo, $token, $now): string {
        $public = "HS22-{$token}-{$suffix}";
        $pdo->prepare("INSERT INTO homeserver_devices (public_id,account_id,subscription_id,domain_registration_id,license_id,device_fingerprint,credential_hash,status,pairing_status,software_version,mcp_version,update_channel,frontend_limit,paired_frontend_count,last_heartbeat_at,paired_at,created_at,updated_at) VALUES (:public,:account,:subscription,:domain,:license,:fingerprint,:credential,'online','paired','22.0.0','1.0.0','stable',4,1,:now,:now,:now,:now)")
            ->execute([
                'public' => $public,
                'account' => $account['account'],
                'subscription' => $account['subscription'],
                'domain' => $account['domain'],
                'license' => $account['license'],
                'fingerprint' => hash('sha256', 'fingerprint-' . $token . $suffix),
                'credential' => hash('sha256', 'credential-' . $token . $suffix),
                'now' => $now,
            ]);
        return $public;
    };

    $primary = $createAccount('PRIMARY');
    $other = $createAccount('OTHER');
    $supportUser = $addMember($primary['account'], 'SUPPORT', 'support_member');
    $billingUser = $addMember($primary['account'], 'BILLING', 'billing_manager');
    $primaryDevice = $createDevice($primary, 'PRIMARY');
    $otherDevice = $createDevice($other, 'OTHER');

    $service = new FederatedSettingsControlCenterService($database, new FederatedSettingsService($database));
    $initial = $service->snapshot($primary['account'], $primary['user'], 'customer_owner');
    $assert(($initial['account']['public_id'] ?? null) === $primary['account_public'], 'Snapshot did not expose the public account identity.');
    $assert(($initial['selected_device_public_id'] ?? 'x') === null, 'Account snapshot unexpectedly selected a HomeServer.');
    $assert(count((array) $initial['devices']) === 1, 'Account-owned HomeServer list is incomplete.');
    $assert(($initial['devices'][0]['public_id'] ?? null) === $primaryDevice, 'Snapshot returned the wrong HomeServer identity.');
    $theme = $setting($initial, 'appearance.theme');
    $assert(is_array($theme) && $theme['requires_device'] === true, 'Shared setting does not require a selected HomeServer.');

    $vp3Request = "REQ22-VP3-{$token}";
    $vp3 = $service->update(
        $primary['account'], $primary['user'], 'customer_owner',
        'updates.channel', 'beta', 0, $primaryDevice, $vp3Request
    );
    $channel = $setting($vp3, 'updates.channel');
    $assert(is_array($channel) && $channel['value'] === 'beta' && $channel['scope'] === 'account', 'VP3 authority setting was not saved at account scope.');
    $scope = $pdo->prepare("SELECT scope_type,device_id FROM federated_settings WHERE account_id=:account AND setting_key='updates.channel' LIMIT 1");
    $scope->execute(['account' => $primary['account']]);
    $scopeRow = $scope->fetch(PDO::FETCH_ASSOC);
    $assert(is_array($scopeRow) && $scopeRow['scope_type'] === 'account' && $scopeRow['device_id'] === null, 'Selected HomeServer incorrectly changed VP3 setting scope.');

    $vp3Replay = $service->update(
        $primary['account'], $primary['user'], 'customer_owner',
        'updates.channel', 'beta', 0, $primaryDevice, $vp3Request
    );
    $assert(($vp3Replay['replayed'] ?? false) === true, 'Account-scoped settings request replay was not detected.');
    $assert($publicException(
        fn () => $service->update($primary['account'], $primary['user'], 'customer_owner', 'updates.channel', 'stable', 1, null, $vp3Request),
        'settings_request_conflict'
    ), 'Settings request ID reuse with a different payload was not rejected.');

    $assert($publicException(
        fn () => $service->update($primary['account'], $primary['user'], 'customer_owner', 'appearance.theme', 'dark', 0, null, "REQ22-NODEV-{$token}"),
        'settings_device_required'
    ), 'Shared setting update without a HomeServer was not rejected.');
    $assert($publicException(
        fn () => $service->update($primary['account'], $primary['user'], 'customer_owner', 'appearance.theme', 'dark', 0, $otherDevice, "REQ22-CROSS-{$token}"),
        'settings_device_not_found'
    ), 'Cross-account HomeServer selection was not rejected.');

    $sharedRequest = "REQ22-SHARED-{$token}";
    $shared = $service->update(
        $primary['account'], $primary['user'], 'customer_owner',
        'appearance.theme', 'dark', 0, $primaryDevice, $sharedRequest
    );
    $sharedTheme = $setting($shared, 'appearance.theme');
    $assert(is_array($sharedTheme) && $sharedTheme['value'] === 'dark' && $sharedTheme['scope'] === 'device', 'Shared setting was not saved at device scope.');
    $deviceScope = $pdo->prepare("SELECT fs.scope_type,d.public_id FROM federated_settings fs JOIN homeserver_devices d ON d.id=fs.device_id WHERE fs.account_id=:account AND fs.setting_key='appearance.theme' LIMIT 1");
    $deviceScope->execute(['account' => $primary['account']]);
    $deviceScopeRow = $deviceScope->fetch(PDO::FETCH_ASSOC);
    $assert(is_array($deviceScopeRow) && $deviceScopeRow['scope_type'] === 'device' && $deviceScopeRow['public_id'] === $primaryDevice, 'Shared setting persisted against the wrong device.');
    $accountOnly = $service->snapshot($primary['account'], $primary['user'], 'customer_owner');
    $accountTheme = $setting($accountOnly, 'appearance.theme');
    $assert(is_array($accountTheme) && $accountTheme['value'] === 'system', 'Device-scoped shared value leaked into the account snapshot.');
    $assert($publicException(
        fn () => $service->update($primary['account'], $primary['user'], 'customer_owner', 'appearance.theme', 'light', 0, $primaryDevice, "REQ22-STALE-{$token}"),
        'settings_revision_conflict'
    ), 'Stale shared setting revision was not rejected.');
    $assert($publicException(
        fn () => $service->update($primary['account'], $primary['user'], 'customer_owner', 'updates.install_window', '03:00-04:00', 0, $primaryDevice, "REQ22-HSAUTH-{$token}"),
        'settings_homeserver_authority'
    ), 'HomeServer-authority setting was mutable from VP3.');

    $assert($publicException(
        fn () => $service->update($primary['account'], $supportUser, 'support_member', 'updates.channel', 'stable', 1, null, "REQ22-SUPPORT-{$token}"),
        'settings_permission_denied'
    ), 'Support member settings mutation was not denied.');
    $assert($publicException(
        fn () => $service->update($primary['account'], $billingUser, 'billing_manager', 'updates.channel', 'stable', 1, null, "REQ22-BILLING-{$token}"),
        'settings_permission_denied'
    ), 'Billing manager settings mutation was not denied.');
    $assert($publicException(
        fn () => $service->update($primary['account'], $primary['user'], 'customer_admin', 'updates.channel', 'stable', 1, null, "REQ22-STALE-ROLE-{$token}"),
        'settings_permission_denied'
    ), 'Stale caller role was not denied.');
    $denied = $pdo->prepare("SELECT COUNT(*) FROM audit_events WHERE account_id=:account AND event_type='settings.updated' AND result='denied' AND request_id LIKE :prefix");
    $denied->execute(['account' => $primary['account'], 'prefix' => 'REQ22-%-' . $token]);
    $assert((int) $denied->fetchColumn() >= 3, 'Denied settings attempts did not persist audit evidence.');

    if (!function_exists('sodium_crypto_sign_keypair')) {
        throw new RuntimeException('The sodium extension is required for Phase 22 signature certification.');
    }
    $pair = sodium_crypto_sign_keypair();
    $private = base64_encode(sodium_crypto_sign_secretkey($pair));
    $public = base64_encode(sodium_crypto_sign_publickey($pair));
    $leaseSigner = new HomeServerLeaseSigner($private, $public, 'phase22-settings-test-v1');
    $browserSigner = new FederatedSettingsControlCenterSigner($leaseSigner);
    $signed = $browserSigner->sign($shared);
    $assert($signed['signature_algorithm'] === 'Ed25519', 'Browser snapshot did not use Ed25519.');
    $assert($leaseSigner->verify($signed['signed_document'], $signed['signature']), 'Browser settings signature could not be verified.');
    $claims = $decodeDocument((string) $signed['signed_document']);
    $assert(($claims['account_public_id'] ?? null) === $primary['account_public'], 'Signed browser document omitted the public account identity.');
    $assert(($claims['selected_device_public_id'] ?? null) === $primaryDevice, 'Signed browser document omitted the selected HomeServer identity.');
    $assert(!array_key_exists('account_id', $claims), 'Signed browser document exposed an internal account ID.');
    $assert((int) ($claims['exp'] ?? 0) > (int) ($claims['iat'] ?? 0), 'Browser settings signature expiration is invalid.');

    $encoded = json_encode($signed, JSON_THROW_ON_ERROR);
    foreach (['credential_hash','device_fingerprint','lease_token','password_hash','private_key','account_id','device_id'] as $forbidden) {
        $assert(!str_contains($encoded, '"' . $forbidden . '"'), "Browser settings snapshot exposed {$forbidden}.");
    }
    $receipt = $pdo->prepare("SELECT request_hash,snapshot_hash,result FROM federated_settings_sync_receipts WHERE account_id=:account AND request_id=:request AND direction='vp3_update' LIMIT 1");
    $receipt->execute(['account' => $primary['account'], 'request' => $sharedRequest]);
    $receiptRow = $receipt->fetch(PDO::FETCH_ASSOC);
    $assert(is_array($receiptRow) && strlen((string) $receiptRow['request_hash']) === 64 && $receiptRow['result'] === 'applied', 'Browser settings receipt is incomplete.');
    $assert(is_array($receiptRow) && hash_equals((string) $receiptRow['snapshot_hash'], (string) $shared['snapshot_hash']), 'Browser settings receipt does not bind the public snapshot hash.');
} catch (Throwable $exception) {
    $failures[] = $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 22 Federated Settings Control Center database failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 22 Federated Settings Control Center database certification passed.\n");

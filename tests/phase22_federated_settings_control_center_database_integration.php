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
    $encoded = strtr($document, '-_', '+/');
    $padding = strlen($encoded) % 4;
    if ($padding > 0) $encoded .= str_repeat('=', 4 - $padding);
    $decoded = base64_decode($encoded, true);
    return is_string($decoded) ? json_decode($decoded, true, 32, JSON_THROW_ON_ERROR) : [];
};

try {
    $token = strtoupper(bin2hex(random_bytes(4)));
    $now = gmdate('Y-m-d H:i:s');
    $ends = gmdate('Y-m-d H:i:s', time() + 2592000);
    $planId = (int) $pdo->query("SELECT id FROM plans WHERE code='standard' LIMIT 1")->fetchColumn();
    if ($planId < 1) throw new RuntimeException('VP3 Standard plan seed is missing.');

    $createAccount = static function (string $suffix, string $role = 'customer_owner') use ($pdo, $token, $now, $ends, $planId): array {
        $email = 'p22-' . strtolower($token . '-' . $suffix) . '@example.test';
        $userPublic = "USR22-{$token}-{$suffix}";
        $accountPublic = "ACC22-{$token}-{$suffix}";
        $pdo->prepare("INSERT INTO users (public_id,email,email_normalized,password_hash,display_name,status,email_verified_at,created_at,updated_at) VALUES (?,?,?,?,?,'active',?,?,?)")
            ->execute([$userPublic, $email, $email, password_hash('Phase22!Testing123', PASSWORD_DEFAULT), 'Phase 22 ' . $suffix, $now, $now, $now]);
        $userId = (int) $pdo->lastInsertId();
        $pdo->prepare("INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at) VALUES (?,'organization','active',?,?,?)")
            ->execute([$accountPublic, 'Phase 22 ' . $suffix, $now, $now]);
        $accountId = (int) $pdo->lastInsertId();
        $pdo->prepare("INSERT INTO account_users (account_id,user_id,role,status,created_at,updated_at) VALUES (?,?,?,'active',?,?)")
            ->execute([$accountId, $userId, $role, $now, $now]);
        $pdo->prepare("INSERT INTO subscriptions (public_id,account_id,plan_id,status,starts_at,current_period_starts_at,current_period_ends_at,created_at,updated_at) VALUES (?,?,?,'active',?,?,?,?,?)")
            ->execute(["SUB22-{$token}-{$suffix}", $accountId, $planId, $now, $now, $ends, $now, $now]);
        $subscriptionId = (int) $pdo->lastInsertId();
        $label = strtolower("p22-{$token}-{$suffix}");
        $pdo->prepare("INSERT INTO domain_registrations (public_id,account_id,subscription_id,label,hostname,status,routing_status,ssl_status,registered_at,created_at,updated_at) VALUES (?,?,?,?,?,'active','active','active',?,?,?)")
            ->execute(["DOM22-{$token}-{$suffix}", $accountId, $subscriptionId, $label, $label . '.vp3.me', $now, $now, $now]);
        $domainId = (int) $pdo->lastInsertId();
        $pdo->prepare("INSERT INTO entitlement_bundles (public_id,account_id,subscription_id,domain_registration_id,plan_id,snapshot_hash,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)")
            ->execute(["BND22-{$token}-{$suffix}", $accountId, $subscriptionId, $domainId, $planId, hash('sha256', $token . $suffix), $now, $now]);
        $bundleId = (int) $pdo->lastInsertId();
        $pdo->prepare("INSERT INTO licenses (public_id,account_id,subscription_id,domain_registration_id,entitlement_bundle_id,product_type,status,starts_at,created_at,updated_at) VALUES (?,?,?,?,?,'homeserver','active',?,?,?)")
            ->execute(["HSL22-{$token}-{$suffix}", $accountId, $subscriptionId, $domainId, $bundleId, $now, $now, $now]);
        return [
            'user' => $userId,
            'account' => $accountId,
            'account_public' => $accountPublic,
            'subscription' => $subscriptionId,
            'domain' => $domainId,
            'license' => (int) $pdo->lastInsertId(),
        ];
    };
    $addMember = static function (int $accountId, string $suffix, string $role) use ($pdo, $token, $now): int {
        $email = 'p22-' . strtolower($token . '-' . $suffix) . '@example.test';
        $pdo->prepare("INSERT INTO users (public_id,email,email_normalized,password_hash,display_name,status,email_verified_at,created_at,updated_at) VALUES (?,?,?,?,?,'active',?,?,?)")
            ->execute(["USR22-{$token}-{$suffix}", $email, $email, password_hash('Phase22!Testing123', PASSWORD_DEFAULT), 'Phase 22 ' . $suffix, $now, $now, $now]);
        $userId = (int) $pdo->lastInsertId();
        $pdo->prepare("INSERT INTO account_users (account_id,user_id,role,status,created_at,updated_at) VALUES (?,?,?,'active',?,?)")
            ->execute([$accountId, $userId, $role, $now, $now]);
        return $userId;
    };
    $createDevice = static function (array $account, string $suffix) use ($pdo, $token, $now): string {
        $public = "HS22-{$token}-{$suffix}";
        $pdo->prepare("INSERT INTO homeserver_devices (public_id,account_id,subscription_id,domain_registration_id,license_id,device_fingerprint,credential_hash,status,pairing_status,software_version,mcp_version,update_channel,frontend_limit,paired_frontend_count,last_heartbeat_at,paired_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,'online','paired','22.0.0','1.0.0','stable',4,1,?,?,?,?)")
            ->execute([$public, $account['account'], $account['subscription'], $account['domain'], $account['license'], hash('sha256', 'fingerprint-' . $token . $suffix), hash('sha256', 'credential-' . $token . $suffix), $now, $now, $now, $now]);
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
    $assert(array_key_exists('selected_device_public_id', $initial) && $initial['selected_device_public_id'] === null, 'Account snapshot unexpectedly selected a HomeServer.');
    $assert(count((array) $initial['devices']) === 1 && ($initial['devices'][0]['public_id'] ?? null) === $primaryDevice, 'Account-owned HomeServer list is incorrect.');
    $theme = $setting($initial, 'appearance.theme');
    $assert(is_array($theme) && $theme['requires_device'] === true, 'Shared setting does not require a selected HomeServer.');

    $vp3Request = "REQ22-VP3-{$token}";
    $vp3 = $service->update($primary['account'], $primary['user'], 'customer_owner', 'updates.channel', 'beta', 0, $primaryDevice, $vp3Request);
    $channel = $setting($vp3, 'updates.channel');
    $assert(is_array($channel) && $channel['value'] === 'beta' && $channel['scope'] === 'account', 'VP3 setting was not saved at account scope.');
    $scope = $pdo->prepare("SELECT scope_type,device_id FROM federated_settings WHERE account_id=? AND setting_key='updates.channel' LIMIT 1");
    $scope->execute([$primary['account']]);
    $scopeRow = $scope->fetch(PDO::FETCH_ASSOC);
    $assert(is_array($scopeRow) && $scopeRow['scope_type'] === 'account' && $scopeRow['device_id'] === null, 'Selected HomeServer incorrectly changed VP3 setting scope.');
    $vp3Replay = $service->update($primary['account'], $primary['user'], 'customer_owner', 'updates.channel', 'beta', 0, $primaryDevice, $vp3Request);
    $assert(($vp3Replay['replayed'] ?? false) === true, 'Account settings replay was not detected.');
    $assert($publicException(fn () => $service->update($primary['account'], $primary['user'], 'customer_owner', 'updates.channel', 'stable', 1, null, $vp3Request), 'settings_request_conflict'), 'Request ID payload conflict was not rejected.');

    $assert($publicException(fn () => $service->update($primary['account'], $primary['user'], 'customer_owner', 'appearance.theme', 'dark', 0, null, "REQ22-NODEV-{$token}"), 'settings_device_required'), 'Shared update without a HomeServer was not rejected.');
    $assert($publicException(fn () => $service->update($primary['account'], $primary['user'], 'customer_owner', 'appearance.theme', 'dark', 0, $otherDevice, "REQ22-CROSS-{$token}"), 'settings_device_not_found'), 'Cross-account HomeServer was not rejected.');

    $sharedRequest = "REQ22-SHARED-{$token}";
    $shared = $service->update($primary['account'], $primary['user'], 'customer_owner', 'appearance.theme', 'dark', 0, $primaryDevice, $sharedRequest);
    $sharedTheme = $setting($shared, 'appearance.theme');
    $assert(is_array($sharedTheme) && $sharedTheme['value'] === 'dark' && $sharedTheme['scope'] === 'device', 'Shared setting was not saved at device scope.');
    $deviceScope = $pdo->prepare("SELECT fs.scope_type,d.public_id FROM federated_settings fs JOIN homeserver_devices d ON d.id=fs.device_id WHERE fs.account_id=? AND fs.setting_key='appearance.theme' LIMIT 1");
    $deviceScope->execute([$primary['account']]);
    $deviceScopeRow = $deviceScope->fetch(PDO::FETCH_ASSOC);
    $assert(is_array($deviceScopeRow) && $deviceScopeRow['scope_type'] === 'device' && $deviceScopeRow['public_id'] === $primaryDevice, 'Shared setting persisted against the wrong device.');
    $accountTheme = $setting($service->snapshot($primary['account'], $primary['user'], 'customer_owner'), 'appearance.theme');
    $assert(is_array($accountTheme) && $accountTheme['value'] === 'system', 'Device value leaked into the account snapshot.');
    $assert($publicException(fn () => $service->update($primary['account'], $primary['user'], 'customer_owner', 'appearance.theme', 'light', 0, $primaryDevice, "REQ22-STALE-{$token}"), 'settings_revision_conflict'), 'Stale revision was not rejected.');
    $assert($publicException(fn () => $service->update($primary['account'], $primary['user'], 'customer_owner', 'updates.install_window', '03:00-04:00', 0, $primaryDevice, "REQ22-HSAUTH-{$token}"), 'settings_not_found'), 'Hidden HomeServer-authority setting was enumerable or mutable from VP3.');

    $assert($publicException(fn () => $service->update($primary['account'], $supportUser, 'support_member', 'updates.channel', 'stable', 1, null, "REQ22-SUPPORT-{$token}"), 'settings_permission_denied'), 'Support member update was not denied.');
    $assert($publicException(fn () => $service->update($primary['account'], $billingUser, 'billing_manager', 'updates.channel', 'stable', 1, null, "REQ22-BILLING-{$token}"), 'settings_permission_denied'), 'Billing manager update was not denied.');
    $assert($publicException(fn () => $service->update($primary['account'], $primary['user'], 'customer_admin', 'updates.channel', 'stable', 1, null, "REQ22-STALE-ROLE-{$token}"), 'settings_permission_denied'), 'Stale role was not denied.');
    $denied = $pdo->prepare("SELECT COUNT(*) FROM audit_events WHERE account_id=? AND event_type='settings.updated' AND result='denied' AND request_id LIKE ?");
    $denied->execute([$primary['account'], "REQ22-%-{$token}"]);
    $assert((int) $denied->fetchColumn() >= 3, 'Denied settings attempts did not persist audit evidence.');

    if (!function_exists('sodium_crypto_sign_keypair')) throw new RuntimeException('The sodium extension is required.');
    $pair = sodium_crypto_sign_keypair();
    $leaseSigner = new HomeServerLeaseSigner(base64_encode(sodium_crypto_sign_secretkey($pair)), base64_encode(sodium_crypto_sign_publickey($pair)), 'phase22-settings-test-v1');
    $signed = (new FederatedSettingsControlCenterSigner($leaseSigner))->sign($shared);
    $assert($signed['signature_algorithm'] === 'Ed25519' && $leaseSigner->verify($signed['signed_document'], $signed['signature']), 'Browser settings signature failed verification.');
    $claims = $decodeDocument((string) $signed['signed_document']);
    $assert(($claims['account_public_id'] ?? null) === $primary['account_public'] && ($claims['selected_device_public_id'] ?? null) === $primaryDevice, 'Signed public identities are incomplete.');
    $assert(!array_key_exists('account_id', $claims) && (int) ($claims['exp'] ?? 0) > (int) ($claims['iat'] ?? 0), 'Signed document exposed an internal ID or invalid expiration.');

    $encoded = json_encode($signed, JSON_THROW_ON_ERROR);
    foreach (['credential_hash','device_fingerprint','lease_token','password_hash','private_key','account_id','device_id'] as $forbidden) {
        $assert(!str_contains($encoded, '"' . $forbidden . '"'), "Browser snapshot exposed {$forbidden}.");
    }
    $receipt = $pdo->prepare("SELECT request_hash,snapshot_hash,result FROM federated_settings_sync_receipts WHERE account_id=? AND request_id=? AND direction='vp3_update' LIMIT 1");
    $receipt->execute([$primary['account'], $sharedRequest]);
    $receiptRow = $receipt->fetch(PDO::FETCH_ASSOC);
    $assert(is_array($receiptRow) && strlen((string) $receiptRow['request_hash']) === 64 && $receiptRow['result'] === 'applied', 'Browser settings receipt is incomplete.');
    $assert(is_array($receiptRow) && hash_equals((string) $receiptRow['snapshot_hash'], (string) $shared['snapshot_hash']), 'Receipt does not bind the public snapshot hash.');
} catch (Throwable $exception) {
    $failures[] = $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 22 Federated Settings Control Center database failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 22 Federated Settings Control Center database certification passed.\n");

<?php

declare(strict_types=1);

use Vp3\Database;
use Vp3\HomeServers\HomeServerFleetQueryService;
use Vp3\HomeServers\HomeServerRegistrationOptionsService;

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

    $createLicense = static function (string $suffix) use ($pdo, $token, $now, $planId): array {
        $pdo->prepare("INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at) VALUES (:public,'individual','active',:name,:now,:now)")
            ->execute(['public' => 'VP3-P14-' . strtoupper($token . '-' . $suffix), 'name' => 'Phase 14 ' . $suffix, 'now' => $now]);
        $accountId = (int) $pdo->lastInsertId();
        $pdo->prepare("INSERT INTO subscriptions (public_id,account_id,plan_id,status,starts_at,current_period_starts_at,current_period_ends_at,created_at,updated_at) VALUES (:public,:account,:plan,'active',:now,:now,:ends,:now,:now)")
            ->execute(['public' => 'SUB-P14-' . strtoupper($token . '-' . $suffix), 'account' => $accountId, 'plan' => $planId, 'now' => $now, 'ends' => gmdate('Y-m-d H:i:s', time() + 2592000)]);
        $subscriptionId = (int) $pdo->lastInsertId();
        $label = 'phase14-' . $token . '-' . $suffix;
        $pdo->prepare("INSERT INTO domain_registrations (public_id,account_id,subscription_id,label,hostname,status,routing_status,ssl_status,registered_at,created_at,updated_at) VALUES (:public,:account,:subscription,:label,:hostname,'active','active','active',:now,:now,:now)")
            ->execute(['public' => 'DOM-P14-' . strtoupper($token . '-' . $suffix), 'account' => $accountId, 'subscription' => $subscriptionId, 'label' => $label, 'hostname' => $label . '.vp3.me', 'now' => $now]);
        $domainId = (int) $pdo->lastInsertId();
        $pdo->prepare("INSERT INTO entitlement_bundles (public_id,account_id,subscription_id,domain_registration_id,plan_id,snapshot_hash,created_at,updated_at) VALUES (:public,:account,:subscription,:domain,:plan,:hash,:now,:now)")
            ->execute(['public' => 'BUNDLE-P14-' . strtoupper($token . '-' . $suffix), 'account' => $accountId, 'subscription' => $subscriptionId, 'domain' => $domainId, 'plan' => $planId, 'hash' => hash('sha256', $suffix . $token), 'now' => $now]);
        $bundleId = (int) $pdo->lastInsertId();
        $licensePublicId = 'HSL-P14-' . strtoupper($token . '-' . $suffix);
        $pdo->prepare("INSERT INTO licenses (public_id,account_id,subscription_id,domain_registration_id,entitlement_bundle_id,product_type,status,starts_at,created_at,updated_at) VALUES (:public,:account,:subscription,:domain,:bundle,'homeserver','active',:now,:now,:now)")
            ->execute(['public' => $licensePublicId, 'account' => $accountId, 'subscription' => $subscriptionId, 'domain' => $domainId, 'bundle' => $bundleId, 'now' => $now]);
        return [
            'account' => $accountId,
            'subscription' => $subscriptionId,
            'domain' => $domainId,
            'license' => (int) $pdo->lastInsertId(),
            'license_public_id' => $licensePublicId,
            'hostname' => $label . '.vp3.me',
        ];
    };

    $occupied = $createLicense('occupied');
    $available = $createLicense('available');
    $other = $createLicense('other');
    $devicePublic = 'HS-P14-' . strtoupper($token);
    $pdo->prepare("INSERT INTO homeserver_devices (public_id,account_id,subscription_id,domain_registration_id,license_id,device_fingerprint,credential_hash,status,pairing_status,software_version,mcp_version,update_channel,frontend_limit,paired_frontend_count,last_heartbeat_at,paired_at,created_at,updated_at) VALUES (:public,:account,:subscription,:domain,:license,:fingerprint,:credential,'online','paired','14.0.0','1.0.0','stable',2,1,:now,:now,:now,:now)")
        ->execute(['public' => $devicePublic, 'account' => $occupied['account'], 'subscription' => $occupied['subscription'], 'domain' => $occupied['domain'], 'license' => $occupied['license'], 'fingerprint' => hash('sha256', 'device-' . $token), 'credential' => hash('sha256', 'credential-' . $token), 'now' => $now]);
    $deviceId = (int) $pdo->lastInsertId();
    $pdo->prepare("INSERT INTO homeserver_entitlement_leases (public_id,device_id,account_id,license_id,entitlement_snapshot_hash,document_hash,signature_hash,signing_key_id,status,issued_at,expires_at,created_at) VALUES (:public,:device,:account,:license,:snapshot,:document,:signature,'phase14-key','active',:now,:expires,:now)")
        ->execute(['public' => 'LEASE-P14-' . strtoupper($token), 'device' => $deviceId, 'account' => $occupied['account'], 'license' => $occupied['license'], 'snapshot' => hash('sha256', 'snapshot'), 'document' => hash('sha256', 'document'), 'signature' => hash('sha256', 'signature'), 'now' => $now, 'expires' => gmdate('Y-m-d H:i:s', time() + 3600)]);
    $pdo->prepare("INSERT INTO homeserver_update_receipts_v1 (public_id,account_id,device_id,release_id,request_id,update_id,disposition,created_at) VALUES (:public,:account,:device,NULL,:request,'UPDATE-P14','installed',:now)")
        ->execute(['public' => 'HSR-P14-' . strtoupper($token), 'account' => $occupied['account'], 'device' => $deviceId, 'request' => 'REQ-P14-' . strtoupper($token), 'now' => $now]);
    $pdo->prepare("INSERT INTO homeserver_control_plane_events (account_id,device_id,request_id,event_type,result,created_at) VALUES (:account,:device,:request,'heartbeat','success',:now)")
        ->execute(['account' => $occupied['account'], 'device' => $deviceId, 'request' => 'EVENT-P14-' . strtoupper($token), 'now' => $now]);

    $fleet = (new HomeServerFleetQueryService($database))->snapshot($occupied['account']);
    $assert($fleet['summary']['total'] === 1 && count($fleet['devices']) === 1, 'Fleet summary did not return exactly the owned device.');
    $assert($fleet['devices'][0]['device_public_id'] === $devicePublic, 'Fleet returned the wrong device.');
    $assert(($fleet['devices'][0]['lease']['status'] ?? null) === 'active', 'Fleet omitted current lease evidence.');
    $assert(($fleet['devices'][0]['last_update_receipt']['disposition'] ?? null) === 'installed', 'Fleet omitted update receipt evidence.');
    $assert($fleet['devices'][0]['event_count_24h'] === 1, 'Fleet event count is incorrect.');
    $assert(!array_key_exists('device_fingerprint', $fleet['devices'][0]), 'Fleet exposed the device fingerprint.');

    $options = (new HomeServerRegistrationOptionsService($database))->eligibleLicenses($available['account']);
    $optionPublicIds = array_column($options, 'license_public_id');
    $assert(in_array($available['license_public_id'], $optionPublicIds, true), 'Unused eligible HomeServer license was omitted.');
    $assert(!in_array($occupied['license_public_id'], $optionPublicIds, true), 'Occupied HomeServer license was offered for registration.');
    $assert(!in_array($other['license_public_id'], $optionPublicIds, true), 'Cross-account HomeServer license was offered.');
    foreach ($options as $option) {
        $assert(!array_key_exists('license_id', $option), 'Eligible license options expose an internal license ID.');
    }

    $otherFleet = (new HomeServerFleetQueryService($database))->snapshot($other['account']);
    $assert($otherFleet['summary']['total'] === 0, 'Cross-account fleet isolation failed.');
} catch (Throwable $exception) {
    $failures[] = $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, implode("\n", $failures) . "\n");
    exit(1);
}

echo "Phase 14 HomeServer fleet database integration passed.\n";

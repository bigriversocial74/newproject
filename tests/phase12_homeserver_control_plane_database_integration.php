<?php

declare(strict_types=1);

use Vp3\Database;
use Vp3\HomeServers\HomeServerControlPlaneService;
use Vp3\HomeServers\HomeServerLeaseSigner;
use Vp3\HomeServers\HomeServerRegistryService;
use Vp3\Releases\ReleaseCatalogService;
use Vp3\Releases\ReleaseManifestSigner;

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
$registry = new HomeServerRegistryService(
    $database,
    new HomeServerLeaseSigner(str_repeat('phase12-lease-key-', 3), 'phase12-lease-key'),
    900,
    3600
);
$control = new HomeServerControlPlaneService($database, $registry, 600, 1800);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

try {
    $token = strtolower(bin2hex(random_bytes(6)));
    $now = gmdate('Y-m-d H:i:s');
    $planId = (int) $pdo->query("SELECT id FROM plans WHERE code='standard' LIMIT 1")->fetchColumn();
    if ($planId < 1) {
        throw new RuntimeException('VP3 Standard plan seed is missing.');
    }

    $createAccountLicense = static function (string $suffix) use ($pdo, $token, $now, $planId): array {
        $pdo->prepare(
            "INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at)
             VALUES (:public,'individual','active',:name,:created,:updated)"
        )->execute([
            'public' => 'VP3-P12-' . strtoupper($token . '-' . $suffix),
            'name' => 'Phase 12 ' . strtoupper($suffix),
            'created' => $now,
            'updated' => $now,
        ]);
        $accountId = (int) $pdo->lastInsertId();
        $pdo->prepare(
            "INSERT INTO subscriptions
             (public_id,account_id,plan_id,status,provider,provider_customer_id,provider_subscription_id,
              starts_at,current_period_starts_at,current_period_ends_at,created_at,updated_at)
             VALUES (:public,:account,:plan,'active','stripe',:customer,:external,:starts,:period_start,:period_end,:created,:updated)"
        )->execute([
            'public' => 'SUB-P12-' . strtoupper($token . '-' . $suffix),
            'account' => $accountId,
            'plan' => $planId,
            'customer' => 'cus_p12_' . $token . '_' . $suffix,
            'external' => 'sub_p12_' . $token . '_' . $suffix,
            'starts' => $now,
            'period_start' => $now,
            'period_end' => gmdate('Y-m-d H:i:s', time() + 2592000),
            'created' => $now,
            'updated' => $now,
        ]);
        $subscriptionId = (int) $pdo->lastInsertId();
        $label = 'phase12-' . $token . '-' . $suffix;
        $pdo->prepare(
            "INSERT INTO domain_registrations
             (public_id,account_id,subscription_id,label,hostname,status,routing_status,ssl_status,registered_at,created_at,updated_at)
             VALUES (:public,:account,:subscription,:label,:hostname,'active','active','active',:registered,:created,:updated)"
        )->execute([
            'public' => 'DOM-P12-' . strtoupper($token . '-' . $suffix),
            'account' => $accountId,
            'subscription' => $subscriptionId,
            'label' => $label,
            'hostname' => $label . '.vp3.me',
            'registered' => $now,
            'created' => $now,
            'updated' => $now,
        ]);
        $domainId = (int) $pdo->lastInsertId();
        $pdo->prepare(
            'INSERT INTO entitlement_bundles
             (public_id,account_id,subscription_id,domain_registration_id,plan_id,snapshot_hash,created_at,updated_at)
             VALUES (:public,:account,:subscription,:domain,:plan,:snapshot,:created,:updated)'
        )->execute([
            'public' => 'BUNDLE-P12-' . strtoupper($token . '-' . $suffix),
            'account' => $accountId,
            'subscription' => $subscriptionId,
            'domain' => $domainId,
            'plan' => $planId,
            'snapshot' => hash('sha256', 'bundle-' . $token . '-' . $suffix),
            'created' => $now,
            'updated' => $now,
        ]);
        $bundleId = (int) $pdo->lastInsertId();
        $pdo->prepare(
            "INSERT INTO licenses
             (public_id,account_id,subscription_id,domain_registration_id,entitlement_bundle_id,product_type,status,starts_at,created_at,updated_at)
             VALUES (:public,:account,:subscription,:domain,:bundle,'homeserver','active',:starts,:created,:updated)"
        )->execute([
            'public' => 'HS-LIC-P12-' . strtoupper($token . '-' . $suffix),
            'account' => $accountId,
            'subscription' => $subscriptionId,
            'domain' => $domainId,
            'bundle' => $bundleId,
            'starts' => $now,
            'created' => $now,
            'updated' => $now,
        ]);
        $licenseId = (int) $pdo->lastInsertId();
        foreach ([
            ['update_channel', 'string', json_encode('stable', JSON_THROW_ON_ERROR)],
            ['mcp_client_limit', 'integer', json_encode(2, JSON_THROW_ON_ERROR)],
            ['homeserver_limit', 'integer', json_encode(1, JSON_THROW_ON_ERROR)],
            ['security_update_access', 'boolean', json_encode(true, JSON_THROW_ON_ERROR)],
        ] as [$key, $type, $value]) {
            $pdo->prepare(
                'INSERT INTO license_entitlements
                 (license_id,entitlement_key,value_type,value_json,source_plan_id,effective_at,created_at,updated_at)
                 VALUES (:license,:key,:type,:value,:plan,:effective,:created,:updated)'
            )->execute([
                'license' => $licenseId,
                'key' => $key,
                'type' => $type,
                'value' => $value,
                'plan' => $planId,
                'effective' => $now,
                'created' => $now,
                'updated' => $now,
            ]);
        }
        return compact('accountId', 'subscriptionId', 'domainId', 'licenseId');
    };

    $source = $createAccountLicense('source');
    $target = $createAccountLicense('target');
    $fingerprint = hash('sha256', 'phase12-device-' . $token);
    $registration = $control->registerDevice(
        $source['accountId'],
        $source['licenseId'],
        $fingerprint,
        'REQ-P12-REGISTER-' . strtoupper($token),
        'IDEM-P12-REGISTER-' . $token
    );
    $assert(is_string($registration['credential']) && is_string($registration['enrollment_code']), 'Registration did not issue one-time credentials.');
    $activation = $control->activateDevice(
        $source['accountId'],
        $registration['device_public_id'],
        (string) $registration['credential'],
        (string) $registration['enrollment_code'],
        'REQ-P12-ACTIVATE-' . strtoupper($token)
    );
    $assert($activation['status'] === 'paired' && isset($activation['lease']['signature']), 'Activation did not issue a signed entitlement lease.');

    $heartbeat = $control->heartbeat(
        $registration['device_public_id'],
        (string) $registration['credential'],
        $fingerprint,
        ['software_version' => '0.1.0', 'mcp_version' => '0.1.0', 'mcp_available' => true, 'pairing_available' => true],
        'REQ-P12-HEARTBEAT-' . strtoupper($token)
    );
    $assert($heartbeat['status'] === 'online' && $heartbeat['software_authority'] === 'vp3', 'VP3 heartbeat authority contract failed.');

    $keypair = sodium_crypto_sign_keypair();
    $manifestSigner = new ReleaseManifestSigner(
        base64_encode(sodium_crypto_sign_secretkey($keypair)),
        base64_encode(sodium_crypto_sign_publickey($keypair)),
        'phase12-release-key'
    );
    $catalog = new ReleaseCatalogService($database, $manifestSigner);
    $productId = (int) $pdo->query("SELECT id FROM software_products WHERE target_type='homeserver' LIMIT 1")->fetchColumn();
    if ($productId < 1) {
        $productId = $catalog->ensureProduct('homeserver', 'VP3 HomeServer', 'homeserver');
    }
    $version = '12.0.' . (string) random_int(1000, 9999);
    $draft = $catalog->createDraftRelease(
        $productId,
        $version,
        'stable',
        [[
            'platform' => 'windows',
            'architecture' => 'x86_64',
            'storage_reference' => 'homeserver/' . $version . '/VP3-HomeServer.exe',
            'sha256' => hash('sha256', 'phase12-installer-' . $token),
            'size_bytes' => 4096,
        ]],
        ['minimum_current_version' => '0.1.0', 'database_family' => 'any'],
        100,
        false,
        'Phase 12 certification release',
        'REQ-P12-RELEASE-' . strtoupper($token)
    );
    $published = $catalog->publishRelease($draft['release_id'], 'REQ-P12-PUBLISH-' . strtoupper($token));
    $assert($manifestSigner->verify($published['manifest'], $published['signature']), 'Published release manifest signature failed verification.');

    $available = $control->latestRelease(
        $registration['device_public_id'],
        (string) $registration['credential'],
        '0.1.0',
        'windows',
        'x86_64',
        'REQ-P12-MANIFEST-' . strtoupper($token)
    );
    $assert($available['available'] === true && $available['version'] === $version, 'Eligible signed release was not returned.');
    $grantToken = (string) $available['installer_authorization']['token'];
    for ($use = 0; $use < 3; $use++) {
        $artifact = $control->consumeInstallerGrant($grantToken);
        $assert($artifact['size_bytes'] === 4096, 'Installer grant did not resolve the expected artifact.');
    }
    $fourthUseRejected = false;
    try {
        $control->consumeInstallerGrant($grantToken);
    } catch (Throwable) {
        $fourthUseRejected = true;
    }
    $assert($fourthUseRejected, 'Consumed installer grant was accepted again.');

    $receipt = $control->recordUpdateReceipt(
        $registration['device_public_id'],
        (string) $registration['credential'],
        'REQ-P12-RECEIPT-' . strtoupper($token),
        'UPDATE-' . strtoupper($token),
        $available['release_public_id'],
        'installed',
        null,
        hash('sha256', 'receipt-' . $token),
        ['version' => $version]
    );
    $receiptReplay = $control->recordUpdateReceipt(
        $registration['device_public_id'],
        (string) $registration['credential'],
        'REQ-P12-RECEIPT-' . strtoupper($token),
        'UPDATE-' . strtoupper($token),
        $available['release_public_id'],
        'installed',
        null,
        hash('sha256', 'receipt-' . $token),
        ['version' => $version]
    );
    $assert($receipt['replayed'] === false && $receiptReplay['replayed'] === true, 'Update receipt idempotency failed.');

    $control->setSuspended($source['accountId'], $registration['device_public_id'], true, 'REQ-P12-SUSPEND-' . strtoupper($token));
    $suspendedRejected = false;
    try {
        $control->refreshLease($registration['device_public_id'], (string) $registration['credential'], 'REQ-P12-SUSPENDED-LEASE');
    } catch (Throwable) {
        $suspendedRejected = true;
    }
    $assert($suspendedRejected, 'Suspended device received an entitlement lease.');
    $control->setSuspended($source['accountId'], $registration['device_public_id'], false, 'REQ-P12-RESUME-' . strtoupper($token));

    $replacement = $control->replaceDevice(
        $source['accountId'],
        $registration['device_public_id'],
        hash('sha256', 'phase12-replacement-' . $token),
        'REQ-P12-REPLACE-' . strtoupper($token),
        'IDEM-P12-REPLACE-' . $token
    );
    $assert($replacement['previous_device_public_id'] === $registration['device_public_id'], 'Replacement did not preserve previous device identity evidence.');

    $transfer = $control->requestTransfer(
        $source['accountId'],
        $replacement['device_public_id'],
        $target['accountId'],
        'REQ-P12-TRANSFER-' . strtoupper($token)
    );
    $accepted = $control->acceptTransfer(
        $target['accountId'],
        $transfer['transfer_code'],
        $target['licenseId'],
        'REQ-P12-ACCEPT-' . strtoupper($token)
    );
    $assert($accepted['license_id'] === $target['licenseId'] && $accepted['credential'] !== '', 'Account-to-account device transfer failed.');

    $activeForSourceLicense = (int) $pdo->query(
        "SELECT COUNT(*) FROM homeserver_devices WHERE license_id={$source['licenseId']} AND status<>'revoked'"
    )->fetchColumn();
    $assert($activeForSourceLicense === 0, 'Source license retained an active device after transfer.');
    $plaintextGrantCount = (int) $pdo->query(
        "SELECT COUNT(*) FROM homeserver_installer_grants WHERE token_hash='" . addslashes($grantToken) . "'"
    )->fetchColumn();
    $assert($plaintextGrantCount === 0, 'Plaintext installer grant token was stored.');
} catch (Throwable $exception) {
    $failures[] = $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, implode("\n", $failures) . "\n");
    exit(1);
}

echo "Phase 12 HomeServer control-plane database integration passed.\n";

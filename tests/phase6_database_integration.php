<?php

declare(strict_types=1);

use Vp3\Database;
use Vp3\HomeServers\HomeServerLeaseSigner;
use Vp3\HomeServers\HomeServerRegistryService;

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
$signer = new HomeServerLeaseSigner(str_repeat('phase6-signing-key-', 3), 'phase6-test-key');
$service = new HomeServerRegistryService($database, $signer, 900, 3600);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

try {
    $token = strtolower(bin2hex(random_bytes(5)));
    $now = gmdate('Y-m-d H:i:s');
    $pdo->prepare(
        'INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at)
         VALUES (:public,\'individual\',\'active\',:name,:created,:updated)'
    )->execute([
        'public' => 'VP3-P6-' . strtoupper($token),
        'name' => 'Phase Six Account',
        'created' => $now,
        'updated' => $now,
    ]);
    $accountId = (int) $pdo->lastInsertId();
    $pdo->prepare(
        'INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at)
         VALUES (:public,\'individual\',\'active\',:name,:created,:updated)'
    )->execute([
        'public' => 'VP3-P6-X-' . strtoupper($token),
        'name' => 'Phase Six Other Account',
        'created' => $now,
        'updated' => $now,
    ]);
    $otherAccountId = (int) $pdo->lastInsertId();
    $planId = (int) $pdo->query("SELECT id FROM plans WHERE code='standard' LIMIT 1")->fetchColumn();
    if ($planId < 1) {
        throw new RuntimeException('Standard plan seed is missing.');
    }
    $pdo->prepare(
        'INSERT INTO subscriptions
         (public_id,account_id,plan_id,status,provider,provider_customer_id,provider_subscription_id,
          starts_at,current_period_starts_at,current_period_ends_at,created_at,updated_at)
         VALUES (:public,:account,:plan,\'active\',\'stripe\',:customer,:external,:starts,:period_start,:period_end,:created,:updated)'
    )->execute([
        'public' => 'SUB-P6-' . strtoupper($token),
        'account' => $accountId,
        'plan' => $planId,
        'customer' => 'cus_p6_' . $token,
        'external' => 'sub_p6_' . $token,
        'starts' => $now,
        'period_start' => $now,
        'period_end' => gmdate('Y-m-d H:i:s', time() + 2592000),
        'created' => $now,
        'updated' => $now,
    ]);
    $subscriptionId = (int) $pdo->lastInsertId();

    $createResources = static function (string $suffix, bool $withHomeServer) use (
        $pdo, $accountId, $subscriptionId, $planId, $now, $token
    ): array {
        $label = 'phase6-' . $token . '-' . $suffix;
        $pdo->prepare(
            'INSERT INTO domain_registrations
             (public_id,account_id,subscription_id,label,hostname,status,routing_status,ssl_status,registered_at,created_at,updated_at)
             VALUES (:public,:account,:subscription,:label,:hostname,\'active\',\'active\',\'active\',:registered,:created,:updated)'
        )->execute([
            'public' => 'DOM-P6-' . strtoupper($token . '-' . $suffix),
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
            'public' => 'BUNDLE-P6-' . strtoupper($token . '-' . $suffix),
            'account' => $accountId,
            'subscription' => $subscriptionId,
            'domain' => $domainId,
            'plan' => $planId,
            'snapshot' => hash('sha256', 'bundle-' . $token . '-' . $suffix),
            'created' => $now,
            'updated' => $now,
        ]);
        $bundleId = (int) $pdo->lastInsertId();
        $insertLicense = $pdo->prepare(
            'INSERT INTO licenses
             (public_id,account_id,subscription_id,domain_registration_id,entitlement_bundle_id,product_type,status,starts_at,created_at,updated_at)
             VALUES (:public,:account,:subscription,:domain,:bundle,:type,\'active\',:starts,:created,:updated)'
        );
        $insertLicense->execute([
            'public' => 'POD-LIC-P6-' . strtoupper($token . '-' . $suffix),
            'account' => $accountId,
            'subscription' => $subscriptionId,
            'domain' => $domainId,
            'bundle' => $bundleId,
            'type' => 'pod',
            'starts' => $now,
            'created' => $now,
            'updated' => $now,
        ]);
        $podLicenseId = (int) $pdo->lastInsertId();
        $pdo->prepare(
            'INSERT INTO pod_deployments
             (public_id,account_id,subscription_id,domain_registration_id,license_id,status,installation_fingerprint,
              installed_version,update_channel,storage_usage_bytes,storage_allowance_bytes,last_heartbeat_at,
              routing_status,ssl_status,backup_status,license_status,activated_at,created_at,updated_at)
             VALUES (:public,:account,:subscription,:domain,:license,\'active\',:fingerprint,\'6.0.0\',\'stable\',0,1073741824,
                     UTC_TIMESTAMP(),\'active\',\'active\',\'verified\',\'active\',UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())'
        )->execute([
            'public' => 'POD-P6-' . strtoupper($token . '-' . $suffix),
            'account' => $accountId,
            'subscription' => $subscriptionId,
            'domain' => $domainId,
            'license' => $podLicenseId,
            'fingerprint' => hash('sha256', 'pod-' . $token . '-' . $suffix),
        ]);
        $deploymentId = (int) $pdo->lastInsertId();
        $homeServerLicenseId = null;
        if ($withHomeServer) {
            $insertLicense->execute([
                'public' => 'HS-LIC-P6-' . strtoupper($token . '-' . $suffix),
                'account' => $accountId,
                'subscription' => $subscriptionId,
                'domain' => $domainId,
                'bundle' => $bundleId,
                'type' => 'homeserver',
                'starts' => $now,
                'created' => $now,
                'updated' => $now,
            ]);
            $homeServerLicenseId = (int) $pdo->lastInsertId();
            foreach ([
                ['update_channel', 'string', json_encode('stable', JSON_THROW_ON_ERROR)],
                ['mcp_client_limit', 'integer', json_encode(1, JSON_THROW_ON_ERROR)],
                ['homeserver_limit', 'integer', json_encode(1, JSON_THROW_ON_ERROR)],
                ['security_update_access', 'boolean', json_encode(true, JSON_THROW_ON_ERROR)],
            ] as [$key, $type, $value]) {
                $pdo->prepare(
                    'INSERT INTO license_entitlements
                     (license_id,entitlement_key,value_type,value_json,source_plan_id,effective_at,created_at,updated_at)
                     VALUES (:license,:key,:type,:value,:plan,:effective,:created,:updated)'
                )->execute([
                    'license' => $homeServerLicenseId,
                    'key' => $key,
                    'type' => $type,
                    'value' => $value,
                    'plan' => $planId,
                    'effective' => $now,
                    'created' => $now,
                    'updated' => $now,
                ]);
            }
        }
        return [
            'domain_id' => $domainId,
            'deployment_id' => $deploymentId,
            'pod_license_id' => $podLicenseId,
            'homeserver_license_id' => $homeServerLicenseId,
        ];
    };

    $primary = $createResources('a', true);
    $secondary = $createResources('b', false);
    $fingerprint = hash('sha256', 'homeserver-device-' . $token);
    $registration = $service->registerDevice(
        $accountId,
        (int) $primary['homeserver_license_id'],
        $fingerprint,
        'REQ-P6-REGISTER-' . strtoupper($token),
        'IDEM-P6-REGISTER-' . $token
    );
    $replay = $service->registerDevice(
        $accountId,
        (int) $primary['homeserver_license_id'],
        $fingerprint,
        'REQ-P6-REGISTER-REPLAY-' . strtoupper($token),
        'IDEM-P6-REGISTER-' . $token
    );
    $assert($registration['replayed'] === false && $replay['replayed'] === true, 'HomeServer device registration is not idempotent.');
    $assert($registration['credential'] !== null && $registration['enrollment_code'] !== null, 'One-time HomeServer enrollment secrets were not issued.');
    $assert($replay['credential'] === null && $replay['enrollment_code'] === null, 'One-time enrollment secrets were exposed on replay.');
    $device = $pdo->query('SELECT * FROM homeserver_devices WHERE id=' . $registration['device_id'])->fetch(PDO::FETCH_ASSOC);
    $assert(is_array($device) && $device['credential_hash'] === hash('sha256', (string) $registration['credential']), 'Device credential hash was not persisted correctly.');
    $assert($device['credential_hash'] !== $registration['credential'], 'Plaintext device credential was stored.');
    $receiptJson = (string) $pdo->query("SELECT response_json FROM homeserver_request_receipts WHERE operation='register_device' AND account_id={$accountId} LIMIT 1")->fetchColumn();
    $assert(!str_contains($receiptJson, (string) $registration['credential']) && !str_contains($receiptJson, (string) $registration['enrollment_code']), 'One-time enrollment secrets leaked into request receipts.');

    $service->activateDevice(
        $accountId,
        (string) $registration['device_public_id'],
        (string) $registration['credential'],
        (string) $registration['enrollment_code'],
        'REQ-P6-ACTIVATE-' . strtoupper($token)
    );
    $reusedCodeRejected = false;
    try {
        $service->activateDevice(
            $accountId,
            (string) $registration['device_public_id'],
            (string) $registration['credential'],
            (string) $registration['enrollment_code'],
            'REQ-P6-ACTIVATE-REPLAY'
        );
    } catch (Throwable) {
        $reusedCodeRejected = true;
    }
    $assert($reusedCodeRejected, 'Consumed enrollment code was accepted twice.');

    $pairingCode = $service->issueFrontendPairingCode(
        $accountId,
        (string) $registration['device_public_id'],
        (string) $registration['credential'],
        'REQ-P6-CODE-' . strtoupper($token)
    );
    $pair = $service->pairFrontend(
        $accountId,
        (string) $registration['device_public_id'],
        (int) $primary['deployment_id'],
        $pairingCode,
        ['knowledge.search', 'models.invoke', 'tools.execute'],
        'REQ-P6-PAIR-' . strtoupper($token),
        'IDEM-P6-PAIR-' . $token
    );
    $pairReplay = $service->pairFrontend(
        $accountId,
        (string) $registration['device_public_id'],
        (int) $primary['deployment_id'],
        'invalid-after-idempotent-completion',
        ['knowledge.search', 'models.invoke', 'tools.execute'],
        'REQ-P6-PAIR-REPLAY-' . strtoupper($token),
        'IDEM-P6-PAIR-' . $token
    );
    $assert($pair['replayed'] === false && $pairReplay['replayed'] === true, 'Frontend pairing idempotency failed.');
    $assert((int) $pdo->query('SELECT paired_frontend_count FROM homeserver_devices WHERE id=' . $registration['device_id'])->fetchColumn() === 1, 'Paired frontend count was not synchronized.');

    $secondCode = $service->issueFrontendPairingCode(
        $accountId,
        (string) $registration['device_public_id'],
        (string) $registration['credential'],
        'REQ-P6-CODE-SECOND-' . strtoupper($token)
    );
    $limitRejected = false;
    try {
        $service->pairFrontend(
            $accountId,
            (string) $registration['device_public_id'],
            (int) $secondary['deployment_id'],
            $secondCode,
            ['knowledge.search'],
            'REQ-P6-PAIR-SECOND-' . strtoupper($token),
            'IDEM-P6-PAIR-SECOND-' . $token
        );
    } catch (Throwable) {
        $limitRejected = true;
    }
    $assert($limitRejected, 'Licensed paired-front-end limit was not enforced.');

    $heartbeat = $service->heartbeat(
        $accountId,
        (string) $registration['device_public_id'],
        $fingerprint,
        (string) $registration['credential'],
        [
            'software_version' => '6.0.1',
            'mcp_version' => '2026.07',
            'mcp_available' => true,
            'pairing_available' => true,
        ],
        'REQ-P6-HEARTBEAT-' . strtoupper($token)
    );
    $assert($heartbeat['status'] === 'online', 'Healthy HomeServer heartbeat did not set online state.');
    $crossAccountRejected = false;
    try {
        $service->heartbeat(
            $otherAccountId,
            (string) $registration['device_public_id'],
            $fingerprint,
            (string) $registration['credential'],
            [],
            'REQ-P6-CROSS-ACCOUNT'
        );
    } catch (Throwable) {
        $crossAccountRejected = true;
    }
    $assert($crossAccountRejected, 'Cross-account HomeServer heartbeat was accepted.');

    $lease = $service->issueEntitlementLease(
        $accountId,
        (string) $registration['device_public_id'],
        (string) $registration['credential'],
        'REQ-P6-LEASE-' . strtoupper($token)
    );
    $assert($signer->verify($lease['document'], $lease['signature']), 'Signed HomeServer entitlement lease failed verification.');
    $assert((int) $pdo->query('SELECT COUNT(*) FROM homeserver_entitlement_leases WHERE device_id=' . $registration['device_id'] . " AND status='active'")->fetchColumn() === 1, 'Active entitlement lease was not recorded.');
    $leaseColumns = (int) $pdo->query(
        "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()
         AND TABLE_NAME='homeserver_entitlement_leases' AND COLUMN_NAME IN ('document','signature','document_json','claims_json')"
    )->fetchColumn();
    $assert($leaseColumns === 0, 'Signed lease payload or signature was persisted instead of hashes.');

    $rotation = $service->rotateCredential(
        $accountId,
        (string) $registration['device_public_id'],
        (string) $registration['credential'],
        'scheduled_rotation',
        'REQ-P6-ROTATE-' . strtoupper($token)
    );
    $oldRejected = false;
    try {
        $service->heartbeat(
            $accountId,
            (string) $registration['device_public_id'],
            $fingerprint,
            (string) $registration['credential'],
            [],
            'REQ-P6-OLD-CREDENTIAL'
        );
    } catch (Throwable) {
        $oldRejected = true;
    }
    $assert($oldRejected, 'Rotated HomeServer credential remained valid.');
    $service->heartbeat(
        $accountId,
        (string) $registration['device_public_id'],
        $fingerprint,
        $rotation['credential'],
        ['software_version' => '6.0.2', 'mcp_version' => '2026.07', 'mcp_available' => false, 'pairing_available' => true],
        'REQ-P6-DEGRADED-' . strtoupper($token)
    );
    $assert($pdo->query('SELECT status FROM homeserver_devices WHERE id=' . $registration['device_id'])->fetchColumn() === 'degraded', 'Degraded HomeServer metadata was not reflected.');

    $service->unpairFrontend(
        $accountId,
        (string) $registration['device_public_id'],
        (int) $primary['deployment_id'],
        'REQ-P6-UNPAIR-' . strtoupper($token)
    );
    $service->pairFrontend(
        $accountId,
        (string) $registration['device_public_id'],
        (int) $secondary['deployment_id'],
        $secondCode,
        ['knowledge.search'],
        'REQ-P6-PAIR-SECOND-RETRY-' . strtoupper($token),
        'IDEM-P6-PAIR-SECOND-RETRY-' . $token
    );
    $assert((int) $pdo->query('SELECT paired_frontend_count FROM homeserver_devices WHERE id=' . $registration['device_id'])->fetchColumn() === 1, 'Frontend count was not correct after unpair and re-pair.');

    $pdo->exec('UPDATE homeserver_devices SET last_heartbeat_at=DATE_SUB(UTC_TIMESTAMP(),INTERVAL 30 MINUTE),status=\'online\' WHERE id=' . $registration['device_id']);
    $assert($service->markOffline(10) >= 1, 'Stale HomeServer was not marked offline.');
    $assert($pdo->query('SELECT status FROM homeserver_devices WHERE id=' . $registration['device_id'])->fetchColumn() === 'offline', 'Offline state was not persisted.');

    $service->revokeDevice(
        $accountId,
        (string) $registration['device_public_id'],
        'REQ-P6-REVOKE-' . strtoupper($token)
    );
    $state = $pdo->query('SELECT status,pairing_status,paired_frontend_count FROM homeserver_devices WHERE id=' . $registration['device_id'])->fetch(PDO::FETCH_ASSOC);
    $assert(is_array($state) && $state['status'] === 'revoked' && $state['pairing_status'] === 'revoked' && (int) $state['paired_frontend_count'] === 0, 'Device revocation did not close the full lifecycle.');
    $assert((int) $pdo->query("SELECT COUNT(*) FROM homeserver_entitlement_leases WHERE device_id={$registration['device_id']} AND status='active'")->fetchColumn() === 0, 'Active leases remained after device revocation.');
    $assert((int) $pdo->query("SELECT COUNT(*) FROM homeserver_frontend_pairs WHERE device_id={$registration['device_id']} AND status='active'")->fetchColumn() === 0, 'Active frontend pairs remained after device revocation.');

    $forbiddenColumns = (int) $pdo->query(
        "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()
         AND TABLE_NAME LIKE 'homeserver_%'
         AND (COLUMN_NAME LIKE '%knowledge%' OR COLUMN_NAME LIKE '%prompt%' OR COLUMN_NAME LIKE '%conversation%'
              OR COLUMN_NAME LIKE '%model_blob%' OR COLUMN_NAME LIKE '%tool_credential%' OR COLUMN_NAME LIKE '%private_file%'
              OR COLUMN_NAME LIKE '%mcp_payload%' OR COLUMN_NAME LIKE '%plaintext%')"
    )->fetchColumn();
    $assert($forbiddenColumns === 0, 'HomeServer private content columns exist in the VP3 control database.');
} catch (Throwable $exception) {
    $failures[] = 'Unhandled Phase 6 integration exception: ' . $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 6 database certification failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 6 HomeServer database lifecycle certification passed.\n");

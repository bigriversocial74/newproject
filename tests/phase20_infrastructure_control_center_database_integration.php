<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\Database;
use Vp3\Infrastructure\InfrastructureControlCenterActionService;
use Vp3\Infrastructure\InfrastructureControlCenterQueryService;
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
$expectCode = static function (callable $operation, string $code, string $message) use (&$failures): void {
    try {
        $operation();
        $failures[] = $message . ' No exception was raised.';
    } catch (AuthPublicException $exception) {
        if ($exception->publicCode() !== $code) {
            $failures[] = $message . ' Received ' . $exception->publicCode() . '.';
        }
    }
};

try {
    $token = strtoupper(bin2hex(random_bytes(5)));
    $now = gmdate('Y-m-d H:i:s');
    $periodEnd = gmdate('Y-m-d H:i:s', time() + 2592000);
    $passwordHash = password_hash('Phase20-Infrastructure!42', PASSWORD_DEFAULT);
    if (!is_string($passwordHash)) {
        throw new RuntimeException('Unable to hash Phase 20 password.');
    }
    $planId = (int) $pdo->query("SELECT id FROM plans WHERE code='standard' LIMIT 1")->fetchColumn();
    if ($planId < 1) {
        throw new RuntimeException('VP3 Standard plan seed is missing.');
    }

    $createAccount = static function (string $suffix) use ($pdo, $token, $now): int {
        $pdo->prepare(
            "INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at)
             VALUES (:public,'organization','active',:name,:created,:updated)"
        )->execute([
            'public' => 'VP3-P20-' . $token . '-' . $suffix,
            'name' => 'Phase 20 ' . $suffix,
            'created' => $now,
            'updated' => $now,
        ]);
        return (int) $pdo->lastInsertId();
    };

    $createUser = static function (string $suffix) use ($pdo, $token, $now, $passwordHash): array {
        $email = strtolower('phase20-' . $token . '-' . $suffix . '@example.test');
        $publicId = 'USER-P20-' . $token . '-' . strtoupper($suffix);
        $pdo->prepare(
            "INSERT INTO users
             (public_id,email,email_normalized,password_hash,display_name,status,email_verified_at,created_at,updated_at)
             VALUES (:public,:email,:normalized,:password,:name,'active',:verified,:created,:updated)"
        )->execute([
            'public' => $publicId,
            'email' => $email,
            'normalized' => $email,
            'password' => $passwordHash,
            'name' => 'Phase 20 ' . $suffix,
            'verified' => $now,
            'created' => $now,
            'updated' => $now,
        ]);
        return ['id' => (int) $pdo->lastInsertId(), 'public_id' => $publicId];
    };

    $membership = static function (int $accountId, int $userId, string $role) use ($pdo, $now): void {
        $pdo->prepare(
            "INSERT INTO account_users (account_id,user_id,role,status,created_at,updated_at)
             VALUES (:account,:user,:role,'active',:created,:updated)"
        )->execute([
            'account' => $accountId,
            'user' => $userId,
            'role' => $role,
            'created' => $now,
            'updated' => $now,
        ]);
    };

    $createPod = static function (int $accountId, string $suffix) use ($pdo, $token, $now, $periodEnd, $planId): array {
        $upper = $token . '-' . strtoupper($suffix);
        $pdo->prepare(
            "INSERT INTO subscriptions
             (public_id,account_id,plan_id,status,provider,provider_customer_id,provider_subscription_id,
              starts_at,current_period_starts_at,current_period_ends_at,created_at,updated_at)
             VALUES
             (:public,:account,:plan,'active','stripe',:customer,:subscription,:starts,:period_start,
              :period_end,:created,:updated)"
        )->execute([
            'public' => 'SUB-P20-' . $upper,
            'account' => $accountId,
            'plan' => $planId,
            'customer' => 'cus_p20_' . strtolower($upper),
            'subscription' => 'sub_p20_' . strtolower($upper),
            'starts' => $now,
            'period_start' => $now,
            'period_end' => $periodEnd,
            'created' => $now,
            'updated' => $now,
        ]);
        $subscriptionId = (int) $pdo->lastInsertId();

        $label = 'phase20-' . strtolower($token) . '-' . strtolower($suffix);
        $hostname = $label . '.vp3.me';
        $domainPublicId = 'DOM-P20-' . $upper;
        $pdo->prepare(
            "INSERT INTO domain_registrations
             (public_id,account_id,subscription_id,label,hostname,status,routing_status,ssl_status,
              registered_at,renews_at,expires_at,created_at,updated_at)
             VALUES
             (:public,:account,:subscription,:label,:hostname,'active','pending','pending',
              :registered,:renews,:expires,:created,:updated)"
        )->execute([
            'public' => $domainPublicId,
            'account' => $accountId,
            'subscription' => $subscriptionId,
            'label' => $label,
            'hostname' => $hostname,
            'registered' => $now,
            'renews' => $periodEnd,
            'expires' => $periodEnd,
            'created' => $now,
            'updated' => $now,
        ]);
        $domainId = (int) $pdo->lastInsertId();

        $pdo->prepare(
            "INSERT INTO entitlement_bundles
             (public_id,account_id,subscription_id,domain_registration_id,plan_id,snapshot_hash,created_at,updated_at)
             VALUES (:public,:account,:subscription,:domain,:plan,:hash,:created,:updated)"
        )->execute([
            'public' => 'BUNDLE-P20-' . $upper,
            'account' => $accountId,
            'subscription' => $subscriptionId,
            'domain' => $domainId,
            'plan' => $planId,
            'hash' => hash('sha256', 'phase20-bundle-' . $upper),
            'created' => $now,
            'updated' => $now,
        ]);
        $bundleId = (int) $pdo->lastInsertId();

        $pdo->prepare(
            "INSERT INTO licenses
             (public_id,account_id,subscription_id,domain_registration_id,entitlement_bundle_id,
              product_type,status,starts_at,renews_at,expires_at,created_at,updated_at)
             VALUES
             (:public,:account,:subscription,:domain,:bundle,'pod','active',:starts,:renews,:expires,
              :created,:updated)"
        )->execute([
            'public' => 'POD-LIC-P20-' . $upper,
            'account' => $accountId,
            'subscription' => $subscriptionId,
            'domain' => $domainId,
            'bundle' => $bundleId,
            'starts' => $now,
            'renews' => $periodEnd,
            'expires' => $periodEnd,
            'created' => $now,
            'updated' => $now,
        ]);
        $licenseId = (int) $pdo->lastInsertId();

        $podPublicId = 'POD-P20-' . $upper;
        $pdo->prepare(
            "INSERT INTO pod_deployments
             (public_id,account_id,subscription_id,domain_registration_id,license_id,status,
              installation_fingerprint,installed_version,update_channel,storage_usage_bytes,
              storage_allowance_bytes,last_heartbeat_at,routing_status,ssl_status,backup_status,
              license_status,created_at,updated_at)
             VALUES
             (:public,:account,:subscription,:domain,:license,'pending',:fingerprint,'20.0.0','stable',
              0,1073741824,UTC_TIMESTAMP(),'pending','pending','verified','active',UTC_TIMESTAMP(),UTC_TIMESTAMP())"
        )->execute([
            'public' => $podPublicId,
            'account' => $accountId,
            'subscription' => $subscriptionId,
            'domain' => $domainId,
            'license' => $licenseId,
            'fingerprint' => hash('sha256', 'phase20-pod-' . $upper),
        ]);

        return [
            'id' => (int) $pdo->lastInsertId(),
            'public_id' => $podPublicId,
            'hostname' => $hostname,
        ];
    };

    $accountA = $createAccount('ALPHA');
    $accountB = $createAccount('BRAVO');
    $ownerA = $createUser('OWNER-A');
    $supportA = $createUser('SUPPORT-A');
    $ownerB = $createUser('OWNER-B');
    $membership($accountA, $ownerA['id'], 'customer_owner');
    $membership($accountA, $supportA['id'], 'support_member');
    $membership($accountB, $ownerB['id'], 'customer_owner');
    $podA = $createPod($accountA, 'ALPHA');
    $podB = $createPod($accountB, 'BRAVO');

    $key = base64_encode(random_bytes(32));
    $cipher = new ProviderSecretCipher($key, 'phase20-test-key');
    $actions = new InfrastructureControlCenterActionService($database, $cipher);
    $query = new InfrastructureControlCenterQueryService($database);
    $secret = ['token' => 'phase20-provider-secret', 'account' => 'provider-production'];

    $hosting = $actions->saveConnection(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        'hosting',
        'phase20-hosting',
        'Phase 20 Hosting',
        $secret,
        'REQ-P20-HOSTING-' . $token
    );
    $dns = $actions->saveConnection(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        'dns',
        'phase20-dns',
        'Phase 20 DNS',
        $secret,
        'REQ-P20-DNS-' . $token
    );
    $certificate = $actions->saveConnection(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        'certificate',
        'phase20-certificate',
        'Phase 20 Certificates',
        $secret,
        'REQ-P20-CERT-' . $token
    );
    $rotated = $actions->saveConnection(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        'hosting',
        'phase20-hosting',
        'Phase 20 Hosting Rotated',
        $secret,
        'REQ-P20-HOSTING2-' . $token
    );
    $assert($rotated['public_id'] === $hosting['public_id'] && $rotated['credential_version'] === 2 && $rotated['rotated'] === true,
        'Provider rotation did not preserve public identity and increment the credential version.');

    $stored = $pdo->prepare('SELECT * FROM provider_connections WHERE public_id=:public AND account_id=:account');
    $stored->execute(['public' => $hosting['public_id'], 'account' => $accountA]);
    $storedConnection = $stored->fetch(PDO::FETCH_ASSOC);
    $assert(is_array($storedConnection), 'Encrypted provider connection did not persist.');
    if (is_array($storedConnection)) {
        $assert(!str_contains((string) $storedConnection['credentials_ciphertext'], 'phase20-provider-secret'),
            'Plaintext provider credentials leaked into ciphertext storage.');
        $plaintext = $cipher->decrypt(
            (string) $storedConnection['credentials_ciphertext'],
            (string) $storedConnection['credentials_nonce'],
            (string) $storedConnection['credentials_tag'],
            'provider-connection|' . $accountA . '|hosting|phase20-hosting|2'
        );
        $assert(str_contains($plaintext, 'phase20-provider-secret'), 'Rotated provider credentials cannot be authenticated and decrypted.');
    }

    $expectCode(
        fn () => $actions->saveConnection(
            $accountA,
            $supportA['id'],
            'support_member',
            'dns',
            'denied-provider',
            'Denied Provider',
            $secret,
            'REQ-P20-DENIED-' . $token
        ),
        'infrastructure_permission_denied',
        'Support member provider credential mutation was accepted.'
    );
    $deniedReceipt = $pdo->prepare(
        "SELECT COUNT(*) FROM provider_receipts
         WHERE account_id=:account AND request_id=:request AND result='denied'"
    );
    $deniedReceipt->execute(['account' => $accountA, 'request' => 'REQ-P20-DENIED-' . $token]);
    $assert((int) $deniedReceipt->fetchColumn() === 1, 'Denied infrastructure action did not persist a provider receipt.');
    $deniedAudit = $pdo->prepare(
        "SELECT COUNT(*) FROM audit_events
         WHERE account_id=:account AND actor_id=:actor AND request_id=:request AND result='denied'"
    );
    $deniedAudit->execute([
        'account' => $accountA,
        'actor' => $supportA['id'],
        'request' => 'REQ-P20-DENIED-' . $token,
    ]);
    $assert((int) $deniedAudit->fetchColumn() === 1, 'Denied infrastructure action did not persist audit evidence.');

    $provision = $actions->enqueueProvision(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        $podA['public_id'],
        $hosting['public_id'],
        $dns['public_id'],
        $certificate['public_id'],
        'REQ-P20-PROVISION-' . $token,
        'IDEM-P20-PROVISION-' . $token
    );
    $replay = $actions->enqueueProvision(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        $podA['public_id'],
        $hosting['public_id'],
        $dns['public_id'],
        $certificate['public_id'],
        'REQ-P20-PROVISION2-' . $token,
        'IDEM-P20-PROVISION-' . $token
    );
    $assert($provision['replayed'] === false && $replay['replayed'] === true && $replay['public_id'] === $provision['public_id'],
        'Infrastructure provision queue is not replay-safe.');

    $operationId = (int) $pdo->query(
        "SELECT id FROM provider_operations WHERE public_id=" . $pdo->quote($provision['public_id'])
    )->fetchColumn();
    $assert($operationId > 0, 'Provision operation did not persist.');
    $assert((int) $pdo->query("SELECT COUNT(*) FROM provider_operation_steps WHERE operation_id={$operationId}")->fetchColumn() === 5,
        'Provision operation does not contain the complete five-stage pipeline.');

    $expectCode(
        fn () => $actions->enqueueProvision(
            $accountA,
            $ownerA['id'],
            'customer_owner',
            $podB['public_id'],
            $hosting['public_id'],
            $dns['public_id'],
            $certificate['public_id'],
            'REQ-P20-CROSS-' . $token,
            'IDEM-P20-CROSS-' . $token
        ),
        'infrastructure_pod_not_found',
        'Cross-account POD provisioning was accepted.'
    );

    $reconcile = $actions->enqueueBindingOperation(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        $provision['binding_public_id'],
        'reconcile',
        '',
        'REQ-P20-RECONCILE-' . $token,
        'IDEM-P20-RECONCILE-' . $token
    );
    $reconcileId = (int) $pdo->query(
        "SELECT id FROM provider_operations WHERE public_id=" . $pdo->quote($reconcile['public_id'])
    )->fetchColumn();
    $assert((int) $pdo->query("SELECT COUNT(*) FROM provider_operation_steps WHERE operation_id={$reconcileId}")->fetchColumn() === 4,
        'Reconcile operation does not contain the complete four-stage pipeline.');

    $paused = $actions->transitionOperation(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        $reconcile['public_id'],
        'pause',
        'REQ-P20-PAUSE-' . $token
    );
    $resumed = $actions->transitionOperation(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        $reconcile['public_id'],
        'resume',
        'REQ-P20-RESUME-' . $token
    );
    $assert($paused['status'] === 'paused' && $resumed['status'] === 'queued',
        'Infrastructure pause/resume transitions are incorrect.');

    $expectCode(
        fn () => $actions->enqueueBindingOperation(
            $accountA,
            $ownerA['id'],
            'customer_owner',
            $provision['binding_public_id'],
            'teardown',
            'DELETE',
            'REQ-P20-TEARDOWN-BAD-' . $token,
            'IDEM-P20-TEARDOWN-BAD-' . $token
        ),
        'infrastructure_teardown_confirmation_required',
        'Infrastructure teardown accepted an incorrect confirmation.'
    );
    $teardown = $actions->enqueueBindingOperation(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        $provision['binding_public_id'],
        'teardown',
        'TEARDOWN',
        'REQ-P20-TEARDOWN-' . $token,
        'IDEM-P20-TEARDOWN-' . $token
    );
    $teardownId = (int) $pdo->query(
        "SELECT id FROM provider_operations WHERE public_id=" . $pdo->quote($teardown['public_id'])
    )->fetchColumn();
    $assert((int) $pdo->query("SELECT COUNT(*) FROM provider_operation_steps WHERE operation_id={$teardownId}")->fetchColumn() === 4,
        'Teardown operation does not contain the reverse-dependency four-stage pipeline.');

    $expectCode(
        fn () => $actions->revokeConnection(
            $accountA,
            $ownerA['id'],
            'customer_owner',
            $hosting['public_id'],
            'REQ-P20-REVOKE-INUSE-' . $token
        ),
        'infrastructure_connection_in_use',
        'An in-use provider connection was revoked.'
    );

    $snapshotA = $query->snapshot($accountA);
    $snapshotB = $query->snapshot($accountB);
    $assert($snapshotA['metrics']['connections_active'] === 3, 'Infrastructure metrics omitted active provider connections.');
    $assert(count($snapshotA['bindings']) === 1 && $snapshotA['bindings'][0]['public_id'] === $provision['binding_public_id'],
        'Infrastructure snapshot omitted the account binding.');
    $assert(count($snapshotA['operations']) === 3, 'Infrastructure snapshot omitted queued operations.');
    $assert(count($snapshotB['connections']) === 0 && count($snapshotB['bindings']) === 0 && count($snapshotB['operations']) === 0,
        'Cross-account infrastructure data leaked into another account.');

    $snapshotJson = json_encode($snapshotA, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    $assert(!str_contains($snapshotJson, 'phase20-provider-secret'), 'Provider credentials leaked into the customer snapshot.');
    $assert(!str_contains($snapshotJson, 'credentials_ciphertext'), 'Encrypted provider credentials leaked into the customer snapshot.');
    $assert(!str_contains($snapshotJson, 'provider_reference'), 'Provider resource references leaked into the customer snapshot.');
    $assert(!str_contains($snapshotJson, 'lease_token'), 'Worker lease data leaked into the customer snapshot.');
    $assert(!str_contains($snapshotJson, 'last_error_message'), 'Raw provider errors leaked into the customer snapshot.');

    $bindingId = (int) $pdo->query(
        "SELECT id FROM infrastructure_bindings WHERE public_id=" . $pdo->quote($provision['binding_public_id'])
    )->fetchColumn();
    $pdo->prepare("UPDATE infrastructure_bindings SET status='disabled',disabled_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP() WHERE id=:id")
        ->execute(['id' => $bindingId]);
    $revoked = $actions->revokeConnection(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        $hosting['public_id'],
        'REQ-P20-REVOKE-' . $token
    );
    $assert($revoked['status'] === 'revoked', 'Unused provider connection revocation did not complete.');

    $forbiddenColumns = (int) $pdo->query(
        "SELECT COUNT(*)
         FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA=DATABASE()
           AND (TABLE_NAME LIKE 'provider_%' OR TABLE_NAME IN ('hosting_allocations','dns_bindings','certificate_orders'))
           AND (COLUMN_NAME LIKE '%plaintext%' OR COLUMN_NAME IN ('credentials','api_secret','provider_reference'))"
    )->fetchColumn();
    $assert($forbiddenColumns === 0, 'Plaintext provider credential or resource-reference columns exist.');
} catch (Throwable $exception) {
    $failures[] = 'Unhandled Phase 20 database integration exception: ' . $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 20 Infrastructure Control Center database failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 20 Infrastructure Control Center database certification passed.\n");

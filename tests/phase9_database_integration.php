<?php

declare(strict_types=1);

use Vp3\Database;
use Vp3\Infrastructure\CertificateProviderAdapter;
use Vp3\Infrastructure\DnsProviderAdapter;
use Vp3\Infrastructure\HostingProviderAdapter;
use Vp3\Infrastructure\InfrastructureProviderService;
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

final class Phase9InfrastructureAdapter implements HostingProviderAdapter, DnsProviderAdapter, CertificateProviderAdapter
{
    public bool $dnsVerified = true;
    /** @var list<string> */
    public array $calls = [];

    public function allocateHosting(array $authContext, array $deployment): array
    {
        $this->calls[] = 'hosting_allocate';
        $this->assertAuth($authContext);
        return [
            'provider_reference' => 'host-ref-' . $deployment['public_id'],
            'endpoint' => '203.0.113.42',
            'region' => 'us-test-1',
            'service_plan' => 'vp3-standard',
        ];
    }

    public function verifyHosting(array $authContext, string $providerReference): array
    {
        $this->calls[] = 'hosting_verify';
        $this->assertAuth($authContext);
        return ['verified' => str_starts_with($providerReference, 'host-ref-')];
    }

    public function releaseHosting(array $authContext, string $providerReference): array
    {
        $this->calls[] = 'hosting_release';
        $this->assertAuth($authContext);
        return ['released' => str_starts_with($providerReference, 'host-ref-')];
    }

    public function upsertRecord(array $authContext, string $hostname, string $recordType, string $recordValue): array
    {
        $this->calls[] = 'dns_bind';
        $this->assertAuth($authContext);
        return ['provider_reference' => 'dns-ref-' . hash('sha256', $hostname . '|' . $recordType . '|' . $recordValue)];
    }

    public function verifyRecord(array $authContext, string $providerReference, string $hostname, string $recordType, string $recordValue): array
    {
        $this->calls[] = 'dns_verify';
        $this->assertAuth($authContext);
        return ['verified' => $this->dnsVerified && str_starts_with($providerReference, 'dns-ref-')];
    }

    public function removeRecord(array $authContext, string $providerReference): array
    {
        $this->calls[] = 'dns_remove';
        $this->assertAuth($authContext);
        return ['removed' => str_starts_with($providerReference, 'dns-ref-')];
    }

    public function requestCertificate(array $authContext, string $hostname): array
    {
        $this->calls[] = 'certificate_request';
        $this->assertAuth($authContext);
        return [
            'provider_reference' => 'cert-ref-' . hash('sha256', $hostname),
            'expires_at' => gmdate('Y-m-d H:i:s', time() + 7776000),
        ];
    }

    public function verifyCertificate(array $authContext, string $providerReference, string $hostname): array
    {
        $this->calls[] = 'certificate_verify';
        $this->assertAuth($authContext);
        return ['verified' => str_starts_with($providerReference, 'cert-ref-')];
    }

    public function revokeCertificate(array $authContext, string $providerReference): array
    {
        $this->calls[] = 'certificate_revoke';
        $this->assertAuth($authContext);
        return ['revoked' => str_starts_with($providerReference, 'cert-ref-')];
    }

    /** @param array<string,mixed> $authContext */
    private function assertAuth(array $authContext): void
    {
        if (($authContext['token'] ?? null) !== 'phase9-provider-secret') {
            throw new RuntimeException('Provider authentication context was not decrypted correctly.');
        }
    }
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
$cipher = new ProviderSecretCipher(base64_encode(random_bytes(32)), 'phase9-test-key');
$adapter = new Phase9InfrastructureAdapter();
$service = new InfrastructureProviderService($database, $cipher, $adapter, $adapter, $adapter);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

try {
    $token = strtolower(bin2hex(random_bytes(5)));
    $now = gmdate('Y-m-d H:i:s');
    $insertAccount = $pdo->prepare("INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at) VALUES (:public,'individual','active',:name,:created,:updated)");
    $insertAccount->execute(['public' => 'VP3-P9-' . strtoupper($token), 'name' => 'Phase Nine Account', 'created' => $now, 'updated' => $now]);
    $accountId = (int) $pdo->lastInsertId();
    $insertAccount->execute(['public' => 'VP3-P9-X-' . strtoupper($token), 'name' => 'Phase Nine Other', 'created' => $now, 'updated' => $now]);
    $otherAccountId = (int) $pdo->lastInsertId();
    $planId = (int) $pdo->query("SELECT id FROM plans WHERE code='standard' LIMIT 1")->fetchColumn();
    $pdo->prepare(
        "INSERT INTO subscriptions (public_id,account_id,plan_id,status,provider,provider_customer_id,provider_subscription_id,starts_at,current_period_starts_at,current_period_ends_at,created_at,updated_at)
         VALUES (:public,:account,:plan,'active','stripe',:customer,:external,:starts,:period_start,:period_end,:created,:updated)"
    )->execute([
        'public' => 'SUB-P9-' . strtoupper($token), 'account' => $accountId, 'plan' => $planId,
        'customer' => 'cus_p9_' . $token, 'external' => 'sub_p9_' . $token,
        'starts' => $now, 'period_start' => $now, 'period_end' => gmdate('Y-m-d H:i:s', time() + 2592000),
        'created' => $now, 'updated' => $now,
    ]);
    $subscriptionId = (int) $pdo->lastInsertId();
    $label = 'phase9-' . $token;
    $hostname = $label . '.vp3.me';
    $pdo->prepare(
        "INSERT INTO domain_registrations (public_id,account_id,subscription_id,label,hostname,status,routing_status,ssl_status,registered_at,created_at,updated_at)
         VALUES (:public,:account,:subscription,:label,:hostname,'active','pending','pending',:registered,:created,:updated)"
    )->execute([
        'public' => 'DOM-P9-' . strtoupper($token), 'account' => $accountId, 'subscription' => $subscriptionId,
        'label' => $label, 'hostname' => $hostname, 'registered' => $now, 'created' => $now, 'updated' => $now,
    ]);
    $domainId = (int) $pdo->lastInsertId();
    $pdo->prepare(
        'INSERT INTO entitlement_bundles (public_id,account_id,subscription_id,domain_registration_id,plan_id,snapshot_hash,created_at,updated_at)
         VALUES (:public,:account,:subscription,:domain,:plan,:snapshot,:created,:updated)'
    )->execute([
        'public' => 'BUNDLE-P9-' . strtoupper($token), 'account' => $accountId, 'subscription' => $subscriptionId,
        'domain' => $domainId, 'plan' => $planId, 'snapshot' => hash('sha256', 'bundle-' . $token),
        'created' => $now, 'updated' => $now,
    ]);
    $bundleId = (int) $pdo->lastInsertId();
    $pdo->prepare(
        "INSERT INTO licenses (public_id,account_id,subscription_id,domain_registration_id,entitlement_bundle_id,product_type,status,starts_at,created_at,updated_at)
         VALUES (:public,:account,:subscription,:domain,:bundle,'pod','active',:starts,:created,:updated)"
    )->execute([
        'public' => 'POD-LIC-P9-' . strtoupper($token), 'account' => $accountId, 'subscription' => $subscriptionId,
        'domain' => $domainId, 'bundle' => $bundleId, 'starts' => $now, 'created' => $now, 'updated' => $now,
    ]);
    $licenseId = (int) $pdo->lastInsertId();
    $pdo->prepare(
        "INSERT INTO pod_deployments (public_id,account_id,subscription_id,domain_registration_id,license_id,status,installation_fingerprint,installed_version,update_channel,storage_usage_bytes,storage_allowance_bytes,last_heartbeat_at,routing_status,ssl_status,backup_status,license_status,created_at,updated_at)
         VALUES (:public,:account,:subscription,:domain,:license,'pending',:fingerprint,'9.0.0','stable',0,1073741824,UTC_TIMESTAMP(),'pending','pending','verified','active',UTC_TIMESTAMP(),UTC_TIMESTAMP())"
    )->execute([
        'public' => 'POD-P9-' . strtoupper($token), 'account' => $accountId, 'subscription' => $subscriptionId,
        'domain' => $domainId, 'license' => $licenseId, 'fingerprint' => hash('sha256', 'pod-' . $token),
    ]);
    $deploymentId = (int) $pdo->lastInsertId();

    $secret = ['token' => 'phase9-provider-secret', 'account' => 'provider-test'];
    $hosting = $service->saveConnection($accountId, 'hosting', 'test-hosting', 'Test Hosting', $secret, 'REQ-P9-CONNECTION-H');
    $dns = $service->saveConnection($accountId, 'dns', 'test-dns', 'Test DNS', $secret, 'REQ-P9-CONNECTION-D');
    $certificate = $service->saveConnection($accountId, 'certificate', 'test-certificate', 'Test Certificates', $secret, 'REQ-P9-CONNECTION-C');
    $storedSecret = $pdo->query('SELECT credentials_ciphertext FROM provider_connections WHERE id=' . $hosting['connection_id'])->fetchColumn();
    $assert(is_string($storedSecret) && !str_contains($storedSecret, 'phase9-provider-secret'), 'Plaintext provider credential was stored.');
    $rotated = $service->saveConnection($accountId, 'hosting', 'test-hosting', 'Test Hosting Rotated', $secret, 'REQ-P9-CONNECTION-H2');
    $assert($rotated['connection_id'] === $hosting['connection_id'] && $rotated['credential_version'] === 2, 'Provider credential rotation did not preserve connection identity and increment version.');

    $provision = $service->enqueueProvision(
        $accountId,
        $deploymentId,
        $hosting['connection_id'],
        $dns['connection_id'],
        $certificate['connection_id'],
        $hostname,
        'REQ-P9-PROVISION',
        'IDEM-P9-PROVISION'
    );
    $provisionReplay = $service->enqueueProvision(
        $accountId,
        $deploymentId,
        $hosting['connection_id'],
        $dns['connection_id'],
        $certificate['connection_id'],
        $hostname,
        'REQ-P9-PROVISION-REPLAY',
        'IDEM-P9-PROVISION'
    );
    $assert($provision['replayed'] === false && $provisionReplay['replayed'] === true, 'Infrastructure provision enqueue is not idempotent.');
    $provisionResult = $service->processNext('phase9-worker');
    $assert(is_array($provisionResult) && $provisionResult['status'] === 'completed', 'Infrastructure provision did not complete.');
    $binding = $pdo->query('SELECT * FROM infrastructure_bindings WHERE id=' . $provision['binding_id'])->fetch(PDO::FETCH_ASSOC);
    $assert(is_array($binding) && $binding['status'] === 'active', 'Infrastructure binding was not activated.');
    $deployment = $pdo->query('SELECT status,routing_status,ssl_status,hosting_reference FROM pod_deployments WHERE id=' . $deploymentId)->fetch(PDO::FETCH_ASSOC);
    $assert(is_array($deployment) && $deployment['status'] === 'active' && $deployment['routing_status'] === 'active' && $deployment['ssl_status'] === 'active', 'POD infrastructure status was not synchronized.');
    $assert(str_starts_with((string) $deployment['hosting_reference'], 'sha256:'), 'Plaintext hosting provider reference was written to the POD registry.');
    $hostingCiphertext = (string) $pdo->query('SELECT provider_reference_ciphertext FROM hosting_allocations WHERE binding_id=' . $provision['binding_id'])->fetchColumn();
    $dnsCiphertext = (string) $pdo->query('SELECT provider_reference_ciphertext FROM dns_bindings WHERE binding_id=' . $provision['binding_id'])->fetchColumn();
    $certificateCiphertext = (string) $pdo->query('SELECT provider_reference_ciphertext FROM certificate_orders WHERE binding_id=' . $provision['binding_id'])->fetchColumn();
    $assert(!str_contains($hostingCiphertext, 'host-ref-') && !str_contains($dnsCiphertext, 'dns-ref-') && !str_contains($certificateCiphertext, 'cert-ref-'), 'Plaintext provider infrastructure reference was stored.');

    $reconcile = $service->enqueueReconcile($accountId, $provision['binding_id'], 'REQ-P9-RECONCILE', 'IDEM-P9-RECONCILE');
    $reconcileResult = $service->processNext('phase9-worker');
    $assert(is_array($reconcileResult) && $reconcileResult['status'] === 'completed', 'Healthy infrastructure reconciliation did not complete.');

    $adapter->dnsVerified = false;
    $reconcileFailure = $service->enqueueReconcile($accountId, $provision['binding_id'], 'REQ-P9-RECONCILE-FAIL', 'IDEM-P9-RECONCILE-FAIL');
    $pdo->exec('UPDATE provider_operations SET max_attempts=1 WHERE id=' . $reconcileFailure['operation_id']);
    $failedResult = $service->processNext('phase9-worker');
    $assert(is_array($failedResult) && $failedResult['status'] === 'failed', 'Failed DNS verification did not fail reconciliation.');
    $adapter->dnsVerified = true;
    $service->resume($accountId, $reconcileFailure['operation_id'], 'REQ-P9-RECONCILE-RESUME');
    $resumedResult = $service->processNext('phase9-worker');
    $assert(is_array($resumedResult) && $resumedResult['status'] === 'completed', 'Failed reconciliation did not resume from completed steps.');
    $hostingVerifyCalls = count(array_keys($adapter->calls, 'hosting_verify', true));
    $assert($hostingVerifyCalls === 2, 'Completed hosting verification was repeated during reconciliation resume.');

    $crossAccountRejected = false;
    try {
        $service->enqueueTeardown($otherAccountId, $provision['binding_id'], 'REQ-P9-CROSS', 'IDEM-P9-CROSS');
    } catch (Throwable) {
        $crossAccountRejected = true;
    }
    $assert($crossAccountRejected, 'Cross-account infrastructure teardown was accepted.');

    $teardown = $service->enqueueTeardown($accountId, $provision['binding_id'], 'REQ-P9-TEARDOWN', 'IDEM-P9-TEARDOWN');
    $beforeTeardown = count($adapter->calls);
    $teardownResult = $service->processNext('phase9-worker');
    $assert(is_array($teardownResult) && $teardownResult['status'] === 'completed', 'Infrastructure teardown did not complete.');
    $teardownCalls = array_slice($adapter->calls, $beforeTeardown);
    $assert($teardownCalls === ['certificate_revoke', 'dns_remove', 'hosting_release'], 'Infrastructure teardown did not execute certificate, DNS, then hosting in reverse dependency order.');
    $assert($pdo->query('SELECT status FROM infrastructure_bindings WHERE id=' . $provision['binding_id'])->fetchColumn() === 'disabled', 'Infrastructure binding was not disabled after teardown.');
    $deploymentAfter = $pdo->query('SELECT routing_status,ssl_status FROM pod_deployments WHERE id=' . $deploymentId)->fetch(PDO::FETCH_ASSOC);
    $assert(is_array($deploymentAfter) && $deploymentAfter['routing_status'] === 'disabled' && $deploymentAfter['ssl_status'] === 'disabled', 'POD routing and SSL state were not disabled after teardown.');

    $service->revokeConnection($accountId, $hosting['connection_id'], 'REQ-P9-REVOKE-H');
    $service->revokeConnection($accountId, $dns['connection_id'], 'REQ-P9-REVOKE-D');
    $service->revokeConnection($accountId, $certificate['connection_id'], 'REQ-P9-REVOKE-C');
    $assert((int) $pdo->query("SELECT COUNT(*) FROM provider_connections WHERE account_id={$accountId} AND status='revoked'")->fetchColumn() === 3, 'Provider connection revocation did not close all credentials.');

    $forbidden = (int) $pdo->query(
        "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()
         AND (TABLE_NAME LIKE 'provider_%' OR TABLE_NAME IN ('hosting_allocations','dns_bindings','certificate_orders'))
         AND (COLUMN_NAME LIKE '%plaintext%' OR COLUMN_NAME IN ('credentials','api_secret','provider_reference'))"
    )->fetchColumn();
    $assert($forbidden === 0, 'Plaintext provider credential or reference columns exist.');
} catch (Throwable $exception) {
    $failures[] = 'Unhandled Phase 9 integration exception: ' . $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 9 database certification failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 9 encrypted provider lifecycle certification passed.\n");

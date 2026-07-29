<?php

declare(strict_types=1);

use Vp3\Database;
use Vp3\Deployments\PodHealthService;
use Vp3\Provisioning\PodProvisioningAdapter;
use Vp3\Provisioning\PodProvisioningService;
use Vp3\Provisioning\ProtectedConfigurationMerger;

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

final class Phase5FakeAdapter implements PodProvisioningAdapter
{
    /** @var list<string> */
    public array $calls = [];
    /** @var list<string> */
    public array $rollbacks = [];
    public bool $failDatabaseOnce = true;
    /** @var array<string,mixed> */
    public array $writtenConfiguration = [];

    public function executeStage(string $stage, array $deployment): array
    {
        $this->calls[] = $stage;
        if ($stage === 'database_created' && $this->failDatabaseOnce) {
            $this->failDatabaseOnce = false;
            throw new RuntimeException('simulated database provider interruption');
        }
        return match ($stage) {
            'hosting_allocated' => ['hosting_reference' => 'host-' . $deployment['public_id']],
            'database_created' => ['database_reference' => 'db-' . $deployment['public_id']],
            'pod_installed' => ['installed_version' => '5.0.0'],
            'license_injected' => ['license_status' => 'active'],
            'ssl_requested' => ['ssl_status' => 'active'],
            'installation_verified' => [
                'installation_fingerprint' => hash('sha256', 'verified-' . $deployment['public_id']),
                'backup_status' => 'verified',
            ],
            default => ['provider_request_id' => 'req-' . $stage],
        };
    }

    public function rollbackStage(string $stage, array $deployment): array
    {
        $this->rollbacks[] = $stage;
        return ['provider_request_id' => 'rollback-' . $stage];
    }

    public function readConfiguration(array $deployment): array
    {
        return [
            'database' => ['host' => 'old-db', 'password' => 'customer-secret'],
            'app' => ['key' => 'customer-key', 'url' => 'https://old.example'],
            'customer' => ['custom_flag' => true],
        ];
    }

    public function buildConfiguration(array $deployment): array
    {
        return [
            'database' => ['host' => 'new-db', 'password' => 'generated-secret'],
            'app' => ['key' => 'generated-key', 'url' => 'https://' . $deployment['public_id'] . '.test'],
            'customer' => ['custom_flag' => false],
            'vp3' => ['deployment_id' => $deployment['public_id']],
        ];
    }

    public function writeConfiguration(array $deployment, array $configuration): array
    {
        $this->writtenConfiguration = $configuration;
        return ['provider_request_id' => 'config-write-' . $deployment['public_id']];
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
$adapter = new Phase5FakeAdapter();
$service = new PodProvisioningService($database, $adapter, new ProtectedConfigurationMerger(), ['database.password', 'app.key', 'customer']);
$health = new PodHealthService($database);
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
        'INSERT INTO accounts (public_id, account_type, status, display_name, created_at, updated_at)
         VALUES (:public_id, :type, :status, :display_name, :created_at, :updated_at)'
    )->execute([
        'public_id' => 'VP3-P5-' . strtoupper($token),
        'type' => 'individual',
        'status' => 'active',
        'display_name' => 'Phase Five Account',
        'created_at' => $now,
        'updated_at' => $now,
    ]);
    $accountId = (int) $pdo->lastInsertId();
    $planId = (int) $pdo->query("SELECT id FROM plans WHERE code='standard' LIMIT 1")->fetchColumn();
    if ($planId < 1) {
        throw new RuntimeException('Standard plan seed is missing.');
    }
    $pdo->prepare(
        'INSERT INTO subscriptions
         (public_id, account_id, plan_id, status, provider, provider_customer_id, provider_subscription_id,
          starts_at, current_period_starts_at, current_period_ends_at, created_at, updated_at)
         VALUES (:public_id, :account_id, :plan_id, :status, :provider, :customer, :subscription,
                 :starts_at, :period_start, :period_end, :created_at, :updated_at)'
    )->execute([
        'public_id' => 'SUB-P5-' . strtoupper($token),
        'account_id' => $accountId,
        'plan_id' => $planId,
        'status' => 'active',
        'provider' => 'stripe',
        'customer' => 'cus_p5_' . $token,
        'subscription' => 'sub_p5_' . $token,
        'starts_at' => $now,
        'period_start' => $now,
        'period_end' => gmdate('Y-m-d H:i:s', time() + 2592000),
        'created_at' => $now,
        'updated_at' => $now,
    ]);
    $subscriptionId = (int) $pdo->lastInsertId();
    $pdo->prepare(
        'INSERT INTO domain_registrations
         (public_id, account_id, subscription_id, label, hostname, status, routing_status, ssl_status,
          reserved_until, created_at, updated_at)
         VALUES (:public_id, :account_id, :subscription_id, :label, :hostname, :status, :routing, :ssl,
                 :reserved_until, :created_at, :updated_at)'
    )->execute([
        'public_id' => 'DOM-P5-' . strtoupper($token),
        'account_id' => $accountId,
        'subscription_id' => $subscriptionId,
        'label' => 'phase5-' . $token,
        'hostname' => 'phase5-' . $token . '.vp3.me',
        'status' => 'reserved',
        'routing' => 'pending',
        'ssl' => 'pending',
        'reserved_until' => gmdate('Y-m-d H:i:s', time() + 3600),
        'created_at' => $now,
        'updated_at' => $now,
    ]);
    $domainId = (int) $pdo->lastInsertId();
    $pdo->prepare(
        'INSERT INTO entitlement_bundles
         (public_id, account_id, subscription_id, domain_registration_id, plan_id, snapshot_hash, created_at, updated_at)
         VALUES (:public_id, :account_id, :subscription_id, :domain_id, :plan_id, :snapshot_hash, :created_at, :updated_at)'
    )->execute([
        'public_id' => 'BUNDLE-P5-' . strtoupper($token),
        'account_id' => $accountId,
        'subscription_id' => $subscriptionId,
        'domain_id' => $domainId,
        'plan_id' => $planId,
        'snapshot_hash' => hash('sha256', 'phase5-' . $token),
        'created_at' => $now,
        'updated_at' => $now,
    ]);
    $bundleId = (int) $pdo->lastInsertId();
    $pdo->prepare(
        'INSERT INTO licenses
         (public_id, account_id, subscription_id, domain_registration_id, entitlement_bundle_id, product_type,
          status, starts_at, created_at, updated_at)
         VALUES (:public_id, :account_id, :subscription_id, :domain_id, :bundle_id, :product_type,
                 :status, :starts_at, :created_at, :updated_at)'
    )->execute([
        'public_id' => 'LIC-P5-' . strtoupper($token),
        'account_id' => $accountId,
        'subscription_id' => $subscriptionId,
        'domain_id' => $domainId,
        'bundle_id' => $bundleId,
        'product_type' => 'pod',
        'status' => 'active',
        'starts_at' => $now,
        'created_at' => $now,
        'updated_at' => $now,
    ]);
    $licenseId = (int) $pdo->lastInsertId();
    foreach ([
        ['update_channel', 'string', json_encode('stable', JSON_THROW_ON_ERROR)],
        ['storage_bytes', 'integer', json_encode(1073741824, JSON_THROW_ON_ERROR)],
    ] as [$key, $type, $value]) {
        $pdo->prepare(
            'INSERT INTO license_entitlements
             (license_id, entitlement_key, value_type, value_json, source_plan_id, effective_at, created_at, updated_at)
             VALUES (:license_id, :key, :type, :value, :plan_id, :effective_at, :created_at, :updated_at)'
        )->execute([
            'license_id' => $licenseId,
            'key' => $key,
            'type' => $type,
            'value' => $value,
            'plan_id' => $planId,
            'effective_at' => $now,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
    }

    $enqueue = $service->enqueue($accountId, $domainId, $licenseId, 'REQ-P5-' . strtoupper($token), 'IDEM-P5-' . $token);
    $replay = $service->enqueue($accountId, $domainId, $licenseId, 'REQ-P5-REPLAY-' . strtoupper($token), 'IDEM-P5-' . $token);
    $assert($enqueue['replayed'] === false && $replay['replayed'] === true, 'Provisioning enqueue is not idempotent.');
    $assert((int) $pdo->query('SELECT COUNT(*) FROM pod_deployments WHERE domain_registration_id=' . $domainId)->fetchColumn() === 1, 'More than one POD deployment was created for one Domain.');
    $assert((int) $pdo->query('SELECT COUNT(*) FROM pod_provisioning_steps WHERE job_id=' . $enqueue['job_id'])->fetchColumn() === 11, 'The complete ordered provisioning stage set was not created.');

    $first = $service->processNext('phase5-worker');
    $assert(is_array($first) && $first['status'] === 'retrying', 'Provider failure did not move the job into retrying state.');
    $completedBeforeRetry = (int) $pdo->query("SELECT COUNT(*) FROM pod_provisioning_steps WHERE job_id={$enqueue['job_id']} AND status='completed'")->fetchColumn();
    $assert($completedBeforeRetry === 3, 'Completed stages before failure were not retained for resume.');
    $pdo->exec("UPDATE pod_provisioning_jobs SET available_at=UTC_TIMESTAMP() WHERE id={$enqueue['job_id']}");
    $second = $service->processNext('phase5-worker');
    $assert(is_array($second) && $second['status'] === 'completed', 'Provisioning did not resume and complete after retry.');
    $assert(count(array_keys($adapter->calls, 'payment_confirmed', true)) === 1, 'Completed stages were repeated during resume.');
    $assert(($adapter->writtenConfiguration['database']['password'] ?? null) === 'customer-secret', 'Existing database secret was overwritten.');
    $assert(($adapter->writtenConfiguration['app']['key'] ?? null) === 'customer-key', 'Existing application key was overwritten.');
    $assert(($adapter->writtenConfiguration['customer']['custom_flag'] ?? null) === true, 'Customer configuration root was overwritten.');
    $assert((int) $pdo->query('SELECT COUNT(*) FROM pod_configuration_receipts WHERE deployment_id=' . $enqueue['deployment_id'])->fetchColumn() === 1, 'Configuration hash receipt was not stored.');
    $assert((int) $pdo->query("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='pod_configuration_receipts' AND COLUMN_NAME LIKE '%json%'")->fetchColumn() === 0, 'Configuration JSON was stored in the control database.');

    $deployment = $pdo->query('SELECT * FROM pod_deployments WHERE id=' . $enqueue['deployment_id'])->fetch(PDO::FETCH_ASSOC);
    $assert(is_array($deployment) && $deployment['status'] === 'active' && $deployment['hosting_reference'] !== null && $deployment['database_reference'] !== null, 'Activation metadata was not completed.');
    $heartbeat = $health->heartbeat(
        $accountId,
        (string) $deployment['public_id'],
        (string) $deployment['installation_fingerprint'],
        [
            'storage_usage_bytes' => 1024,
            'routing_status' => 'active',
            'ssl_status' => 'active',
            'backup_status' => 'verified',
            'license_status' => 'active',
            'installed_version' => '5.0.1',
        ],
        'REQ-HEARTBEAT-' . strtoupper($token)
    );
    $assert($heartbeat['status'] === 'active', 'Valid heartbeat did not keep deployment active.');
    $denied = false;
    try {
        $health->heartbeat($accountId + 999, (string) $deployment['public_id'], (string) $deployment['installation_fingerprint'], [], 'REQ-DENIED');
    } catch (Throwable) {
        $denied = true;
    }
    $assert($denied, 'Cross-account heartbeat was accepted.');

    $service->enqueueRollback($accountId, $enqueue['deployment_id'], 'REQ-ROLLBACK-' . strtoupper($token), 'IDEM-ROLLBACK-' . $token);
    $rollbackResult = $service->processNext('phase5-worker');
    $assert(is_array($rollbackResult) && $rollbackResult['status'] === 'completed', 'Rollback job did not complete.');
    $assert($adapter->rollbacks[0] === 'deployment_active' && end($adapter->rollbacks) === 'payment_confirmed', 'Rollback did not execute in reverse stage order.');
    $assert($pdo->query('SELECT status FROM pod_deployments WHERE id=' . $enqueue['deployment_id'])->fetchColumn() === 'archived', 'Rollback did not archive the deployment safely.');

    $pdo->prepare(
        'INSERT INTO billing_outbox
         (job_type, dedupe_key, account_id, subscription_id, payload_json, status, attempts, available_at, created_at, updated_at)
         VALUES (:job_type, :dedupe_key, :account_id, :subscription_id, :payload, :status, 0, UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP())'
    )->execute([
        'job_type' => 'provisioning',
        'dedupe_key' => 'phase5-outbox-' . $token,
        'account_id' => $accountId,
        'subscription_id' => $subscriptionId,
        'payload' => json_encode(['source' => 'phase5-test'], JSON_THROW_ON_ERROR),
        'status' => 'pending',
    ]);
    $service->reconcileBillingOutbox();
    $assert($pdo->query("SELECT status FROM billing_outbox WHERE dedupe_key='phase5-outbox-{$token}'")->fetchColumn() === 'failed', 'Billing reconciliation did not fail safely when no unprovisioned Domain remained.');
} catch (Throwable $exception) {
    $failures[] = 'Unhandled Phase 5 integration exception: ' . $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 5 database certification failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 5 database integration certification passed.\n");

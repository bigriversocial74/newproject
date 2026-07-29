<?php

declare(strict_types=1);

use Vp3\Database;
use Vp3\Infrastructure\CertificateProviderAdapter;
use Vp3\Infrastructure\DnsProviderAdapter;
use Vp3\Infrastructure\HostingProviderAdapter;
use Vp3\Infrastructure\InfrastructureProviderService;
use Vp3\Infrastructure\ProviderSecretCipher;
use Vp3\Provisioning\PodProvisioningAdapter;
use Vp3\Provisioning\PodProvisioningService;
use Vp3\Provisioning\ProtectedConfigurationMerger;
use Vp3\Updates\SoftwareUpdateAdapter;
use Vp3\Updates\SoftwareUpdateService;
use Vp3\Operations\OperationalAuditService;
use Vp3\Operations\OperationalIncidentService;
use Vp3\Operations\OperationalNotificationAdapter;
use Vp3\Operations\OperationalNotificationService;
use Vp3\Operations\OperationsSecretCipher;

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

final class Phase11APodLeaseAdapter implements PodProvisioningAdapter
{
    public bool $stealLease = true;

    public function __construct(private readonly PDO $pdo)
    {
    }

    public function executeStage(string $stage, array $deployment): array
    {
        if ($this->stealLease && $stage === 'hosting_allocated') {
            $this->pdo->exec(
                "UPDATE pod_provisioning_jobs SET lease_token='" . str_repeat('c', 64) . "',locked_by='phase11a-pod-thief',
                 locked_until=DATE_ADD(UTC_TIMESTAMP(),INTERVAL 10 MINUTE),updated_at=UTC_TIMESTAMP()
                 WHERE status='running' AND locked_by='phase11a-pod-loss-worker'"
            );
        }
        return match ($stage) {
            'hosting_allocated' => ['hosting_reference' => 'phase11a-host-' . $deployment['public_id']],
            'database_created' => ['database_reference' => 'phase11a-db-' . $deployment['public_id']],
            'pod_installed' => ['installed_version' => '11.1.0'],
            'license_injected' => ['license_status' => 'active'],
            'ssl_requested' => ['ssl_status' => 'active'],
            'installation_verified' => [
                'installation_fingerprint' => hash('sha256', 'phase11a-' . $deployment['public_id']),
                'backup_status' => 'verified',
            ],
            default => ['provider_request_id' => 'phase11a-' . $stage],
        };
    }

    public function rollbackStage(string $stage, array $deployment): array
    {
        return ['provider_request_id' => 'phase11a-rollback-' . $stage];
    }

    public function readConfiguration(array $deployment): array
    {
        return ['database' => ['password' => 'preserve'], 'app' => ['key' => 'preserve']];
    }

    public function buildConfiguration(array $deployment): array
    {
        return ['database' => ['password' => 'replace'], 'app' => ['key' => 'replace'], 'vp3' => ['pod' => $deployment['public_id']]];
    }

    public function writeConfiguration(array $deployment, array $configuration): array
    {
        return ['provider_request_id' => 'phase11a-config-' . $deployment['public_id']];
    }
}

final class Phase11AInfrastructureLeaseAdapter implements HostingProviderAdapter, DnsProviderAdapter, CertificateProviderAdapter
{
    public bool $stealLease = true;

    public function __construct(private readonly PDO $pdo)
    {
    }

    public function allocateHosting(array $authContext, array $deployment): array
    {
        if ($this->stealLease) {
            $this->pdo->exec(
                "UPDATE provider_operations SET lease_token='" . str_repeat('d', 64) . "',locked_by='phase11a-infra-thief',
                 locked_until=DATE_ADD(UTC_TIMESTAMP(),INTERVAL 10 MINUTE),updated_at=UTC_TIMESTAMP()
                 WHERE status='hosting' AND locked_by='phase11a-infra-loss-worker'"
            );
        }
        return ['provider_reference' => 'phase11a-host-ref-' . $deployment['public_id'], 'endpoint' => '203.0.113.111', 'region' => 'test-1'];
    }

    public function verifyHosting(array $authContext, string $providerReference): array
    {
        return ['verified' => true];
    }

    public function releaseHosting(array $authContext, string $providerReference): array
    {
        return ['released' => true];
    }

    public function upsertRecord(array $authContext, string $hostname, string $recordType, string $recordValue): array
    {
        return ['provider_reference' => 'phase11a-dns-' . hash('sha256', $hostname . $recordValue)];
    }

    public function verifyRecord(array $authContext, string $providerReference, string $hostname, string $recordType, string $recordValue): array
    {
        return ['verified' => true];
    }

    public function removeRecord(array $authContext, string $providerReference): array
    {
        return ['removed' => true];
    }

    public function requestCertificate(array $authContext, string $hostname): array
    {
        return ['provider_reference' => 'phase11a-cert-' . hash('sha256', $hostname), 'expires_at' => gmdate('Y-m-d H:i:s', time() + 86400)];
    }

    public function verifyCertificate(array $authContext, string $providerReference, string $hostname): array
    {
        return ['verified' => true];
    }

    public function revokeCertificate(array $authContext, string $providerReference): array
    {
        return ['revoked' => true];
    }
}

final class Phase11AUpdateLeaseAdapter implements SoftwareUpdateAdapter
{
    public bool $stealLease = true;

    public function __construct(private readonly PDO $pdo)
    {
    }

    public function createPreUpdateBackup(array $target, array $release): array
    {
        return ['reference' => 'phase11a-backup', 'hash' => hash('sha256', 'phase11a-backup'), 'verified' => true];
    }

    public function executeStage(string $stage, array $target, array $release, array $job): array
    {
        if ($this->stealLease && $stage === 'downloading') {
            $this->pdo->exec(
                "UPDATE update_jobs SET lease_token='" . str_repeat('e', 64) . "',locked_by='phase11a-update-thief',
                 locked_until=DATE_ADD(UTC_TIMESTAMP(),INTERVAL 10 MINUTE),updated_at=UTC_TIMESTAMP()
                 WHERE status='running' AND current_stage='downloading' AND locked_by='phase11a-update-loss-worker'"
            );
        }
        return $stage === 'verifying' ? ['verified' => true] : ['provider_request_id' => 'phase11a-' . $stage];
    }

    public function rollback(array $target, array $release, array $job): array
    {
        return ['restored' => true];
    }
}

final class Phase11ALeaseAdapter implements OperationalNotificationAdapter
{
    public bool $stealLease = false;

    public function __construct(private readonly PDO $pdo)
    {
    }

    public function deliver(array $destination, array $payload): array
    {
        if ($this->stealLease) {
            $statement = $this->pdo->prepare(
                "UPDATE operational_notifications SET lease_token=:token,locked_by='lease-thief',
                 locked_until=DATE_ADD(UTC_TIMESTAMP(),INTERVAL 15 MINUTE),updated_at=UTC_TIMESTAMP()
                 WHERE status='running' AND locked_by='phase11a-loss-worker'"
            );
            $statement->execute(['token' => str_repeat('b', 64)]);
        }
        return ['provider_message_id' => 'phase11a-' . hash('sha256', json_encode($payload, JSON_THROW_ON_ERROR))];
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
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

try {
    foreach (['billing_outbox', 'pod_provisioning_jobs', 'update_jobs', 'backup_jobs', 'restore_jobs', 'provider_operations', 'operational_notifications'] as $table) {
        foreach (['locked_until', 'lease_token'] as $column) {
            $statement = $pdo->prepare(
                'SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=:table AND COLUMN_NAME=:column'
            );
            $statement->execute(['table' => $table, 'column' => $column]);
            $assert((int) $statement->fetchColumn() === 1, $table . ' is missing queue lease column ' . $column . '.');
        }
    }
    $statement = $pdo->prepare(
        "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='billing_outbox' AND COLUMN_NAME='locked_by'"
    );
    $statement->execute();
    $assert((int) $statement->fetchColumn() === 1, 'billing_outbox is missing worker ownership.');

    $token = strtolower(bin2hex(random_bytes(5)));
    $now = gmdate('Y-m-d H:i:s');
    $pdo->prepare(
        "INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at)
         VALUES (:public,'individual','active',:name,:created,:updated)"
    )->execute([
        'public' => 'VP3-P11A-' . strtoupper($token),
        'name' => 'Phase 11A Account',
        'created' => $now,
        'updated' => $now,
    ]);
    $accountId = (int) $pdo->lastInsertId();

    $cipher = new OperationsSecretCipher(base64_encode(random_bytes(32)), 'phase11a-key');
    $adapter = new Phase11ALeaseAdapter($pdo);
    $audit = new OperationalAuditService($database);
    $notifications = new OperationalNotificationService($database, $cipher, $adapter, $audit, 60);
    $incidents = new OperationalIncidentService($database, $audit, $notifications);

    while ($notifications->processNext('phase11a-drain-worker') !== null) {
        // Drain retained queued notifications before isolated lease tests.
    }

    $channel = $notifications->saveChannel(
        $accountId,
        'email',
        'Phase 11A Lease Channel',
        ['email' => 'phase11a-' . $token . '@example.test'],
        'info',
        'REQ-P11A-CHANNEL-' . $token
    );
    $incident = $incidents->open(
        $accountId,
        'phase11a_lease',
        1,
        'warning',
        'Future lease must not be reclaimed',
        ['test' => 'future_lease', 'token_hash' => hash('sha256', $token)],
        false
    );
    $notificationId = (int) $pdo->query(
        'SELECT id FROM operational_notifications WHERE incident_id=' . (int) $incident['incident_id'] . ' ORDER BY id DESC LIMIT 1'
    )->fetchColumn();
    $pdo->prepare(
        "UPDATE operational_notifications SET status='running',locked_by='active-worker',locked_at=UTC_TIMESTAMP(),
         locked_until=DATE_ADD(UTC_TIMESTAMP(),INTERVAL 10 MINUTE),lease_token=:token WHERE id=:id"
    )->execute(['token' => str_repeat('a', 64), 'id' => $notificationId]);
    $assert($notifications->processNext('phase11a-other-worker') === null, 'A non-expired running lease was reclaimed by another worker.');

    $pdo->prepare('UPDATE operational_notifications SET locked_until=DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 MINUTE) WHERE id=:id')
        ->execute(['id' => $notificationId]);
    $recovered = $notifications->processNext('phase11a-recovery-worker');
    $assert(($recovered['notification_id'] ?? null) === $notificationId && ($recovered['status'] ?? null) === 'delivered', 'Expired notification lease was not recovered exactly once.');

    $lossIncident = $incidents->open(
        $accountId,
        'phase11a_lease',
        2,
        'warning',
        'Lost lease cannot finalize',
        ['test' => 'lease_loss', 'token_hash' => hash('sha256', 'loss-' . $token)],
        false
    );
    $lossNotificationId = (int) $pdo->query(
        'SELECT id FROM operational_notifications WHERE incident_id=' . (int) $lossIncident['incident_id'] . ' ORDER BY id DESC LIMIT 1'
    )->fetchColumn();
    $adapter->stealLease = true;
    $lost = $notifications->processNext('phase11a-loss-worker');
    $assert(($lost['notification_id'] ?? null) === $lossNotificationId && ($lost['status'] ?? null) === 'lease_lost', 'Worker did not detect lease theft during delivery.');
    $storedStatus = (string) $pdo->query('SELECT status FROM operational_notifications WHERE id=' . $lossNotificationId)->fetchColumn();
    $assert($storedStatus === 'running', 'A worker finalized a notification after losing its lease.');
    $deliveredReceipts = (int) $pdo->query(
        "SELECT COUNT(*) FROM operational_notification_receipts WHERE notification_id={$lossNotificationId} AND result='delivered'"
    )->fetchColumn();
    $assert($deliveredReceipts === 0, 'A delivered receipt was written after lease ownership was lost.');

    $adapter->stealLease = false;
    $pdo->prepare('UPDATE operational_notifications SET locked_until=DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 MINUTE) WHERE id=:id')
        ->execute(['id' => $lossNotificationId]);
    $replayed = $notifications->processNext('phase11a-final-worker');
    $assert(($replayed['notification_id'] ?? null) === $lossNotificationId && ($replayed['status'] ?? null) === 'delivered', 'Lease-lost notification could not be recovered by a new worker.');

    // POD provider calls cannot persist step or configuration receipts after lease theft.
    $podJob = $pdo->query(
        "SELECT j.id,j.deployment_id FROM pod_provisioning_jobs j
         JOIN accounts a ON a.id=j.account_id WHERE a.public_id LIKE 'VP3-P5-%' AND j.job_type='provision'
         ORDER BY j.id DESC LIMIT 1"
    )->fetch(PDO::FETCH_ASSOC);
    if (!is_array($podJob)) {
        throw new RuntimeException('Retained Phase 5 POD fixture is missing.');
    }
    $pdo->exec("UPDATE pod_provisioning_jobs SET status='failed' WHERE id<>" . (int) $podJob['id'] . " AND status IN ('queued','retrying','running')");
    $pdo->prepare("UPDATE pod_provisioning_steps SET status='completed',completed_at=COALESCE(completed_at,UTC_TIMESTAMP()) WHERE job_id=:job")
        ->execute(['job' => $podJob['id']]);
    $pdo->prepare("UPDATE pod_provisioning_steps SET status='pending',completed_at=NULL,provider_receipt_hash=NULL,last_error_code=NULL,last_error_message=NULL WHERE job_id=:job AND stage='hosting_allocated'")
        ->execute(['job' => $podJob['id']]);
    $pdo->prepare("UPDATE pod_provisioning_jobs SET status='queued',attempts=0,current_stage=NULL,available_at=UTC_TIMESTAMP(),locked_at=NULL,locked_by=NULL,locked_until=NULL,lease_token=NULL,completed_at=NULL,last_error_code=NULL,last_error_message=NULL WHERE id=:id")
        ->execute(['id' => $podJob['id']]);
    $podReceiptBefore = (int) $pdo->query("SELECT COUNT(*) FROM pod_provisioning_receipts WHERE job_id=" . (int) $podJob['id'] . " AND operation='hosting_allocated'")->fetchColumn();
    $podAdapter = new Phase11APodLeaseAdapter($pdo);
    $podService = new PodProvisioningService($database, $podAdapter, new ProtectedConfigurationMerger(), ['database.password', 'app.key'], 60);
    $podLost = $podService->processNext('phase11a-pod-loss-worker');
    $assert(($podLost['job_id'] ?? null) === (int) $podJob['id'] && ($podLost['status'] ?? null) === 'lease_lost', 'POD worker did not detect lease theft during provider execution.');
    $podStepStatus = (string) $pdo->query("SELECT status FROM pod_provisioning_steps WHERE job_id=" . (int) $podJob['id'] . " AND stage='hosting_allocated'")->fetchColumn();
    $assert($podStepStatus === 'running', 'Stale POD worker finalized a step after lease theft.');
    $podReceiptAfter = (int) $pdo->query("SELECT COUNT(*) FROM pod_provisioning_receipts WHERE job_id=" . (int) $podJob['id'] . " AND operation='hosting_allocated'")->fetchColumn();
    $assert($podReceiptAfter === $podReceiptBefore, 'Stale POD worker wrote a receipt after lease theft.');
    $podAdapter->stealLease = false;
    $pdo->prepare('UPDATE pod_provisioning_jobs SET locked_until=DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 MINUTE) WHERE id=:id')->execute(['id' => $podJob['id']]);
    $podRecovered = $podService->processNext('phase11a-pod-recovery-worker');
    $assert(($podRecovered['job_id'] ?? null) === (int) $podJob['id'] && ($podRecovered['status'] ?? null) === 'completed', 'Lease-lost POD job could not be recovered.');

    // Update provider calls cannot persist success or failure evidence after lease theft.
    $sourceUpdateJob = $pdo->query(
        "SELECT j.account_id,j.target_type,j.pod_deployment_id,j.homeserver_device_id,j.release_id,j.previous_version,j.target_version
         FROM update_jobs j JOIN accounts a ON a.id=j.account_id
         WHERE a.public_id LIKE 'VP3-P7-%' ORDER BY j.id DESC LIMIT 1"
    )->fetch(PDO::FETCH_ASSOC);
    if (!is_array($sourceUpdateJob)) {
        throw new RuntimeException('Retained Phase 7 update fixture is missing.');
    }
    $updatePublicId = 'UPDATE-JOB-P11A-' . strtoupper(bin2hex(random_bytes(8)));
    $updateRequestId = 'REQ-P11A-UPDATE-' . $token;
    $pdo->prepare(
        "INSERT INTO update_jobs
         (public_id,account_id,target_type,pod_deployment_id,homeserver_device_id,release_id,status,current_stage,
          previous_version,target_version,pre_update_backup_verified,attempts,max_attempts,idempotency_key,request_id,
          available_at,created_at,updated_at)
         VALUES (:public,:account,:target_type,:pod,:homeserver,:release,'queued',NULL,:previous,:target,1,0,3,:idempotency,
                 :request,UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())"
    )->execute([
        'public' => $updatePublicId,
        'account' => $sourceUpdateJob['account_id'],
        'target_type' => $sourceUpdateJob['target_type'],
        'pod' => $sourceUpdateJob['pod_deployment_id'],
        'homeserver' => $sourceUpdateJob['homeserver_device_id'],
        'release' => $sourceUpdateJob['release_id'],
        'previous' => $sourceUpdateJob['previous_version'],
        'target' => $sourceUpdateJob['target_version'],
        'idempotency' => 'IDEM-P11A-UPDATE-' . $token,
        'request' => $updateRequestId,
    ]);
    $updateJob = ['id' => (int) $pdo->lastInsertId()];
    $pdo->prepare(
        "INSERT INTO update_steps (job_id,stage,sequence_no,status,attempts,created_at,updated_at)
         VALUES (:job,'downloading',1,'pending',0,UTC_TIMESTAMP(),UTC_TIMESTAMP())"
    )->execute(['job' => $updateJob['id']]);
    $pdo->prepare(
        "INSERT INTO update_steps (job_id,stage,sequence_no,status,attempts,created_at,updated_at)
         VALUES (:job,'completed',2,'pending',0,UTC_TIMESTAMP(),UTC_TIMESTAMP())"
    )->execute(['job' => $updateJob['id']]);
    $pdo->exec("UPDATE update_jobs SET status='failed' WHERE id<>" . (int) $updateJob['id'] . " AND status IN ('queued','running','validating','backing_up','downloading','installing','migrating','verifying','rolling_back')");
    $updateReceiptBefore = 0;
    $updateAdapter = new Phase11AUpdateLeaseAdapter($pdo);
    $updateService = new SoftwareUpdateService($database, $updateAdapter, 60);
    $updateLost = $updateService->processNext('phase11a-update-loss-worker');
    $assert(($updateLost['job_id'] ?? null) === (int) $updateJob['id'] && ($updateLost['status'] ?? null) === 'lease_lost', 'Update worker did not detect lease theft during provider execution.');
    $updateStepStatus = (string) $pdo->query("SELECT status FROM update_steps WHERE job_id=" . (int) $updateJob['id'] . " AND stage='downloading'")->fetchColumn();
    $assert($updateStepStatus === 'running', 'Stale update worker finalized a step after lease theft.');
    $updateReceiptAfter = (int) $pdo->query("SELECT COUNT(*) FROM update_receipts WHERE job_id=" . (int) $updateJob['id'] . " AND operation='downloading'")->fetchColumn();
    $assert($updateReceiptAfter === $updateReceiptBefore, 'Stale update worker wrote a receipt after lease theft.');
    $updateAdapter->stealLease = false;
    $pdo->prepare('UPDATE update_jobs SET locked_until=DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 MINUTE) WHERE id=:id')->execute(['id' => $updateJob['id']]);
    $updateRecovered = $updateService->processNext('phase11a-update-recovery-worker');
    $assert(
        ($updateRecovered['job_id'] ?? null) === (int) $updateJob['id'] && ($updateRecovered['status'] ?? null) === 'completed',
        'Lease-lost update job could not be recovered: ' . json_encode($updateRecovered, JSON_UNESCAPED_SLASHES)
    );

    // Infrastructure provider results cannot create allocation records after lease theft.
    $pdo->prepare("UPDATE pod_deployments SET status='active',routing_status='active',ssl_status='active',license_status='active',updated_at=UTC_TIMESTAMP() WHERE id=:id")
        ->execute(['id' => $podJob['deployment_id']]);
    $deploymentStatement = $pdo->prepare(
        "SELECT p.id,p.account_id,d.hostname FROM pod_deployments p
         JOIN domain_registrations d ON d.id=p.domain_registration_id
         WHERE p.id=:deployment AND p.status IN ('pending','provisioning','active','degraded','failed') LIMIT 1"
    );
    $deploymentStatement->execute(['deployment' => $podJob['deployment_id']]);
    $deployment = $deploymentStatement->fetch(PDO::FETCH_ASSOC);
    if (!is_array($deployment)) {
        throw new RuntimeException('Retained POD fixture for infrastructure lease testing is missing.');
    }
    $infraCipher = new ProviderSecretCipher(base64_encode(random_bytes(32)), 'phase11a-infra-key');
    $infraAdapter = new Phase11AInfrastructureLeaseAdapter($pdo);
    $infraService = new InfrastructureProviderService($database, $infraCipher, $infraAdapter, $infraAdapter, $infraAdapter, 60);
    $secret = ['token' => 'phase11a-provider'];
    $hostingConnection = $infraService->saveConnection((int) $deployment['account_id'], 'hosting', 'phase11a-host-' . $token, 'Phase 11A Hosting', $secret, 'REQ-P11A-INFRA-H-' . $token);
    $dnsConnection = $infraService->saveConnection((int) $deployment['account_id'], 'dns', 'phase11a-dns-' . $token, 'Phase 11A DNS', $secret, 'REQ-P11A-INFRA-D-' . $token);
    $certificateConnection = $infraService->saveConnection((int) $deployment['account_id'], 'certificate', 'phase11a-cert-' . $token, 'Phase 11A Certificate', $secret, 'REQ-P11A-INFRA-C-' . $token);
    $infra = $infraService->enqueueProvision(
        (int) $deployment['account_id'],
        (int) $deployment['id'],
        $hostingConnection['connection_id'],
        $dnsConnection['connection_id'],
        $certificateConnection['connection_id'],
        (string) $deployment['hostname'],
        'REQ-P11A-INFRA-' . $token,
        'IDEM-P11A-INFRA-' . $token
    );
    $pdo->exec("UPDATE provider_operations SET status='failed' WHERE id<>" . (int) $infra['operation_id'] . " AND status IN ('queued','running','hosting','dns','certificate','verifying')");
    $infraLost = $infraService->processNext('phase11a-infra-loss-worker');
    $assert(($infraLost['operation_id'] ?? null) === (int) $infra['operation_id'] && ($infraLost['status'] ?? null) === 'lease_lost', 'Infrastructure worker did not detect lease theft during provider execution.');
    $allocationCount = (int) $pdo->query('SELECT COUNT(*) FROM hosting_allocations WHERE binding_id=' . (int) $infra['binding_id'])->fetchColumn();
    $assert($allocationCount === 0, 'Stale infrastructure worker persisted a hosting allocation after lease theft.');
    $infraStepStatus = (string) $pdo->query("SELECT status FROM provider_operation_steps WHERE operation_id=" . (int) $infra['operation_id'] . " AND stage='hosting_allocate'")->fetchColumn();
    $assert($infraStepStatus === 'running', 'Stale infrastructure worker finalized a step after lease theft.');
    $infraAdapter->stealLease = false;
    $pdo->prepare('UPDATE provider_operations SET locked_until=DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 MINUTE) WHERE id=:id')->execute(['id' => $infra['operation_id']]);
    $infraRecovered = $infraService->processNext('phase11a-infra-recovery-worker');
    $assert(($infraRecovered['operation_id'] ?? null) === (int) $infra['operation_id'] && ($infraRecovered['status'] ?? null) === 'completed', 'Lease-lost infrastructure operation could not be recovered.');

} catch (Throwable $exception) {
    $failures[] = $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 11A database failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

fwrite(STDOUT, "Phase 11A queue lease and crash-recovery certification passed.\n");

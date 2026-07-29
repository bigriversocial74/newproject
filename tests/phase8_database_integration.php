<?php

declare(strict_types=1);

use Vp3\Backups\BackupMetadataCipher;
use Vp3\Backups\BackupProviderAdapter;
use Vp3\Backups\BackupService;
use Vp3\Database;

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

final class Phase8BackupAdapter implements BackupProviderAdapter
{
    public int $counter = 0;
    public bool $verifyNext = true;
    public int $restores = 0;
    public int $deletes = 0;
    /** @var array<string,string> */
    public array $references = [];

    public function createBackup(array $target, string $purpose): array
    {
        $this->counter++;
        $reference = 'provider://private/' . $target['public_id'] . '/' . $purpose . '/' . $this->counter;
        $hash = hash('sha256', 'snapshot-' . $reference);
        $this->references[$hash] = $reference;
        return ['reference' => $reference, 'snapshot_hash' => $hash, 'size_bytes' => 1024 * $this->counter];
    }

    public function verifyBackup(array $target, string $providerReference, string $snapshotHash): array
    {
        $verified = $this->verifyNext;
        $this->verifyNext = true;
        return [
            'verified' => $verified,
            'verification_hash' => hash('sha256', 'verify-' . $providerReference . '-' . $snapshotHash),
            'metadata' => ['region' => 'test', 'storage_class' => 'encrypted'],
        ];
    }

    public function restoreBackup(array $target, string $providerReference, string $snapshotHash): array
    {
        $this->restores++;
        return [
            'restored' => isset($this->references[$snapshotHash]) && $this->references[$snapshotHash] === $providerReference,
            'verification_hash' => hash('sha256', 'restore-' . $providerReference . '-' . $snapshotHash),
            'metadata' => ['provider_request_id' => 'restore-' . $this->restores],
        ];
    }

    public function deleteBackup(array $target, string $providerReference, string $snapshotHash): array
    {
        $this->deletes++;
        return [
            'deleted' => isset($this->references[$snapshotHash]) && $this->references[$snapshotHash] === $providerReference,
            'receipt_hash' => hash('sha256', 'delete-' . $providerReference . '-' . $snapshotHash),
        ];
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
$adapter = new Phase8BackupAdapter();
$cipher = new BackupMetadataCipher(base64_encode(random_bytes(32)), 'phase8-test-key');
$service = new BackupService($database, $adapter, $cipher, 80.0, 95.0);
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
    $insertAccount->execute(['public' => 'VP3-P8-' . strtoupper($token), 'name' => 'Phase Eight Account', 'created' => $now, 'updated' => $now]);
    $accountId = (int) $pdo->lastInsertId();
    $insertAccount->execute(['public' => 'VP3-P8-X-' . strtoupper($token), 'name' => 'Phase Eight Other', 'created' => $now, 'updated' => $now]);
    $otherAccountId = (int) $pdo->lastInsertId();
    $planId = (int) $pdo->query("SELECT id FROM plans WHERE code='standard' LIMIT 1")->fetchColumn();
    $pdo->prepare(
        "INSERT INTO subscriptions (public_id,account_id,plan_id,status,provider,provider_customer_id,provider_subscription_id,starts_at,current_period_starts_at,current_period_ends_at,created_at,updated_at)
         VALUES (:public,:account,:plan,'active','stripe',:customer,:external,:starts,:period_start,:period_end,:created,:updated)"
    )->execute([
        'public' => 'SUB-P8-' . strtoupper($token), 'account' => $accountId, 'plan' => $planId,
        'customer' => 'cus_p8_' . $token, 'external' => 'sub_p8_' . $token,
        'starts' => $now, 'period_start' => $now, 'period_end' => gmdate('Y-m-d H:i:s', time() + 2592000),
        'created' => $now, 'updated' => $now,
    ]);
    $subscriptionId = (int) $pdo->lastInsertId();
    $label = 'phase8-' . $token;
    $pdo->prepare(
        "INSERT INTO domain_registrations (public_id,account_id,subscription_id,label,hostname,status,routing_status,ssl_status,registered_at,created_at,updated_at)
         VALUES (:public,:account,:subscription,:label,:hostname,'active','active','active',:registered,:created,:updated)"
    )->execute([
        'public' => 'DOM-P8-' . strtoupper($token), 'account' => $accountId, 'subscription' => $subscriptionId,
        'label' => $label, 'hostname' => $label . '.vp3.me', 'registered' => $now, 'created' => $now, 'updated' => $now,
    ]);
    $domainId = (int) $pdo->lastInsertId();
    $pdo->prepare(
        'INSERT INTO entitlement_bundles (public_id,account_id,subscription_id,domain_registration_id,plan_id,snapshot_hash,created_at,updated_at)
         VALUES (:public,:account,:subscription,:domain,:plan,:snapshot,:created,:updated)'
    )->execute([
        'public' => 'BUNDLE-P8-' . strtoupper($token), 'account' => $accountId, 'subscription' => $subscriptionId,
        'domain' => $domainId, 'plan' => $planId, 'snapshot' => hash('sha256', 'bundle-' . $token),
        'created' => $now, 'updated' => $now,
    ]);
    $bundleId = (int) $pdo->lastInsertId();
    $pdo->prepare(
        "INSERT INTO licenses (public_id,account_id,subscription_id,domain_registration_id,entitlement_bundle_id,product_type,status,starts_at,created_at,updated_at)
         VALUES (:public,:account,:subscription,:domain,:bundle,'pod','active',:starts,:created,:updated)"
    )->execute([
        'public' => 'POD-LIC-P8-' . strtoupper($token), 'account' => $accountId, 'subscription' => $subscriptionId,
        'domain' => $domainId, 'bundle' => $bundleId, 'starts' => $now, 'created' => $now, 'updated' => $now,
    ]);
    $licenseId = (int) $pdo->lastInsertId();
    $pdo->prepare(
        "INSERT INTO pod_deployments (public_id,account_id,subscription_id,domain_registration_id,license_id,status,installation_fingerprint,installed_version,update_channel,storage_usage_bytes,storage_allowance_bytes,last_heartbeat_at,routing_status,ssl_status,backup_status,license_status,activated_at,created_at,updated_at)
         VALUES (:public,:account,:subscription,:domain,:license,'active',:fingerprint,'8.0.0','stable',0,1000,UTC_TIMESTAMP(),'active','active','verified','active',UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())"
    )->execute([
        'public' => 'POD-P8-' . strtoupper($token), 'account' => $accountId, 'subscription' => $subscriptionId,
        'domain' => $domainId, 'license' => $licenseId, 'fingerprint' => hash('sha256', 'pod-' . $token),
    ]);
    $deploymentId = (int) $pdo->lastInsertId();

    $policy = $service->savePolicy($accountId, 'pod', $deploymentId, 60, 1, 1, 'REQ-P8-POLICY');
    $assert($policy['policy_id'] > 0, 'Backup policy was not created.');
    $scheduled = $service->enqueueDuePolicies(5);
    $assert($scheduled === 1, 'Due backup policy was not queued exactly once.');
    $scheduledResult = $service->processNextBackup('phase8-worker');
    $assert(is_array($scheduledResult) && $scheduledResult['status'] === 'completed', 'Scheduled backup did not complete with verification.');

    $job = $service->enqueueBackup($accountId, 'pod', $deploymentId, 'on_demand', 'REQ-P8-ONDEMAND', 'IDEM-P8-ONDEMAND', $policy['policy_id']);
    $replay = $service->enqueueBackup($accountId, 'pod', $deploymentId, 'on_demand', 'REQ-P8-ONDEMAND-REPLAY', 'IDEM-P8-ONDEMAND', $policy['policy_id']);
    $assert($job['replayed'] === false && $replay['replayed'] === true, 'Backup enqueue is not idempotent.');
    $result = $service->processNextBackup('phase8-worker');
    $assert(is_array($result) && $result['status'] === 'completed', 'On-demand backup did not complete.');
    $snapshotId = (int) $result['snapshot_id'];
    $snapshot = $pdo->query('SELECT * FROM backup_snapshots WHERE id=' . $snapshotId)->fetch(PDO::FETCH_ASSOC);
    $plaintextReference = $adapter->references[(string) $snapshot['snapshot_hash']];
    $assert(!str_contains((string) $snapshot['provider_reference_ciphertext'], $plaintextReference), 'Plaintext provider backup reference was stored.');
    $decrypted = $cipher->decrypt(
        (string) $snapshot['provider_reference_ciphertext'],
        (string) $snapshot['provider_reference_nonce'],
        (string) $snapshot['provider_reference_tag'],
        'vp3-backup-reference|' . $accountId . '|' . $snapshot['backup_job_id'] . '|' . $snapshot['snapshot_hash']
    );
    $assert($decrypted === $plaintextReference, 'Encrypted provider reference could not be authenticated and decrypted.');
    $assert($snapshot['status'] === 'verified' && $snapshot['verification_status'] === 'verified', 'Snapshot was marked complete without verified status.');

    $restore = $service->enqueueRestore($accountId, $snapshotId, 'REQ-P8-RESTORE', 'IDEM-P8-RESTORE');
    $restoreReplay = $service->enqueueRestore($accountId, $snapshotId, 'REQ-P8-RESTORE-REPLAY', 'IDEM-P8-RESTORE');
    $assert($restore['replayed'] === false && $restoreReplay['replayed'] === true, 'Restore enqueue is not idempotent.');
    $restoreResult = $service->processNextRestore('phase8-worker');
    $assert(is_array($restoreResult) && $restoreResult['status'] === 'completed' && $adapter->restores === 1, 'Verified restore did not complete.');
    $crossAccountRejected = false;
    try {
        $service->enqueueRestore($otherAccountId, $snapshotId, 'REQ-P8-CROSS', 'IDEM-P8-CROSS');
    } catch (Throwable) {
        $crossAccountRejected = true;
    }
    $assert($crossAccountRejected, 'Cross-account restore was accepted.');

    $adapter->verifyNext = false;
    $failed = $service->enqueueBackup($accountId, 'pod', $deploymentId, 'on_demand', 'REQ-P8-FAIL', 'IDEM-P8-FAIL', $policy['policy_id']);
    $pdo->exec('UPDATE backup_jobs SET max_attempts=1 WHERE id=' . $failed['job_id']);
    $failedResult = $service->processNextBackup('phase8-worker');
    $assert(is_array($failedResult) && $failedResult['status'] === 'failed', 'Unverified backup was not failed.');
    $assert((int) $pdo->query("SELECT COUNT(*) FROM backup_snapshots WHERE backup_job_id={$failed['job_id']} AND status='verified'")->fetchColumn() === 0, 'Unverified snapshot was marked verified.');

    $retentionJobs = $service->applyRetention(10);
    $assert($retentionJobs >= 1, 'Retention did not queue deletion beyond the retained snapshot count.');
    $deleteResult = $service->processNextBackup('phase8-worker');
    $assert(is_array($deleteResult) && $deleteResult['status'] === 'completed' && $adapter->deletes >= 1, 'Retention deletion did not complete.');
    $assert((int) $pdo->query("SELECT COUNT(*) FROM backup_snapshots WHERE status='deleted' AND account_id={$accountId}")->fetchColumn() >= 1, 'Expired snapshot was not marked deleted after provider confirmation.');

    $warning = $service->observeStorage($accountId, 'pod', $deploymentId, 850, 1000, 'REQ-P8-STORAGE-WARNING');
    $assert($warning['alert_severity'] === 'warning', 'Warning storage threshold did not open an alert.');
    $critical = $service->observeStorage($accountId, 'pod', $deploymentId, 970, 1000, 'REQ-P8-STORAGE-CRITICAL');
    $assert($critical['alert_severity'] === 'critical', 'Critical storage threshold did not escalate the alert.');
    $resolved = $service->observeStorage($accountId, 'pod', $deploymentId, 500, 1000, 'REQ-P8-STORAGE-RESOLVED');
    $assert($resolved['alert_severity'] === null, 'Healthy storage observation still reported an alert.');
    $assert((int) $pdo->query("SELECT COUNT(*) FROM storage_alerts WHERE account_id={$accountId} AND status='resolved'")->fetchColumn() >= 1, 'Storage alert was not resolved after utilization recovered.');

    $forbiddenColumns = (int) $pdo->query(
        "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()
         AND TABLE_NAME LIKE 'backup_%' AND (COLUMN_NAME LIKE '%content%' OR COLUMN_NAME='provider_reference')"
    )->fetchColumn();
    $assert($forbiddenColumns === 0, 'Backup contents or plaintext provider references are represented in the VP3 database.');
} catch (Throwable $exception) {
    $failures[] = 'Unhandled Phase 8 integration exception: ' . $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 8 database certification failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 8 backup, restore, retention, and storage certification passed.\n");

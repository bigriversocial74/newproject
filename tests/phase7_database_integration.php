<?php

declare(strict_types=1);

use Vp3\Database;
use Vp3\Releases\ReleaseCatalogService;
use Vp3\Releases\ReleaseManifestSigner;
use Vp3\Updates\SoftwareUpdateAdapter;
use Vp3\Updates\SoftwareUpdateService;

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

final class Phase7UpdateAdapter implements SoftwareUpdateAdapter
{
    public bool $backupVerified = true;
    public bool $failVerificationOnce = true;
    /** @var list<string> */
    public array $stages = [];
    public int $rollbacks = 0;

    public function createPreUpdateBackup(array $target, array $release): array
    {
        $this->stages[] = 'backing_up';
        return [
            'reference' => 'backup://' . $target['public_id'] . '/' . $release['version'],
            'hash' => hash('sha256', 'backup-' . $target['public_id'] . '-' . $release['version']),
            'verified' => $this->backupVerified,
        ];
    }

    public function executeStage(string $stage, array $target, array $release, array $job): array
    {
        $this->stages[] = $stage;
        if ($stage === 'verifying' && $this->failVerificationOnce) {
            $this->failVerificationOnce = false;
            return ['verified' => false, 'provider_request_id' => 'verify-failed'];
        }
        return match ($stage) {
            'downloading' => ['artifact_sha256' => hash('sha256', 'artifact-' . $release['version'])],
            'migrating' => ['migration_count' => 2],
            'verifying' => ['verified' => true],
            default => ['provider_request_id' => 'stage-' . $stage],
        };
    }

    public function rollback(array $target, array $release, array $job): array
    {
        $this->rollbacks++;
        return ['restored' => true, 'provider_request_id' => 'rollback-' . $job['public_id']];
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
$keypair = sodium_crypto_sign_keypair();
$signer = new ReleaseManifestSigner(
    base64_encode(sodium_crypto_sign_secretkey($keypair)),
    base64_encode(sodium_crypto_sign_publickey($keypair)),
    'phase7-test-key'
);
$catalog = new ReleaseCatalogService($database, $signer);
$adapter = new Phase7UpdateAdapter();
$updates = new SoftwareUpdateService($database, $adapter);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

try {
    $token = strtolower(bin2hex(random_bytes(5)));
    $now = gmdate('Y-m-d H:i:s');
    $pdo->prepare("INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at) VALUES (:public,'individual','active',:name,:created,:updated)")
        ->execute(['public' => 'VP3-P7-' . strtoupper($token), 'name' => 'Phase Seven Account', 'created' => $now, 'updated' => $now]);
    $accountId = (int) $pdo->lastInsertId();
    $planId = (int) $pdo->query("SELECT id FROM plans WHERE code='standard' LIMIT 1")->fetchColumn();
    $pdo->prepare(
        "INSERT INTO subscriptions (public_id,account_id,plan_id,status,provider,provider_customer_id,provider_subscription_id,starts_at,current_period_starts_at,current_period_ends_at,created_at,updated_at)
         VALUES (:public,:account,:plan,'active','stripe',:customer,:external,:starts,:period_start,:period_end,:created,:updated)"
    )->execute([
        'public' => 'SUB-P7-' . strtoupper($token), 'account' => $accountId, 'plan' => $planId,
        'customer' => 'cus_p7_' . $token, 'external' => 'sub_p7_' . $token,
        'starts' => $now, 'period_start' => $now, 'period_end' => gmdate('Y-m-d H:i:s', time() + 2592000),
        'created' => $now, 'updated' => $now,
    ]);
    $subscriptionId = (int) $pdo->lastInsertId();
    $label = 'phase7-' . $token;
    $pdo->prepare(
        "INSERT INTO domain_registrations (public_id,account_id,subscription_id,label,hostname,status,routing_status,ssl_status,registered_at,created_at,updated_at)
         VALUES (:public,:account,:subscription,:label,:hostname,'active','active','active',:registered,:created,:updated)"
    )->execute([
        'public' => 'DOM-P7-' . strtoupper($token), 'account' => $accountId, 'subscription' => $subscriptionId,
        'label' => $label, 'hostname' => $label . '.vp3.me', 'registered' => $now, 'created' => $now, 'updated' => $now,
    ]);
    $domainId = (int) $pdo->lastInsertId();
    $pdo->prepare(
        'INSERT INTO entitlement_bundles (public_id,account_id,subscription_id,domain_registration_id,plan_id,snapshot_hash,created_at,updated_at)
         VALUES (:public,:account,:subscription,:domain,:plan,:snapshot,:created,:updated)'
    )->execute([
        'public' => 'BUNDLE-P7-' . strtoupper($token), 'account' => $accountId, 'subscription' => $subscriptionId,
        'domain' => $domainId, 'plan' => $planId, 'snapshot' => hash('sha256', 'bundle-' . $token),
        'created' => $now, 'updated' => $now,
    ]);
    $bundleId = (int) $pdo->lastInsertId();
    $pdo->prepare(
        "INSERT INTO licenses (public_id,account_id,subscription_id,domain_registration_id,entitlement_bundle_id,product_type,status,starts_at,created_at,updated_at)
         VALUES (:public,:account,:subscription,:domain,:bundle,'pod','active',:starts,:created,:updated)"
    )->execute([
        'public' => 'POD-LIC-P7-' . strtoupper($token), 'account' => $accountId, 'subscription' => $subscriptionId,
        'domain' => $domainId, 'bundle' => $bundleId, 'starts' => $now, 'created' => $now, 'updated' => $now,
    ]);
    $licenseId = (int) $pdo->lastInsertId();
    $pdo->prepare(
        "INSERT INTO pod_deployments (public_id,account_id,subscription_id,domain_registration_id,license_id,status,installation_fingerprint,installed_version,update_channel,storage_usage_bytes,storage_allowance_bytes,last_heartbeat_at,routing_status,ssl_status,backup_status,license_status,activated_at,created_at,updated_at)
         VALUES (:public,:account,:subscription,:domain,:license,'active',:fingerprint,'6.0.0','stable',0,1073741824,UTC_TIMESTAMP(),'active','active','verified','active',UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())"
    )->execute([
        'public' => 'POD-P7-' . strtoupper($token), 'account' => $accountId, 'subscription' => $subscriptionId,
        'domain' => $domainId, 'license' => $licenseId, 'fingerprint' => hash('sha256', 'pod-' . $token),
    ]);
    $deploymentId = (int) $pdo->lastInsertId();

    $productId = $catalog->ensureProduct('vp3-pod', 'VP3 POD', 'pod');
    $artifact = static fn (string $version): array => [[
        'platform' => 'linux', 'architecture' => 'x86_64',
        'storage_reference' => 'releases/pod/' . $version . '/pod.tar.gz',
        'sha256' => hash('sha256', 'artifact-' . $version), 'size_bytes' => 4096,
    ]];
    $compatibility = ['minimum_current_version' => '5.0.0', 'maximum_current_version' => '6.9.9', 'minimum_php_version' => '8.2.0', 'database_family' => 'any'];
    $draft = $catalog->createDraftRelease($productId, '7.0.0', 'stable', $artifact('7.0.0'), $compatibility, 100, false, 'Phase 7.0.0', 'REQ-P7-DRAFT');
    $signed = $catalog->publishRelease($draft['release_id'], 'REQ-P7-PUBLISH');
    $stored = $catalog->signedManifest($draft['release_id']);
    $assert($signed['manifest'] === $stored['manifest'] && $signed['signature'] === $stored['signature'], 'Exact immutable signed manifest was not retained.');
    $assert($signer->verify($stored['manifest'], $stored['signature']), 'Ed25519 release manifest verification failed.');

    $job = $updates->enqueue($accountId, 'pod', $deploymentId, $draft['release_id'], 'REQ-P7-UPDATE-1', 'IDEM-P7-UPDATE-1');
    $replay = $updates->enqueue($accountId, 'pod', $deploymentId, $draft['release_id'], 'REQ-P7-UPDATE-1-REPLAY', 'IDEM-P7-UPDATE-1');
    $assert($job['replayed'] === false && $replay['replayed'] === true, 'Update enqueue is not idempotent.');
    $result = $updates->processNext('phase7-worker');
    $assert(is_array($result) && $result['status'] === 'rolled_back', 'Failed verification did not trigger automatic rollback.');
    $assert($adapter->rollbacks === 1, 'Update rollback adapter was not called exactly once.');
    $assert($pdo->query('SELECT installed_version FROM pod_deployments WHERE id=' . $deploymentId)->fetchColumn() === '6.0.0', 'Rollback did not restore the previous version.');
    $assert((int) $pdo->query('SELECT pre_update_backup_verified FROM update_jobs WHERE id=' . $job['job_id'])->fetchColumn() === 1, 'Verified pre-update backup was not recorded.');

    $draft2 = $catalog->createDraftRelease($productId, '7.0.1', 'stable', $artifact('7.0.1'), $compatibility, 100, false, 'Phase 7.0.1', 'REQ-P7-DRAFT-2');
    $catalog->publishRelease($draft2['release_id'], 'REQ-P7-PUBLISH-2');
    $job2 = $updates->enqueue($accountId, 'pod', $deploymentId, $draft2['release_id'], 'REQ-P7-UPDATE-2', 'IDEM-P7-UPDATE-2');
    $result2 = $updates->processNext('phase7-worker');
    $assert(is_array($result2) && $result2['status'] === 'completed', 'Verified update did not complete.');
    $assert($pdo->query('SELECT installed_version FROM pod_deployments WHERE id=' . $deploymentId)->fetchColumn() === '7.0.1', 'Successful update did not synchronize installed version.');
    $assert((int) $pdo->query("SELECT COUNT(*) FROM update_steps WHERE job_id={$job2['job_id']} AND status='completed'")->fetchColumn() === 7, 'All ordered update stages were not completed.');

    $draft3 = $catalog->createDraftRelease($productId, '7.0.2', 'stable', $artifact('7.0.2'), ['minimum_current_version' => '7.0.0', 'maximum_current_version' => '7.9.9'], 100, false, 'Phase 7.0.2', 'REQ-P7-DRAFT-3');
    $catalog->publishRelease($draft3['release_id'], 'REQ-P7-PUBLISH-3');
    $adapter->backupVerified = false;
    $job3 = $updates->enqueue($accountId, 'pod', $deploymentId, $draft3['release_id'], 'REQ-P7-UPDATE-3', 'IDEM-P7-UPDATE-3');
    $beforeInstallCalls = count(array_keys($adapter->stages, 'installing', true));
    $result3 = $updates->processNext('phase7-worker');
    $assert(is_array($result3) && $result3['status'] === 'failed', 'Unverified backup did not fail the update.');
    $assert(count(array_keys($adapter->stages, 'installing', true)) === $beforeInstallCalls, 'Installation started without a verified backup.');
    $adapter->backupVerified = true;

    $zero = $catalog->createDraftRelease($productId, '7.1.0', 'stable', $artifact('7.1.0'), ['minimum_current_version' => '7.0.0'], 0, false, 'Zero rollout', 'REQ-P7-ZERO');
    $catalog->publishRelease($zero['release_id'], 'REQ-P7-ZERO-PUBLISH');
    $outsideRejected = false;
    try {
        $updates->enqueue($accountId, 'pod', $deploymentId, $zero['release_id'], 'REQ-P7-ZERO-UPDATE', 'IDEM-P7-ZERO');
    } catch (Throwable) {
        $outsideRejected = true;
    }
    $assert($outsideRejected, 'Target outside a zero-percent rollout cohort was accepted.');

    $security = $catalog->createDraftRelease($productId, '7.1.1', 'security', $artifact('7.1.1'), ['minimum_current_version' => '7.0.0'], 0, true, 'Emergency security release', 'REQ-P7-SECURITY');
    $catalog->publishRelease($security['release_id'], 'REQ-P7-SECURITY-PUBLISH');
    $securityJob = $updates->enqueue($accountId, 'pod', $deploymentId, $security['release_id'], 'REQ-P7-SECURITY-UPDATE', 'IDEM-P7-SECURITY');
    $assert($securityJob['replayed'] === false, 'Emergency security release did not bypass staged rollout safely.');

    $beta = $catalog->createDraftRelease($productId, '8.0.0-beta.1', 'beta', $artifact('8.0.0-beta.1'), ['minimum_current_version' => '7.0.0'], 100, false, 'Beta release', 'REQ-P7-BETA');
    $catalog->publishRelease($beta['release_id'], 'REQ-P7-BETA-PUBLISH');
    $betaRejected = false;
    try {
        $updates->enqueue($accountId, 'pod', $deploymentId, $beta['release_id'], 'REQ-P7-BETA-UPDATE', 'IDEM-P7-BETA');
    } catch (Throwable) {
        $betaRejected = true;
    }
    $assert($betaRejected, 'Stable target accepted a beta release.');
} catch (Throwable $exception) {
    $failures[] = 'Unhandled Phase 7 integration exception: ' . $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 7 database certification failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 7 signed release and update lifecycle certification passed.\n");

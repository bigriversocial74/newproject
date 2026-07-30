<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\Database;
use Vp3\DomainCodes\DomainRegistryService;
use Vp3\Lifecycle\DomainPodLifecycleActionService;
use Vp3\Lifecycle\DomainPodLifecycleQueryService;
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
    $lower = strtolower($token);
    $now = gmdate('Y-m-d H:i:s');
    $periodEnd = gmdate('Y-m-d H:i:s', time() + 2592000);
    $passwordHash = password_hash('Phase21-Lifecycle!42', PASSWORD_DEFAULT);
    if (!is_string($passwordHash)) {
        throw new RuntimeException('Unable to hash the Phase 21 password.');
    }
    $planId = (int) $pdo->query("SELECT id FROM plans WHERE code='standard' LIMIT 1")->fetchColumn();
    if ($planId < 1) {
        throw new RuntimeException('VP3 Standard plan seed is missing.');
    }

    $createAccount = static function (string $suffix) use ($pdo, $token, $now): int {
        $pdo->prepare(
            "INSERT INTO accounts
             (public_id,account_type,status,display_name,created_at,updated_at)
             VALUES (:public,'organization','active',:name,:created,:updated)"
        )->execute([
            'public' => 'VP3-P21-' . $token . '-' . $suffix,
            'name' => 'Phase 21 ' . $suffix,
            'created' => $now,
            'updated' => $now,
        ]);
        return (int) $pdo->lastInsertId();
    };

    $createUser = static function (string $suffix) use ($pdo, $token, $now, $passwordHash): array {
        $email = strtolower('phase21-' . $token . '-' . $suffix . '@example.test');
        $pdo->prepare(
            "INSERT INTO users
             (public_id,email,email_normalized,password_hash,display_name,status,email_verified_at,created_at,updated_at)
             VALUES (:public,:email,:normalized,:password,:name,'active',:verified,:created,:updated)"
        )->execute([
            'public' => 'USER-P21-' . $token . '-' . strtoupper($suffix),
            'email' => $email,
            'normalized' => $email,
            'password' => $passwordHash,
            'name' => 'Phase 21 ' . $suffix,
            'verified' => $now,
            'created' => $now,
            'updated' => $now,
        ]);
        return ['id' => (int) $pdo->lastInsertId(), 'email' => $email];
    };

    $membership = static function (int $accountId, int $userId, string $role) use ($pdo, $now): void {
        $pdo->prepare(
            "INSERT INTO account_users
             (account_id,user_id,role,status,created_at,updated_at)
             VALUES (:account,:user,:role,'active',:created,:updated)"
        )->execute([
            'account' => $accountId,
            'user' => $userId,
            'role' => $role,
            'created' => $now,
            'updated' => $now,
        ]);
    };

    $createSubscription = static function (int $accountId, string $suffix) use ($pdo, $token, $now, $periodEnd, $planId): array {
        $publicId = 'SUB-P21-' . $token . '-' . $suffix;
        $pdo->prepare(
            "INSERT INTO subscriptions
             (public_id,account_id,plan_id,status,provider,provider_customer_id,provider_subscription_id,
              starts_at,current_period_starts_at,current_period_ends_at,created_at,updated_at)
             VALUES
             (:public,:account,:plan,'active','stripe',:customer,:provider_subscription,
              :starts,:period_start,:period_end,:created,:updated)"
        )->execute([
            'public' => $publicId,
            'account' => $accountId,
            'plan' => $planId,
            'customer' => 'cus_p21_' . strtolower($token . $suffix),
            'provider_subscription' => 'sub_p21_' . strtolower($token . $suffix),
            'starts' => $now,
            'period_start' => $now,
            'period_end' => $periodEnd,
            'created' => $now,
            'updated' => $now,
        ]);
        return ['id' => (int) $pdo->lastInsertId(), 'public_id' => $publicId];
    };

    $accountA = $createAccount('A');
    $accountB = $createAccount('B');
    $ownerA = $createUser('owner-a');
    $supportA = $createUser('support-a');
    $billingA = $createUser('billing-a');
    $ownerB = $createUser('owner-b');
    $membership($accountA, $ownerA['id'], 'customer_owner');
    $membership($accountA, $supportA['id'], 'support_member');
    $membership($accountA, $billingA['id'], 'billing_manager');
    $membership($accountB, $ownerB['id'], 'customer_owner');
    $subscriptionA = $createSubscription($accountA, 'A');
    $subscriptionB = $createSubscription($accountB, 'B');

    $adapter = new class implements PodProvisioningAdapter {
        public function executeStage(string $stage, array $deployment): array { return ['completed' => true, 'stage' => $stage]; }
        public function rollbackStage(string $stage, array $deployment): array { return ['completed' => true, 'stage' => $stage]; }
        public function readConfiguration(array $deployment): array { return []; }
        public function buildConfiguration(array $deployment): array { return []; }
        public function writeConfiguration(array $deployment, array $configuration): array { return ['written' => true]; }
    };
    $domainRegistry = new DomainRegistryService($database);
    $podProvisioning = new PodProvisioningService(
        $database,
        $adapter,
        new ProtectedConfigurationMerger(),
        ['database.password', 'app.key', 'customer'],
        30
    );
    $actions = new DomainPodLifecycleActionService($database, $domainRegistry, $podProvisioning);
    $query = new DomainPodLifecycleQueryService($database);

    $availability = $actions->availability($accountA, $ownerA['id'], 'customer_owner', 'p21-' . $lower . '-one');
    $assert($availability['available'] === true, 'Owner could not check Domain availability.');

    $domainOne = $actions->registerDomain(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        $subscriptionA['public_id'],
        'p21-' . $lower . '-one',
        'REQ-P21-DOMAIN1-' . $token,
        'IDEM-P21-DOMAIN1-' . $token
    );
    $domainOneReplay = $actions->registerDomain(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        $subscriptionA['public_id'],
        'p21-' . $lower . '-one',
        'REQ-P21-DOMAIN1-R-' . $token,
        'IDEM-P21-DOMAIN1-' . $token
    );
    $assert($domainOneReplay['domain_public_id'] === $domainOne['domain_public_id'], 'Domain registration replay changed public identity.');
    $assert(!array_key_exists('domain_id', $domainOne) && !array_key_exists('pod_license_id', $domainOne), 'Domain result exposed internal IDs.');

    $expectCode(
        fn () => $actions->registerDomain(
            $accountA,
            $ownerA['id'],
            'customer_admin',
            $subscriptionA['public_id'],
            'p21-' . $lower . '-stale',
            'REQ-P21-STALE-' . $token,
            'IDEM-P21-STALE-' . $token
        ),
        'lifecycle_permission_denied',
        'Stale caller role was accepted for Domain registration.'
    );
    $expectCode(
        fn () => $actions->registerDomain(
            $accountA,
            $supportA['id'],
            'support_member',
            $subscriptionA['public_id'],
            'p21-' . $lower . '-support',
            'REQ-P21-SUPPORT-' . $token,
            'IDEM-P21-SUPPORT-' . $token
        ),
        'lifecycle_permission_denied',
        'Support member was accepted for Domain registration.'
    );
    $expectCode(
        fn () => $actions->registerDomain(
            $accountA,
            $billingA['id'],
            'billing_manager',
            $subscriptionA['public_id'],
            'p21-' . $lower . '-billing',
            'REQ-P21-BILLING-' . $token,
            'IDEM-P21-BILLING-' . $token
        ),
        'lifecycle_permission_denied',
        'Billing manager was accepted for Domain registration.'
    );
    $deniedAudit = $pdo->prepare(
        "SELECT COUNT(*) FROM audit_events
         WHERE account_id=:account AND result='denied'
           AND request_id IN (:stale,:support,:billing)"
    );
    $deniedAudit->execute([
        'account' => $accountA,
        'stale' => 'REQ-P21-STALE-' . $token,
        'support' => 'REQ-P21-SUPPORT-' . $token,
        'billing' => 'REQ-P21-BILLING-' . $token,
    ]);
    $assert((int) $deniedAudit->fetchColumn() === 3, 'Unauthorized lifecycle attempts did not persist audit evidence.');

    $expectCode(
        fn () => $actions->registerDomain(
            $accountA,
            $ownerA['id'],
            'customer_owner',
            $subscriptionB['public_id'],
            'p21-' . $lower . '-cross',
            'REQ-P21-CROSS-' . $token,
            'IDEM-P21-CROSS-' . $token
        ),
        'lifecycle_subscription_not_found',
        'Cross-account subscription registration was accepted.'
    );

    $suspended = $actions->suspendDomain(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        $domainOne['domain_public_id'],
        'Phase 21 lifecycle test',
        'REQ-P21-SUSPEND-' . $token,
        'IDEM-P21-SUSPEND-' . $token
    );
    $assert($suspended['status'] === 'suspended', 'Domain suspension did not complete.');
    $expectCode(
        fn () => $actions->releaseDomain(
            $accountA,
            $ownerA['id'],
            'customer_owner',
            $domainOne['domain_public_id'],
            'DELETE',
            'REQ-P21-RELEASE-BAD-' . $token,
            'IDEM-P21-RELEASE-BAD-' . $token
        ),
        'lifecycle_release_confirmation_required',
        'Domain release accepted an incorrect confirmation.'
    );
    $released = $actions->releaseDomain(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        $domainOne['domain_public_id'],
        'RELEASE',
        'REQ-P21-RELEASE-' . $token,
        'IDEM-P21-RELEASE-' . $token
    );
    $assert($released['status'] === 'released', 'Confirmed Domain release did not complete.');

    $domainTwo = $actions->registerDomain(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        $subscriptionA['public_id'],
        'p21-' . $lower . '-two',
        'REQ-P21-DOMAIN2-' . $token,
        'IDEM-P21-DOMAIN2-' . $token
    );
    $provision = $actions->provisionPod(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        $domainTwo['domain_public_id'],
        'REQ-P21-PROVISION-' . $token,
        'IDEM-P21-PROVISION-' . $token
    );
    $provisionReplay = $actions->provisionPod(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        $domainTwo['domain_public_id'],
        'REQ-P21-PROVISION-R-' . $token,
        'IDEM-P21-PROVISION-' . $token
    );
    $assert($provisionReplay['replayed'] === true && $provisionReplay['job_public_id'] === $provision['job_public_id'],
        'POD provisioning replay is incorrect.');
    $expectCode(
        fn () => $actions->provisionPod(
            $accountA,
            $ownerA['id'],
            'customer_owner',
            $domainTwo['domain_public_id'],
            'REQ-P21-PROVISION-DUP-' . $token,
            'IDEM-P21-PROVISION-DUP-' . $token
        ),
        'lifecycle_pod_already_exists',
        'A second POD deployment was accepted for the Domain.'
    );

    $paused = $actions->transitionPodJob(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        $provision['job_public_id'],
        'pause',
        'REQ-P21-PAUSE-' . $token
    );
    $resumed = $actions->transitionPodJob(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        $provision['job_public_id'],
        'resume',
        'REQ-P21-RESUME-' . $token
    );
    $assert($paused['status'] === 'paused' && $resumed['status'] === 'retrying', 'POD pause/resume transitions are incorrect.');

    $jobIdStatement = $pdo->prepare('SELECT id,deployment_id FROM pod_provisioning_jobs WHERE public_id=:public AND account_id=:account');
    $jobIdStatement->execute(['public' => $provision['job_public_id'], 'account' => $accountA]);
    $jobRow = $jobIdStatement->fetch(PDO::FETCH_ASSOC);
    if (!is_array($jobRow)) {
        throw new RuntimeException('Provisioning job fixture was not found.');
    }
    $pdo->prepare("UPDATE pod_provisioning_jobs SET status='failed',updated_at=UTC_TIMESTAMP() WHERE id=:id")
        ->execute(['id' => $jobRow['id']]);
    $retried = $actions->transitionPodJob(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        $provision['job_public_id'],
        'retry',
        'REQ-P21-RETRY-' . $token
    );
    $assert($retried['status'] === 'retrying', 'POD retry transition did not complete.');

    $expectCode(
        fn () => $actions->transitionPodJob(
            $accountA,
            $supportA['id'],
            'support_member',
            $provision['job_public_id'],
            'pause',
            'REQ-P21-POD-SUPPORT-' . $token
        ),
        'lifecycle_permission_denied',
        'Support member was accepted for a POD job transition.'
    );
    $expectCode(
        fn () => $actions->transitionPodJob(
            $accountB,
            $ownerB['id'],
            'customer_owner',
            $provision['job_public_id'],
            'pause',
            'REQ-P21-POD-CROSS-' . $token
        ),
        'lifecycle_pod_job_not_found',
        'Cross-account POD job transition was accepted.'
    );

    $expectCode(
        fn () => $actions->rollbackPod(
            $accountA,
            $ownerA['id'],
            'customer_owner',
            $provision['deployment_public_id'],
            'ROLLBACK',
            'REQ-P21-ROLLBACK-OPEN-' . $token,
            'IDEM-P21-ROLLBACK-OPEN-' . $token
        ),
        'lifecycle_pod_job_open',
        'Rollback was queued while another POD lifecycle job remained open.'
    );
    $expectCode(
        fn () => $actions->rollbackPod(
            $accountA,
            $ownerA['id'],
            'customer_owner',
            $provision['deployment_public_id'],
            'DELETE',
            'REQ-P21-ROLLBACK-BAD-' . $token,
            'IDEM-P21-ROLLBACK-BAD-' . $token
        ),
        'lifecycle_rollback_confirmation_required',
        'POD rollback accepted an incorrect confirmation.'
    );

    $pdo->prepare(
        "UPDATE pod_provisioning_jobs
         SET status='completed',current_stage='deployment_active',completed_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP()
         WHERE id=:id"
    )->execute(['id' => $jobRow['id']]);
    $pdo->prepare(
        "UPDATE pod_deployments
         SET status='active',routing_status='active',ssl_status='active',backup_status='verified',
             license_status='active',activated_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP()
         WHERE id=:id"
    )->execute(['id' => $jobRow['deployment_id']]);

    $rollback = $actions->rollbackPod(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        $provision['deployment_public_id'],
        'ROLLBACK',
        'REQ-P21-ROLLBACK-' . $token,
        'IDEM-P21-ROLLBACK-' . $token
    );
    $rollbackReplay = $actions->rollbackPod(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        $provision['deployment_public_id'],
        'ROLLBACK',
        'REQ-P21-ROLLBACK-R-' . $token,
        'IDEM-P21-ROLLBACK-' . $token
    );
    $assert($rollback['status'] === 'queued' && $rollbackReplay['replayed'] === true
        && $rollbackReplay['job_public_id'] === $rollback['job_public_id'],
        'POD rollback replay is incorrect.');
    $expectCode(
        fn () => $actions->rollbackPod(
            $accountA,
            $ownerA['id'],
            'customer_owner',
            $provision['deployment_public_id'],
            'ROLLBACK',
            'REQ-P21-ROLLBACK-DUP-' . $token,
            'IDEM-P21-ROLLBACK-DUP-' . $token
        ),
        'lifecycle_pod_job_open',
        'A second rollback was queued while rollback remained open.'
    );

    $snapshotA = $query->snapshot($accountA);
    $snapshotB = $query->snapshot($accountB);
    $assert(count($snapshotA['subscriptions']) === 1, 'Lifecycle snapshot omitted the account subscription.');
    $assert(count($snapshotA['domains']) === 2, 'Lifecycle snapshot omitted account Domains.');
    $assert(count($snapshotA['pods']) === 1, 'Lifecycle snapshot omitted the POD deployment.');
    $assert(count($snapshotB['domains']) === 0 && count($snapshotB['pods']) === 0,
        'Cross-account lifecycle data leaked into another account.');

    $walk = static function (mixed $value) use (&$walk, $assert): void {
        if (!is_array($value)) {
            return;
        }
        foreach ($value as $key => $item) {
            $assert(!in_array((string) $key, [
                'id', 'source_id', 'last_error_code', 'last_error_message', 'installation_fingerprint',
                'hosting_reference', 'database_reference', 'locked_by', 'lease_token', 'metadata_json',
            ], true), 'Lifecycle snapshot exposed forbidden key ' . $key . '.');
            $walk($item);
        }
    };
    $walk($snapshotA);
    $snapshotJson = json_encode($snapshotA, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    $assert(!str_contains($snapshotJson, 'Phase21-Lifecycle!42'), 'Authentication data leaked into the lifecycle snapshot.');
} catch (Throwable $exception) {
    $failures[] = 'Unhandled Phase 21 lifecycle exception: ' . $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 21 Domain/POD lifecycle database failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 21 Domain/POD lifecycle database certification passed.\n");

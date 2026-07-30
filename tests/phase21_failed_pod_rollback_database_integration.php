<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\Database;
use Vp3\Lifecycle\PodRollbackLifecycleService;
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
    $accountId = (int) $pdo->query(
        "SELECT id FROM accounts
         WHERE public_id LIKE 'VP3-P21-%-A'
         ORDER BY id DESC LIMIT 1"
    )->fetchColumn();
    if ($accountId < 1) {
        throw new RuntimeException('The Phase 21 lifecycle fixture must run before failed rollback proof.');
    }

    $ownerStatement = $pdo->prepare(
        "SELECT user_id,role FROM account_users
         WHERE account_id=:account AND status='active' AND role='customer_owner'
         ORDER BY user_id LIMIT 1"
    );
    $ownerStatement->execute(['account' => $accountId]);
    $owner = $ownerStatement->fetch(PDO::FETCH_ASSOC);
    if (!is_array($owner)) {
        throw new RuntimeException('The Phase 21 owner fixture was not found.');
    }

    $deploymentStatement = $pdo->prepare(
        'SELECT id,public_id FROM pod_deployments
         WHERE account_id=:account ORDER BY id DESC LIMIT 1'
    );
    $deploymentStatement->execute(['account' => $accountId]);
    $deployment = $deploymentStatement->fetch(PDO::FETCH_ASSOC);
    if (!is_array($deployment)) {
        throw new RuntimeException('The Phase 21 POD fixture was not found.');
    }

    $pdo->prepare(
        "UPDATE pod_provisioning_jobs
         SET status='completed',current_stage=COALESCE(current_stage,'completed'),
             completed_at=COALESCE(completed_at,UTC_TIMESTAMP()),locked_at=NULL,locked_by=NULL,
             locked_until=NULL,lease_token=NULL,updated_at=UTC_TIMESTAMP()
         WHERE account_id=:account AND deployment_id=:deployment"
    )->execute(['account' => $accountId, 'deployment' => $deployment['id']]);

    $failedJobPublicId = 'POD-JOB-P21-FAILED-' . strtoupper(bin2hex(random_bytes(8)));
    $failedIdempotency = 'IDEM-P21-FAILED-' . strtoupper(bin2hex(random_bytes(8)));
    $failedRequest = 'REQ-P21-FAILED-' . strtoupper(bin2hex(random_bytes(8)));
    $pdo->prepare(
        "INSERT INTO pod_provisioning_jobs
         (public_id,deployment_id,account_id,job_type,status,current_stage,attempts,max_attempts,
          idempotency_key,request_id,available_at,started_at,last_error_code,last_error_message,
          created_at,updated_at)
         VALUES
         (:public,:deployment,:account,'provision','failed','verify',1,5,:idempotency,:request,
          UTC_TIMESTAMP(),UTC_TIMESTAMP(),'provider_failed','Synthetic test failure',UTC_TIMESTAMP(),UTC_TIMESTAMP())"
    )->execute([
        'public' => $failedJobPublicId,
        'deployment' => $deployment['id'],
        'account' => $accountId,
        'idempotency' => $failedIdempotency,
        'request' => $failedRequest,
    ]);
    $failedJobId = (int) $pdo->lastInsertId();

    $adapter = new class implements PodProvisioningAdapter {
        public function executeStage(string $stage, array $deployment): array { return ['completed' => true, 'stage' => $stage]; }
        public function rollbackStage(string $stage, array $deployment): array { return ['completed' => true, 'stage' => $stage]; }
        public function readConfiguration(array $deployment): array { return []; }
        public function buildConfiguration(array $deployment): array { return []; }
        public function writeConfiguration(array $deployment, array $configuration): array { return ['written' => true]; }
    };
    $podProvisioning = new PodProvisioningService(
        $database,
        $adapter,
        new ProtectedConfigurationMerger(),
        ['database.password', 'app.key', 'customer'],
        30
    );
    $service = new PodRollbackLifecycleService($database, $podProvisioning);
    $suffix = strtoupper(bin2hex(random_bytes(6)));

    $expectCode(
        fn () => $service->enqueue(
            $accountId,
            (int) $owner['user_id'],
            'customer_admin',
            (string) $deployment['public_id'],
            'ROLLBACK',
            'REQ-P21-ROLLBACK-STALE-' . $suffix,
            'IDEM-P21-ROLLBACK-STALE-' . $suffix
        ),
        'lifecycle_permission_denied',
        'Stale caller role was accepted for failed-job rollback replacement.'
    );
    $audit = $pdo->prepare(
        "SELECT COUNT(*) FROM audit_events
         WHERE account_id=:account AND actor_id=:actor AND request_id=:request AND result='denied'"
    );
    $audit->execute([
        'account' => $accountId,
        'actor' => $owner['user_id'],
        'request' => 'REQ-P21-ROLLBACK-STALE-' . $suffix,
    ]);
    $assert((int) $audit->fetchColumn() === 1, 'Stale-role rollback denial did not persist audit evidence.');

    $expectCode(
        fn () => $service->enqueue(
            $accountId,
            (int) $owner['user_id'],
            (string) $owner['role'],
            (string) $deployment['public_id'],
            'DELETE',
            'REQ-P21-ROLLBACK-CONFIRM-' . $suffix,
            'IDEM-P21-ROLLBACK-CONFIRM-' . $suffix
        ),
        'lifecycle_rollback_confirmation_required',
        'Failed-job rollback accepted an incorrect confirmation.'
    );

    $queued = $service->enqueue(
        $accountId,
        (int) $owner['user_id'],
        (string) $owner['role'],
        (string) $deployment['public_id'],
        'ROLLBACK',
        'REQ-P21-ROLLBACK-REPLACE-' . $suffix,
        'IDEM-P21-ROLLBACK-REPLACE-' . $suffix
    );
    $assert($queued['status'] === 'queued' && $queued['replaced_failed_jobs'] >= 1,
        'Failed POD job was not atomically replaced by rollback.');

    $failedStatus = $pdo->prepare('SELECT status FROM pod_provisioning_jobs WHERE id=:id');
    $failedStatus->execute(['id' => $failedJobId]);
    $assert($failedStatus->fetchColumn() === 'canceled', 'Replaced failed POD job was not canceled.');

    $replay = $service->enqueue(
        $accountId,
        (int) $owner['user_id'],
        (string) $owner['role'],
        (string) $deployment['public_id'],
        'ROLLBACK',
        'REQ-P21-ROLLBACK-REPLAY-' . $suffix,
        'IDEM-P21-ROLLBACK-REPLACE-' . $suffix
    );
    $assert($replay['replayed'] === true && $replay['job_public_id'] === $queued['job_public_id'],
        'Failed-job rollback replay changed job identity.');

    $expectCode(
        fn () => $service->enqueue(
            $accountId,
            (int) $owner['user_id'],
            (string) $owner['role'],
            (string) $deployment['public_id'],
            'ROLLBACK',
            'REQ-P21-ROLLBACK-OPEN2-' . $suffix,
            'IDEM-P21-ROLLBACK-OPEN2-' . $suffix
        ),
        'lifecycle_pod_job_open',
        'A second rollback was queued while replacement rollback remained active.'
    );

    $open = $pdo->prepare(
        "SELECT COUNT(*) FROM pod_provisioning_jobs
         WHERE account_id=:account AND deployment_id=:deployment
           AND status IN ('queued','running','waiting','retrying','paused')"
    );
    $open->execute(['account' => $accountId, 'deployment' => $deployment['id']]);
    $assert((int) $open->fetchColumn() === 1, 'More than one active POD lifecycle job remains after failed-job replacement.');
} catch (Throwable $exception) {
    $failures[] = 'Unhandled failed POD rollback exception: ' . $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 21 failed POD rollback failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 21 failed POD rollback certification passed.\n");

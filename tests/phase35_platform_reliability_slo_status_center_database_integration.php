<?php

declare(strict_types=1);

use Vp3\Database;
use Vp3\Deployment\PlatformOperatorAuthorizer;
use Vp3\Operations\NullOperationalNotificationAdapter;
use Vp3\Operations\OperationalAuditService;
use Vp3\Operations\OperationalIncidentService;
use Vp3\Operations\OperationalNotificationService;
use Vp3\Operations\OperationsSecretCipher;
use Vp3\Reliability\ReliabilityControlCenterActionService;
use Vp3\Reliability\ReliabilityControlCenterQueryService;
use Vp3\Reliability\ReliabilityProbeExecutor;
use Vp3\Reliability\ReliabilityWorkerService;

$root = dirname(__DIR__);
$autoload = $root . '/vendor/autoload.php';
if (is_file($autoload)) {
    require $autoload;
} else {
    spl_autoload_register(static function (string $class) use ($root): void {
        $prefix = 'Vp3\\';
        if (!str_starts_with($class, $prefix)) return;
        $path = $root . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($path)) require $path;
    });
}

$dsn = (string) (getenv('VP3_TEST_DSN') ?: '');
if ($dsn === '') {
    fwrite(STDOUT, "Phase 35 reliability database integration skipped.\n");
    exit(0);
}
$config = [
    'dsn' => $dsn,
    'username' => (string) (getenv('VP3_TEST_DB_USER') ?: ''),
    'password' => (string) (getenv('VP3_TEST_DB_PASSWORD') ?: ''),
    'options' => [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ],
];
$database = new Database($config);
$pdo = $database->pdo();
$suffix = strtolower(bin2hex(random_bytes(5)));
$now = gmdate('Y-m-d H:i:s');
$accountPublicId = 'ACC-R35-' . strtoupper(bin2hex(random_bytes(6)));
$userPublicId = 'USR-R35-' . strtoupper(bin2hex(random_bytes(6)));
$email = 'phase35-' . $suffix . '@example.test';
$accountId = 0;
$userId = 0;

$assert = static function (bool $condition, string $message): void {
    if (!$condition) throw new RuntimeException($message);
};
$setDue = static function () use ($pdo): void {
    $pdo->exec("UPDATE reliability_probes SET next_due_at=UTC_TIMESTAMP(6),locked_by_hash=NULL,lock_expires_at=NULL");
};

try {
    $pdo->prepare(
        "INSERT INTO accounts
         (public_id,account_type,status,display_name,legal_name,created_at,updated_at)
         VALUES (:public_id,'organization','active','Phase 35 Operators',NULL,:created,:updated)"
    )->execute(['public_id' => $accountPublicId, 'created' => $now, 'updated' => $now]);
    $accountId = (int) $pdo->lastInsertId();

    $pdo->prepare(
        "INSERT INTO users
         (public_id,email,email_normalized,password_hash,display_name,status,email_verified_at,last_login_at,created_at,updated_at)
         VALUES (:public_id,:email,:normalized,:password_hash,'Phase 35 Owner','active',:verified,NULL,:created,:updated)"
    )->execute([
        'public_id' => $userPublicId,
        'email' => $email,
        'normalized' => $email,
        'password_hash' => password_hash('StrongPhase35Password!', PASSWORD_DEFAULT),
        'verified' => $now,
        'created' => $now,
        'updated' => $now,
    ]);
    $userId = (int) $pdo->lastInsertId();
    $pdo->prepare(
        "INSERT INTO account_users (account_id,user_id,role,status,created_at,updated_at)
         VALUES (:account_id,:user_id,'customer_owner','active',:created,:updated)"
    )->execute(['account_id' => $accountId, 'user_id' => $userId, 'created' => $now, 'updated' => $now]);
    $pdo->prepare(
        "INSERT INTO platform_operator_accounts
         (public_id,account_scope,operator_status,granted_by_user_id,granted_at,created_at,updated_at)
         VALUES (:public_id,:account_id,'active',:user_id,:granted,:created,:updated)"
    )->execute([
        'public_id' => 'POP-' . strtoupper(bin2hex(random_bytes(10))),
        'account_id' => $accountId,
        'user_id' => $userId,
        'granted' => $now,
        'created' => $now,
        'updated' => $now,
    ]);
} catch (PDOException $exception) {
    if ($accountId > 0) $pdo->prepare('DELETE FROM accounts WHERE id=:id')->execute(['id' => $accountId]);
    if ($userId > 0) $pdo->prepare('DELETE FROM users WHERE id=:id')->execute(['id' => $userId]);
    throw $exception;
}

$createdEnvironment = false;
$environmentPublicId = $pdo->query(
    "SELECT public_id FROM platform_deployment_environments WHERE environment_key='production' LIMIT 1"
)->fetchColumn();
if (!is_string($environmentPublicId)) {
    $createdEnvironment = true;
    $environmentPublicId = 'ENV-' . strtoupper(bin2hex(random_bytes(10)));
    $pdo->prepare(
        "INSERT INTO platform_deployment_environments
         (public_id,environment_key,display_name,base_url,environment_status,readiness_status,
          current_candidate_id,config_fingerprint,readiness_evidence_hash,worker_id_hash,
          worker_last_seen_at,last_health_at,created_by_user_id,created_at,updated_at)
         VALUES (:public_id,'production','Phase 35 Production','https://status.example.test','active','ready',
                 NULL,:fingerprint,:evidence,:worker_hash,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6),:user_id,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))"
    )->execute([
        'public_id' => $environmentPublicId,
        'fingerprint' => hash('sha256', 'phase35-environment-' . $suffix),
        'evidence' => hash('sha256', 'phase35-ready-' . $suffix),
        'worker_hash' => hash('sha256', 'phase35-release-worker'),
        'user_id' => $userId,
    ]);
}

try {
    $authorizer = new PlatformOperatorAuthorizer($database);
    $audit = new OperationalAuditService($database);
    $cipher = new OperationsSecretCipher(base64_encode(random_bytes(32)), 'phase35-test-operations');
    $notifications = new OperationalNotificationService(
        $database,
        $cipher,
        new NullOperationalNotificationAdapter(),
        $audit,
        60
    );
    $incidents = new OperationalIncidentService($database, $audit, $notifications);

    $sequence = [
        ['status' => 'failure', 'latency_ms' => 900, 'error_code' => 'synthetic_failure_1', 'evidence' => ['case' => 1]],
        ['status' => 'failure', 'latency_ms' => 950, 'error_code' => 'synthetic_failure_2', 'evidence' => ['case' => 2]],
        ['status' => 'success', 'latency_ms' => 120, 'value_numeric' => 1, 'evidence' => ['case' => 3]],
        ['status' => 'success', 'latency_ms' => 110, 'value_numeric' => 1, 'evidence' => ['case' => 4]],
    ];
    $executor = new ReliabilityProbeExecutor(
        $database,
        $root,
        static function (array $probe) use (&$sequence): array {
            if ($sequence === []) throw new RuntimeException('Unexpected extra probe execution.');
            return array_shift($sequence);
        }
    );
    $worker = new ReliabilityWorkerService($database, $executor, $incidents, 60);
    $actions = new ReliabilityControlCenterActionService($database, $authorizer, $worker);
    $query = new ReliabilityControlCenterQueryService($database, $authorizer);

    $componentRequest = 'phase35-component-' . $suffix;
    $component = $actions->saveComponent(
        $accountId,
        $userId,
        'customer_owner',
        null,
        'platform-api-' . $suffix,
        'VP3 Platform API',
        'platform',
        'public',
        $environmentPublicId,
        true,
        10,
        $componentRequest
    );
    $assert(str_starts_with((string) $component['public_id'], 'REL-CMP-'), 'Component public identity was not created.');
    $assert(!array_key_exists('id', $component), 'Component response exposed an internal database ID.');
    $componentReplay = $actions->saveComponent(
        $accountId,
        $userId,
        'customer_owner',
        null,
        'platform-api-' . $suffix,
        'VP3 Platform API',
        'platform',
        'public',
        $environmentPublicId,
        true,
        10,
        $componentRequest
    );
    $assert($componentReplay['public_id'] === $component['public_id'], 'Component request replay did not return the original component.');
    try {
        $actions->saveComponent(
            $accountId, $userId, 'customer_owner', null, 'platform-api-' . $suffix,
            'Changed Name', 'platform', 'public', $environmentPublicId, true, 10, $componentRequest
        );
        throw new RuntimeException('Conflicting component request replay was accepted.');
    } catch (RuntimeException $exception) {
        $assert($exception->getMessage() === 'reliability_request_conflict', 'Unexpected component request conflict result.');
    }

    $objective = $actions->saveObjective(
        $accountId,
        $userId,
        'customer_owner',
        (string) $component['public_id'],
        9990,
        500,
        43200,
        2.0,
        14.4,
        2,
        2,
        'phase35-objective-' . $suffix
    );
    $assert((int) $objective['consecutive_failure_threshold'] === 2, 'Reliability failure threshold was not saved.');

    $probe = $actions->saveProbe(
        $accountId,
        $userId,
        'customer_owner',
        (string) $component['public_id'],
        null,
        'database',
        'primary',
        60,
        1000,
        true,
        'phase35-probe-' . $suffix
    );
    $assert(str_starts_with((string) $probe['public_id'], 'REL-PRB-'), 'Probe public identity was not created.');
    $assert(!array_key_exists('target_value', $probe) && !array_key_exists('id', $probe), 'Probe response exposed protected target or internal identity.');

    $first = $worker->processNext('phase35-worker');
    $assert(is_array($first) && $first['status'] === 'unknown', 'A single failed probe caused a false reliability incident.');
    $openCount = (int) $pdo->query("SELECT COUNT(*) FROM reliability_incident_links WHERE link_status='open'")->fetchColumn();
    $assert($openCount === 0, 'A single failed probe opened an incident.');

    $setDue();
    $second = $worker->processNext('phase35-worker');
    $assert(is_array($second) && $second['status'] === 'major_outage', 'Consecutive failures did not produce a major outage.');
    $openCount = (int) $pdo->query("SELECT COUNT(*) FROM reliability_incident_links WHERE link_status='open'")->fetchColumn();
    $assert($openCount === 1, 'Sustained objective breach did not open one operational incident.');

    $windowPublicId = 'PMW-' . strtoupper(bin2hex(random_bytes(10)));
    $pdo->prepare(
        "INSERT INTO platform_maintenance_windows
         (public_id,environment_id,account_scope,request_id,window_status,starts_at,ends_at,reason,
          created_by_user_id,approved_by_user_id,created_at,updated_at)
         SELECT :public_id,e.id,:account_id,:request_id,'open',
                DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 1 MINUTE),DATE_ADD(UTC_TIMESTAMP(6),INTERVAL 30 MINUTE),
                'Phase 35 maintenance suppression',:user_id,:user_id,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6)
         FROM platform_deployment_environments e WHERE e.public_id=:environment_public_id"
    )->execute([
        'public_id' => $windowPublicId,
        'account_id' => $accountId,
        'request_id' => 'phase35-window-' . $suffix,
        'user_id' => $userId,
        'environment_public_id' => $environmentPublicId,
    ]);
    $setDue();
    $maintenance = $worker->processNext('phase35-worker');
    $assert(is_array($maintenance) && $maintenance['observation'] === 'maintenance' && $maintenance['status'] === 'maintenance', 'Approved maintenance was not synchronized into reliability.');
    $failureCount = (int) $pdo->query("SELECT COUNT(*) FROM reliability_probe_results WHERE result_status='failure'")->fetchColumn();
    $assert($failureCount === 2, 'Maintenance observation consumed the failure budget.');
    $pdo->prepare(
        "UPDATE platform_maintenance_windows SET window_status='closed',ends_at=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 1 SECOND)
         WHERE public_id=:public_id"
    )->execute(['public_id' => $windowPublicId]);

    $setDue();
    $third = $worker->processNext('phase35-worker');
    $assert(is_array($third) && $third['status'] === 'maintenance', 'Recovery completed before the configured success threshold.');
    $setDue();
    $fourth = $worker->processNext('phase35-worker');
    $assert(is_array($fourth) && $fourth['status'] === 'operational', 'Reliability recovery threshold did not restore operational status.');
    $resolvedCount = (int) $pdo->query("SELECT COUNT(*) FROM reliability_incident_links WHERE link_status='resolved'")->fetchColumn();
    $assert($resolvedCount === 1, 'Reliability recovery did not resolve the linked operational incident.');

    $settings = $actions->saveStatusSettings(
        $accountId,
        $userId,
        'customer_owner',
        'phase35-' . $suffix,
        'VP3 Phase 35 Status',
        'Customer-safe reliability status.',
        true,
        true,
        'phase35-status-settings-' . $suffix
    );
    $assert($settings['public_enabled'] === true, 'Public status page was not enabled.');

    $message = $actions->publishStatusMessage(
        $accountId,
        $userId,
        'customer_owner',
        (string) $component['public_id'],
        'Reliability certification complete',
        'Phase 35 synthetic monitoring and recovery are operating normally.',
        gmdate('Y-m-d H:i:s'),
        null,
        'phase35-message-' . $suffix
    );
    $assert(!array_key_exists('id', $message), 'Status message response exposed an internal ID.');

    $snapshot = $query->snapshot($accountId, $userId, 'customer_owner');
    $assert($snapshot['overall_status'] === 'operational', 'Control Center snapshot did not report operational status.');
    $assert(count($snapshot['components']) === 1, 'Control Center snapshot did not return the account component.');
    $serialized = json_encode($snapshot, JSON_THROW_ON_ERROR);
    $assert(!str_contains($serialized, '"target_value"') && !str_contains($serialized, '"account_scope"'), 'Control Center snapshot exposed protected reliability data.');

    $public = $query->publicStatus('phase35-' . $suffix);
    $publicJson = json_encode($public, JSON_THROW_ON_ERROR);
    $assert($public['overall_status'] === 'operational', 'Public status did not report the component state.');
    $assert(!str_contains($publicJson, 'REL-CMP-') && !str_contains($publicJson, 'REL-PRB-'), 'Public status exposed private public resource identities.');
    $assert(!str_contains($publicJson, 'target_value') && !str_contains($publicJson, 'primary'), 'Public status exposed a probe target.');

    $events = $pdo->query(
        'SELECT component_id,previous_hash,event_hash,previous_status,current_status,reason_code,evidence_hash,occurred_at
         FROM reliability_status_events ORDER BY component_id,id'
    )->fetchAll(PDO::FETCH_ASSOC);
    $previous = str_repeat('0', 64);
    foreach ($events as $event) {
        $assert(hash_equals($previous, (string) $event['previous_hash']), 'Reliability status event chain previous hash mismatch.');
        $expected = hash('sha256', implode('|', [
            $previous,
            (int) $event['component_id'],
            (string) $event['previous_status'],
            (string) $event['current_status'],
            (string) $event['reason_code'],
            (string) $event['evidence_hash'],
            (string) $event['occurred_at'],
        ]));
        $assert(hash_equals($expected, (string) $event['event_hash']), 'Reliability status event chain hash mismatch.');
        $previous = (string) $event['event_hash'];
    }
    $assert(count($events) >= 3, 'Reliability status transitions were not durably recorded.');

    fwrite(STDOUT, "Phase 35 reliability SLO, maintenance, incident, recovery, replay and public-status certification passed.\n");
} finally {
    if (($createdEnvironment ?? false) === true && isset($environmentPublicId)) {
        $pdo->prepare('DELETE FROM platform_deployment_environments WHERE public_id=:public_id')
            ->execute(['public_id' => $environmentPublicId]);
    }
    if ($accountId > 0) {
        $pdo->prepare('DELETE FROM accounts WHERE id=:id')->execute(['id' => $accountId]);
    }
    if ($userId > 0) {
        $pdo->prepare('DELETE FROM users WHERE id=:id')->execute(['id' => $userId]);
    }
}

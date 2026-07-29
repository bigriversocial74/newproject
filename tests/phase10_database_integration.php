<?php

declare(strict_types=1);

use Vp3\Database;
use Vp3\Operations\OperationalAuditService;
use Vp3\Operations\OperationalIncidentService;
use Vp3\Operations\OperationalNotificationAdapter;
use Vp3\Operations\OperationalNotificationService;
use Vp3\Operations\OperationsMonitorService;
use Vp3\Operations\OperationsReadinessService;
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

final class Phase10NotificationAdapter implements OperationalNotificationAdapter
{
    public bool $failNext = false;
    /** @var list<array{destination:array<string,mixed>,payload:array<string,mixed>}> */
    public array $deliveries = [];

    public function deliver(array $destination, array $payload): array
    {
        if ($this->failNext) {
            $this->failNext = false;
            throw new RuntimeException('Synthetic notification failure.');
        }
        $this->deliveries[] = ['destination' => $destination, 'payload' => $payload];
        return ['provider_message_id' => 'ops-test-' . count($this->deliveries)];
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
$cipher = new OperationsSecretCipher(base64_encode(random_bytes(32)), 'phase10-test-key');
$adapter = new Phase10NotificationAdapter();
$audit = new OperationalAuditService($database);
$notifications = new OperationalNotificationService($database, $cipher, $adapter, $audit);
$incidents = new OperationalIncidentService($database, $audit, $notifications);
$monitor = new OperationsMonitorService($database, $incidents, $audit, 10, 10);
$service = new OperationsReadinessService($database, $audit, $notifications, $incidents, $monitor);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

try {
    $token = strtolower(bin2hex(random_bytes(5)));
    $now = gmdate('Y-m-d H:i:s');
    $insertAccount = $pdo->prepare(
        "INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at)
         VALUES (:public,'individual','active',:name,:created,:updated)"
    );
    $insertAccount->execute([
        'public' => 'VP3-P10-' . strtoupper($token),
        'name' => 'Phase Ten Account',
        'created' => $now,
        'updated' => $now,
    ]);
    $accountId = (int) $pdo->lastInsertId();
    $insertAccount->execute([
        'public' => 'VP3-P10-X-' . strtoupper($token),
        'name' => 'Phase Ten Other',
        'created' => $now,
        'updated' => $now,
    ]);
    $otherAccountId = (int) $pdo->lastInsertId();

    $destination = ['email' => 'ops-' . $token . '@example.test', 'tenant' => 'phase10'];
    $channel = $service->saveNotificationChannel($accountId, 'email', 'Primary Operations', $destination, 'info', 'REQ-P10-CHANNEL');
    $channelReplay = $service->saveNotificationChannel($accountId, 'email', 'Primary Operations', $destination, 'info', 'REQ-P10-CHANNEL');
    $assert($channelReplay['channel_id'] === $channel['channel_id'], 'Notification channel request was not idempotent.');
    $storedDestination = (string) $pdo->query('SELECT destination_ciphertext FROM operational_notification_channels WHERE id=' . $channel['channel_id'])->fetchColumn();
    $assert(!str_contains($storedDestination, (string) $destination['email']), 'Plaintext notification destination was stored.');

    $manual = $service->openIncident($accountId, 'manual_test', 1, 'critical', 'Synthetic operational incident', ['token' => $token]);
    $service->resolveIncident($accountId, $manual['incident_id'], $accountId, 'REQ-P10-RESOLVE', ['reason' => 'synthetic recovery']);
    $queuedStatuses = $pdo->query(
        'SELECT event_status FROM operational_notifications WHERE incident_id=' . $manual['incident_id'] . ' ORDER BY id ASC'
    )->fetchAll(PDO::FETCH_COLUMN);
    $assert($queuedStatuses === ['open', 'resolved'], 'Opened and resolved notification states were not snapshotted immutably.');

    $firstDelivery = $service->processNextNotification('phase10-worker');
    $secondDelivery = $service->processNextNotification('phase10-worker');
    $assert(($firstDelivery['status'] ?? null) === 'delivered' && ($secondDelivery['status'] ?? null) === 'delivered', 'Incident notifications were not delivered.');
    $assert(($adapter->deliveries[0]['payload']['status'] ?? null) === 'open', 'Opened notification changed after incident resolution.');
    $assert(($adapter->deliveries[1]['payload']['status'] ?? null) === 'resolved', 'Resolved notification did not preserve its queued state.');
    $assert(($adapter->deliveries[0]['destination']['email'] ?? null) === $destination['email'], 'Notification destination was not authenticated and decrypted.');

    $crossAccount = $service->openIncident($accountId, 'manual_test', 2, 'warning', 'Cross-account incident', ['token' => $token]);
    $denied = false;
    try {
        $service->acknowledgeIncident($otherAccountId, $crossAccount['incident_id'], $otherAccountId, 'REQ-P10-DENIED');
    } catch (RuntimeException) {
        $denied = true;
    }
    $assert($denied, 'Cross-account incident acknowledgement was not denied.');

    $adapter->failNext = true;
    $retryIncident = $service->openIncident($accountId, 'manual_test', 3, 'warning', 'Retry notification incident', ['token' => $token]);
    $retry = $service->processNextNotification('phase10-worker');
    $assert(($retry['status'] ?? null) === 'queued', 'Transient notification failure was not queued for retry.');
    $pdo->exec("UPDATE operational_notifications SET available_at=UTC_TIMESTAMP() WHERE status='queued'");
    $retrySuccess = $service->processNextNotification('phase10-worker');
    $assert(($retrySuccess['status'] ?? null) === 'delivered', 'Queued notification retry was not delivered.');

    $service->recordHealthSignal($accountId, 'synthetic_runtime', 77, false, 'critical', ['probe' => 'failed'], 'REQ-P10-SIGNAL-BAD');
    $monitorBad = $service->runMonitoringPass('phase10-monitor');
    $activeSignalIncident = (int) $pdo->query(
        "SELECT COUNT(*) FROM operational_incidents
         WHERE account_scope={$accountId} AND source_type='health_signal' AND status IN ('open','acknowledged')"
    )->fetchColumn();
    $assert($monitorBad['opened'] >= 1 && $activeSignalIncident === 1, 'Unhealthy signal did not open a deduplicated incident.');
    $service->recordHealthSignal($accountId, 'synthetic_runtime', 77, true, 'critical', ['probe' => 'recovered'], 'REQ-P10-SIGNAL-GOOD');
    $monitorGood = $service->runMonitoringPass('phase10-monitor');
    $resolvedSignalIncident = (int) $pdo->query(
        "SELECT COUNT(*) FROM operational_incidents
         WHERE account_scope={$accountId} AND source_type='health_signal' AND status='resolved'"
    )->fetchColumn();
    $assert($monitorGood['resolved'] >= 1 && $resolvedSignalIncident === 1, 'Recovered signal did not resolve its managed incident.');

    $assert($service->verifyAuditChain(), 'Operational audit chain did not verify before tampering.');
    $lastAudit = $pdo->query('SELECT id,payload_hash FROM operational_audit_chain ORDER BY id DESC LIMIT 1')->fetch(PDO::FETCH_ASSOC);
    $pdo->prepare('UPDATE operational_audit_chain SET payload_hash=:payload WHERE id=:id')->execute([
        'payload' => hash('sha256', 'tampered'),
        'id' => (int) $lastAudit['id'],
    ]);
    $assert(!$service->verifyAuditChain(), 'Operational audit-chain tampering was not detected.');
    $pdo->prepare('UPDATE operational_audit_chain SET payload_hash=:payload WHERE id=:id')->execute([
        'payload' => (string) $lastAudit['payload_hash'],
        'id' => (int) $lastAudit['id'],
    ]);
    $assert($service->verifyAuditChain(), 'Operational audit chain did not recover after restoring original evidence.');

    $baseline = $service->assessReadiness('test', $accountId);
    $blocker = $service->openIncident($accountId, 'manual_readiness', 99, 'critical', 'Readiness blocker incident', ['token' => $token]);
    $blocked = $service->assessReadiness('test', $accountId);
    $service->resolveIncident($accountId, $blocker['incident_id'], $accountId, 'REQ-P10-READY-RESOLVE', ['reason' => 'test complete']);
    $recovered = $service->assessReadiness('test', $accountId);
    $assert($blocked['blockers'] >= $baseline['blockers'] + 1, 'Critical incident did not increase readiness blockers.');
    $assert($recovered['blockers'] <= $blocked['blockers'] - 1, 'Resolved critical incident did not remove its readiness blocker.');
    $assert($blocked['score'] < $recovered['score'], 'Readiness score did not improve after resolving a blocker.');

    $plaintextMatches = (int) $pdo->query(
        "SELECT COUNT(*) FROM operational_notification_channels
         WHERE destination_ciphertext LIKE '%example.test%'"
    )->fetchColumn();
    $assert($plaintextMatches === 0, 'Operational database contains a plaintext destination fragment.');
    $assert((int) $pdo->query('SELECT COUNT(*) FROM operational_readiness_checks')->fetchColumn() > 0, 'Readiness check evidence was not persisted.');
    $assert((int) $pdo->query('SELECT COUNT(*) FROM operational_notification_receipts')->fetchColumn() >= 3, 'Notification receipts were not persisted.');

    $service->resolveIncident($accountId, $crossAccount['incident_id'], $accountId, 'REQ-P10-CROSS-RESOLVE', ['reason' => 'cleanup']);
    $service->resolveIncident($accountId, $retryIncident['incident_id'], $accountId, 'REQ-P10-RETRY-RESOLVE', ['reason' => 'cleanup']);
} catch (Throwable $exception) {
    $failures[] = 'Unhandled Phase 10 integration exception: ' . $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 10 database certification failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 10 operations readiness database certification passed.\n");

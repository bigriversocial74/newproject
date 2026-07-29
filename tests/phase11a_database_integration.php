<?php

declare(strict_types=1);

use Vp3\Database;
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

} catch (Throwable $exception) {
    $failures[] = $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 11A database failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

fwrite(STDOUT, "Phase 11A queue lease and crash-recovery certification passed.\n");

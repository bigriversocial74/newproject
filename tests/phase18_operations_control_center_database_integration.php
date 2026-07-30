<?php

declare(strict_types=1);

use Vp3\Auth\AuthPublicException;
use Vp3\Database;
use Vp3\Operations\NullOperationalNotificationAdapter;
use Vp3\Operations\OperationalAuditService;
use Vp3\Operations\OperationalIncidentService;
use Vp3\Operations\OperationalNotificationService;
use Vp3\Operations\OperationsControlCenterActionService;
use Vp3\Operations\OperationsControlCenterQueryService;
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

$accountIds = [];
$userIds = [];
$priorAuditMax = (int) $pdo->query('SELECT COALESCE(MAX(id),0) FROM operational_audit_chain')->fetchColumn();
$priorAuditHead = (string) $pdo->query('SELECT last_chain_hash FROM operational_audit_heads WHERE id=1')->fetchColumn();

try {
    $suffix = strtoupper(bin2hex(random_bytes(5)));
    $now = gmdate('Y-m-d H:i:s');
    $passwordHash = password_hash('Phase18-Operations-Test!42', PASSWORD_DEFAULT);
    if (!is_string($passwordHash)) {
        throw new RuntimeException('Unable to hash the test password.');
    }

    $createAccount = static function (string $label) use ($pdo, $suffix, $now, &$accountIds): int {
        $publicId = 'P18-' . substr($suffix, 0, 8) . '-' . strtoupper(substr($label, 0, 3));
        $pdo->prepare(
            "INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at)
             VALUES (:public_id,'organization','active',:display_name,:created_at,:updated_at)"
        )->execute([
            'public_id' => $publicId,
            'display_name' => 'Phase 18 ' . ucfirst($label),
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        $id = (int) $pdo->lastInsertId();
        $accountIds[] = $id;
        return $id;
    };
    $createUser = static function (string $label) use ($pdo, $suffix, $now, $passwordHash, &$userIds): array {
        $publicId = 'U18-' . substr($suffix, 0, 6) . '-' . strtoupper(substr(hash('sha256', $label), 0, 8));
        $email = strtolower($label . '-' . $suffix . '@example.test');
        $pdo->prepare(
            "INSERT INTO users
             (public_id,email,email_normalized,password_hash,display_name,status,email_verified_at,created_at,updated_at)
             VALUES (:public_id,:email,:email_normalized,:password_hash,:display_name,'active',:verified_at,:created_at,:updated_at)"
        )->execute([
            'public_id' => $publicId,
            'email' => $email,
            'email_normalized' => $email,
            'password_hash' => $passwordHash,
            'display_name' => 'Phase 18 ' . ucfirst($label),
            'verified_at' => $now,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        $id = (int) $pdo->lastInsertId();
        $userIds[] = $id;
        return ['id' => $id, 'public_id' => $publicId, 'email' => $email];
    };
    $addMembership = static function (int $accountId, int $userId, string $role) use ($pdo, $now): void {
        $pdo->prepare(
            "INSERT INTO account_users (account_id,user_id,role,status,created_at,updated_at)
             VALUES (:account_id,:user_id,:role,'active',:created_at,:updated_at)"
        )->execute([
            'account_id' => $accountId,
            'user_id' => $userId,
            'role' => $role,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
    };

    $accountA = $createAccount('alpha');
    $accountB = $createAccount('bravo');
    $ownerA = $createUser('owner-a');
    $supportA = $createUser('support-a');
    $billingA = $createUser('billing-a');
    $ownerB = $createUser('owner-b');
    $addMembership($accountA, $ownerA['id'], 'customer_owner');
    $addMembership($accountA, $supportA['id'], 'support_member');
    $addMembership($accountA, $billingA['id'], 'billing_manager');
    $addMembership($accountB, $ownerB['id'], 'customer_owner');

    $keyBase64 = base64_encode(random_bytes(32));
    $cipher = new OperationsSecretCipher($keyBase64, 'phase18-test-key');
    $audit = new OperationalAuditService($database);
    $notifications = new OperationalNotificationService(
        $database,
        $cipher,
        new NullOperationalNotificationAdapter(),
        $audit,
        30
    );
    $incidents = new OperationalIncidentService($database, $audit, $notifications);
    $query = new OperationsControlCenterQueryService($database);
    $actions = new OperationsControlCenterActionService($database, $audit, $notifications, $cipher);

    $channelEmail = 'ops-' . strtolower($suffix) . '@example.test';
    $channel = $actions->saveSmtpChannel(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        'Primary Operations',
        $channelEmail,
        'warning',
        'REQ-P18-CHANNEL-' . $suffix
    );
    $assert(preg_match('/^OPS-CHANNEL-[A-F0-9]{20}$/', $channel['public_id']) === 1,
        'Owner channel creation did not return a bounded public ID.');

    $storedChannel = $pdo->prepare(
        'SELECT * FROM operational_notification_channels WHERE public_id=:public_id AND account_scope=:account_id'
    );
    $storedChannel->execute(['public_id' => $channel['public_id'], 'account_id' => $accountA]);
    $storedChannelRow = $storedChannel->fetch(PDO::FETCH_ASSOC);
    $assert(is_array($storedChannelRow), 'Encrypted notification channel did not persist.');
    if (is_array($storedChannelRow)) {
        $assert(!str_contains((string) $storedChannelRow['destination_ciphertext'], $channelEmail),
            'Notification destination leaked into ciphertext storage.');
        $decrypted = $cipher->decrypt(
            (string) $storedChannelRow['destination_ciphertext'],
            (string) $storedChannelRow['destination_nonce'],
            (string) $storedChannelRow['destination_tag'],
            'operations-channel|' . $accountA . '|smtp|' . hash('sha256', 'Primary Operations')
        );
        $assert($decrypted === json_encode(['email' => $channelEmail], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            'Encrypted notification destination did not authenticate and decrypt correctly.');
    }

    $signalInsert = $pdo->prepare(
        "INSERT INTO operational_health_signals
         (account_scope,source_type,source_id,health_status,severity,evidence_hash,observed_at,created_at,updated_at)
         VALUES (:account_scope,:source_type,:source_id,:health_status,:severity,:evidence_hash,:observed_at,:created_at,:updated_at)"
    );
    $signalInsert->execute([
        'account_scope' => $accountA,
        'source_type' => 'pod_deployment',
        'source_id' => 101,
        'health_status' => 'unhealthy',
        'severity' => 'critical',
        'evidence_hash' => hash('sha256', 'alpha-signal'),
        'observed_at' => $now,
        'created_at' => $now,
        'updated_at' => $now,
    ]);
    $signalInsert->execute([
        'account_scope' => $accountB,
        'source_type' => 'homeserver_device',
        'source_id' => 202,
        'health_status' => 'healthy',
        'severity' => 'info',
        'evidence_hash' => hash('sha256', 'bravo-signal'),
        'observed_at' => $now,
        'created_at' => $now,
        'updated_at' => $now,
    ]);

    $incidentA = $incidents->open(
        $accountA,
        'pod_deployment',
        101,
        'critical',
        'Alpha POD routing unavailable',
        ['evidence' => hash('sha256', 'alpha-routing')],
        true
    );
    $incidentB = $incidents->open(
        $accountB,
        'homeserver_device',
        202,
        'warning',
        'Bravo HomeServer heartbeat delayed',
        ['evidence' => hash('sha256', 'bravo-heartbeat')],
        true
    );

    $supportSnapshot = $query->snapshot($accountA, $supportA['id'], 'support_member');
    $supportJson = json_encode($supportSnapshot, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    $assert($supportSnapshot['permissions']['can_acknowledge'] === true
        && $supportSnapshot['permissions']['can_resolve'] === false
        && $supportSnapshot['permissions']['can_manage_channels'] === false,
        'Support-member Operations permissions are incorrect.');
    $assert((int) $supportSnapshot['metrics']['signals_critical'] === 1
        && (int) $supportSnapshot['metrics']['incidents_open'] === 1,
        'Account health or incident metrics are incorrect.');
    $assert(str_contains($supportJson, (string) $incidentA['public_id'])
        && !str_contains($supportJson, (string) $incidentB['public_id'])
        && !str_contains($supportJson, 'Bravo HomeServer heartbeat delayed'),
        'Operations snapshot failed cross-account incident isolation.');
    $assert(!str_contains($supportJson, $channelEmail)
        && !str_contains($supportJson, 'destination_ciphertext')
        && !str_contains($supportJson, 'destination_nonce')
        && !str_contains($supportJson, 'destination_tag')
        && !str_contains($supportJson, 'encryption_key_id'),
        'Operations snapshot exposed notification destination or encryption material.');
    $firstSignalReference = $supportSnapshot['health_signals'][0]['source_reference'] ?? null;
    $assert(is_string($firstSignalReference) && strlen($firstSignalReference) === 12 && $firstSignalReference !== '101',
        'Operations snapshot exposed the raw internal health source ID.');

    $expectCode(
        static fn () => $query->snapshot($accountA, $billingA['id'], 'billing_manager'),
        'operations_access_denied',
        'Billing manager accessed the Operations control center.'
    );

    $ackRequest = 'REQ-P18-ACK-' . $suffix;
    $actions->acknowledgeIncident(
        $accountA,
        $supportA['id'],
        'support_member',
        (string) $incidentA['public_id'],
        $ackRequest
    );
    $actions->acknowledgeIncident(
        $accountA,
        $supportA['id'],
        'support_member',
        (string) $incidentA['public_id'],
        $ackRequest
    );
    $incidentStatus = $pdo->prepare('SELECT status FROM operational_incidents WHERE public_id=:public_id');
    $incidentStatus->execute(['public_id' => $incidentA['public_id']]);
    $assert($incidentStatus->fetchColumn() === 'acknowledged', 'Support member did not acknowledge the account incident.');
    $ackEvents = $pdo->prepare(
        "SELECT COUNT(*) FROM operational_incident_events e
         INNER JOIN operational_incidents i ON i.id=e.incident_id
         WHERE i.public_id=:public_id AND e.event_type='acknowledged'"
    );
    $ackEvents->execute(['public_id' => $incidentA['public_id']]);
    $assert((int) $ackEvents->fetchColumn() === 1, 'Acknowledgement replay created duplicate incident evidence.');

    $expectCode(
        static fn () => $actions->resolveIncident(
            $accountA,
            $supportA['id'],
            'support_member',
            (string) $incidentA['public_id'],
            'REQ-P18-SUPPORT-RESOLVE-' . $suffix,
            'Support attempted resolution.'
        ),
        'operations_permission_denied',
        'Support member resolved an incident.'
    );
    $incidentStatus->execute(['public_id' => $incidentA['public_id']]);
    $assert($incidentStatus->fetchColumn() === 'acknowledged', 'Denied support resolution changed incident state.');

    $actions->resolveIncident(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        (string) $incidentA['public_id'],
        'REQ-P18-OWNER-RESOLVE-' . $suffix,
        'Routing restored and health verification completed.'
    );
    $resolved = $pdo->prepare(
        'SELECT status,resolution_hash,resolved_by FROM operational_incidents WHERE public_id=:public_id'
    );
    $resolved->execute(['public_id' => $incidentA['public_id']]);
    $resolvedRow = $resolved->fetch(PDO::FETCH_ASSOC);
    $assert(is_array($resolvedRow)
        && $resolvedRow['status'] === 'resolved'
        && preg_match('/^[a-f0-9]{64}$/', (string) $resolvedRow['resolution_hash']) === 1
        && (int) $resolvedRow['resolved_by'] === $ownerA['id'],
        'Owner incident resolution or evidence hashing failed.');

    $expectCode(
        static fn () => $actions->acknowledgeIncident(
            $accountA,
            $ownerA['id'],
            'customer_owner',
            (string) $incidentB['public_id'],
            'REQ-P18-CROSS-INC-' . $suffix
        ),
        'operations_resource_not_found',
        'Cross-account incident mutation was accepted.'
    );
    $incidentStatus->execute(['public_id' => $incidentB['public_id']]);
    $assert($incidentStatus->fetchColumn() === 'open', 'Cross-account incident mutation changed the isolated incident.');

    $pdo->prepare(
        "UPDATE account_users SET role='support_member',updated_at=UTC_TIMESTAMP()
         WHERE account_id=:account_id AND user_id=:user_id"
    )->execute(['account_id' => $accountA, 'user_id' => $ownerA['id']]);
    $expectCode(
        static fn () => $actions->saveSmtpChannel(
            $accountA,
            $ownerA['id'],
            'customer_owner',
            'Stale Owner Channel',
            'stale-' . strtolower($suffix) . '@example.test',
            'critical',
            'REQ-P18-STALE-ROLE-' . $suffix
        ),
        'operations_permission_denied',
        'Stale owner role created a notification channel.'
    );
    $staleChannel = $pdo->prepare(
        'SELECT COUNT(*) FROM operational_notification_channels WHERE account_scope=:account_id AND label=:label'
    );
    $staleChannel->execute(['account_id' => $accountA, 'label' => 'Stale Owner Channel']);
    $assert((int) $staleChannel->fetchColumn() === 0, 'Stale-role channel mutation persisted data.');
    $pdo->prepare(
        "UPDATE account_users SET role='customer_owner',updated_at=UTC_TIMESTAMP()
         WHERE account_id=:account_id AND user_id=:user_id"
    )->execute(['account_id' => $accountA, 'user_id' => $ownerA['id']]);

    $expectCode(
        static fn () => $actions->setChannelStatus(
            $accountB,
            $ownerB['id'],
            'customer_owner',
            (string) $channel['public_id'],
            'paused',
            'REQ-P18-CROSS-CHANNEL-' . $suffix
        ),
        'operations_resource_not_found',
        'Cross-account notification-channel mutation was accepted.'
    );
    $storedChannel->execute(['public_id' => $channel['public_id'], 'account_id' => $accountA]);
    $assert(($storedChannel->fetch(PDO::FETCH_ASSOC)['status'] ?? null) === 'active',
        'Cross-account channel mutation changed the isolated channel.');

    $actions->setChannelStatus(
        $accountA,
        $ownerA['id'],
        'customer_owner',
        (string) $channel['public_id'],
        'paused',
        'REQ-P18-PAUSE-' . $suffix
    );
    $storedChannel->execute(['public_id' => $channel['public_id'], 'account_id' => $accountA]);
    $assert(($storedChannel->fetch(PDO::FETCH_ASSOC)['status'] ?? null) === 'paused',
        'Owner did not pause the notification channel.');
    $queuedForChannel = $pdo->prepare(
        "SELECT COUNT(*) FROM operational_notifications n
         INNER JOIN operational_notification_channels c ON c.id=n.channel_id
         WHERE c.public_id=:public_id AND n.status='queued'"
    );
    $queuedForChannel->execute(['public_id' => $channel['public_id']]);
    $assert((int) $queuedForChannel->fetchColumn() === 0,
        'Pausing a channel did not cancel its queued deliveries.');

    $finalSnapshotA = $query->snapshot($accountA, $ownerA['id'], 'customer_owner');
    $finalSnapshotB = $query->snapshot($accountB, $ownerB['id'], 'customer_owner');
    $finalJsonA = json_encode($finalSnapshotA, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    $finalJsonB = json_encode($finalSnapshotB, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    $assert(str_contains($finalJsonA, (string) $incidentA['public_id'])
        && !str_contains($finalJsonA, (string) $incidentB['public_id'])
        && str_contains($finalJsonB, (string) $incidentB['public_id'])
        && !str_contains($finalJsonB, (string) $incidentA['public_id']),
        'Final Operations snapshots are not account isolated.');
    $assert(!str_contains($finalJsonA, $channelEmail),
        'Final Operations snapshot exposed encrypted destination plaintext.');

    $badReceipts = $pdo->prepare(
        "SELECT COUNT(*) FROM operational_request_receipts
         WHERE account_scope IN (:account_a,:account_b)
           AND (CHAR_LENGTH(receipt_hash)<>64 OR receipt_hash REGEXP '[^0-9a-f]')"
    );
    $badReceipts->execute(['account_a' => $accountA, 'account_b' => $accountB]);
    $assert((int) $badReceipts->fetchColumn() === 0, 'Operations request receipt hashes are malformed.');
    $badAudit = $pdo->query(
        "SELECT COUNT(*) FROM operational_audit_chain
         WHERE id>{$priorAuditMax} AND (CHAR_LENGTH(chain_hash)<>64 OR chain_hash REGEXP '[^0-9a-f]')"
    );
    $assert((int) $badAudit->fetchColumn() === 0, 'Operations audit-chain hashes are malformed.');
    $assert($audit->verify(), 'Operations audit chain failed verification after Phase 18 mutations.');
} catch (Throwable $exception) {
    $failures[] = $exception::class . ': ' . $exception->getMessage();
} finally {
    if ($accountIds !== []) {
        $marks = implode(',', array_fill(0, count($accountIds), '?'));
        $incidentIds = $pdo->prepare("SELECT id FROM operational_incidents WHERE account_scope IN ({$marks})");
        $incidentIds->execute($accountIds);
        $incidentIdList = array_map('intval', $incidentIds->fetchAll(PDO::FETCH_COLUMN));
        if ($incidentIdList !== []) {
            $incidentMarks = implode(',', array_fill(0, count($incidentIdList), '?'));
            $pdo->prepare("DELETE FROM operational_notification_receipts WHERE notification_id IN (SELECT id FROM operational_notifications WHERE incident_id IN ({$incidentMarks}))")
                ->execute($incidentIdList);
            $pdo->prepare("DELETE FROM operational_notifications WHERE incident_id IN ({$incidentMarks})")
                ->execute($incidentIdList);
            $pdo->prepare("DELETE FROM operational_incident_events WHERE incident_id IN ({$incidentMarks})")
                ->execute($incidentIdList);
        }
        $pdo->prepare("DELETE FROM operational_notification_channels WHERE account_scope IN ({$marks})")->execute($accountIds);
        $pdo->prepare("DELETE FROM operational_request_receipts WHERE account_scope IN ({$marks})")->execute($accountIds);
        $pdo->prepare("DELETE FROM operational_incidents WHERE account_scope IN ({$marks})")->execute($accountIds);
        $pdo->prepare("DELETE FROM operational_health_signals WHERE account_scope IN ({$marks})")->execute($accountIds);
        $pdo->prepare("DELETE FROM account_users WHERE account_id IN ({$marks})")->execute($accountIds);
        $pdo->prepare("DELETE FROM accounts WHERE id IN ({$marks})")->execute($accountIds);
    }
    if ($userIds !== []) {
        $marks = implode(',', array_fill(0, count($userIds), '?'));
        $pdo->prepare("DELETE FROM users WHERE id IN ({$marks})")->execute($userIds);
    }
    $pdo->prepare('DELETE FROM operational_audit_chain WHERE id>:prior_max')->execute(['prior_max' => $priorAuditMax]);
    $pdo->prepare('UPDATE operational_audit_heads SET last_chain_hash=:head,updated_at=UTC_TIMESTAMP(6) WHERE id=1')
        ->execute(['head' => $priorAuditHead]);
}

if ($failures !== []) {
    fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL);
    exit(1);
}

echo "Phase 18 operations control center database integration passed.\n";

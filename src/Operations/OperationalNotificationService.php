<?php

declare(strict_types=1);

namespace Vp3\Operations;

use PDO;
use RuntimeException;
use Throwable;
use Vp3\Database;

final class OperationalNotificationService
{
    /** @var array<string,int> */
    private const SEVERITY_RANK = ['info' => 1, 'warning' => 2, 'critical' => 3];

    public function __construct(
        private readonly Database $database,
        private readonly OperationsSecretCipher $cipher,
        private readonly OperationalNotificationAdapter $adapter,
        private readonly OperationalAuditService $audit
    ) {
    }

    /** @param array<string,mixed> $destination @return array{channel_id:int,public_id:string} */
    public function saveChannel(
        int $accountScope,
        string $channelType,
        string $label,
        array $destination,
        string $severityThreshold,
        string $requestId
    ): array {
        $channelType = strtolower(trim($channelType));
        $label = trim($label);
        $severityThreshold = strtolower(trim($severityThreshold));
        if ($accountScope < 0 || $channelType === '' || $label === '' || $destination === []
            || !isset(self::SEVERITY_RANK[$severityThreshold]) || trim($requestId) === '') {
            throw new RuntimeException('A valid operational notification channel is required.');
        }

        return $this->database->transaction(function (PDO $pdo) use (
            $accountScope, $channelType, $label, $destination, $severityThreshold, $requestId
        ): array {
            $prior = $this->requestReceipt($pdo, $accountScope, $requestId, 'notification_channel_save');
            if ($prior !== null && $prior['resource_id'] !== null) {
                return $this->channelIdentity($pdo, (int) $prior['resource_id']);
            }
            $find = $pdo->prepare(
                'SELECT * FROM operational_notification_channels
                 WHERE account_scope=:account AND channel_type=:channel_type AND label=:label LIMIT 1 FOR UPDATE'
            );
            $find->execute(['account' => $accountScope, 'channel_type' => $channelType, 'label' => $label]);
            $existing = $find->fetch(PDO::FETCH_ASSOC);
            $encrypted = $this->cipher->encrypt(
                $this->json($destination),
                $this->channelContext($accountScope, $channelType, $label)
            );
            $now = gmdate('Y-m-d H:i:s');
            if (is_array($existing)) {
                $channelId = (int) $existing['id'];
                $publicId = (string) $existing['public_id'];
                $pdo->prepare(
                    "UPDATE operational_notification_channels
                     SET status='active',severity_threshold=:threshold,destination_ciphertext=:ciphertext,
                         destination_nonce=:nonce,destination_tag=:tag,encryption_key_id=:key_id,
                         revoked_at=NULL,updated_at=:updated WHERE id=:id"
                )->execute([
                    'threshold' => $severityThreshold,
                    'ciphertext' => $encrypted['ciphertext'],
                    'nonce' => $encrypted['nonce'],
                    'tag' => $encrypted['tag'],
                    'key_id' => $encrypted['key_id'],
                    'updated' => $now,
                    'id' => $channelId,
                ]);
            } else {
                $publicId = 'OPS-CHANNEL-' . strtoupper(bin2hex(random_bytes(10)));
                $pdo->prepare(
                    "INSERT INTO operational_notification_channels
                     (public_id,account_scope,channel_type,label,status,severity_threshold,destination_ciphertext,
                      destination_nonce,destination_tag,encryption_key_id,created_at,updated_at)
                     VALUES (:public,:account,:channel_type,:label,'active',:threshold,:ciphertext,
                             :nonce,:tag,:key_id,:created,:updated)"
                )->execute([
                    'public' => $publicId,
                    'account' => $accountScope,
                    'channel_type' => $channelType,
                    'label' => $label,
                    'threshold' => $severityThreshold,
                    'ciphertext' => $encrypted['ciphertext'],
                    'nonce' => $encrypted['nonce'],
                    'tag' => $encrypted['tag'],
                    'key_id' => $encrypted['key_id'],
                    'created' => $now,
                    'updated' => $now,
                ]);
                $channelId = (int) $pdo->lastInsertId();
            }
            $receiptHash = hash('sha256', $accountScope . '|' . $channelId . '|' . $requestId . '|' . $encrypted['key_id']);
            $this->insertRequestReceipt($pdo, $accountScope, $requestId, 'notification_channel_save', 'success', 'notification_channel', $channelId, $receiptHash);
            $this->audit->appendWithPdo($pdo, 'notification_channel', $channelId, 'saved', 'system', 0, $receiptHash);
            return ['channel_id' => $channelId, 'public_id' => $publicId];
        });
    }

    public function setChannelStatus(int $accountScope, int $channelId, string $status, int $actorId, string $requestId): void
    {
        $status = strtolower(trim($status));
        if ($accountScope < 0 || $channelId < 1 || !in_array($status, ['active', 'paused', 'revoked'], true)
            || $actorId < 0 || trim($requestId) === '') {
            throw new RuntimeException('A valid notification channel status change is required.');
        }
        $outcome = $this->database->transaction(function (PDO $pdo) use ($accountScope, $channelId, $status, $actorId, $requestId): string {
            if ($this->requestReceipt($pdo, $accountScope, $requestId, 'notification_channel_status') !== null) {
                return 'ignored';
            }
            $find = $pdo->prepare('SELECT * FROM operational_notification_channels WHERE id=:id LIMIT 1 FOR UPDATE');
            $find->execute(['id' => $channelId]);
            $channel = $find->fetch(PDO::FETCH_ASSOC);
            if (!is_array($channel) || (int) $channel['account_scope'] !== $accountScope) {
                $receiptHash = hash('sha256', $accountScope . '|' . $channelId . '|' . $requestId . '|denied');
                $this->insertRequestReceipt($pdo, $accountScope, $requestId, 'notification_channel_status', 'denied', 'notification_channel', $channelId, $receiptHash);
                $this->audit->appendWithPdo($pdo, 'notification_channel', $channelId, 'access_denied', 'account_user', $actorId, $receiptHash);
                return 'denied';
            }
            $pdo->prepare(
                'UPDATE operational_notification_channels
                 SET status=:status,revoked_at=IF(:revoked_status=\'revoked\',UTC_TIMESTAMP(),NULL),updated_at=UTC_TIMESTAMP()
                 WHERE id=:id'
            )->execute(['status' => $status, 'revoked_status' => $status, 'id' => $channelId]);
            if ($status !== 'active') {
                $pdo->prepare(
                    "UPDATE operational_notifications
                     SET status='canceled',updated_at=UTC_TIMESTAMP()
                     WHERE channel_id=:channel AND status='queued'"
                )->execute(['channel' => $channelId]);
            }
            $receiptHash = hash('sha256', $accountScope . '|' . $channelId . '|' . $status . '|' . $requestId);
            $this->insertRequestReceipt($pdo, $accountScope, $requestId, 'notification_channel_status', 'success', 'notification_channel', $channelId, $receiptHash);
            $this->audit->appendWithPdo($pdo, 'notification_channel', $channelId, $status, 'account_user', $actorId, $receiptHash);
            return 'success';
        });
        if ($outcome === 'denied') {
            throw new RuntimeException('Operational notification channel does not belong to this account.');
        }
    }

    public function queueWithPdo(
        PDO $pdo,
        int $incidentId,
        int $eventId,
        string $eventType,
        string $eventStatus,
        string $severity,
        string $payloadHash
    ): void {
        $incident = $pdo->prepare('SELECT account_scope FROM operational_incidents WHERE id=:id LIMIT 1');
        $incident->execute(['id' => $incidentId]);
        $accountScope = $incident->fetchColumn();
        if (!is_numeric($accountScope)) {
            return;
        }
        $channels = $pdo->prepare(
            "SELECT * FROM operational_notification_channels WHERE account_scope=:account AND status='active' ORDER BY id ASC"
        );
        $channels->execute(['account' => (int) $accountScope]);
        foreach ($channels->fetchAll(PDO::FETCH_ASSOC) as $channel) {
            if (self::SEVERITY_RANK[$severity] < self::SEVERITY_RANK[(string) $channel['severity_threshold']]) {
                continue;
            }
            $deliveryKey = hash('sha256', $incidentId . '|' . $eventId . '|' . $channel['id'] . '|' . $eventType);
            $pdo->prepare(
                "INSERT IGNORE INTO operational_notifications
                 (public_id,incident_id,incident_event_id,channel_id,event_type,event_status,severity,delivery_key,
                  payload_hash,status,attempts,max_attempts,available_at,created_at,updated_at)
                 VALUES (:public,:incident,:event,:channel,:event_type,:event_status,:severity,:delivery_key,
                         :payload,'queued',0,5,UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())"
            )->execute([
                'public' => 'OPS-NOTIFY-' . strtoupper(bin2hex(random_bytes(10))),
                'incident' => $incidentId,
                'event' => $eventId,
                'channel' => (int) $channel['id'],
                'event_type' => $eventType,
                'event_status' => $eventStatus,
                'severity' => $severity,
                'delivery_key' => $deliveryKey,
                'payload' => $payloadHash,
            ]);
        }
    }

    /** @return array{notification_id:int,status:string,receipt_hash:string}|null */
    public function processNext(string $workerId): ?array
    {
        $workerId = trim($workerId);
        if ($workerId === '') {
            throw new RuntimeException('An operational notification worker ID is required.');
        }
        $notification = $this->database->transaction(function (PDO $pdo) use ($workerId): ?array {
            $claim = $pdo->query(
                "SELECT n.*,i.public_id AS incident_public_id,i.account_scope,i.title,
                        c.channel_type,c.label,c.destination_ciphertext,c.destination_nonce,c.destination_tag
                 FROM operational_notifications n
                 INNER JOIN operational_incidents i ON i.id=n.incident_id
                 INNER JOIN operational_notification_channels c ON c.id=n.channel_id
                 WHERE n.status='queued' AND n.available_at<=UTC_TIMESTAMP() AND c.status='active'
                 ORDER BY n.id ASC LIMIT 1 FOR UPDATE SKIP LOCKED"
            );
            $row = $claim->fetch(PDO::FETCH_ASSOC);
            if (!is_array($row)) {
                return null;
            }
            $pdo->prepare(
                "UPDATE operational_notifications
                 SET status='running',attempts=attempts+1,locked_at=UTC_TIMESTAMP(),locked_by=:worker,updated_at=UTC_TIMESTAMP()
                 WHERE id=:id"
            )->execute(['worker' => substr($workerId, 0, 128), 'id' => (int) $row['id']]);
            $row['attempts'] = (int) $row['attempts'] + 1;
            return $row;
        });
        if ($notification === null) {
            return null;
        }

        try {
            $context = $this->channelContext(
                (int) $notification['account_scope'],
                (string) $notification['channel_type'],
                (string) $notification['label']
            );
            $destinationJson = $this->cipher->decrypt(
                (string) $notification['destination_ciphertext'],
                (string) $notification['destination_nonce'],
                (string) $notification['destination_tag'],
                $context
            );
            $destination = json_decode($destinationJson, true, 32, JSON_THROW_ON_ERROR);
            if (!is_array($destination)) {
                throw new RuntimeException('Operational notification destination is invalid.');
            }
            $payload = [
                'incident_public_id' => (string) $notification['incident_public_id'],
                'event_type' => (string) $notification['event_type'],
                'status' => (string) $notification['event_status'],
                'severity' => (string) $notification['severity'],
                'title' => (string) $notification['title'],
                'payload_hash' => (string) $notification['payload_hash'],
            ];
            $responseHash = $this->hashValue($this->adapter->deliver($destination, $payload));
            $receiptHash = hash('sha256', $notification['delivery_key'] . '|delivered|' . $responseHash);
            $this->database->transaction(function (PDO $pdo) use ($notification, $responseHash, $receiptHash): void {
                $pdo->prepare(
                    "UPDATE operational_notifications
                     SET status='delivered',delivered_at=UTC_TIMESTAMP(),locked_at=NULL,locked_by=NULL,updated_at=UTC_TIMESTAMP()
                     WHERE id=:id"
                )->execute(['id' => (int) $notification['id']]);
                $this->insertNotificationReceipt($pdo, (int) $notification['id'], 'delivered', $receiptHash, $responseHash);
                $this->audit->appendWithPdo($pdo, 'notification', (int) $notification['id'], 'delivered', 'worker', 0, $receiptHash);
            });
            return ['notification_id' => (int) $notification['id'], 'status' => 'delivered', 'receipt_hash' => $receiptHash];
        } catch (Throwable $exception) {
            $errorHash = hash('sha256', $exception::class . '|' . $exception->getMessage());
            $status = (int) $notification['attempts'] >= (int) $notification['max_attempts'] ? 'failed' : 'queued';
            $receiptHash = hash('sha256', $notification['delivery_key'] . '|' . $status . '|' . $errorHash . '|' . $notification['attempts']);
            $this->database->transaction(function (PDO $pdo) use ($notification, $status, $errorHash, $receiptHash): void {
                $pdo->prepare(
                    "UPDATE operational_notifications
                     SET status=:status,available_at=DATE_ADD(UTC_TIMESTAMP(),INTERVAL 5 MINUTE),
                         locked_at=NULL,locked_by=NULL,last_error_hash=:error,updated_at=UTC_TIMESTAMP()
                     WHERE id=:id"
                )->execute(['status' => $status, 'error' => $errorHash, 'id' => (int) $notification['id']]);
                $this->insertNotificationReceipt($pdo, (int) $notification['id'], 'failed', $receiptHash, $errorHash);
                $this->audit->appendWithPdo($pdo, 'notification', (int) $notification['id'], $status, 'worker', 0, $receiptHash);
            });
            return ['notification_id' => (int) $notification['id'], 'status' => $status, 'receipt_hash' => $receiptHash];
        }
    }

    private function insertNotificationReceipt(PDO $pdo, int $notificationId, string $result, string $receiptHash, string $responseHash): void
    {
        $pdo->prepare(
            'INSERT INTO operational_notification_receipts
             (notification_id,result,receipt_hash,response_hash,created_at)
             VALUES (:notification,:result,:receipt,:response,UTC_TIMESTAMP())'
        )->execute([
            'notification' => $notificationId,
            'result' => $result,
            'receipt' => $receiptHash,
            'response' => $responseHash,
        ]);
    }

    /** @return array{channel_id:int,public_id:string} */
    private function channelIdentity(PDO $pdo, int $channelId): array
    {
        $statement = $pdo->prepare('SELECT id,public_id FROM operational_notification_channels WHERE id=:id LIMIT 1');
        $statement->execute(['id' => $channelId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('Operational notification channel was not found.');
        }
        return ['channel_id' => (int) $row['id'], 'public_id' => (string) $row['public_id']];
    }

    /** @return array<string,mixed>|null */
    private function requestReceipt(PDO $pdo, int $accountScope, string $requestId, string $operation): ?array
    {
        $statement = $pdo->prepare(
            'SELECT * FROM operational_request_receipts
             WHERE account_scope=:account AND request_id=:request_id AND operation=:operation LIMIT 1'
        );
        $statement->execute(['account' => $accountScope, 'request_id' => $requestId, 'operation' => $operation]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        return is_array($row) ? $row : null;
    }

    private function insertRequestReceipt(
        PDO $pdo,
        int $accountScope,
        string $requestId,
        string $operation,
        string $result,
        ?string $resourceType,
        ?int $resourceId,
        string $receiptHash
    ): void {
        $pdo->prepare(
            'INSERT INTO operational_request_receipts
             (account_scope,request_id,operation,result,resource_type,resource_id,receipt_hash,created_at)
             VALUES (:account,:request_id,:operation,:result,:resource_type,:resource_id,:receipt,UTC_TIMESTAMP())'
        )->execute([
            'account' => $accountScope,
            'request_id' => substr(trim($requestId), 0, 80),
            'operation' => substr(trim($operation), 0, 100),
            'result' => $result,
            'resource_type' => $resourceType,
            'resource_id' => $resourceId,
            'receipt' => $receiptHash,
        ]);
    }

    private function channelContext(int $accountScope, string $channelType, string $label): string
    {
        return 'operations-channel|' . $accountScope . '|' . strtolower(trim($channelType)) . '|' . hash('sha256', trim($label));
    }

    private function hashValue(mixed $value): string
    {
        return hash('sha256', $this->json($value));
    }

    private function json(mixed $value): string
    {
        return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}

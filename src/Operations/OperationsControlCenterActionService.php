<?php

declare(strict_types=1);

namespace Vp3\Operations;

use DateTimeImmutable;
use DateTimeZone;
use PDO;
use Vp3\Auth\AuthPublicException;
use Vp3\Database;

final class OperationsControlCenterActionService
{
    private const VIEW_ROLES = ['customer_owner', 'customer_admin', 'support_member'];
    private const MANAGER_ROLES = ['customer_owner', 'customer_admin'];
    private const SEVERITIES = ['info', 'warning', 'critical'];

    public function __construct(
        private readonly Database $database,
        private readonly OperationalAuditService $audit,
        private readonly OperationalNotificationService $notifications,
        private readonly OperationsSecretCipher $cipher
    ) {
    }

    public function acknowledgeIncident(
        int $accountId,
        int $actorUserId,
        string $actorRole,
        string $incidentPublicId,
        string $requestId
    ): void {
        $this->changeIncidentState(
            $accountId,
            $actorUserId,
            $actorRole,
            $incidentPublicId,
            'acknowledged',
            $requestId,
            null,
            self::VIEW_ROLES
        );
    }

    public function resolveIncident(
        int $accountId,
        int $actorUserId,
        string $actorRole,
        string $incidentPublicId,
        string $requestId,
        string $resolutionSummary
    ): void {
        $resolutionSummary = trim($resolutionSummary);
        if ($resolutionSummary === '' || mb_strlen($resolutionSummary) > 500) {
            throw new AuthPublicException(
                'operations_resolution_invalid',
                'A resolution summary of 1 to 500 characters is required.',
                422
            );
        }
        $this->changeIncidentState(
            $accountId,
            $actorUserId,
            $actorRole,
            $incidentPublicId,
            'resolved',
            $requestId,
            ['summary_hash' => hash('sha256', $resolutionSummary)],
            self::MANAGER_ROLES
        );
    }

    /** @return array{public_id:string,status:string} */
    public function saveSmtpChannel(
        int $accountId,
        int $actorUserId,
        string $actorRole,
        string $label,
        string $email,
        string $severityThreshold,
        string $requestId
    ): array {
        $label = trim($label);
        $email = strtolower(trim($email));
        $severityThreshold = strtolower(trim($severityThreshold));
        if ($label === '' || mb_strlen($label) > 190 || !filter_var($email, FILTER_VALIDATE_EMAIL)
            || !in_array($severityThreshold, self::SEVERITIES, true)) {
            throw new AuthPublicException(
                'operations_channel_invalid',
                'A valid channel label, email address, and severity threshold are required.',
                422
            );
        }

        $result = $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $actorUserId,
            $actorRole,
            $label,
            $email,
            $severityThreshold,
            $requestId
        ): array {
            $operation = 'control_center_notification_channel_save';
            $prior = $this->requestReceipt($pdo, $accountId, $requestId, $operation);
            if (is_array($prior)) {
                if ((string) $prior['result'] !== 'success' || $prior['resource_id'] === null) {
                    return ['outcome' => 'denied_replay'];
                }
                $identity = $this->channelIdentity($pdo, $accountId, (int) $prior['resource_id']);
                return $identity === null
                    ? ['outcome' => 'invalid_replay']
                    : ['outcome' => 'success', 'public_id' => $identity['public_id'], 'status' => $identity['status']];
            }

            if (!$this->actorAuthorized($pdo, $accountId, $actorUserId, $actorRole, self::MANAGER_ROLES)) {
                $hash = hash('sha256', $accountId . '|' . $actorUserId . '|' . $requestId . '|channel_denied');
                $this->insertRequestReceipt($pdo, $accountId, $requestId, $operation, 'denied', null, null, $hash);
                $this->audit->appendWithPdo($pdo, 'notification_channel', 0, 'access_denied', 'account_user', $actorUserId, $hash);
                return ['outcome' => 'permission_denied'];
            }

            $type = 'smtp';
            $find = $pdo->prepare(
                'SELECT id,public_id FROM operational_notification_channels
                 WHERE account_scope=:account AND channel_type=:type AND label=:label LIMIT 1 FOR UPDATE'
            );
            $find->execute(['account' => $accountId, 'type' => $type, 'label' => $label]);
            $existing = $find->fetch(PDO::FETCH_ASSOC);
            $destination = json_encode(['email' => $email], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            $encrypted = $this->cipher->encrypt($destination, $this->channelContext($accountId, $type, $label));
            $now = gmdate('Y-m-d H:i:s');

            if (is_array($existing)) {
                $channelId = (int) $existing['id'];
                $publicId = (string) $existing['public_id'];
                $pdo->prepare(
                    "UPDATE operational_notification_channels
                     SET status='active',severity_threshold=:threshold,destination_ciphertext=:ciphertext,
                         destination_nonce=:nonce,destination_tag=:tag,encryption_key_id=:key_id,
                         revoked_at=NULL,updated_at=:updated
                     WHERE id=:id AND account_scope=:account"
                )->execute([
                    'threshold' => $severityThreshold,
                    'ciphertext' => $encrypted['ciphertext'],
                    'nonce' => $encrypted['nonce'],
                    'tag' => $encrypted['tag'],
                    'key_id' => $encrypted['key_id'],
                    'updated' => $now,
                    'id' => $channelId,
                    'account' => $accountId,
                ]);
            } else {
                $publicId = 'OPS-CHANNEL-' . strtoupper(bin2hex(random_bytes(10)));
                $pdo->prepare(
                    "INSERT INTO operational_notification_channels
                     (public_id,account_scope,channel_type,label,status,severity_threshold,destination_ciphertext,
                      destination_nonce,destination_tag,encryption_key_id,created_at,updated_at)
                     VALUES (:public,:account,:type,:label,'active',:threshold,:ciphertext,:nonce,:tag,:key_id,:created,:updated)"
                )->execute([
                    'public' => $publicId,
                    'account' => $accountId,
                    'type' => $type,
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

            $receiptHash = hash('sha256', $accountId . '|' . $channelId . '|' . $requestId . '|' . $encrypted['key_id']);
            $this->insertRequestReceipt(
                $pdo,
                $accountId,
                $requestId,
                $operation,
                'success',
                'notification_channel',
                $channelId,
                $receiptHash
            );
            $this->audit->appendWithPdo(
                $pdo,
                'notification_channel',
                $channelId,
                'saved',
                'account_user',
                $actorUserId,
                $receiptHash
            );
            return ['outcome' => 'success', 'public_id' => $publicId, 'status' => 'active'];
        });

        $this->throwOutcome((string) $result['outcome']);
        return ['public_id' => (string) $result['public_id'], 'status' => (string) $result['status']];
    }

    public function setChannelStatus(
        int $accountId,
        int $actorUserId,
        string $actorRole,
        string $channelPublicId,
        string $status,
        string $requestId
    ): void {
        $channelPublicId = trim($channelPublicId);
        $status = strtolower(trim($status));
        if (!preg_match('/^OPS-CHANNEL-[A-F0-9]{20}$/', $channelPublicId)
            || !in_array($status, ['active', 'paused', 'revoked'], true)) {
            throw new AuthPublicException('operations_channel_invalid', 'The notification channel action is invalid.', 422);
        }

        $outcome = $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $actorUserId,
            $actorRole,
            $channelPublicId,
            $status,
            $requestId
        ): string {
            $operation = 'control_center_notification_channel_status';
            $prior = $this->requestReceipt($pdo, $accountId, $requestId, $operation);
            if (is_array($prior)) {
                return (string) $prior['result'] === 'success' ? 'success' : 'denied_replay';
            }

            if (!$this->actorAuthorized($pdo, $accountId, $actorUserId, $actorRole, self::MANAGER_ROLES)) {
                $hash = hash('sha256', $accountId . '|' . $actorUserId . '|' . $requestId . '|channel_status_denied');
                $this->insertRequestReceipt($pdo, $accountId, $requestId, $operation, 'denied', null, null, $hash);
                $this->audit->appendWithPdo($pdo, 'notification_channel', 0, 'access_denied', 'account_user', $actorUserId, $hash);
                return 'permission_denied';
            }

            $find = $pdo->prepare(
                'SELECT id,status FROM operational_notification_channels
                 WHERE public_id=:public AND account_scope=:account LIMIT 1 FOR UPDATE'
            );
            $find->execute(['public' => $channelPublicId, 'account' => $accountId]);
            $channel = $find->fetch(PDO::FETCH_ASSOC);
            if (!is_array($channel)) {
                $hash = hash('sha256', $accountId . '|' . $channelPublicId . '|' . $requestId . '|not_found');
                $this->insertRequestReceipt($pdo, $accountId, $requestId, $operation, 'denied', null, null, $hash);
                $this->audit->appendWithPdo($pdo, 'notification_channel', 0, 'not_found', 'account_user', $actorUserId, $hash);
                return 'not_found';
            }

            $channelId = (int) $channel['id'];
            if ((string) $channel['status'] !== $status) {
                $pdo->prepare(
                    "UPDATE operational_notification_channels
                     SET status=:status,
                         revoked_at=CASE WHEN :revocation='revoked' THEN UTC_TIMESTAMP() ELSE NULL END,
                         updated_at=UTC_TIMESTAMP()
                     WHERE id=:id AND account_scope=:account"
                )->execute([
                    'status' => $status,
                    'revocation' => $status,
                    'id' => $channelId,
                    'account' => $accountId,
                ]);
                if ($status !== 'active') {
                    $pdo->prepare(
                        "UPDATE operational_notifications
                         SET status='canceled',updated_at=UTC_TIMESTAMP()
                         WHERE channel_id=:channel AND status='queued'"
                    )->execute(['channel' => $channelId]);
                }
            }

            $hash = hash('sha256', $accountId . '|' . $channelId . '|' . $status . '|' . $requestId);
            $this->insertRequestReceipt(
                $pdo,
                $accountId,
                $requestId,
                $operation,
                'success',
                'notification_channel',
                $channelId,
                $hash
            );
            $this->audit->appendWithPdo(
                $pdo,
                'notification_channel',
                $channelId,
                $status,
                'account_user',
                $actorUserId,
                $hash
            );
            return 'success';
        });

        $this->throwOutcome($outcome);
    }

    /** @param list<string> $allowedRoles @param array<string,string>|null $resolution */
    private function changeIncidentState(
        int $accountId,
        int $actorUserId,
        string $actorRole,
        string $incidentPublicId,
        string $newStatus,
        string $requestId,
        ?array $resolution,
        array $allowedRoles
    ): void {
        $incidentPublicId = trim($incidentPublicId);
        if (!preg_match('/^OPS-INC-[A-F0-9]{20}$/', $incidentPublicId)) {
            throw new AuthPublicException('operations_incident_invalid', 'The operational incident was not found.', 404);
        }

        $outcome = $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $actorUserId,
            $actorRole,
            $incidentPublicId,
            $newStatus,
            $requestId,
            $resolution,
            $allowedRoles
        ): string {
            $operation = 'control_center_incident_' . $newStatus;
            $prior = $this->requestReceipt($pdo, $accountId, $requestId, $operation);
            if (is_array($prior)) {
                return (string) $prior['result'] === 'success' || (string) $prior['result'] === 'ignored'
                    ? 'success'
                    : 'denied_replay';
            }

            if (!$this->actorAuthorized($pdo, $accountId, $actorUserId, $actorRole, $allowedRoles)) {
                $hash = hash('sha256', $accountId . '|' . $actorUserId . '|' . $requestId . '|incident_role_denied');
                $this->insertRequestReceipt($pdo, $accountId, $requestId, $operation, 'denied', null, null, $hash);
                $this->audit->appendWithPdo($pdo, 'incident', 0, 'access_denied', 'account_user', $actorUserId, $hash);
                return 'permission_denied';
            }

            $find = $pdo->prepare(
                'SELECT * FROM operational_incidents
                 WHERE public_id=:public AND account_scope=:account LIMIT 1 FOR UPDATE'
            );
            $find->execute(['public' => $incidentPublicId, 'account' => $accountId]);
            $incident = $find->fetch(PDO::FETCH_ASSOC);
            if (!is_array($incident)) {
                $hash = hash('sha256', $accountId . '|' . $incidentPublicId . '|' . $requestId . '|incident_not_found');
                $this->insertRequestReceipt($pdo, $accountId, $requestId, $operation, 'denied', null, null, $hash);
                $this->audit->appendWithPdo($pdo, 'incident', 0, 'not_found', 'account_user', $actorUserId, $hash);
                return 'not_found';
            }

            $incidentId = (int) $incident['id'];
            $currentStatus = (string) $incident['status'];
            if ($currentStatus === 'resolved' || $currentStatus === $newStatus) {
                $hash = hash('sha256', $accountId . '|' . $incidentId . '|' . $requestId . '|ignored|' . $newStatus);
                $this->insertRequestReceipt($pdo, $accountId, $requestId, $operation, 'ignored', 'incident', $incidentId, $hash);
                return 'success';
            }

            $now = gmdate('Y-m-d H:i:s');
            $resolutionHash = $resolution === null
                ? null
                : hash('sha256', json_encode($resolution, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
            if ($newStatus === 'acknowledged') {
                $pdo->prepare(
                    "UPDATE operational_incidents
                     SET status='acknowledged',acknowledged_at=:acknowledged_at,
                         acknowledged_by=:actor,updated_at=:updated_at
                     WHERE id=:id AND account_scope=:account"
                )->execute([
                    'acknowledged_at' => $now,
                    'actor' => $actorUserId,
                    'updated_at' => $now,
                    'id' => $incidentId,
                    'account' => $accountId,
                ]);
            } else {
                $pdo->prepare(
                    "UPDATE operational_incidents
                     SET status='resolved',active_marker=NULL,resolved_at=:resolved_at,
                         resolved_by=:actor,resolution_hash=:resolution_hash,updated_at=:updated_at
                     WHERE id=:id AND account_scope=:account"
                )->execute([
                    'resolved_at' => $now,
                    'actor' => $actorUserId,
                    'resolution_hash' => $resolutionHash ?? hash('sha256', 'resolved'),
                    'updated_at' => $now,
                    'id' => $incidentId,
                    'account' => $accountId,
                ]);
            }

            $payloadHash = hash('sha256', implode('|', [
                (string) $incident['public_id'],
                $newStatus,
                (string) $incident['severity'],
                $resolutionHash ?? '',
            ]));
            $eventId = $this->appendIncidentEvent(
                $pdo,
                $incidentId,
                $newStatus,
                (string) $incident['severity'],
                $actorUserId,
                $payloadHash
            );
            $this->audit->appendWithPdo(
                $pdo,
                'incident',
                $incidentId,
                $newStatus,
                'account_user',
                $actorUserId,
                $payloadHash
            );
            $this->notifications->queueWithPdo(
                $pdo,
                $incidentId,
                $eventId,
                $newStatus,
                $newStatus,
                (string) $incident['severity'],
                $payloadHash
            );
            $receiptHash = hash('sha256', $accountId . '|' . $incidentId . '|' . $requestId . '|' . $newStatus . '|' . $payloadHash);
            $this->insertRequestReceipt(
                $pdo,
                $accountId,
                $requestId,
                $operation,
                'success',
                'incident',
                $incidentId,
                $receiptHash
            );
            return 'success';
        });

        $this->throwOutcome($outcome);
    }

    /** @param list<string> $allowedRoles */
    private function actorAuthorized(
        PDO $pdo,
        int $accountId,
        int $actorUserId,
        string $actorRole,
        array $allowedRoles
    ): bool {
        $statement = $pdo->prepare(
            "SELECT role FROM account_users
             WHERE account_id=:account AND user_id=:actor AND status='active'
             LIMIT 1 FOR UPDATE"
        );
        $statement->execute(['account' => $accountId, 'actor' => $actorUserId]);
        $storedRole = $statement->fetchColumn();
        return is_string($storedRole)
            && hash_equals($storedRole, $actorRole)
            && in_array($storedRole, $allowedRoles, true);
    }

    private function appendIncidentEvent(
        PDO $pdo,
        int $incidentId,
        string $status,
        string $severity,
        int $actorUserId,
        string $payloadHash
    ): int {
        $last = $pdo->prepare(
            'SELECT chain_hash FROM operational_incident_events
             WHERE incident_id=:incident ORDER BY id DESC LIMIT 1 FOR UPDATE'
        );
        $last->execute(['incident' => $incidentId]);
        $previous = $last->fetchColumn();
        $previous = is_string($previous) ? $previous : str_repeat('0', 64);
        $occurredAt = (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:s.u');
        $chainHash = hash('sha256', implode('|', [
            $previous,
            $incidentId,
            $status,
            $status,
            $severity,
            'account_user',
            $actorUserId,
            $payloadHash,
            $occurredAt,
        ]));
        $pdo->prepare(
            'INSERT INTO operational_incident_events
             (incident_id,event_type,event_status,severity,actor_type,actor_id,payload_hash,
              previous_chain_hash,chain_hash,occurred_at)
             VALUES (:incident,:event_type,:event_status,:severity,:actor_type,:actor_id,:payload,
                     :previous_chain,:chain_hash,:occurred_at)'
        )->execute([
            'incident' => $incidentId,
            'event_type' => $status,
            'event_status' => $status,
            'severity' => $severity,
            'actor_type' => 'account_user',
            'actor_id' => $actorUserId,
            'payload' => $payloadHash,
            'previous_chain' => $previous,
            'chain_hash' => $chainHash,
            'occurred_at' => $occurredAt,
        ]);
        return (int) $pdo->lastInsertId();
    }

    /** @return array<string,mixed>|null */
    private function requestReceipt(PDO $pdo, int $accountId, string $requestId, string $operation): ?array
    {
        $statement = $pdo->prepare(
            'SELECT * FROM operational_request_receipts
             WHERE account_scope=:account AND request_id=:request_id AND operation=:operation
             LIMIT 1 FOR UPDATE'
        );
        $statement->execute([
            'account' => $accountId,
            'request_id' => $requestId,
            'operation' => $operation,
        ]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        return is_array($row) ? $row : null;
    }

    private function insertRequestReceipt(
        PDO $pdo,
        int $accountId,
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
             VALUES (:account,:request_id,:operation,:result,:resource_type,:resource_id,:receipt_hash,UTC_TIMESTAMP())'
        )->execute([
            'account' => $accountId,
            'request_id' => substr(trim($requestId), 0, 80),
            'operation' => substr(trim($operation), 0, 100),
            'result' => $result,
            'resource_type' => $resourceType,
            'resource_id' => $resourceId,
            'receipt_hash' => $receiptHash,
        ]);
    }

    /** @return array{public_id:string,status:string}|null */
    private function channelIdentity(PDO $pdo, int $accountId, int $channelId): ?array
    {
        $statement = $pdo->prepare(
            'SELECT public_id,status FROM operational_notification_channels
             WHERE id=:id AND account_scope=:account LIMIT 1'
        );
        $statement->execute(['id' => $channelId, 'account' => $accountId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        return is_array($row)
            ? ['public_id' => (string) $row['public_id'], 'status' => (string) $row['status']]
            : null;
    }

    private function channelContext(int $accountId, string $type, string $label): string
    {
        return 'operations-channel|' . $accountId . '|' . strtolower(trim($type)) . '|' . hash('sha256', trim($label));
    }

    private function throwOutcome(string $outcome): void
    {
        if ($outcome === 'success') {
            return;
        }
        if ($outcome === 'permission_denied' || $outcome === 'denied_replay') {
            throw new AuthPublicException(
                'operations_permission_denied',
                'The current account role cannot complete this operations action.',
                403
            );
        }
        throw new AuthPublicException(
            'operations_resource_not_found',
            'The requested operational resource was not found.',
            404
        );
    }
}

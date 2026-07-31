<?php

declare(strict_types=1);

namespace Vp3\Security;

use InvalidArgumentException;
use PDO;
use RuntimeException;
use Vp3\Auth\AuthPublicException;
use Vp3\Database;
use Vp3\Operations\OperationalIncidentService;
use Vp3\Operations\OperationsSecretCipher;

final class SecurityIncidentResponseService
{
    private const MANAGER_ROLES = ['customer_owner', 'customer_admin'];
    private const RESPONDER_ROLES = ['customer_owner', 'customer_admin', 'support_member'];

    public function __construct(
        private readonly Database $database,
        private readonly OperationalIncidentService $incidents,
        private readonly OperationsSecretCipher $cipher,
        private readonly SecurityReauthenticationService $reauthentication,
        private readonly SecurityAuditService $audit
    ) {
    }

    /** @return array{case_public_id:string,incident_public_id:string,status:string,replayed:bool} */
    public function promoteAuditEvent(
        int $accountId,
        int $actorUserId,
        string $actorRole,
        string $eventPublicId,
        string $requestId
    ): array {
        $eventPublicId = trim($eventPublicId);
        $requestId = $this->requestId($requestId);
        if (!preg_match('/^SAE-[A-F0-9]{32}$/', $eventPublicId)) {
            throw new AuthPublicException('security_event_invalid', 'The security event was not found.', 404);
        }

        $result = $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $actorUserId,
            $actorRole,
            $eventPublicId,
            $requestId
        ): array {
            $this->assertActor($pdo, $accountId, $actorUserId, $actorRole, self::MANAGER_ROLES, true);
            $prior = $this->responseAction($pdo, $accountId, $requestId, 'promote_audit_event');
            if (is_array($prior)) {
                $case = $prior['case_id'] === null
                    ? null
                    : $this->caseById($pdo, $accountId, (int) $prior['case_id']);
                if (is_array($case) && in_array((string) $prior['result'], ['success', 'ignored'], true)) {
                    return $this->promotionResult($case, true);
                }
                return ['error' => 'security_response_replay_denied', 'status' => 409];
            }

            $event = $pdo->prepare(
                'SELECT id,public_id,event_type,category,risk_level,result,resource_type,resource_public_id,chain_hash,occurred_at
                 FROM security_audit_events
                 WHERE public_id=:public_id AND account_scope=:account_scope LIMIT 1 FOR UPDATE'
            );
            $event->execute(['public_id' => $eventPublicId, 'account_scope' => $accountId]);
            $eventRow = $event->fetch(PDO::FETCH_ASSOC);
            if (!is_array($eventRow)) {
                $this->recordAction(
                    $pdo,
                    $accountId,
                    null,
                    $actorUserId,
                    null,
                    $requestId,
                    'promote_audit_event',
                    'denied',
                    hash('sha256', $eventPublicId . '|not_found')
                );
                return ['error' => 'security_event_invalid', 'status' => 404];
            }
            if (!$this->qualifiesForIncident($eventRow)) {
                $this->recordAction(
                    $pdo,
                    $accountId,
                    null,
                    $actorUserId,
                    null,
                    $requestId,
                    'promote_audit_event',
                    'denied',
                    hash('sha256', $eventPublicId . '|not_qualified')
                );
                return ['error' => 'security_event_not_escalatable', 'status' => 422];
            }

            $existing = $pdo->prepare(
                'SELECT c.id,c.public_id,c.case_status,i.public_id AS incident_public_id
                 FROM security_incident_cases c
                 INNER JOIN operational_incidents i ON i.id=c.operational_incident_id
                 WHERE c.source_audit_event_id=:event_id AND c.account_scope=:account_scope LIMIT 1 FOR UPDATE'
            );
            $existing->execute(['event_id' => (int) $eventRow['id'], 'account_scope' => $accountId]);
            $existingRow = $existing->fetch(PDO::FETCH_ASSOC);
            if (is_array($existingRow)) {
                $this->recordAction(
                    $pdo,
                    $accountId,
                    (int) $existingRow['id'],
                    $actorUserId,
                    null,
                    $requestId,
                    'promote_audit_event',
                    'ignored',
                    hash('sha256', $eventPublicId . '|already_promoted|' . (string) $existingRow['public_id'])
                );
                return $this->promotionResult($existingRow, true);
            }

            $incident = $this->incidents->open(
                $accountId,
                'security_audit',
                (int) $eventRow['id'],
                $this->incidentSeverity((string) $eventRow['risk_level']),
                mb_substr('Security incident: ' . (string) $eventRow['event_type'], 0, 190),
                [
                    'audit_event_public_id' => $eventPublicId,
                    'event_type' => (string) $eventRow['event_type'],
                    'category' => (string) $eventRow['category'],
                    'risk_level' => (string) $eventRow['risk_level'],
                    'result' => (string) $eventRow['result'],
                    'chain_hash' => (string) $eventRow['chain_hash'],
                ],
                false
            );

            $casePublicId = 'SEC-CASE-' . strtoupper(bin2hex(random_bytes(10)));
            $now = $this->now();
            $pdo->prepare(
                "INSERT INTO security_incident_cases
                 (public_id,account_scope,operational_incident_id,source_audit_event_id,case_status,
                  assigned_user_id,created_by_user_id,last_action_at,created_at,updated_at)
                 VALUES (:public_id,:account_scope,:incident_id,:event_id,'triage',NULL,:created_by,:last_action_at,:created_at,:updated_at)"
            )->execute([
                'public_id' => $casePublicId,
                'account_scope' => $accountId,
                'incident_id' => (int) $incident['incident_id'],
                'event_id' => (int) $eventRow['id'],
                'created_by' => $actorUserId,
                'last_action_at' => $now,
                'created_at' => $now,
                'updated_at' => $now,
            ]);
            $caseId = (int) $pdo->lastInsertId();
            $this->recordAction(
                $pdo,
                $accountId,
                $caseId,
                $actorUserId,
                null,
                $requestId,
                'promote_audit_event',
                'success',
                hash('sha256', implode('|', [$eventPublicId, $casePublicId, (string) $incident['public_id'], $requestId]))
            );

            return [
                'case_public_id' => $casePublicId,
                'incident_public_id' => (string) $incident['public_id'],
                'status' => 'triage',
                'replayed' => false,
            ];
        });

        if (isset($result['error'])) {
            $this->audit->record(
                'security.incident.promotion_denied',
                'platform',
                'high',
                'denied',
                $accountId,
                'account_user',
                $actorUserId,
                null,
                'security_audit_event',
                $eventPublicId,
                ['reason' => (string) $result['error']],
                $requestId
            );
            $message = $result['error'] === 'security_event_invalid'
                ? 'The security event was not found.'
                : ($result['error'] === 'security_event_not_escalatable'
                    ? 'The security event does not meet the incident threshold.'
                    : 'The prior security response was not successful.');
            throw new AuthPublicException((string) $result['error'], $message, (int) $result['status']);
        }

        $this->audit->record(
            'security.incident.promoted',
            'platform',
            'high',
            'success',
            $accountId,
            'account_user',
            $actorUserId,
            null,
            'security_incident_case',
            (string) $result['case_public_id'],
            [
                'source_event_public_id' => $eventPublicId,
                'incident_public_id' => (string) $result['incident_public_id'],
                'replayed' => (bool) $result['replayed'],
            ],
            $requestId
        );
        return $result;
    }

    public function assignCase(
        int $accountId,
        int $actorUserId,
        string $actorRole,
        string $casePublicId,
        string $assigneeUserPublicId,
        string $requestId
    ): void {
        $requestId = $this->requestId($requestId);
        $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $actorUserId,
            $actorRole,
            $casePublicId,
            $assigneeUserPublicId,
            $requestId
        ): void {
            $this->assertActor($pdo, $accountId, $actorUserId, $actorRole, self::MANAGER_ROLES, true);
            if (is_array($this->responseAction($pdo, $accountId, $requestId, 'assign_case'))) {
                return;
            }
            $case = $this->caseForUpdate($pdo, $accountId, $casePublicId);
            $assignee = $pdo->prepare(
                "SELECT u.id,u.public_id,au.role
                 FROM users u INNER JOIN account_users au ON au.user_id=u.id
                 WHERE u.public_id=:public_id AND au.account_id=:account_scope AND au.status='active'
                   AND au.role IN ('customer_owner','customer_admin','support_member') LIMIT 1 FOR UPDATE"
            );
            $assignee->execute(['public_id' => trim($assigneeUserPublicId), 'account_scope' => $accountId]);
            $assigneeRow = $assignee->fetch(PDO::FETCH_ASSOC);
            if (!is_array($assigneeRow)) {
                throw new AuthPublicException('security_assignee_invalid', 'The selected security responder is not available.', 422);
            }
            $now = $this->now();
            $pdo->prepare(
                "UPDATE security_incident_cases
                 SET assigned_user_id=:assignee,
                     case_status=CASE WHEN case_status='triage' THEN 'investigating' ELSE case_status END,
                     last_action_at=:last_action_at,
                     updated_at=:updated_at
                 WHERE id=:id AND account_scope=:account_scope"
            )->execute([
                'assignee' => (int) $assigneeRow['id'],
                'last_action_at' => $now,
                'updated_at' => $now,
                'id' => (int) $case['id'],
                'account_scope' => $accountId,
            ]);
            $this->recordAction(
                $pdo,
                $accountId,
                (int) $case['id'],
                $actorUserId,
                (int) $assigneeRow['id'],
                $requestId,
                'assign_case',
                'success',
                hash('sha256', $casePublicId . '|' . (string) $assigneeRow['public_id'] . '|' . $requestId)
            );
        });

        $this->audit->record(
            'security.incident.assigned',
            'platform',
            'medium',
            'success',
            $accountId,
            'account_user',
            $actorUserId,
            null,
            'security_incident_case',
            $casePublicId,
            ['assignee_user_public_id' => $assigneeUserPublicId],
            $requestId
        );
    }

    /** @return array{note_public_id:string,note_hash:string,created_at:string} */
    public function addEncryptedNote(
        int $accountId,
        int $actorUserId,
        string $actorRole,
        string $casePublicId,
        string $note,
        string $requestId
    ): array {
        $note = trim($note);
        $requestId = $this->requestId($requestId);
        if ($note === '' || mb_strlen($note) > 4000) {
            throw new InvalidArgumentException('A security incident note of 1 to 4000 characters is required.');
        }

        $result = $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $actorUserId,
            $actorRole,
            $casePublicId,
            $note,
            $requestId
        ): array {
            $this->assertActor($pdo, $accountId, $actorUserId, $actorRole, self::RESPONDER_ROLES, true);
            if (is_array($this->responseAction($pdo, $accountId, $requestId, 'add_note'))) {
                throw new AuthPublicException('security_note_replayed', 'This security note request has already been processed.', 409);
            }
            $case = $this->caseForUpdate($pdo, $accountId, $casePublicId);
            if ($actorRole === 'support_member' && (int) ($case['assigned_user_id'] ?? 0) !== $actorUserId) {
                throw new AuthPublicException('security_case_assignment_required', 'This security case must be assigned to you before adding notes.', 403);
            }

            $notePublicId = 'SEC-NOTE-' . strtoupper(bin2hex(random_bytes(10)));
            $noteHash = hash('sha256', $note);
            $encrypted = $this->cipher->encrypt(
                $note,
                implode('|', ['security-incident-note', $accountId, $casePublicId, $notePublicId])
            );
            $now = $this->now();
            $pdo->prepare(
                'INSERT INTO security_incident_notes
                 (public_id,case_id,author_user_id,note_ciphertext,note_nonce,note_tag,encryption_key_id,note_hash,created_at)
                 VALUES (:public_id,:case_id,:author_user_id,:ciphertext,:nonce,:tag,:key_id,:note_hash,:created_at)'
            )->execute([
                'public_id' => $notePublicId,
                'case_id' => (int) $case['id'],
                'author_user_id' => $actorUserId,
                'ciphertext' => $encrypted['ciphertext'],
                'nonce' => $encrypted['nonce'],
                'tag' => $encrypted['tag'],
                'key_id' => $encrypted['key_id'],
                'note_hash' => $noteHash,
                'created_at' => $now,
            ]);
            $pdo->prepare(
                'UPDATE security_incident_cases
                 SET last_action_at=:last_action_at,updated_at=:updated_at
                 WHERE id=:id'
            )->execute([
                'last_action_at' => $now,
                'updated_at' => $now,
                'id' => (int) $case['id'],
            ]);
            $this->recordAction(
                $pdo,
                $accountId,
                (int) $case['id'],
                $actorUserId,
                null,
                $requestId,
                'add_note',
                'success',
                hash('sha256', $notePublicId . '|' . $noteHash . '|' . $requestId)
            );
            return ['note_public_id' => $notePublicId, 'note_hash' => $noteHash, 'created_at' => $now];
        });

        $this->audit->record(
            'security.incident.note_added',
            'platform',
            'low',
            'success',
            $accountId,
            'account_user',
            $actorUserId,
            null,
            'security_incident_case',
            $casePublicId,
            ['note_public_id' => $result['note_public_id'], 'note_hash' => $result['note_hash']],
            $requestId
        );
        return $result;
    }

    public function emergencyRevokeUserSessions(
        int $accountId,
        int $actorUserId,
        string $actorRole,
        string $targetUserPublicId,
        ?string $casePublicId,
        string $reauthenticationPublicId,
        string $requestId
    ): int {
        $requestId = $this->requestId($requestId);
        $targetUserPublicId = trim($targetUserPublicId);
        $casePublicId = $casePublicId === null || trim($casePublicId) === '' ? null : trim($casePublicId);

        $this->assertActor(
            $this->database->pdo(),
            $accountId,
            $actorUserId,
            $actorRole,
            self::MANAGER_ROLES,
            false
        );
        $prior = $this->responseAction(
            $this->database->pdo(),
            $accountId,
            $requestId,
            'emergency_revoke_sessions'
        );
        if (is_array($prior)) {
            if ($this->emergencyReplayMatches($this->database->pdo(), $accountId, $prior, $targetUserPublicId, $casePublicId)) {
                return 0;
            }
            throw new AuthPublicException(
                'security_response_request_conflict',
                'The request ID was already used for a different emergency response.',
                409
            );
        }

        $context = [
            'target_user_public_id' => $targetUserPublicId,
            'case_public_id' => $casePublicId,
        ];
        $this->reauthentication->consume(
            trim($reauthenticationPublicId),
            $accountId,
            $actorUserId,
            'security.emergency_revoke_sessions',
            $context
        );

        $count = $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $actorUserId,
            $actorRole,
            $targetUserPublicId,
            $casePublicId,
            $requestId
        ): int {
            $this->assertActor($pdo, $accountId, $actorUserId, $actorRole, self::MANAGER_ROLES, true);
            $prior = $this->responseAction($pdo, $accountId, $requestId, 'emergency_revoke_sessions');
            if (is_array($prior)) {
                if ($this->emergencyReplayMatches($pdo, $accountId, $prior, $targetUserPublicId, $casePublicId)) {
                    return 0;
                }
                throw new AuthPublicException(
                    'security_response_request_conflict',
                    'The request ID was already used for a different emergency response.',
                    409
                );
            }

            $target = $pdo->prepare(
                "SELECT u.id,u.public_id
                 FROM users u INNER JOIN account_users au ON au.user_id=u.id
                 WHERE u.public_id=:public_id AND au.account_id=:account_scope AND au.status='active'
                 LIMIT 1 FOR UPDATE"
            );
            $target->execute(['public_id' => $targetUserPublicId, 'account_scope' => $accountId]);
            $targetRow = $target->fetch(PDO::FETCH_ASSOC);
            if (!is_array($targetRow)) {
                throw new AuthPublicException('security_response_target_invalid', 'The target account user was not found.', 404);
            }

            $caseId = null;
            if ($casePublicId !== null) {
                $case = $this->caseForUpdate($pdo, $accountId, $casePublicId);
                $caseId = (int) $case['id'];
            }

            $sessions = $pdo->prepare(
                'SELECT id,session_public_id FROM auth_sessions
                 WHERE user_id=:user_id AND revoked_at IS NULL FOR UPDATE'
            );
            $sessions->execute(['user_id' => (int) $targetRow['id']]);
            $sessionRows = $sessions->fetchAll(PDO::FETCH_ASSOC);
            $now = $this->nowSeconds();
            $update = $pdo->prepare(
                "UPDATE auth_sessions
                 SET revoked_at=:revoked_at,
                     revocation_reason='security_incident_response',
                     revoked_by_user_id=:actor_user_id,
                     updated_at=:updated_at
                 WHERE user_id=:target_user_id AND revoked_at IS NULL"
            );
            $update->execute([
                'revoked_at' => $now,
                'actor_user_id' => $actorUserId,
                'updated_at' => $now,
                'target_user_id' => (int) $targetRow['id'],
            ]);
            $revokedCount = $update->rowCount();
            $sessionEvidence = array_map(
                static fn (array $row): string => hash('sha256', (string) $row['session_public_id']),
                $sessionRows
            );
            sort($sessionEvidence, SORT_STRING);
            $evidenceHash = hash('sha256', json_encode([
                'target_user_public_id' => (string) $targetRow['public_id'],
                'case_public_id' => $casePublicId,
                'revoked_count' => $revokedCount,
                'session_evidence' => $sessionEvidence,
                'request_id' => $requestId,
            ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
            $this->recordAction(
                $pdo,
                $accountId,
                $caseId,
                $actorUserId,
                (int) $targetRow['id'],
                $requestId,
                'emergency_revoke_sessions',
                'success',
                $evidenceHash
            );
            if ($caseId !== null) {
                $containedAt = $this->now();
                $pdo->prepare(
                    "UPDATE security_incident_cases
                     SET case_status='contained',last_action_at=:last_action_at,updated_at=:updated_at
                     WHERE id=:id"
                )->execute([
                    'last_action_at' => $containedAt,
                    'updated_at' => $containedAt,
                    'id' => $caseId,
                ]);
            }
            return $revokedCount;
        });

        $this->audit->record(
            'security.response.sessions_revoked',
            'session',
            'critical',
            'success',
            $accountId,
            'account_user',
            $actorUserId,
            null,
            'user',
            $targetUserPublicId,
            ['case_public_id' => $casePublicId, 'revoked_count' => $count],
            $requestId
        );
        return $count;
    }

    /** @param list<string> $allowedRoles */
    private function assertActor(
        PDO $pdo,
        int $accountId,
        int $actorUserId,
        string $actorRole,
        array $allowedRoles,
        bool $lock
    ): void {
        $sql = "SELECT role FROM account_users
                WHERE account_id=:account_id AND user_id=:user_id AND status='active' LIMIT 1";
        if ($lock) {
            $sql .= ' FOR UPDATE';
        }
        $statement = $pdo->prepare($sql);
        $statement->execute(['account_id' => $accountId, 'user_id' => $actorUserId]);
        $storedRole = $statement->fetchColumn();
        if (!is_string($storedRole)
            || !hash_equals($storedRole, $actorRole)
            || !in_array($storedRole, $allowedRoles, true)) {
            throw new AuthPublicException(
                'security_response_access_denied',
                'An authorized active account membership is required.',
                403
            );
        }
    }

    /** @return array<string,mixed> */
    private function caseForUpdate(PDO $pdo, int $accountId, string $casePublicId): array
    {
        if (!preg_match('/^SEC-CASE-[A-F0-9]{20}$/', trim($casePublicId))) {
            throw new AuthPublicException('security_case_invalid', 'The security incident case was not found.', 404);
        }
        $statement = $pdo->prepare(
            'SELECT * FROM security_incident_cases
             WHERE public_id=:public_id AND account_scope=:account_scope LIMIT 1 FOR UPDATE'
        );
        $statement->execute(['public_id' => trim($casePublicId), 'account_scope' => $accountId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new AuthPublicException('security_case_invalid', 'The security incident case was not found.', 404);
        }
        return $row;
    }

    /** @return array<string,mixed>|null */
    private function caseById(PDO $pdo, int $accountId, int $caseId): ?array
    {
        $statement = $pdo->prepare(
            'SELECT c.*,i.public_id AS incident_public_id
             FROM security_incident_cases c
             INNER JOIN operational_incidents i ON i.id=c.operational_incident_id
             WHERE c.id=:id AND c.account_scope=:account_scope LIMIT 1'
        );
        $statement->execute(['id' => $caseId, 'account_scope' => $accountId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        return is_array($row) ? $row : null;
    }

    /** @return array<string,mixed>|null */
    private function responseAction(PDO $pdo, int $accountId, string $requestId, string $actionType): ?array
    {
        $statement = $pdo->prepare(
            'SELECT * FROM security_response_actions
             WHERE account_scope=:account_scope AND request_id=:request_id AND action_type=:action_type LIMIT 1'
        );
        $statement->execute([
            'account_scope' => $accountId,
            'request_id' => $requestId,
            'action_type' => $actionType,
        ]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        return is_array($row) ? $row : null;
    }

    /** @param array<string,mixed> $prior */
    private function emergencyReplayMatches(
        PDO $pdo,
        int $accountId,
        array $prior,
        string $targetUserPublicId,
        ?string $casePublicId
    ): bool {
        if ((string) ($prior['result'] ?? '') !== 'success' || $prior['target_user_id'] === null) {
            return false;
        }
        $target = $pdo->prepare('SELECT public_id FROM users WHERE id=:id LIMIT 1');
        $target->execute(['id' => (int) $prior['target_user_id']]);
        $storedTarget = $target->fetchColumn();
        if (!is_string($storedTarget) || !hash_equals($storedTarget, $targetUserPublicId)) {
            return false;
        }

        if ($casePublicId === null) {
            return $prior['case_id'] === null;
        }
        if ($prior['case_id'] === null) {
            return false;
        }
        $case = $pdo->prepare(
            'SELECT public_id FROM security_incident_cases
             WHERE id=:id AND account_scope=:account_scope LIMIT 1'
        );
        $case->execute(['id' => (int) $prior['case_id'], 'account_scope' => $accountId]);
        $storedCase = $case->fetchColumn();
        return is_string($storedCase) && hash_equals($storedCase, $casePublicId);
    }

    private function recordAction(
        PDO $pdo,
        int $accountId,
        ?int $caseId,
        int $actorUserId,
        ?int $targetUserId,
        string $requestId,
        string $actionType,
        string $result,
        string $evidenceHash
    ): void {
        $pdo->prepare(
            'INSERT INTO security_response_actions
             (public_id,account_scope,case_id,actor_user_id,target_user_id,request_id,action_type,result,evidence_hash,created_at)
             VALUES (:public_id,:account_scope,:case_id,:actor_user_id,:target_user_id,:request_id,:action_type,:result,:evidence_hash,:created_at)'
        )->execute([
            'public_id' => 'SEC-ACTION-' . strtoupper(bin2hex(random_bytes(10))),
            'account_scope' => $accountId,
            'case_id' => $caseId,
            'actor_user_id' => $actorUserId,
            'target_user_id' => $targetUserId,
            'request_id' => $requestId,
            'action_type' => $actionType,
            'result' => $result,
            'evidence_hash' => $evidenceHash,
            'created_at' => $this->now(),
        ]);
    }

    /** @param array<string,mixed> $case */
    private function promotionResult(array $case, bool $replayed): array
    {
        return [
            'case_public_id' => (string) $case['public_id'],
            'incident_public_id' => (string) $case['incident_public_id'],
            'status' => (string) $case['case_status'],
            'replayed' => $replayed,
        ];
    }

    /** @param array<string,mixed> $event */
    private function qualifiesForIncident(array $event): bool
    {
        return in_array((string) $event['risk_level'], ['high', 'critical'], true)
            || in_array((string) $event['result'], ['failure', 'denied'], true)
            || (string) $event['category'] === 'integrity';
    }

    private function incidentSeverity(string $risk): string
    {
        return match ($risk) {
            'critical' => 'critical',
            'high', 'medium' => 'warning',
            default => 'info',
        };
    }

    private function requestId(string $requestId): string
    {
        $requestId = trim($requestId);
        if (!preg_match('/^[A-Za-z0-9._:-]{8,80}$/', $requestId)) {
            throw new InvalidArgumentException('A valid security response request ID is required.');
        }
        return $requestId;
    }

    private function now(): string
    {
        return gmdate('Y-m-d H:i:s') . '.000000';
    }

    private function nowSeconds(): string
    {
        return gmdate('Y-m-d H:i:s');
    }
}

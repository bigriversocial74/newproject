<?php

declare(strict_types=1);

namespace Vp3\Security;

use PDO;
use Vp3\Auth\AuthPublicException;
use Vp3\Database;
use Vp3\Operations\OperationalIncidentService;

final class SecurityIncidentResolutionService
{
    private const MANAGER_ROLES = ['customer_owner', 'customer_admin'];

    public function __construct(
        private readonly Database $database,
        private readonly OperationalIncidentService $incidents,
        private readonly SecurityReauthenticationService $reauthentication,
        private readonly SecurityAuditService $audit
    ) {
    }

    public function resolve(
        int $accountId,
        int $actorUserId,
        string $actorRole,
        string $casePublicId,
        string $resolutionSummary,
        string $reauthenticationPublicId,
        string $requestId
    ): bool {
        $casePublicId = trim($casePublicId);
        $resolutionSummary = trim($resolutionSummary);
        $requestId = trim($requestId);
        if (!preg_match('/^SEC-CASE-[A-F0-9]{20}$/', $casePublicId)
            || mb_strlen($resolutionSummary) < 10
            || mb_strlen($resolutionSummary) > 2000
            || !preg_match('/^[A-Za-z0-9._:-]{8,80}$/', $requestId)) {
            throw new \InvalidArgumentException('A valid security case, resolution summary, and request ID are required.');
        }

        $this->assertManager($this->database->pdo(), $accountId, $actorUserId, $actorRole, false);
        $prior = $this->responseAction($this->database->pdo(), $accountId, $requestId);
        if (is_array($prior)) {
            if ($this->replayMatches($this->database->pdo(), $accountId, $prior, $casePublicId)) {
                return false;
            }
            throw new AuthPublicException(
                'security_response_request_conflict',
                'The request ID was already used for a different security response.',
                409
            );
        }

        $context = [
            'case_public_id' => $casePublicId,
            'resolution_hash' => hash('sha256', $resolutionSummary),
        ];
        $this->reauthentication->consume(
            trim($reauthenticationPublicId),
            $accountId,
            $actorUserId,
            'security.resolve_incident_case',
            $context
        );

        $resolved = $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $actorUserId,
            $actorRole,
            $casePublicId,
            $resolutionSummary,
            $requestId
        ): bool {
            $this->assertManager($pdo, $accountId, $actorUserId, $actorRole, true);
            $prior = $this->responseAction($pdo, $accountId, $requestId);
            if (is_array($prior)) {
                if ($this->replayMatches($pdo, $accountId, $prior, $casePublicId)) {
                    return false;
                }
                throw new AuthPublicException(
                    'security_response_request_conflict',
                    'The request ID was already used for a different security response.',
                    409
                );
            }

            $caseStatement = $pdo->prepare(
                'SELECT c.id,c.public_id,c.case_status,c.operational_incident_id,i.public_id AS incident_public_id
                 FROM security_incident_cases c
                 INNER JOIN operational_incidents i ON i.id=c.operational_incident_id
                 WHERE c.public_id=:public_id AND c.account_scope=:account LIMIT 1 FOR UPDATE'
            );
            $caseStatement->execute(['public_id' => $casePublicId, 'account' => $accountId]);
            $case = $caseStatement->fetch(PDO::FETCH_ASSOC);
            if (!is_array($case)) {
                throw new AuthPublicException('security_case_invalid', 'The security incident case was not found.', 404);
            }

            if ((string) $case['case_status'] === 'resolved') {
                $this->recordAction(
                    $pdo,
                    $accountId,
                    (int) $case['id'],
                    $actorUserId,
                    $requestId,
                    'ignored',
                    hash('sha256', $casePublicId . '|already_resolved|' . $requestId)
                );
                return false;
            }

            $this->incidents->resolve(
                $accountId,
                (int) $case['operational_incident_id'],
                $actorUserId,
                $requestId . '-OPS',
                [
                    'security_case_public_id' => $casePublicId,
                    'resolution_hash' => hash('sha256', $resolutionSummary),
                ]
            );

            $now = $this->now();
            $pdo->prepare(
                "UPDATE security_incident_cases
                 SET case_status='resolved',last_action_at=:last_action_at,updated_at=:updated_at
                 WHERE id=:id AND account_scope=:account"
            )->execute([
                'last_action_at' => $now,
                'updated_at' => $now,
                'id' => (int) $case['id'],
                'account' => $accountId,
            ]);
            $this->recordAction(
                $pdo,
                $accountId,
                (int) $case['id'],
                $actorUserId,
                $requestId,
                'success',
                hash('sha256', implode('|', [
                    $casePublicId,
                    (string) $case['incident_public_id'],
                    hash('sha256', $resolutionSummary),
                    $requestId,
                ]))
            );
            return true;
        });

        $this->audit->record(
            'security.incident.resolved',
            'platform',
            'high',
            $resolved ? 'success' : 'ignored',
            $accountId,
            'account_user',
            $actorUserId,
            null,
            'security_incident_case',
            $casePublicId,
            ['resolution_hash' => hash('sha256', $resolutionSummary)],
            $requestId
        );
        return $resolved;
    }

    private function assertManager(PDO $pdo, int $accountId, int $userId, string $role, bool $lock): void
    {
        if ($accountId < 1 || $userId < 1 || !in_array($role, self::MANAGER_ROLES, true)) {
            throw new AuthPublicException('security_response_access_denied', 'An active account owner or administrator is required.', 403);
        }
        $statement = $pdo->prepare(
            "SELECT role FROM account_users
             WHERE account_id=:account AND user_id=:user AND status='active' LIMIT 1" . ($lock ? ' FOR UPDATE' : '')
        );
        $statement->execute(['account' => $accountId, 'user' => $userId]);
        $storedRole = $statement->fetchColumn();
        if (!is_string($storedRole) || !hash_equals($storedRole, $role) || !in_array($storedRole, self::MANAGER_ROLES, true)) {
            throw new AuthPublicException('security_response_access_denied', 'An active account owner or administrator is required.', 403);
        }
    }

    /** @return array<string,mixed>|null */
    private function responseAction(PDO $pdo, int $accountId, string $requestId): ?array
    {
        $statement = $pdo->prepare(
            "SELECT * FROM security_response_actions
             WHERE account_scope=:account AND request_id=:request_id AND action_type='resolve_case' LIMIT 1"
        );
        $statement->execute(['account' => $accountId, 'request_id' => $requestId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        return is_array($row) ? $row : null;
    }

    /** @param array<string,mixed> $prior */
    private function replayMatches(PDO $pdo, int $accountId, array $prior, string $casePublicId): bool
    {
        if ($prior['case_id'] === null || !in_array((string) $prior['result'], ['success', 'ignored'], true)) {
            return false;
        }
        $statement = $pdo->prepare(
            'SELECT public_id FROM security_incident_cases WHERE id=:id AND account_scope=:account LIMIT 1'
        );
        $statement->execute(['id' => (int) $prior['case_id'], 'account' => $accountId]);
        $stored = $statement->fetchColumn();
        return is_string($stored) && hash_equals($stored, $casePublicId);
    }

    private function recordAction(
        PDO $pdo,
        int $accountId,
        int $caseId,
        int $actorUserId,
        string $requestId,
        string $result,
        string $evidenceHash
    ): void {
        $pdo->prepare(
            "INSERT INTO security_response_actions
             (public_id,account_scope,case_id,actor_user_id,target_user_id,request_id,
              action_type,result,evidence_hash,created_at)
             VALUES (:public_id,:account,:case_id,:actor,NULL,:request_id,'resolve_case',:result,:evidence_hash,:created_at)"
        )->execute([
            'public_id' => 'SEC-ACTION-' . strtoupper(bin2hex(random_bytes(10))),
            'account' => $accountId,
            'case_id' => $caseId,
            'actor' => $actorUserId,
            'request_id' => $requestId,
            'result' => $result,
            'evidence_hash' => $evidenceHash,
            'created_at' => $this->now(),
        ]);
    }

    private function now(): string
    {
        return (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s.u');
    }
}

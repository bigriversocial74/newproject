<?php

declare(strict_types=1);

namespace Vp3\Auth;

use DateTimeImmutable;
use PDO;
use Vp3\Database;

final class DatabaseSessionService
{
    public function __construct(
        private readonly Database $database,
        private readonly int $inactivityTtlSeconds,
        private readonly int $absoluteTtlSeconds,
        private readonly AuthAuditService $audit
    ) {
        if ($this->inactivityTtlSeconds < 60 || $this->absoluteTtlSeconds < $this->inactivityTtlSeconds) {
            throw new AuthPublicException('session_configuration_invalid', 'Session configuration is invalid.', 500);
        }
    }

    /** @return array{token:string,public_id:string,inactivity_expires_at:string,absolute_expires_at:string} */
    public function create(int $userId, string $ip, string $userAgent, ?string $rotatedFromPublicId = null): array
    {
        return $this->database->transaction(function (PDO $pdo) use ($userId, $ip, $userAgent, $rotatedFromPublicId): array {
            $session = $this->insertSession($pdo, $userId, $ip, $userAgent, $rotatedFromPublicId, null);
            $this->auditCreated($session['public_id'], $userId, $ip, $userAgent, $rotatedFromPublicId !== null);
            return $session;
        });
    }

    /** @return array{user:array{id:int,public_id:string,email:string,display_name:string,status:string},session:array{public_id:string,last_seen_at:string,inactivity_expires_at:string,absolute_expires_at:string,created_at:string}} */
    public function validate(string $token, string $ip, string $userAgent, bool $touch = true): array
    {
        if ($token === '') {
            throw new AuthPublicException('authentication_required', 'Authentication is required.', 401);
        }

        $pdo = $this->database->pdo();
        $row = $this->findSession($pdo, $this->hashToken($token), false);
        if (!$row) {
            $this->auditRejected(null, null, $ip, $userAgent, 'unknown_token');
            throw $this->invalidSession();
        }

        $now = new DateTimeImmutable('now');
        $publicId = (string) $row['session_public_id'];
        $userId = (int) $row['user_id'];
        if ($row['revoked_at'] !== null) {
            $this->auditRejected($publicId, $userId, $ip, $userAgent, 'revoked');
            throw $this->invalidSession();
        }

        $inactivity = new DateTimeImmutable((string) ($row['inactivity_expires_at'] ?: $row['expires_at']));
        $absolute = new DateTimeImmutable((string) ($row['absolute_expires_at'] ?: $row['expires_at']));
        if ((string) $row['user_status'] !== 'active') {
            $this->revokeAndReject((int) $row['id'], $publicId, $userId, $ip, $userAgent, 'user_not_active', $now);
            throw $this->invalidSession();
        }
        if ($now >= $inactivity || $now >= $absolute) {
            $this->expire((int) $row['id'], $publicId, $userId, $ip, $userAgent, $now >= $absolute ? 'absolute' : 'inactivity', $now);
            throw $this->invalidSession();
        }
        if (!$this->bindingMatches($row, $ip, $userAgent)) {
            $this->revokeAndReject((int) $row['id'], $publicId, $userId, $ip, $userAgent, 'binding_mismatch', $now);
            throw $this->invalidSession();
        }

        $nextInactivity = $this->capInactivity($now, $absolute);
        if ($touch) {
            $pdo->prepare(
                'UPDATE auth_sessions
                 SET last_seen_at = :last_seen_at, inactivity_expires_at = :inactivity_expires_at, updated_at = :updated_at
                 WHERE id = :id AND revoked_at IS NULL'
            )->execute([
                'last_seen_at' => $now->format('Y-m-d H:i:s'),
                'inactivity_expires_at' => $nextInactivity->format('Y-m-d H:i:s'),
                'updated_at' => $now->format('Y-m-d H:i:s'),
                'id' => $row['id'],
            ]);
        }

        return $this->context($row, $now, $nextInactivity, $absolute);
    }

    /** @return array{token:string,public_id:string,inactivity_expires_at:string,absolute_expires_at:string} */
    public function rotate(string $token, string $ip, string $userAgent): array
    {
        if ($token === '') {
            throw new AuthPublicException('authentication_required', 'Authentication is required.', 401);
        }

        $result = $this->database->transaction(function (PDO $pdo) use ($token, $ip, $userAgent): array {
            $row = $this->findSession($pdo, $this->hashToken($token), true);
            if (!$row) {
                return ['error' => 'unknown_token'];
            }

            $now = new DateTimeImmutable('now');
            $publicId = (string) $row['session_public_id'];
            $userId = (int) $row['user_id'];
            $inactivity = new DateTimeImmutable((string) ($row['inactivity_expires_at'] ?: $row['expires_at']));
            $absolute = new DateTimeImmutable((string) ($row['absolute_expires_at'] ?: $row['expires_at']));

            if ($row['revoked_at'] !== null) {
                return ['error' => 'revoked', 'public_id' => $publicId, 'user_id' => $userId];
            }
            if ((string) $row['user_status'] !== 'active') {
                $this->revokeById($pdo, (int) $row['id'], 'user_not_active', $now);
                $this->auditRejected($publicId, $userId, $ip, $userAgent, 'user_not_active');
                return ['error' => 'user_not_active'];
            }
            if ($now >= $inactivity || $now >= $absolute) {
                $reason = $now >= $absolute ? 'absolute' : 'inactivity';
                $this->revokeById($pdo, (int) $row['id'], 'expired', $now);
                $this->auditExpired($publicId, $userId, $ip, $userAgent, $reason);
                return ['error' => 'expired'];
            }
            if (!$this->bindingMatches($row, $ip, $userAgent)) {
                $this->revokeById($pdo, (int) $row['id'], 'binding_mismatch', $now);
                $this->auditRejected($publicId, $userId, $ip, $userAgent, 'binding_mismatch');
                return ['error' => 'binding_mismatch'];
            }

            $revoke = $pdo->prepare(
                'UPDATE auth_sessions
                 SET revoked_at = :revoked_at, revocation_reason = :reason, updated_at = :updated_at
                 WHERE id = :id AND revoked_at IS NULL'
            );
            $revoke->execute([
                'revoked_at' => $now->format('Y-m-d H:i:s'),
                'reason' => 'rotated',
                'updated_at' => $now->format('Y-m-d H:i:s'),
                'id' => $row['id'],
            ]);
            if ($revoke->rowCount() !== 1) {
                return ['error' => 'rotation_race', 'public_id' => $publicId, 'user_id' => $userId];
            }

            $replacement = $this->insertSession($pdo, $userId, $ip, $userAgent, $publicId, $absolute);
            $requestId = $this->audit->sessionEvent('rotated', $publicId, $userId, $ip, $userAgent);
            $this->audit->record('auth.session.rotated', 'success', $userId, null, 'auth_session', $publicId, [], $requestId);
            $this->auditCreated($replacement['public_id'], $userId, $ip, $userAgent, true);
            return ['session' => $replacement];
        });

        if (isset($result['session']) && is_array($result['session'])) {
            return $result['session'];
        }
        $reason = (string) ($result['error'] ?? 'invalid_session');
        if (in_array($reason, ['unknown_token', 'revoked', 'rotation_race'], true)) {
            $this->auditRejected(
                isset($result['public_id']) ? (string) $result['public_id'] : null,
                isset($result['user_id']) ? (int) $result['user_id'] : null,
                $ip,
                $userAgent,
                $reason
            );
        }
        throw $this->invalidSession();
    }

    /** @return list<array{public_id:string,last_seen_at:string,inactivity_expires_at:string,absolute_expires_at:string,created_at:string,current:bool}> */
    public function listForUser(int $userId, ?string $currentPublicId = null): array
    {
        $statement = $this->database->pdo()->prepare(
            'SELECT session_public_id, last_seen_at, inactivity_expires_at, absolute_expires_at, created_at
             FROM auth_sessions
             WHERE user_id = :user_id AND revoked_at IS NULL
               AND absolute_expires_at > :now_absolute AND inactivity_expires_at > :now_inactivity
             ORDER BY last_seen_at DESC, id DESC'
        );
        $now = (new DateTimeImmutable('now'))->format('Y-m-d H:i:s');
        $statement->execute(['user_id' => $userId, 'now_absolute' => $now, 'now_inactivity' => $now]);
        $sessions = [];
        foreach ($statement->fetchAll() as $row) {
            $sessions[] = [
                'public_id' => (string) $row['session_public_id'],
                'last_seen_at' => (new DateTimeImmutable((string) $row['last_seen_at']))->format(DATE_ATOM),
                'inactivity_expires_at' => (new DateTimeImmutable((string) $row['inactivity_expires_at']))->format(DATE_ATOM),
                'absolute_expires_at' => (new DateTimeImmutable((string) $row['absolute_expires_at']))->format(DATE_ATOM),
                'created_at' => (new DateTimeImmutable((string) $row['created_at']))->format(DATE_ATOM),
                'current' => $currentPublicId !== null && hash_equals($currentPublicId, (string) $row['session_public_id']),
            ];
        }
        return $sessions;
    }

    public function revokeCurrent(string $token, string $ip, string $userAgent, string $reason = 'logout'): bool
    {
        $current = $this->validate($token, $ip, $userAgent, false);
        return $this->revokeSelected($current['user']['id'], $current['session']['public_id'], $ip, $userAgent, $reason);
    }

    public function revokeSelected(int $actorUserId, string $sessionPublicId, string $ip, string $userAgent, string $reason = 'selected_device'): bool
    {
        return $this->database->transaction(function (PDO $pdo) use ($actorUserId, $sessionPublicId, $ip, $userAgent, $reason): bool {
            $now = new DateTimeImmutable('now');
            $statement = $pdo->prepare(
                'UPDATE auth_sessions
                 SET revoked_at = :revoked_at, revocation_reason = :reason,
                     revoked_by_user_id = :actor_user_id, updated_at = :updated_at
                 WHERE session_public_id = :public_id AND user_id = :target_user_id AND revoked_at IS NULL'
            );
            $statement->execute([
                'revoked_at' => $now->format('Y-m-d H:i:s'),
                'reason' => $reason,
                'actor_user_id' => $actorUserId,
                'updated_at' => $now->format('Y-m-d H:i:s'),
                'public_id' => $sessionPublicId,
                'target_user_id' => $actorUserId,
            ]);
            if ($statement->rowCount() !== 1) {
                $this->audit->record('auth.session.revocation_denied', 'denied', $actorUserId, null, 'auth_session', $sessionPublicId, ['reason' => 'not_found_or_cross_user']);
                return false;
            }
            $requestId = $this->audit->sessionEvent('revoked', $sessionPublicId, $actorUserId, $ip, $userAgent, ['reason' => $reason]);
            $this->audit->record('auth.session.revoked', 'success', $actorUserId, null, 'auth_session', $sessionPublicId, ['reason' => $reason], $requestId);
            if ($reason === 'logout') {
                $this->audit->record('auth.logout', 'success', $actorUserId, null, 'auth_session', $sessionPublicId, [], $requestId);
            }
            return true;
        });
    }

    public function revokeAllForUser(int $userId, string $reason, ?string $exceptPublicId = null, string $ip = '', string $userAgent = ''): int
    {
        return $this->database->transaction(function (PDO $pdo) use ($userId, $reason, $exceptPublicId, $ip, $userAgent): int {
            $selectSql = 'SELECT session_public_id FROM auth_sessions WHERE user_id = :target_user_id AND revoked_at IS NULL';
            $selectParams = ['target_user_id' => $userId];
            if ($exceptPublicId !== null) {
                $selectSql .= ' AND session_public_id <> :except_public_id';
                $selectParams['except_public_id'] = $exceptPublicId;
            }
            $select = $pdo->prepare($selectSql . ' FOR UPDATE');
            $select->execute($selectParams);
            $publicIds = array_map(static fn (array $row): string => (string) $row['session_public_id'], $select->fetchAll());

            $now = new DateTimeImmutable('now');
            $updateSql = 'UPDATE auth_sessions
                          SET revoked_at = :revoked_at, revocation_reason = :reason,
                              revoked_by_user_id = :actor_user_id, updated_at = :updated_at
                          WHERE user_id = :target_user_id AND revoked_at IS NULL';
            $updateParams = [
                'revoked_at' => $now->format('Y-m-d H:i:s'),
                'reason' => $reason,
                'actor_user_id' => $userId,
                'updated_at' => $now->format('Y-m-d H:i:s'),
                'target_user_id' => $userId,
            ];
            if ($exceptPublicId !== null) {
                $updateSql .= ' AND session_public_id <> :except_public_id';
                $updateParams['except_public_id'] = $exceptPublicId;
            }
            $pdo->prepare($updateSql)->execute($updateParams);

            foreach ($publicIds as $publicId) {
                $requestId = $this->audit->sessionEvent('revoked', $publicId, $userId, $ip, $userAgent, ['reason' => $reason]);
                $this->audit->record('auth.session.revoked', 'success', $userId, null, 'auth_session', $publicId, ['reason' => $reason], $requestId);
            }
            $this->audit->record($exceptPublicId === null ? 'auth.logout_all' : 'auth.logout_others', 'success', $userId, null, 'user', null, [
                'revoked_count' => count($publicIds),
                'reason' => $reason,
            ]);
            return count($publicIds);
        });
    }

    /** @return array<string,mixed>|false */
    private function findSession(PDO $pdo, string $hash, bool $lock): array|false
    {
        $sql = 'SELECT s.id, s.user_id, s.session_public_id, s.ip_hash, s.user_agent_hash, s.last_seen_at,
                       s.expires_at, s.inactivity_expires_at, s.absolute_expires_at, s.revoked_at, s.created_at,
                       u.public_id AS user_public_id, u.email, u.display_name, u.status AS user_status
                FROM auth_sessions s JOIN users u ON u.id = s.user_id
                WHERE s.session_hash = :session_hash LIMIT 1';
        if ($lock) {
            $sql .= ' FOR UPDATE';
        }
        $statement = $pdo->prepare($sql);
        $statement->execute(['session_hash' => $hash]);
        return $statement->fetch();
    }

    /** @param array<string,mixed> $row */
    private function bindingMatches(array $row, string $ip, string $userAgent): bool
    {
        $ipHash = $ip === '' ? null : hash('sha256', $ip);
        $userAgentHash = $userAgent === '' ? null : hash('sha256', $userAgent);
        return ($row['ip_hash'] === null || hash_equals((string) $row['ip_hash'], (string) $ipHash))
            && ($row['user_agent_hash'] === null || hash_equals((string) $row['user_agent_hash'], (string) $userAgentHash));
    }

    private function capInactivity(DateTimeImmutable $now, DateTimeImmutable $absolute): DateTimeImmutable
    {
        $next = $now->modify('+' . $this->inactivityTtlSeconds . ' seconds');
        return $next > $absolute ? $absolute : $next;
    }

    /** @param array<string,mixed> $row */
    private function context(array $row, DateTimeImmutable $now, DateTimeImmutable $inactivity, DateTimeImmutable $absolute): array
    {
        return [
            'user' => [
                'id' => (int) $row['user_id'],
                'public_id' => (string) $row['user_public_id'],
                'email' => (string) $row['email'],
                'display_name' => (string) $row['display_name'],
                'status' => (string) $row['user_status'],
            ],
            'session' => [
                'public_id' => (string) $row['session_public_id'],
                'last_seen_at' => $now->format(DATE_ATOM),
                'inactivity_expires_at' => $inactivity->format(DATE_ATOM),
                'absolute_expires_at' => $absolute->format(DATE_ATOM),
                'created_at' => (new DateTimeImmutable((string) $row['created_at']))->format(DATE_ATOM),
            ],
        ];
    }

    private function insertSession(PDO $pdo, int $userId, string $ip, string $userAgent, ?string $rotatedFromPublicId, ?DateTimeImmutable $absolute): array
    {
        $token = $this->newToken();
        $publicId = 'SES-' . strtoupper(bin2hex(random_bytes(12)));
        $now = new DateTimeImmutable('now');
        $absolute ??= $now->modify('+' . $this->absoluteTtlSeconds . ' seconds');
        $inactivity = $this->capInactivity($now, $absolute);
        $pdo->prepare(
            'INSERT INTO auth_sessions
             (user_id, session_public_id, session_hash, ip_hash, user_agent_hash, last_seen_at, expires_at,
              inactivity_expires_at, absolute_expires_at, rotated_from_public_id, updated_at, created_at)
             VALUES (:user_id, :public_id, :session_hash, :ip_hash, :user_agent_hash, :last_seen_at, :expires_at,
              :inactivity_expires_at, :absolute_expires_at, :rotated_from_public_id, :updated_at, :created_at)'
        )->execute([
            'user_id' => $userId,
            'public_id' => $publicId,
            'session_hash' => $this->hashToken($token),
            'ip_hash' => $ip === '' ? null : hash('sha256', $ip),
            'user_agent_hash' => $userAgent === '' ? null : hash('sha256', $userAgent),
            'last_seen_at' => $now->format('Y-m-d H:i:s'),
            'expires_at' => $absolute->format('Y-m-d H:i:s'),
            'inactivity_expires_at' => $inactivity->format('Y-m-d H:i:s'),
            'absolute_expires_at' => $absolute->format('Y-m-d H:i:s'),
            'rotated_from_public_id' => $rotatedFromPublicId,
            'updated_at' => $now->format('Y-m-d H:i:s'),
            'created_at' => $now->format('Y-m-d H:i:s'),
        ]);
        return [
            'token' => $token,
            'public_id' => $publicId,
            'inactivity_expires_at' => $inactivity->format(DATE_ATOM),
            'absolute_expires_at' => $absolute->format(DATE_ATOM),
        ];
    }

    private function auditCreated(string $publicId, int $userId, string $ip, string $userAgent, bool $rotated): void
    {
        $requestId = $this->audit->sessionEvent('created', $publicId, $userId, $ip, $userAgent, ['rotated' => $rotated]);
        $this->audit->record('auth.session.created', 'success', $userId, null, 'auth_session', $publicId, ['rotated' => $rotated], $requestId);
    }

    private function revokeAndReject(int $id, string $publicId, int $userId, string $ip, string $userAgent, string $reason, DateTimeImmutable $now): void
    {
        $this->database->transaction(function (PDO $pdo) use ($id, $publicId, $userId, $ip, $userAgent, $reason, $now): void {
            $this->revokeById($pdo, $id, $reason, $now);
            $this->auditRejected($publicId, $userId, $ip, $userAgent, $reason);
        });
    }

    private function expire(int $id, string $publicId, int $userId, string $ip, string $userAgent, string $reason, DateTimeImmutable $now): void
    {
        $this->database->transaction(function (PDO $pdo) use ($id, $publicId, $userId, $ip, $userAgent, $reason, $now): void {
            $this->revokeById($pdo, $id, 'expired', $now);
            $this->auditExpired($publicId, $userId, $ip, $userAgent, $reason);
        });
    }

    private function auditRejected(?string $publicId, ?int $userId, string $ip, string $userAgent, string $reason): void
    {
        $requestId = $this->audit->sessionEvent('rejected', $publicId, $userId, $ip, $userAgent, ['reason' => $reason]);
        $this->audit->record('auth.session.rejected', 'denied', $userId, null, 'auth_session', $publicId, ['reason' => $reason], $requestId);
    }

    private function auditExpired(string $publicId, int $userId, string $ip, string $userAgent, string $reason): void
    {
        $requestId = $this->audit->sessionEvent('expired', $publicId, $userId, $ip, $userAgent, ['reason' => $reason]);
        $this->audit->record('auth.session.expired', 'denied', $userId, null, 'auth_session', $publicId, ['reason' => $reason], $requestId);
    }

    private function revokeById(PDO $pdo, int $id, string $reason, DateTimeImmutable $now): void
    {
        $pdo->prepare(
            'UPDATE auth_sessions SET revoked_at = :revoked_at, revocation_reason = :reason, updated_at = :updated_at
             WHERE id = :id AND revoked_at IS NULL'
        )->execute([
            'revoked_at' => $now->format('Y-m-d H:i:s'),
            'reason' => $reason,
            'updated_at' => $now->format('Y-m-d H:i:s'),
            'id' => $id,
        ]);
    }

    private function invalidSession(): AuthPublicException
    {
        return new AuthPublicException('invalid_session', 'The session is invalid or expired.', 401);
    }

    private function newToken(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '=');
    }

    private function hashToken(string $token): string
    {
        return hash('sha256', $token);
    }
}

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
        $token = $this->newToken();
        $publicId = 'SES-' . strtoupper(bin2hex(random_bytes(12)));
        $now = new DateTimeImmutable('now');
        $inactivityExpiresAt = $now->modify('+' . $this->inactivityTtlSeconds . ' seconds');
        $absoluteExpiresAt = $now->modify('+' . $this->absoluteTtlSeconds . ' seconds');

        $statement = $this->database->pdo()->prepare(
            'INSERT INTO auth_sessions
             (user_id, session_public_id, session_hash, ip_hash, user_agent_hash, last_seen_at, expires_at,
              inactivity_expires_at, absolute_expires_at, rotated_from_public_id, updated_at, created_at)
             VALUES (:user_id, :public_id, :session_hash, :ip_hash, :user_agent_hash, :last_seen_at, :expires_at,
              :inactivity_expires_at, :absolute_expires_at, :rotated_from_public_id, :updated_at, :created_at)'
        );
        $statement->execute([
            'user_id' => $userId,
            'public_id' => $publicId,
            'session_hash' => $this->hashToken($token),
            'ip_hash' => $ip === '' ? null : hash('sha256', $ip),
            'user_agent_hash' => $userAgent === '' ? null : hash('sha256', $userAgent),
            'last_seen_at' => $now->format('Y-m-d H:i:s'),
            'expires_at' => $absoluteExpiresAt->format('Y-m-d H:i:s'),
            'inactivity_expires_at' => $inactivityExpiresAt->format('Y-m-d H:i:s'),
            'absolute_expires_at' => $absoluteExpiresAt->format('Y-m-d H:i:s'),
            'rotated_from_public_id' => $rotatedFromPublicId,
            'updated_at' => $now->format('Y-m-d H:i:s'),
            'created_at' => $now->format('Y-m-d H:i:s'),
        ]);
        $requestId = $this->audit->sessionEvent('created', $publicId, $userId, $ip, $userAgent, [
            'rotated' => $rotatedFromPublicId !== null,
        ]);
        $this->audit->record('auth.session.created', 'success', $userId, null, 'auth_session', $publicId, [], $requestId);

        return [
            'token' => $token,
            'public_id' => $publicId,
            'inactivity_expires_at' => $inactivityExpiresAt->format(DATE_ATOM),
            'absolute_expires_at' => $absoluteExpiresAt->format(DATE_ATOM),
        ];
    }

    /** @return array{user:array{id:int,public_id:string,email:string,display_name:string,status:string},session:array{public_id:string,last_seen_at:string,inactivity_expires_at:string,absolute_expires_at:string,created_at:string}} */
    public function validate(string $token, string $ip, string $userAgent, bool $touch = true): array
    {
        if ($token === '') {
            throw new AuthPublicException('authentication_required', 'Authentication is required.', 401);
        }

        $pdo = $this->database->pdo();
        $statement = $pdo->prepare(
            'SELECT s.id, s.user_id, s.session_public_id, s.ip_hash, s.user_agent_hash, s.last_seen_at,
                    s.expires_at, s.inactivity_expires_at, s.absolute_expires_at, s.revoked_at, s.created_at,
                    u.public_id AS user_public_id, u.email, u.display_name, u.status AS user_status
             FROM auth_sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.session_hash = :session_hash
             LIMIT 1'
        );
        $statement->execute(['session_hash' => $this->hashToken($token)]);
        $row = $statement->fetch();
        if (!$row) {
            $this->audit->sessionEvent('rejected', null, null, $ip, $userAgent, ['reason' => 'unknown_token']);
            throw new AuthPublicException('invalid_session', 'The session is invalid or expired.', 401);
        }

        $now = new DateTimeImmutable('now');
        $publicId = (string) $row['session_public_id'];
        $userId = (int) $row['user_id'];
        if ($row['revoked_at'] !== null) {
            $this->reject($publicId, $userId, $ip, $userAgent, 'revoked');
        }
        if ((string) $row['user_status'] !== 'active') {
            $this->revokeById((int) $row['id'], 'user_not_active', $now);
            $this->reject($publicId, $userId, $ip, $userAgent, 'user_not_active');
        }

        $inactivity = new DateTimeImmutable((string) ($row['inactivity_expires_at'] ?: $row['expires_at']));
        $absolute = new DateTimeImmutable((string) ($row['absolute_expires_at'] ?: $row['expires_at']));
        if ($now >= $inactivity || $now >= $absolute) {
            $this->revokeById((int) $row['id'], 'expired', $now);
            $requestId = $this->audit->sessionEvent('expired', $publicId, $userId, $ip, $userAgent, [
                'reason' => $now >= $absolute ? 'absolute' : 'inactivity',
            ]);
            $this->audit->record('auth.session.expired', 'denied', $userId, null, 'auth_session', $publicId, [], $requestId);
            throw new AuthPublicException('invalid_session', 'The session is invalid or expired.', 401);
        }

        $ipHash = $ip === '' ? null : hash('sha256', $ip);
        $uaHash = $userAgent === '' ? null : hash('sha256', $userAgent);
        if (($row['ip_hash'] !== null && !hash_equals((string) $row['ip_hash'], (string) $ipHash))
            || ($row['user_agent_hash'] !== null && !hash_equals((string) $row['user_agent_hash'], (string) $uaHash))) {
            $this->revokeById((int) $row['id'], 'binding_mismatch', $now);
            $this->reject($publicId, $userId, $ip, $userAgent, 'binding_mismatch');
        }

        $nextInactivity = $now->modify('+' . $this->inactivityTtlSeconds . ' seconds');
        if ($nextInactivity > $absolute) {
            $nextInactivity = $absolute;
        }
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

        return [
            'user' => [
                'id' => $userId,
                'public_id' => (string) $row['user_public_id'],
                'email' => (string) $row['email'],
                'display_name' => (string) $row['display_name'],
                'status' => (string) $row['user_status'],
            ],
            'session' => [
                'public_id' => $publicId,
                'last_seen_at' => $now->format(DATE_ATOM),
                'inactivity_expires_at' => $nextInactivity->format(DATE_ATOM),
                'absolute_expires_at' => $absolute->format(DATE_ATOM),
                'created_at' => (new DateTimeImmutable((string) $row['created_at']))->format(DATE_ATOM),
            ],
        ];
    }

    /** @return array{token:string,public_id:string,inactivity_expires_at:string,absolute_expires_at:string} */
    public function rotate(string $token, string $ip, string $userAgent): array
    {
        $current = $this->validate($token, $ip, $userAgent, false);
        $rotated = $this->database->transaction(function (PDO $pdo) use ($token, $ip, $userAgent, $current): array {
            $now = new DateTimeImmutable('now');
            $revoke = $pdo->prepare(
                'UPDATE auth_sessions SET revoked_at = :revoked_at, revocation_reason = :reason, updated_at = :updated_at
                 WHERE session_hash = :session_hash AND revoked_at IS NULL'
            );
            $revoke->execute([
                'revoked_at' => $now->format('Y-m-d H:i:s'),
                'reason' => 'rotated',
                'updated_at' => $now->format('Y-m-d H:i:s'),
                'session_hash' => $this->hashToken($token),
            ]);
            if ($revoke->rowCount() !== 1) {
                throw new AuthPublicException('invalid_session', 'The session is invalid or expired.', 401);
            }

            $newToken = $this->newToken();
            $publicId = 'SES-' . strtoupper(bin2hex(random_bytes(12)));
            $inactivityExpiresAt = $now->modify('+' . $this->inactivityTtlSeconds . ' seconds');
            $absoluteExpiresAt = $now->modify('+' . $this->absoluteTtlSeconds . ' seconds');
            $pdo->prepare(
                'INSERT INTO auth_sessions
                 (user_id, session_public_id, session_hash, ip_hash, user_agent_hash, last_seen_at, expires_at,
                  inactivity_expires_at, absolute_expires_at, rotated_from_public_id, updated_at, created_at)
                 VALUES (:user_id, :public_id, :session_hash, :ip_hash, :user_agent_hash, :last_seen_at, :expires_at,
                  :inactivity_expires_at, :absolute_expires_at, :rotated_from_public_id, :updated_at, :created_at)'
            )->execute([
                'user_id' => $current['user']['id'],
                'public_id' => $publicId,
                'session_hash' => $this->hashToken($newToken),
                'ip_hash' => $ip === '' ? null : hash('sha256', $ip),
                'user_agent_hash' => $userAgent === '' ? null : hash('sha256', $userAgent),
                'last_seen_at' => $now->format('Y-m-d H:i:s'),
                'expires_at' => $absoluteExpiresAt->format('Y-m-d H:i:s'),
                'inactivity_expires_at' => $inactivityExpiresAt->format('Y-m-d H:i:s'),
                'absolute_expires_at' => $absoluteExpiresAt->format('Y-m-d H:i:s'),
                'rotated_from_public_id' => $current['session']['public_id'],
                'updated_at' => $now->format('Y-m-d H:i:s'),
                'created_at' => $now->format('Y-m-d H:i:s'),
            ]);
            return [
                'token' => $newToken,
                'public_id' => $publicId,
                'inactivity_expires_at' => $inactivityExpiresAt->format(DATE_ATOM),
                'absolute_expires_at' => $absoluteExpiresAt->format(DATE_ATOM),
            ];
        });

        $requestId = $this->audit->sessionEvent('rotated', $current['session']['public_id'], $current['user']['id'], $ip, $userAgent);
        $this->audit->record('auth.session.rotated', 'success', $current['user']['id'], null, 'auth_session', $current['session']['public_id'], [], $requestId);
        $this->audit->sessionEvent('created', $rotated['public_id'], $current['user']['id'], $ip, $userAgent, ['rotated' => true]);
        return $rotated;
    }

    /** @return list<array{public_id:string,last_seen_at:string,inactivity_expires_at:string,absolute_expires_at:string,created_at:string,current:bool}> */
    public function listForUser(int $userId, ?string $currentPublicId = null): array
    {
        $statement = $this->database->pdo()->prepare(
            'SELECT session_public_id, last_seen_at, inactivity_expires_at, absolute_expires_at, created_at
             FROM auth_sessions
             WHERE user_id = :user_id AND revoked_at IS NULL AND absolute_expires_at > :now AND inactivity_expires_at > :now
             ORDER BY last_seen_at DESC, id DESC'
        );
        $statement->execute(['user_id' => $userId, 'now' => (new DateTimeImmutable('now'))->format('Y-m-d H:i:s')]);
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
        $now = new DateTimeImmutable('now');
        $statement = $this->database->pdo()->prepare(
            'UPDATE auth_sessions
             SET revoked_at = :revoked_at, revocation_reason = :reason, revoked_by_user_id = :actor_user_id, updated_at = :updated_at
             WHERE session_public_id = :public_id AND user_id = :user_id AND revoked_at IS NULL'
        );
        $statement->execute([
            'revoked_at' => $now->format('Y-m-d H:i:s'),
            'reason' => $reason,
            'actor_user_id' => $actorUserId,
            'updated_at' => $now->format('Y-m-d H:i:s'),
            'public_id' => $sessionPublicId,
            'user_id' => $actorUserId,
        ]);
        if ($statement->rowCount() < 1) {
            $this->audit->record('auth.session.revocation_denied', 'denied', $actorUserId, null, 'auth_session', $sessionPublicId, ['reason' => 'not_found_or_cross_user']);
            return false;
        }
        $requestId = $this->audit->sessionEvent('revoked', $sessionPublicId, $actorUserId, $ip, $userAgent, ['reason' => $reason]);
        $this->audit->record('auth.session.revoked', 'success', $actorUserId, null, 'auth_session', $sessionPublicId, ['reason' => $reason], $requestId);
        return true;
    }

    public function revokeAllForUser(int $userId, string $reason, ?string $exceptPublicId = null, string $ip = '', string $userAgent = ''): int
    {
        $now = new DateTimeImmutable('now');
        $sql = 'UPDATE auth_sessions
                SET revoked_at = :revoked_at, revocation_reason = :reason, revoked_by_user_id = :user_id, updated_at = :updated_at
                WHERE user_id = :user_id AND revoked_at IS NULL';
        $params = [
            'revoked_at' => $now->format('Y-m-d H:i:s'),
            'reason' => $reason,
            'user_id' => $userId,
            'updated_at' => $now->format('Y-m-d H:i:s'),
        ];
        if ($exceptPublicId !== null) {
            $sql .= ' AND session_public_id <> :except_public_id';
            $params['except_public_id'] = $exceptPublicId;
        }
        $statement = $this->database->pdo()->prepare($sql);
        $statement->execute($params);
        $count = $statement->rowCount();
        $this->audit->record(
            $exceptPublicId === null ? 'auth.logout_all' : 'auth.logout_others',
            'success',
            $userId,
            null,
            'user',
            null,
            ['revoked_count' => $count, 'reason' => $reason]
        );
        return $count;
    }

    private function reject(string $publicId, int $userId, string $ip, string $userAgent, string $reason): never
    {
        $requestId = $this->audit->sessionEvent('rejected', $publicId, $userId, $ip, $userAgent, ['reason' => $reason]);
        $this->audit->record('auth.session.rejected', 'denied', $userId, null, 'auth_session', $publicId, ['reason' => $reason], $requestId);
        throw new AuthPublicException('invalid_session', 'The session is invalid or expired.', 401);
    }

    private function revokeById(int $id, string $reason, DateTimeImmutable $now): void
    {
        $this->database->pdo()->prepare(
            'UPDATE auth_sessions SET revoked_at = :revoked_at, revocation_reason = :reason, updated_at = :updated_at
             WHERE id = :id AND revoked_at IS NULL'
        )->execute([
            'revoked_at' => $now->format('Y-m-d H:i:s'),
            'reason' => $reason,
            'updated_at' => $now->format('Y-m-d H:i:s'),
            'id' => $id,
        ]);
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

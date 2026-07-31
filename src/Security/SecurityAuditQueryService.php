<?php

declare(strict_types=1);

namespace Vp3\Security;

use InvalidArgumentException;
use PDO;
use RuntimeException;
use Vp3\Database;

final class SecurityAuditQueryService
{
    private const FULL_ACCOUNT_ROLES = [
        'customer_owner',
        'customer_admin',
        'vp3_admin',
        'vp3_super_admin',
    ];

    public function __construct(private readonly Database $database)
    {
    }

    /**
     * @param array<string,scalar|null> $filters
     * @return array{events:list<array<string,mixed>>,summary:array<string,int>,chain_valid:bool}
     */
    public function snapshot(
        int $accountId,
        int $userId,
        string $role,
        array $filters = [],
        int $limit = 100
    ): array {
        if ($accountId <= 0 || $userId <= 0) {
            throw new InvalidArgumentException('A valid account and user are required.');
        }

        $limit = max(1, min($limit, 500));
        [$visibilitySql, $visibilityParams] = $this->visibility($userId, $role);
        [$filterSql, $filterParams] = $this->filters($filters);

        $sql = 'SELECT public_id,sequence_number,request_id,correlation_id,event_type,category,
                       risk_level,result,actor_type,actor_public_id,resource_type,resource_public_id,
                       metadata_json,chain_hash,occurred_at
                FROM security_audit_events
                WHERE account_scope=:account_scope'
            . $visibilitySql
            . $filterSql
            . ' ORDER BY sequence_number DESC LIMIT ' . $limit;

        $statement = $this->database->pdo()->prepare($sql);
        $statement->execute(array_merge(
            ['account_scope' => $accountId],
            $visibilityParams,
            $filterParams
        ));

        $events = [];
        $summary = [
            'total' => 0,
            'high_or_critical' => 0,
            'denied_or_failed' => 0,
            'integrity_events' => 0,
        ];

        while (($row = $statement->fetch(PDO::FETCH_ASSOC)) !== false) {
            $metadata = null;
            if ($row['metadata_json'] !== null) {
                $decoded = json_decode((string) $row['metadata_json'], true);
                $metadata = is_array($decoded) ? $decoded : null;
            }

            $risk = (string) $row['risk_level'];
            $result = (string) $row['result'];
            $category = (string) $row['category'];
            ++$summary['total'];
            if (in_array($risk, ['high', 'critical'], true)) {
                ++$summary['high_or_critical'];
            }
            if (in_array($result, ['denied', 'failure'], true)) {
                ++$summary['denied_or_failed'];
            }
            if ($category === 'integrity') {
                ++$summary['integrity_events'];
            }

            $events[] = [
                'public_id' => (string) $row['public_id'],
                'sequence_number' => (int) $row['sequence_number'],
                'request_id' => (string) $row['request_id'],
                'correlation_id' => $row['correlation_id'] === null ? null : (string) $row['correlation_id'],
                'event_type' => (string) $row['event_type'],
                'category' => $category,
                'risk_level' => $risk,
                'result' => $result,
                'actor_type' => (string) $row['actor_type'],
                'actor_public_id' => $row['actor_public_id'] === null ? null : (string) $row['actor_public_id'],
                'resource_type' => $row['resource_type'] === null ? null : (string) $row['resource_type'],
                'resource_public_id' => $row['resource_public_id'] === null ? null : (string) $row['resource_public_id'],
                'metadata' => $metadata,
                'chain_hash' => (string) $row['chain_hash'],
                'occurred_at' => (string) $row['occurred_at'],
            ];
        }

        return [
            'events' => $events,
            'summary' => $summary,
            'chain_valid' => (new SecurityAuditService($this->database))->verifyScope($accountId),
        ];
    }

    public function canExport(string $role): bool
    {
        return in_array($role, self::FULL_ACCOUNT_ROLES, true);
    }

    /** @return array{0:string,1:array<string,int|string>} */
    private function visibility(int $userId, string $role): array
    {
        if (in_array($role, self::FULL_ACCOUNT_ROLES, true)) {
            return ['', []];
        }

        if ($role === 'billing_manager') {
            return [
                ' AND (category=:visible_category OR actor_id=:visible_actor)',
                ['visible_category' => 'billing', 'visible_actor' => $userId],
            ];
        }

        if (in_array($role, ['support_member', 'vp3_support', 'vp3_operations'], true)) {
            return [' AND actor_id=:visible_actor', ['visible_actor' => $userId]];
        }

        throw new RuntimeException('The current role cannot view security audit events.');
    }

    /**
     * @param array<string,scalar|null> $filters
     * @return array{0:string,1:array<string,string>}
     */
    private function filters(array $filters): array
    {
        $sql = '';
        $params = [];
        $allowedEnums = [
            'category' => ['authentication', 'session', 'mfa', 'team', 'billing', 'domain', 'pod', 'homeserver', 'settings', 'integrity', 'platform'],
            'risk_level' => ['info', 'low', 'medium', 'high', 'critical'],
            'result' => ['success', 'failure', 'denied', 'ignored'],
        ];

        foreach ($allowedEnums as $key => $allowed) {
            $value = isset($filters[$key]) ? trim((string) $filters[$key]) : '';
            if ($value === '') {
                continue;
            }
            if (!in_array($value, $allowed, true)) {
                throw new InvalidArgumentException('Invalid security audit filter: ' . $key . '.');
            }
            $sql .= ' AND ' . $key . '=:' . $key;
            $params[$key] = $value;
        }

        foreach (['event_type', 'request_id'] as $key) {
            $value = isset($filters[$key]) ? trim((string) $filters[$key]) : '';
            if ($value !== '') {
                $sql .= ' AND ' . $key . '=:' . $key;
                $params[$key] = mb_substr($value, 0, $key === 'event_type' ? 120 : 80);
            }
        }

        foreach (['from' => '>=', 'to' => '<='] as $key => $operator) {
            $value = isset($filters[$key]) ? trim((string) $filters[$key]) : '';
            if ($value !== '') {
                $timestamp = strtotime($value);
                if ($timestamp === false) {
                    throw new InvalidArgumentException('Invalid security audit date filter: ' . $key . '.');
                }
                $sql .= ' AND occurred_at' . $operator . ':' . $key . '_time';
                $params[$key . '_time'] = gmdate('Y-m-d H:i:s', $timestamp);
            }
        }

        return [$sql, $params];
    }
}

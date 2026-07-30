<?php

declare(strict_types=1);

namespace Vp3\Operations;

use PDO;
use Vp3\Auth\AuthPublicException;
use Vp3\Database;

final class OperationsControlCenterQueryService
{
    private const VIEW_ROLES = ['customer_owner', 'customer_admin', 'support_member'];
    private const MANAGER_ROLES = ['customer_owner', 'customer_admin'];

    public function __construct(private readonly Database $database)
    {
    }

    /** @return array<string,mixed> */
    public function snapshot(int $accountId, int $currentUserId, string $role): array
    {
        if ($accountId < 1 || $currentUserId < 1 || !in_array($role, self::VIEW_ROLES, true)) {
            throw new AuthPublicException(
                'operations_access_denied',
                'An active operations-enabled account membership is required.',
                403
            );
        }

        $pdo = $this->database->pdo();
        $this->assertCurrentMembership($pdo, $accountId, $currentUserId, $role);

        $signalMetrics = $pdo->prepare(
            "SELECT COUNT(*) AS total,
                    COALESCE(SUM(health_status='healthy'),0) AS healthy,
                    COALESCE(SUM(health_status='unhealthy'),0) AS unhealthy,
                    COALESCE(SUM(health_status='unhealthy' AND severity='critical'),0) AS critical
             FROM operational_health_signals WHERE account_scope=:account"
        );
        $signalMetrics->execute(['account' => $accountId]);
        $signalSummary = $signalMetrics->fetch(PDO::FETCH_ASSOC) ?: [];

        $incidentMetrics = $pdo->prepare(
            "SELECT COUNT(*) AS total,
                    COALESCE(SUM(status='open'),0) AS open_count,
                    COALESCE(SUM(status='acknowledged'),0) AS acknowledged_count,
                    COALESCE(SUM(status='resolved'),0) AS resolved_count,
                    COALESCE(SUM(status<>'resolved' AND severity='critical'),0) AS active_critical
             FROM operational_incidents WHERE account_scope=:account"
        );
        $incidentMetrics->execute(['account' => $accountId]);
        $incidentSummary = $incidentMetrics->fetch(PDO::FETCH_ASSOC) ?: [];

        $deliveryMetrics = $pdo->prepare(
            "SELECT COUNT(*) AS total,
                    COALESCE(SUM(n.status='queued'),0) AS queued,
                    COALESCE(SUM(n.status='running'),0) AS running,
                    COALESCE(SUM(n.status='delivered'),0) AS delivered,
                    COALESCE(SUM(n.status='failed'),0) AS failed
             FROM operational_notifications n
             INNER JOIN operational_incidents i ON i.id=n.incident_id
             WHERE i.account_scope=:account"
        );
        $deliveryMetrics->execute(['account' => $accountId]);
        $deliverySummary = $deliveryMetrics->fetch(PDO::FETCH_ASSOC) ?: [];

        $signals = $pdo->prepare(
            "SELECT source_type,source_id,health_status,severity,observed_at,updated_at
             FROM operational_health_signals
             WHERE account_scope=:account
             ORDER BY FIELD(health_status,'unhealthy','healthy'),
                      FIELD(severity,'critical','warning','info'),observed_at DESC,id DESC
             LIMIT 100"
        );
        $signals->execute(['account' => $accountId]);
        $signalRows = array_map(static fn (array $row): array => [
            'source_type' => (string) $row['source_type'],
            'source_reference' => substr(hash('sha256', (string) $row['source_type'] . '|' . (string) $row['source_id']), 0, 12),
            'status' => (string) $row['health_status'],
            'severity' => (string) $row['severity'],
            'observed_at' => (string) $row['observed_at'],
            'updated_at' => (string) $row['updated_at'],
        ], $signals->fetchAll(PDO::FETCH_ASSOC));

        $incidents = $pdo->prepare(
            "SELECT public_id,source_type,source_id,severity,status,monitor_managed,title,occurrence_count,
                    first_detected_at,last_detected_at,acknowledged_at,resolved_at,updated_at
             FROM operational_incidents
             WHERE account_scope=:account
             ORDER BY FIELD(status,'open','acknowledged','resolved'),
                      FIELD(severity,'critical','warning','info'),last_detected_at DESC,id DESC
             LIMIT 100"
        );
        $incidents->execute(['account' => $accountId]);
        $incidentRows = array_map(static fn (array $row): array => [
            'public_id' => (string) $row['public_id'],
            'source_type' => (string) $row['source_type'],
            'source_reference' => substr(hash('sha256', (string) $row['source_type'] . '|' . (string) $row['source_id']), 0, 12),
            'severity' => (string) $row['severity'],
            'status' => (string) $row['status'],
            'monitor_managed' => (bool) $row['monitor_managed'],
            'title' => (string) $row['title'],
            'occurrence_count' => (int) $row['occurrence_count'],
            'first_detected_at' => (string) $row['first_detected_at'],
            'last_detected_at' => (string) $row['last_detected_at'],
            'acknowledged_at' => $row['acknowledged_at'] === null ? null : (string) $row['acknowledged_at'],
            'resolved_at' => $row['resolved_at'] === null ? null : (string) $row['resolved_at'],
            'updated_at' => (string) $row['updated_at'],
        ], $incidents->fetchAll(PDO::FETCH_ASSOC));

        $events = $pdo->prepare(
            "SELECT i.public_id AS incident_public_id,e.event_type,e.event_status,e.severity,e.actor_type,e.occurred_at
             FROM operational_incident_events e
             INNER JOIN operational_incidents i ON i.id=e.incident_id
             WHERE i.account_scope=:account
             ORDER BY e.occurred_at DESC,e.id DESC
             LIMIT 250"
        );
        $events->execute(['account' => $accountId]);
        $eventRows = array_map(static fn (array $row): array => [
            'incident_public_id' => (string) $row['incident_public_id'],
            'event_type' => (string) $row['event_type'],
            'status' => (string) $row['event_status'],
            'severity' => (string) $row['severity'],
            'actor_type' => (string) $row['actor_type'],
            'occurred_at' => (string) $row['occurred_at'],
        ], $events->fetchAll(PDO::FETCH_ASSOC));

        $channels = $pdo->prepare(
            "SELECT public_id,channel_type,label,status,severity_threshold,created_at,updated_at,revoked_at
             FROM operational_notification_channels
             WHERE account_scope=:account
             ORDER BY FIELD(status,'active','paused','revoked'),label,id"
        );
        $channels->execute(['account' => $accountId]);
        $channelRows = array_map(static fn (array $row): array => [
            'public_id' => (string) $row['public_id'],
            'type' => (string) $row['channel_type'],
            'label' => (string) $row['label'],
            'status' => (string) $row['status'],
            'severity_threshold' => (string) $row['severity_threshold'],
            'created_at' => (string) $row['created_at'],
            'updated_at' => (string) $row['updated_at'],
            'revoked_at' => $row['revoked_at'] === null ? null : (string) $row['revoked_at'],
        ], $channels->fetchAll(PDO::FETCH_ASSOC));

        $deliveries = $pdo->prepare(
            "SELECT n.public_id,i.public_id AS incident_public_id,c.public_id AS channel_public_id,c.label AS channel_label,
                    n.event_type,n.event_status,n.severity,n.status,n.attempts,n.max_attempts,n.created_at,n.delivered_at,n.updated_at
             FROM operational_notifications n
             INNER JOIN operational_incidents i ON i.id=n.incident_id
             INNER JOIN operational_notification_channels c ON c.id=n.channel_id
             WHERE i.account_scope=:account AND c.account_scope=:channel_account
             ORDER BY n.created_at DESC,n.id DESC
             LIMIT 100"
        );
        $deliveries->execute(['account' => $accountId, 'channel_account' => $accountId]);
        $deliveryRows = array_map(static fn (array $row): array => [
            'public_id' => (string) $row['public_id'],
            'incident_public_id' => (string) $row['incident_public_id'],
            'channel_public_id' => (string) $row['channel_public_id'],
            'channel_label' => (string) $row['channel_label'],
            'event_type' => (string) $row['event_type'],
            'event_status' => (string) $row['event_status'],
            'severity' => (string) $row['severity'],
            'status' => (string) $row['status'],
            'attempts' => (int) $row['attempts'],
            'max_attempts' => (int) $row['max_attempts'],
            'created_at' => (string) $row['created_at'],
            'delivered_at' => $row['delivered_at'] === null ? null : (string) $row['delivered_at'],
            'updated_at' => (string) $row['updated_at'],
        ], $deliveries->fetchAll(PDO::FETCH_ASSOC));

        $canManage = in_array($role, self::MANAGER_ROLES, true);
        return [
            'permissions' => [
                'can_view' => true,
                'can_acknowledge' => true,
                'can_resolve' => $canManage,
                'can_manage_channels' => $canManage,
            ],
            'metrics' => [
                'signals_total' => (int) ($signalSummary['total'] ?? 0),
                'signals_healthy' => (int) ($signalSummary['healthy'] ?? 0),
                'signals_unhealthy' => (int) ($signalSummary['unhealthy'] ?? 0),
                'signals_critical' => (int) ($signalSummary['critical'] ?? 0),
                'incidents_open' => (int) ($incidentSummary['open_count'] ?? 0),
                'incidents_acknowledged' => (int) ($incidentSummary['acknowledged_count'] ?? 0),
                'incidents_resolved' => (int) ($incidentSummary['resolved_count'] ?? 0),
                'active_critical' => (int) ($incidentSummary['active_critical'] ?? 0),
                'deliveries_queued' => (int) ($deliverySummary['queued'] ?? 0),
                'deliveries_running' => (int) ($deliverySummary['running'] ?? 0),
                'deliveries_delivered' => (int) ($deliverySummary['delivered'] ?? 0),
                'deliveries_failed' => (int) ($deliverySummary['failed'] ?? 0),
            ],
            'health_signals' => $signalRows,
            'incidents' => $incidentRows,
            'incident_events' => $eventRows,
            'notification_channels' => $channelRows,
            'deliveries' => $deliveryRows,
        ];
    }

    private function assertCurrentMembership(PDO $pdo, int $accountId, int $userId, string $role): void
    {
        $statement = $pdo->prepare(
            "SELECT role FROM account_users
             WHERE account_id=:account AND user_id=:user AND status='active' LIMIT 1"
        );
        $statement->execute(['account' => $accountId, 'user' => $userId]);
        $storedRole = $statement->fetchColumn();
        if (!is_string($storedRole) || !hash_equals($storedRole, $role) || !in_array($storedRole, self::VIEW_ROLES, true)) {
            throw new AuthPublicException(
                'operations_access_denied',
                'An active operations-enabled account membership is required.',
                403
            );
        }
    }
}

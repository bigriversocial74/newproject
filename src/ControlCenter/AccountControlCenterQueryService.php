<?php

declare(strict_types=1);

namespace Vp3\ControlCenter;

use PDO;
use RuntimeException;
use Vp3\Database;
use Vp3\HomeServers\HomeServerFleetQueryService;

final class AccountControlCenterQueryService
{
    public function __construct(private readonly Database $database)
    {
    }

    /** @return array<string,mixed> */
    public function snapshot(int $accountId): array
    {
        if ($accountId < 1) {
            throw new RuntimeException('A valid VP3 account is required.');
        }

        $account = $this->account($accountId);
        $subscriptions = $this->subscriptions($accountId);
        $domains = $this->domains($accountId);
        $pods = $this->pods($accountId);
        $incidents = $this->incidents($accountId);
        $homeServers = (new HomeServerFleetQueryService($this->database))->snapshot($accountId);

        $metrics = [
            'domains_total' => count($domains),
            'domains_active' => $this->countWhere($domains, static fn (array $row): bool => in_array($row['status'], ['active', 'grace'], true)),
            'domains_attention' => $this->countWhere($domains, static fn (array $row): bool => !in_array($row['status'], ['active', 'grace', 'reserved'], true) || $row['routing_status'] !== 'active' || $row['ssl_status'] !== 'active'),
            'pods_total' => count($pods),
            'pods_active' => $this->countWhere($pods, static fn (array $row): bool => $row['status'] === 'active'),
            'pods_attention' => $this->countWhere($pods, static fn (array $row): bool => $row['status'] !== 'active' || $row['routing_status'] !== 'active' || $row['ssl_status'] !== 'active' || $row['backup_status'] === 'failed'),
            'homeservers_total' => (int) $homeServers['summary']['total'],
            'homeservers_online' => (int) $homeServers['summary']['online'],
            'homeservers_attention' => (int) $homeServers['summary']['attention'],
            'subscriptions_active' => $this->countWhere($subscriptions, static fn (array $row): bool => in_array($row['status'], ['trialing', 'active'], true)),
            'subscriptions_attention' => $this->countWhere($subscriptions, static fn (array $row): bool => in_array($row['status'], ['past_due', 'grace'], true)),
            'open_incidents' => count($incidents),
            'critical_incidents' => $this->countWhere($incidents, static fn (array $row): bool => $row['severity'] === 'critical'),
        ];

        return [
            'account' => $account,
            'metrics' => $metrics,
            'subscriptions' => $subscriptions,
            'domains' => $domains,
            'pods' => $pods,
            'homeservers' => $homeServers,
            'incidents' => $incidents,
            'attention' => $this->attention($subscriptions, $domains, $pods, $homeServers, $incidents),
            'generated_at' => gmdate(DATE_ATOM),
        ];
    }

    /** @return array<string,mixed> */
    private function account(int $accountId): array
    {
        $statement = $this->database->pdo()->prepare(
            'SELECT id,public_id,display_name,status,created_at,updated_at FROM accounts WHERE id=:id LIMIT 1'
        );
        $statement->execute(['id' => $accountId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row) || $row['status'] !== 'active') {
            throw new RuntimeException('The selected VP3 account is unavailable.');
        }
        return [
            'id' => (int) $row['id'],
            'public_id' => (string) $row['public_id'],
            'display_name' => (string) $row['display_name'],
            'status' => (string) $row['status'],
            'created_at' => (string) $row['created_at'],
            'updated_at' => (string) $row['updated_at'],
        ];
    }

    /** @return list<array<string,mixed>> */
    private function subscriptions(int $accountId): array
    {
        $statement = $this->database->pdo()->prepare(
            'SELECT s.id,s.public_id,s.status,s.current_period_starts_at,s.current_period_ends_at,s.grace_ends_at,
                    p.public_id AS plan_public_id,p.code AS plan_code,p.name AS plan_name,p.billing_interval,p.currency,p.price_minor
             FROM subscriptions s
             JOIN plans p ON p.id=s.plan_id
             WHERE s.account_id=:account
             ORDER BY FIELD(s.status,\'active\',\'trialing\',\'grace\',\'past_due\',\'canceled\',\'expired\'),s.id DESC'
        );
        $statement->execute(['account' => $accountId]);
        return array_map(static fn (array $row): array => [
            'id' => (int) $row['id'],
            'public_id' => (string) $row['public_id'],
            'status' => (string) $row['status'],
            'current_period_starts_at' => $row['current_period_starts_at'] !== null ? (string) $row['current_period_starts_at'] : null,
            'current_period_ends_at' => $row['current_period_ends_at'] !== null ? (string) $row['current_period_ends_at'] : null,
            'grace_ends_at' => $row['grace_ends_at'] !== null ? (string) $row['grace_ends_at'] : null,
            'plan' => [
                'public_id' => (string) $row['plan_public_id'],
                'code' => (string) $row['plan_code'],
                'name' => (string) $row['plan_name'],
                'billing_interval' => (string) $row['billing_interval'],
                'currency' => (string) $row['currency'],
                'price_minor' => (int) $row['price_minor'],
            ],
        ], $statement->fetchAll(PDO::FETCH_ASSOC));
    }

    /** @return list<array<string,mixed>> */
    private function domains(int $accountId): array
    {
        $statement = $this->database->pdo()->prepare(
            "SELECT d.id,d.public_id,d.hostname,d.status,d.routing_status,d.ssl_status,d.reserved_until,d.registered_at,
                    d.renews_at,d.expires_at,d.suspended_at,d.updated_at,
                    s.public_id AS subscription_public_id,s.status AS subscription_status,
                    p.name AS plan_name,p.code AS plan_code,
                    lp.public_id AS pod_license_public_id,lp.status AS pod_license_status,
                    lh.public_id AS homeserver_license_public_id,lh.status AS homeserver_license_status,
                    pd.public_id AS pod_public_id,pd.status AS pod_status,
                    hs.public_id AS homeserver_public_id,hs.status AS homeserver_status,
                    COALESCE(hold_count.active_holds,0) AS active_holds
             FROM domain_registrations d
             JOIN subscriptions s ON s.id=d.subscription_id
             JOIN plans p ON p.id=s.plan_id
             LEFT JOIN licenses lp ON lp.domain_registration_id=d.id AND lp.product_type='pod'
             LEFT JOIN licenses lh ON lh.domain_registration_id=d.id AND lh.product_type='homeserver'
             LEFT JOIN pod_deployments pd ON pd.domain_registration_id=d.id
             LEFT JOIN homeserver_devices hs ON hs.domain_registration_id=d.id AND hs.status<>'revoked'
             LEFT JOIN (
                 SELECT domain_registration_id,COUNT(*) AS active_holds
                 FROM domain_admin_holds WHERE status='active' GROUP BY domain_registration_id
             ) hold_count ON hold_count.domain_registration_id=d.id
             WHERE d.account_id=:account
             ORDER BY FIELD(d.status,'active','grace','reserved','pending','suspended','expired','transferred','released'),d.id DESC"
        );
        $statement->execute(['account' => $accountId]);
        return array_map(static fn (array $row): array => [
            'id' => (int) $row['id'],
            'public_id' => (string) $row['public_id'],
            'hostname' => (string) $row['hostname'],
            'status' => (string) $row['status'],
            'routing_status' => (string) $row['routing_status'],
            'ssl_status' => (string) $row['ssl_status'],
            'reserved_until' => $row['reserved_until'] !== null ? (string) $row['reserved_until'] : null,
            'registered_at' => $row['registered_at'] !== null ? (string) $row['registered_at'] : null,
            'renews_at' => $row['renews_at'] !== null ? (string) $row['renews_at'] : null,
            'expires_at' => $row['expires_at'] !== null ? (string) $row['expires_at'] : null,
            'suspended_at' => $row['suspended_at'] !== null ? (string) $row['suspended_at'] : null,
            'updated_at' => (string) $row['updated_at'],
            'subscription' => [
                'public_id' => (string) $row['subscription_public_id'],
                'status' => (string) $row['subscription_status'],
                'plan_name' => (string) $row['plan_name'],
                'plan_code' => (string) $row['plan_code'],
            ],
            'pod_license' => $row['pod_license_public_id'] === null ? null : [
                'public_id' => (string) $row['pod_license_public_id'],
                'status' => (string) $row['pod_license_status'],
            ],
            'homeserver_license' => $row['homeserver_license_public_id'] === null ? null : [
                'public_id' => (string) $row['homeserver_license_public_id'],
                'status' => (string) $row['homeserver_license_status'],
            ],
            'pod' => $row['pod_public_id'] === null ? null : [
                'public_id' => (string) $row['pod_public_id'],
                'status' => (string) $row['pod_status'],
            ],
            'homeserver' => $row['homeserver_public_id'] === null ? null : [
                'public_id' => (string) $row['homeserver_public_id'],
                'status' => (string) $row['homeserver_status'],
            ],
            'active_holds' => (int) $row['active_holds'],
        ], $statement->fetchAll(PDO::FETCH_ASSOC));
    }

    /** @return list<array<string,mixed>> */
    private function pods(int $accountId): array
    {
        $statement = $this->database->pdo()->prepare(
            "SELECT pd.id,pd.public_id,pd.status,pd.installed_version,pd.update_channel,pd.storage_usage_bytes,
                    pd.storage_allowance_bytes,pd.last_heartbeat_at,pd.routing_status,pd.ssl_status,pd.backup_status,
                    pd.license_status,pd.activated_at,pd.suspended_at,pd.updated_at,
                    d.public_id AS domain_public_id,d.hostname,d.status AS domain_status,
                    l.public_id AS license_public_id,
                    j.id AS latest_job_id,j.public_id AS latest_job_public_id,j.job_type AS latest_job_type,
                    j.status AS latest_job_status,j.current_stage AS latest_job_stage,j.attempts AS latest_job_attempts,
                    j.last_error_code AS latest_job_error,j.updated_at AS latest_job_updated_at
             FROM pod_deployments pd
             JOIN domain_registrations d ON d.id=pd.domain_registration_id
             JOIN licenses l ON l.id=pd.license_id
             LEFT JOIN pod_provisioning_jobs j ON j.id=(
                 SELECT j2.id FROM pod_provisioning_jobs j2
                 WHERE j2.deployment_id=pd.id ORDER BY j2.id DESC LIMIT 1
             )
             WHERE pd.account_id=:account
             ORDER BY FIELD(pd.status,'active','provisioning','pending','degraded','suspended','failed','archived'),pd.id DESC"
        );
        $statement->execute(['account' => $accountId]);
        return array_map(static function (array $row): array {
            $usage = (int) $row['storage_usage_bytes'];
            $allowance = (int) $row['storage_allowance_bytes'];
            return [
                'id' => (int) $row['id'],
                'public_id' => (string) $row['public_id'],
                'status' => (string) $row['status'],
                'installed_version' => $row['installed_version'] !== null ? (string) $row['installed_version'] : null,
                'update_channel' => (string) $row['update_channel'],
                'storage_usage_bytes' => $usage,
                'storage_allowance_bytes' => $allowance,
                'storage_usage_percent' => $allowance > 0 ? round(($usage / $allowance) * 100, 2) : 0.0,
                'last_heartbeat_at' => $row['last_heartbeat_at'] !== null ? (string) $row['last_heartbeat_at'] : null,
                'routing_status' => (string) $row['routing_status'],
                'ssl_status' => (string) $row['ssl_status'],
                'backup_status' => (string) $row['backup_status'],
                'license_status' => (string) $row['license_status'],
                'activated_at' => $row['activated_at'] !== null ? (string) $row['activated_at'] : null,
                'suspended_at' => $row['suspended_at'] !== null ? (string) $row['suspended_at'] : null,
                'updated_at' => (string) $row['updated_at'],
                'domain' => [
                    'public_id' => (string) $row['domain_public_id'],
                    'hostname' => (string) $row['hostname'],
                    'status' => (string) $row['domain_status'],
                ],
                'license_public_id' => (string) $row['license_public_id'],
                'latest_job' => $row['latest_job_public_id'] === null ? null : [
                    'id' => (int) $row['latest_job_id'],
                    'public_id' => (string) $row['latest_job_public_id'],
                    'job_type' => (string) $row['latest_job_type'],
                    'status' => (string) $row['latest_job_status'],
                    'current_stage' => $row['latest_job_stage'] !== null ? (string) $row['latest_job_stage'] : null,
                    'attempts' => (int) $row['latest_job_attempts'],
                    'last_error_code' => $row['latest_job_error'] !== null ? (string) $row['latest_job_error'] : null,
                    'updated_at' => (string) $row['latest_job_updated_at'],
                ],
            ];
        }, $statement->fetchAll(PDO::FETCH_ASSOC));
    }

    /** @return list<array<string,mixed>> */
    private function incidents(int $accountId): array
    {
        $statement = $this->database->pdo()->prepare(
            "SELECT public_id,severity,status,source_type,source_id,title,occurrence_count,first_detected_at,last_detected_at
             FROM operational_incidents
             WHERE account_scope=:account AND status IN ('open','acknowledged')
             ORDER BY FIELD(severity,'critical','warning','info'),last_detected_at DESC,id DESC
             LIMIT 20"
        );
        $statement->execute(['account' => $accountId]);
        return array_map(static fn (array $row): array => [
            'public_id' => (string) $row['public_id'],
            'severity' => (string) $row['severity'],
            'status' => (string) $row['status'],
            'source_type' => (string) $row['source_type'],
            'source_id' => (int) $row['source_id'],
            'title' => (string) $row['title'],
            'occurrence_count' => (int) $row['occurrence_count'],
            'first_detected_at' => (string) $row['first_detected_at'],
            'last_detected_at' => (string) $row['last_detected_at'],
        ], $statement->fetchAll(PDO::FETCH_ASSOC));
    }

    /**
     * @param list<array<string,mixed>> $subscriptions
     * @param list<array<string,mixed>> $domains
     * @param list<array<string,mixed>> $pods
     * @param array<string,mixed> $homeServers
     * @param list<array<string,mixed>> $incidents
     * @return list<array<string,mixed>>
     */
    private function attention(array $subscriptions, array $domains, array $pods, array $homeServers, array $incidents): array
    {
        $items = [];
        foreach ($incidents as $incident) {
            $items[] = [
                'type' => 'incident',
                'severity' => $incident['severity'],
                'title' => $incident['title'],
                'detail' => ucfirst((string) $incident['status']) . ' · ' . (int) $incident['occurrence_count'] . ' occurrence(s)',
                'href' => '/dashboard.php#incidents',
            ];
        }
        foreach ($subscriptions as $subscription) {
            if (in_array($subscription['status'], ['past_due', 'grace'], true)) {
                $items[] = [
                    'type' => 'billing',
                    'severity' => $subscription['status'] === 'past_due' ? 'critical' : 'warning',
                    'title' => $subscription['plan']['name'] . ' subscription needs attention',
                    'detail' => 'Subscription status: ' . $subscription['status'],
                    'href' => '/dashboard.php#subscriptions',
                ];
            }
        }
        foreach ($domains as $domain) {
            if (!in_array($domain['status'], ['active', 'grace', 'reserved'], true) || $domain['routing_status'] !== 'active' || $domain['ssl_status'] !== 'active') {
                $items[] = [
                    'type' => 'domain',
                    'severity' => in_array($domain['status'], ['suspended', 'expired'], true) || $domain['ssl_status'] === 'failed' ? 'critical' : 'warning',
                    'title' => $domain['hostname'],
                    'detail' => 'Domain ' . $domain['status'] . ' · routing ' . $domain['routing_status'] . ' · SSL ' . $domain['ssl_status'],
                    'href' => '/domains.php#' . rawurlencode((string) $domain['public_id']),
                ];
            }
        }
        foreach ($pods as $pod) {
            if ($pod['status'] !== 'active' || $pod['routing_status'] !== 'active' || $pod['ssl_status'] !== 'active' || $pod['backup_status'] === 'failed') {
                $items[] = [
                    'type' => 'pod',
                    'severity' => in_array($pod['status'], ['failed', 'suspended'], true) || $pod['backup_status'] === 'failed' ? 'critical' : 'warning',
                    'title' => $pod['domain']['hostname'],
                    'detail' => 'POD ' . $pod['status'] . ' · backup ' . $pod['backup_status'],
                    'href' => '/pods.php#' . rawurlencode((string) $pod['public_id']),
                ];
            }
        }
        foreach ($homeServers['devices'] as $device) {
            if (in_array($device['status'], ['offline', 'degraded', 'suspended', 'revoked'], true)) {
                $items[] = [
                    'type' => 'homeserver',
                    'severity' => in_array($device['status'], ['suspended', 'revoked'], true) ? 'critical' : 'warning',
                    'title' => $device['device_public_id'],
                    'detail' => 'HomeServer status: ' . $device['status'],
                    'href' => '/homeservers.php',
                ];
            }
        }

        usort($items, static function (array $left, array $right): int {
            $weight = ['critical' => 0, 'warning' => 1, 'info' => 2];
            return ($weight[$left['severity']] ?? 3) <=> ($weight[$right['severity']] ?? 3);
        });
        return array_slice($items, 0, 30);
    }

    /** @param list<array<string,mixed>> $rows */
    private function countWhere(array $rows, callable $predicate): int
    {
        return count(array_filter($rows, $predicate));
    }
}

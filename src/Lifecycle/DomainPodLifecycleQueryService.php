<?php

declare(strict_types=1);

namespace Vp3\Lifecycle;

use RuntimeException;
use Vp3\ControlCenter\AccountControlCenterQueryService;
use Vp3\Database;

final class DomainPodLifecycleQueryService
{
    public function __construct(private readonly Database $database)
    {
    }

    /** @return array<string,mixed> */
    public function snapshot(int $accountId): array
    {
        if ($accountId < 1) {
            throw new RuntimeException('A valid account is required.');
        }

        $source = (new AccountControlCenterQueryService($this->database))->snapshot($accountId);
        $subscriptions = array_map(static fn (array $row): array => [
            'public_id' => (string) $row['public_id'],
            'status' => (string) $row['status'],
            'current_period_starts_at' => $row['current_period_starts_at'],
            'current_period_ends_at' => $row['current_period_ends_at'],
            'grace_ends_at' => $row['grace_ends_at'],
            'plan' => [
                'public_id' => (string) $row['plan']['public_id'],
                'code' => (string) $row['plan']['code'],
                'name' => (string) $row['plan']['name'],
                'billing_interval' => (string) $row['plan']['billing_interval'],
                'currency' => (string) $row['plan']['currency'],
                'price_minor' => (int) $row['plan']['price_minor'],
            ],
        ], $source['subscriptions']);

        $domains = array_map(static fn (array $row): array => [
            'public_id' => (string) $row['public_id'],
            'hostname' => (string) $row['hostname'],
            'status' => (string) $row['status'],
            'routing_status' => (string) $row['routing_status'],
            'ssl_status' => (string) $row['ssl_status'],
            'reserved_until' => $row['reserved_until'],
            'registered_at' => $row['registered_at'],
            'renews_at' => $row['renews_at'],
            'expires_at' => $row['expires_at'],
            'suspended_at' => $row['suspended_at'],
            'updated_at' => (string) $row['updated_at'],
            'subscription' => [
                'public_id' => (string) $row['subscription']['public_id'],
                'status' => (string) $row['subscription']['status'],
                'plan_name' => (string) $row['subscription']['plan_name'],
                'plan_code' => (string) $row['subscription']['plan_code'],
            ],
            'pod_license' => $row['pod_license'] === null ? null : [
                'public_id' => (string) $row['pod_license']['public_id'],
                'status' => (string) $row['pod_license']['status'],
            ],
            'homeserver_license' => $row['homeserver_license'] === null ? null : [
                'public_id' => (string) $row['homeserver_license']['public_id'],
                'status' => (string) $row['homeserver_license']['status'],
            ],
            'pod' => $row['pod'] === null ? null : [
                'public_id' => (string) $row['pod']['public_id'],
                'status' => (string) $row['pod']['status'],
            ],
            'homeserver' => $row['homeserver'] === null ? null : [
                'public_id' => (string) $row['homeserver']['public_id'],
                'status' => (string) $row['homeserver']['status'],
            ],
            'active_holds' => (int) $row['active_holds'],
            'eligible_for_pod' => $row['pod'] === null
                && $row['pod_license'] !== null
                && in_array((string) $row['status'], ['active', 'grace'], true)
                && in_array((string) $row['pod_license']['status'], ['active', 'grace'], true),
        ], $source['domains']);

        $pods = array_map(static fn (array $row): array => [
            'public_id' => (string) $row['public_id'],
            'status' => (string) $row['status'],
            'installed_version' => $row['installed_version'],
            'update_channel' => (string) $row['update_channel'],
            'storage_usage_bytes' => (int) $row['storage_usage_bytes'],
            'storage_allowance_bytes' => (int) $row['storage_allowance_bytes'],
            'storage_usage_percent' => (float) $row['storage_usage_percent'],
            'last_heartbeat_at' => $row['last_heartbeat_at'],
            'routing_status' => (string) $row['routing_status'],
            'ssl_status' => (string) $row['ssl_status'],
            'backup_status' => (string) $row['backup_status'],
            'license_status' => (string) $row['license_status'],
            'activated_at' => $row['activated_at'],
            'suspended_at' => $row['suspended_at'],
            'updated_at' => (string) $row['updated_at'],
            'domain' => [
                'public_id' => (string) $row['domain']['public_id'],
                'hostname' => (string) $row['domain']['hostname'],
                'status' => (string) $row['domain']['status'],
            ],
            'license_public_id' => (string) $row['license_public_id'],
            'latest_job' => $row['latest_job'] === null ? null : [
                'public_id' => (string) $row['latest_job']['public_id'],
                'job_type' => (string) $row['latest_job']['job_type'],
                'status' => (string) $row['latest_job']['status'],
                'current_stage' => $row['latest_job']['current_stage'],
                'attempts' => (int) $row['latest_job']['attempts'],
                'requires_attention' => $row['latest_job']['last_error_code'] !== null,
                'updated_at' => (string) $row['latest_job']['updated_at'],
            ],
        ], $source['pods']);

        return [
            'account' => [
                'public_id' => (string) $source['account']['public_id'],
                'display_name' => (string) $source['account']['display_name'],
                'status' => (string) $source['account']['status'],
            ],
            'metrics' => [
                'domains_total' => (int) $source['metrics']['domains_total'],
                'domains_active' => (int) $source['metrics']['domains_active'],
                'domains_attention' => (int) $source['metrics']['domains_attention'],
                'pods_total' => (int) $source['metrics']['pods_total'],
                'pods_active' => (int) $source['metrics']['pods_active'],
                'pods_attention' => (int) $source['metrics']['pods_attention'],
                'open_incidents' => (int) $source['metrics']['open_incidents'],
            ],
            'subscriptions' => $subscriptions,
            'domains' => $domains,
            'pods' => $pods,
            'generated_at' => (string) $source['generated_at'],
        ];
    }
}

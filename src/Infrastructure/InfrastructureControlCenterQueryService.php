<?php

declare(strict_types=1);

namespace Vp3\Infrastructure;

use PDO;
use RuntimeException;
use Vp3\Database;

final class InfrastructureControlCenterQueryService
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

        $pdo = $this->database->pdo();
        $account = $pdo->prepare(
            "SELECT public_id,display_name,status
             FROM accounts
             WHERE id=:account AND status='active'
             LIMIT 1"
        );
        $account->execute(['account' => $accountId]);
        $accountRow = $account->fetch(PDO::FETCH_ASSOC);
        if (!is_array($accountRow)) {
            throw new RuntimeException('The active account was not found.');
        }

        $connections = $this->connections($pdo, $accountId);
        $pods = $this->pods($pdo, $accountId);
        $bindings = $this->bindings($pdo, $accountId);
        $operations = $this->operations($pdo, $accountId);

        $metrics = [
            'connections_active' => count(array_filter($connections, static fn (array $row): bool => $row['status'] === 'active')),
            'pods_total' => count($pods),
            'bindings_active' => count(array_filter($bindings, static fn (array $row): bool => $row['status'] === 'active')),
            'operations_open' => count(array_filter(
                $operations,
                static fn (array $row): bool => !in_array($row['status'], ['completed', 'canceled'], true)
            )),
            'operations_failed' => count(array_filter($operations, static fn (array $row): bool => $row['status'] === 'failed')),
        ];

        $attention = [];
        foreach ($bindings as $binding) {
            if (in_array($binding['status'], ['degraded', 'failed'], true)) {
                $attention[] = [
                    'kind' => 'binding',
                    'severity' => $binding['status'] === 'failed' ? 'critical' : 'warning',
                    'title' => $binding['hostname'] . ' infrastructure is ' . $binding['status'],
                    'resource_public_id' => $binding['public_id'],
                ];
            }
        }
        foreach ($operations as $operation) {
            if (in_array($operation['status'], ['failed', 'paused'], true)) {
                $attention[] = [
                    'kind' => 'operation',
                    'severity' => $operation['status'] === 'failed' ? 'critical' : 'warning',
                    'title' => ucfirst($operation['operation_type']) . ' operation is ' . $operation['status'],
                    'resource_public_id' => $operation['public_id'],
                ];
            }
        }

        return [
            'account' => [
                'public_id' => (string) $accountRow['public_id'],
                'display_name' => (string) $accountRow['display_name'],
                'status' => (string) $accountRow['status'],
            ],
            'metrics' => $metrics,
            'connections' => $connections,
            'pods' => $pods,
            'bindings' => $bindings,
            'operations' => $operations,
            'attention' => array_slice($attention, 0, 20),
        ];
    }

    /** @return list<array<string,mixed>> */
    private function connections(PDO $pdo, int $accountId): array
    {
        $statement = $pdo->prepare(
            "SELECT c.public_id,c.provider_type,c.provider_code,c.display_name,c.status,c.credential_version,
                    c.created_at,c.updated_at,c.revoked_at,
                    (
                      SELECT COUNT(*)
                      FROM infrastructure_bindings b
                      WHERE b.account_id=c.account_id
                        AND b.status<>'disabled'
                        AND (
                          b.hosting_connection_id=c.id
                          OR b.dns_connection_id=c.id
                          OR b.certificate_connection_id=c.id
                        )
                    ) active_binding_count
             FROM provider_connections c
             WHERE c.account_id=:account
             ORDER BY FIELD(c.status,'active','disabled','revoked'),c.provider_type,c.display_name,c.id"
        );
        $statement->execute(['account' => $accountId]);

        $rows = [];
        foreach ($statement->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $rows[] = [
                'public_id' => (string) $row['public_id'],
                'provider_type' => (string) $row['provider_type'],
                'provider_code' => (string) $row['provider_code'],
                'display_name' => (string) $row['display_name'],
                'status' => (string) $row['status'],
                'credential_version' => (int) $row['credential_version'],
                'active_binding_count' => (int) $row['active_binding_count'],
                'created_at' => (string) $row['created_at'],
                'updated_at' => (string) $row['updated_at'],
                'revoked_at' => $row['revoked_at'] === null ? null : (string) $row['revoked_at'],
            ];
        }
        return $rows;
    }

    /** @return list<array<string,mixed>> */
    private function pods(PDO $pdo, int $accountId): array
    {
        $statement = $pdo->prepare(
            "SELECT p.public_id,d.hostname,p.status,p.routing_status,p.ssl_status,p.installed_version,p.updated_at,
                    b.public_id binding_public_id,b.status binding_status
             FROM pod_deployments p
             JOIN domain_registrations d
               ON d.id=p.domain_registration_id
              AND d.account_id=p.account_id
             LEFT JOIN infrastructure_bindings b
               ON b.deployment_id=p.id
              AND b.account_id=p.account_id
             WHERE p.account_id=:account
               AND p.status IN ('pending','provisioning','active','degraded','failed')
             ORDER BY d.hostname,p.id"
        );
        $statement->execute(['account' => $accountId]);

        $rows = [];
        foreach ($statement->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $rows[] = [
                'public_id' => (string) $row['public_id'],
                'hostname' => (string) $row['hostname'],
                'status' => (string) $row['status'],
                'routing_status' => (string) $row['routing_status'],
                'ssl_status' => (string) $row['ssl_status'],
                'installed_version' => $row['installed_version'] === null ? null : (string) $row['installed_version'],
                'binding_public_id' => $row['binding_public_id'] === null ? null : (string) $row['binding_public_id'],
                'binding_status' => $row['binding_status'] === null ? null : (string) $row['binding_status'],
                'updated_at' => (string) $row['updated_at'],
            ];
        }
        return $rows;
    }

    /** @return list<array<string,mixed>> */
    private function bindings(PDO $pdo, int $accountId): array
    {
        $statement = $pdo->prepare(
            "SELECT b.public_id,b.hostname,b.status,b.activated_at,b.disabled_at,b.created_at,b.updated_at,
                    p.public_id pod_public_id,p.status pod_status,p.routing_status,p.ssl_status,
                    hc.public_id hosting_connection_public_id,hc.display_name hosting_connection_name,
                    dc.public_id dns_connection_public_id,dc.display_name dns_connection_name,
                    cc.public_id certificate_connection_public_id,cc.display_name certificate_connection_name,
                    ha.status hosting_status,db.status dns_status,db.last_verified_at dns_last_verified_at,
                    co.status certificate_status,co.expires_at certificate_expires_at,co.last_verified_at certificate_last_verified_at
             FROM infrastructure_bindings b
             JOIN pod_deployments p ON p.id=b.deployment_id AND p.account_id=b.account_id
             JOIN provider_connections hc ON hc.id=b.hosting_connection_id AND hc.account_id=b.account_id
             JOIN provider_connections dc ON dc.id=b.dns_connection_id AND dc.account_id=b.account_id
             JOIN provider_connections cc ON cc.id=b.certificate_connection_id AND cc.account_id=b.account_id
             LEFT JOIN hosting_allocations ha ON ha.binding_id=b.id AND ha.account_id=b.account_id
             LEFT JOIN dns_bindings db ON db.binding_id=b.id AND db.account_id=b.account_id AND db.status<>'removed'
             LEFT JOIN certificate_orders co ON co.binding_id=b.id AND co.account_id=b.account_id AND co.status<>'revoked'
             WHERE b.account_id=:account
             ORDER BY FIELD(b.status,'failed','degraded','provisioning','pending','active','tearing_down','disabled'),b.updated_at DESC,b.id DESC"
        );
        $statement->execute(['account' => $accountId]);

        $rows = [];
        foreach ($statement->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $rows[] = [
                'public_id' => (string) $row['public_id'],
                'pod_public_id' => (string) $row['pod_public_id'],
                'hostname' => (string) $row['hostname'],
                'status' => (string) $row['status'],
                'pod_status' => (string) $row['pod_status'],
                'routing_status' => (string) $row['routing_status'],
                'ssl_status' => (string) $row['ssl_status'],
                'hosting_connection' => [
                    'public_id' => (string) $row['hosting_connection_public_id'],
                    'display_name' => (string) $row['hosting_connection_name'],
                ],
                'dns_connection' => [
                    'public_id' => (string) $row['dns_connection_public_id'],
                    'display_name' => (string) $row['dns_connection_name'],
                ],
                'certificate_connection' => [
                    'public_id' => (string) $row['certificate_connection_public_id'],
                    'display_name' => (string) $row['certificate_connection_name'],
                ],
                'hosting_status' => $row['hosting_status'] === null ? null : (string) $row['hosting_status'],
                'dns_status' => $row['dns_status'] === null ? null : (string) $row['dns_status'],
                'dns_last_verified_at' => $row['dns_last_verified_at'] === null ? null : (string) $row['dns_last_verified_at'],
                'certificate_status' => $row['certificate_status'] === null ? null : (string) $row['certificate_status'],
                'certificate_expires_at' => $row['certificate_expires_at'] === null ? null : (string) $row['certificate_expires_at'],
                'certificate_last_verified_at' => $row['certificate_last_verified_at'] === null ? null : (string) $row['certificate_last_verified_at'],
                'activated_at' => $row['activated_at'] === null ? null : (string) $row['activated_at'],
                'disabled_at' => $row['disabled_at'] === null ? null : (string) $row['disabled_at'],
                'created_at' => (string) $row['created_at'],
                'updated_at' => (string) $row['updated_at'],
            ];
        }
        return $rows;
    }

    /** @return list<array<string,mixed>> */
    private function operations(PDO $pdo, int $accountId): array
    {
        $statement = $pdo->prepare(
            "SELECT o.id,o.public_id,o.operation_type,o.status,o.current_stage,o.attempts,o.max_attempts,
                    o.started_at,o.completed_at,o.created_at,o.updated_at,
                    b.public_id binding_public_id,b.hostname,p.public_id pod_public_id
             FROM provider_operations o
             JOIN infrastructure_bindings b ON b.id=o.binding_id AND b.account_id=o.account_id
             JOIN pod_deployments p ON p.id=b.deployment_id AND p.account_id=b.account_id
             WHERE o.account_id=:account
             ORDER BY o.created_at DESC,o.id DESC
             LIMIT 100"
        );
        $statement->execute(['account' => $accountId]);
        $operationRows = $statement->fetchAll(PDO::FETCH_ASSOC);
        if ($operationRows === []) {
            return [];
        }

        $stepStatement = $pdo->prepare(
            "SELECT stage,sequence_no,status,attempts,started_at,completed_at,rolled_back_at
             FROM provider_operation_steps
             WHERE operation_id=:operation
             ORDER BY sequence_no,id"
        );

        $rows = [];
        foreach ($operationRows as $row) {
            $stepStatement->execute(['operation' => (int) $row['id']]);
            $steps = [];
            foreach ($stepStatement->fetchAll(PDO::FETCH_ASSOC) as $step) {
                $steps[] = [
                    'stage' => (string) $step['stage'],
                    'sequence_no' => (int) $step['sequence_no'],
                    'status' => (string) $step['status'],
                    'attempts' => (int) $step['attempts'],
                    'started_at' => $step['started_at'] === null ? null : (string) $step['started_at'],
                    'completed_at' => $step['completed_at'] === null ? null : (string) $step['completed_at'],
                    'rolled_back_at' => $step['rolled_back_at'] === null ? null : (string) $step['rolled_back_at'],
                ];
            }
            $rows[] = [
                'public_id' => (string) $row['public_id'],
                'binding_public_id' => (string) $row['binding_public_id'],
                'pod_public_id' => (string) $row['pod_public_id'],
                'hostname' => (string) $row['hostname'],
                'operation_type' => (string) $row['operation_type'],
                'status' => (string) $row['status'],
                'current_stage' => $row['current_stage'] === null ? null : (string) $row['current_stage'],
                'attempts' => (int) $row['attempts'],
                'max_attempts' => (int) $row['max_attempts'],
                'steps' => $steps,
                'started_at' => $row['started_at'] === null ? null : (string) $row['started_at'],
                'completed_at' => $row['completed_at'] === null ? null : (string) $row['completed_at'],
                'created_at' => (string) $row['created_at'],
                'updated_at' => (string) $row['updated_at'],
            ];
        }
        return $rows;
    }
}

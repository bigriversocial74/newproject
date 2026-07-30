<?php

declare(strict_types=1);

namespace Vp3\Recovery;

use PDO;
use Vp3\Database;

final class RecoveryControlCenterQueryService
{
    public function __construct(private readonly Database $database)
    {
    }

    /** @return array<string,mixed> */
    public function snapshot(int $accountId): array
    {
        $pods = $this->pods($accountId);
        $snapshots = $this->snapshots($accountId);
        $backupJobs = $this->backupJobs($accountId);
        $restoreJobs = $this->restoreJobs($accountId);
        $updateJobs = $this->updateJobs($accountId);
        $releases = $this->eligibleReleases($pods);

        $used = array_sum(array_column($pods, 'storage_usage_bytes'));
        $allowance = array_sum(array_column($pods, 'storage_allowance_bytes'));
        $verifiedSnapshots = count(array_filter($snapshots, static fn (array $row): bool => $row['status'] === 'verified'));
        $activeRecoveryJobs = count(array_filter(
            [...$backupJobs, ...$restoreJobs, ...$updateJobs],
            static fn (array $row): bool => !in_array($row['status'], ['completed', 'failed', 'canceled', 'rolled_back'], true)
        ));

        return [
            'metrics' => [
                'pods' => count($pods),
                'storage_usage_bytes' => $used,
                'storage_allowance_bytes' => $allowance,
                'storage_usage_percent' => $allowance > 0 ? round(($used / $allowance) * 100, 2) : 0.0,
                'verified_snapshots' => $verifiedSnapshots,
                'active_jobs' => $activeRecoveryJobs,
                'available_releases' => array_sum(array_map('count', $releases)),
            ],
            'pods' => $pods,
            'snapshots' => $snapshots,
            'backup_jobs' => $backupJobs,
            'restore_jobs' => $restoreJobs,
            'update_jobs' => $updateJobs,
            'eligible_releases' => $releases,
        ];
    }

    /** @return list<array<string,mixed>> */
    private function pods(int $accountId): array
    {
        $statement = $this->database->pdo()->prepare(
            "SELECT pd.public_id,pd.status,pd.installed_version,pd.update_channel,pd.storage_usage_bytes,
                    pd.storage_allowance_bytes,pd.backup_status,pd.updated_at,d.hostname,
                    bp.public_id AS policy_public_id,bp.status AS policy_status,bp.schedule_interval_minutes,
                    bp.retention_count,bp.retention_days,bp.next_run_at,bp.last_run_at,
                    so.utilization_percent AS observed_utilization,so.observed_at
             FROM pod_deployments pd
             JOIN domain_registrations d ON d.id=pd.domain_registration_id
             LEFT JOIN backup_policies bp ON bp.pod_deployment_id=pd.id AND bp.target_type='pod'
             LEFT JOIN storage_observations so ON so.id=(
                 SELECT so2.id FROM storage_observations so2
                 WHERE so2.account_id=pd.account_id AND so2.target_type='pod' AND so2.pod_deployment_id=pd.id
                 ORDER BY so2.observed_at DESC,so2.id DESC LIMIT 1
             )
             WHERE pd.account_id=:account
             ORDER BY d.hostname,pd.id"
        );
        $statement->execute(['account' => $accountId]);
        return array_map(static function (array $row): array {
            $usage = (int) $row['storage_usage_bytes'];
            $allowance = (int) $row['storage_allowance_bytes'];
            return [
                'public_id' => (string) $row['public_id'],
                'hostname' => (string) $row['hostname'],
                'status' => (string) $row['status'],
                'installed_version' => $row['installed_version'] !== null ? (string) $row['installed_version'] : null,
                'update_channel' => (string) $row['update_channel'],
                'storage_usage_bytes' => $usage,
                'storage_allowance_bytes' => $allowance,
                'storage_usage_percent' => $allowance > 0 ? round(($usage / $allowance) * 100, 2) : 0.0,
                'backup_status' => (string) $row['backup_status'],
                'updated_at' => (string) $row['updated_at'],
                'storage_observation' => $row['observed_at'] === null ? null : [
                    'utilization_percent' => (float) $row['observed_utilization'],
                    'observed_at' => (string) $row['observed_at'],
                ],
                'policy' => $row['policy_public_id'] === null ? null : [
                    'public_id' => (string) $row['policy_public_id'],
                    'status' => (string) $row['policy_status'],
                    'interval_minutes' => (int) $row['schedule_interval_minutes'],
                    'retention_count' => (int) $row['retention_count'],
                    'retention_days' => (int) $row['retention_days'],
                    'next_run_at' => $row['next_run_at'] !== null ? (string) $row['next_run_at'] : null,
                    'last_run_at' => $row['last_run_at'] !== null ? (string) $row['last_run_at'] : null,
                ],
            ];
        }, $statement->fetchAll(PDO::FETCH_ASSOC));
    }

    /** @return list<array<string,mixed>> */
    private function snapshots(int $accountId): array
    {
        $statement = $this->database->pdo()->prepare(
            "SELECT s.public_id,s.status,s.size_bytes,s.verification_status,s.verified_at,s.expires_at,
                    s.created_at,pd.public_id AS pod_public_id,d.hostname
             FROM backup_snapshots s
             JOIN pod_deployments pd ON pd.id=s.pod_deployment_id
             JOIN domain_registrations d ON d.id=pd.domain_registration_id
             WHERE s.account_id=:account AND s.target_type='pod'
             ORDER BY s.created_at DESC,s.id DESC LIMIT 60"
        );
        $statement->execute(['account' => $accountId]);
        return array_map(static fn (array $row): array => [
            'public_id' => (string) $row['public_id'],
            'pod_public_id' => (string) $row['pod_public_id'],
            'hostname' => (string) $row['hostname'],
            'status' => (string) $row['status'],
            'verification_status' => (string) $row['verification_status'],
            'size_bytes' => (int) $row['size_bytes'],
            'verified_at' => $row['verified_at'] !== null ? (string) $row['verified_at'] : null,
            'expires_at' => $row['expires_at'] !== null ? (string) $row['expires_at'] : null,
            'created_at' => (string) $row['created_at'],
            'restorable' => $row['status'] === 'verified' && $row['verification_status'] === 'verified',
        ], $statement->fetchAll(PDO::FETCH_ASSOC));
    }

    /** @return list<array<string,mixed>> */
    private function backupJobs(int $accountId): array
    {
        $statement = $this->database->pdo()->prepare(
            "SELECT j.public_id,j.job_type,j.status,j.attempts,j.started_at,j.completed_at,j.created_at,j.updated_at,
                    pd.public_id AS pod_public_id,d.hostname
             FROM backup_jobs j
             JOIN pod_deployments pd ON pd.id=j.pod_deployment_id
             JOIN domain_registrations d ON d.id=pd.domain_registration_id
             WHERE j.account_id=:account AND j.target_type='pod' AND j.job_type<>'retention_delete'
             ORDER BY j.created_at DESC,j.id DESC LIMIT 40"
        );
        $statement->execute(['account' => $accountId]);
        return array_map(static fn (array $row): array => [
            'public_id' => (string) $row['public_id'],
            'pod_public_id' => (string) $row['pod_public_id'],
            'hostname' => (string) $row['hostname'],
            'job_type' => (string) $row['job_type'],
            'status' => (string) $row['status'],
            'attempts' => (int) $row['attempts'],
            'started_at' => $row['started_at'] !== null ? (string) $row['started_at'] : null,
            'completed_at' => $row['completed_at'] !== null ? (string) $row['completed_at'] : null,
            'created_at' => (string) $row['created_at'],
            'updated_at' => (string) $row['updated_at'],
        ], $statement->fetchAll(PDO::FETCH_ASSOC));
    }

    /** @return list<array<string,mixed>> */
    private function restoreJobs(int $accountId): array
    {
        $statement = $this->database->pdo()->prepare(
            "SELECT r.public_id,r.status,r.attempts,r.started_at,r.completed_at,r.created_at,r.updated_at,
                    s.public_id AS snapshot_public_id,pd.public_id AS pod_public_id,d.hostname
             FROM restore_jobs r
             JOIN backup_snapshots s ON s.id=r.snapshot_id
             JOIN pod_deployments pd ON pd.id=s.pod_deployment_id
             JOIN domain_registrations d ON d.id=pd.domain_registration_id
             WHERE r.account_id=:account AND s.target_type='pod'
             ORDER BY r.created_at DESC,r.id DESC LIMIT 40"
        );
        $statement->execute(['account' => $accountId]);
        return array_map(static fn (array $row): array => [
            'public_id' => (string) $row['public_id'],
            'snapshot_public_id' => (string) $row['snapshot_public_id'],
            'pod_public_id' => (string) $row['pod_public_id'],
            'hostname' => (string) $row['hostname'],
            'status' => (string) $row['status'],
            'attempts' => (int) $row['attempts'],
            'started_at' => $row['started_at'] !== null ? (string) $row['started_at'] : null,
            'completed_at' => $row['completed_at'] !== null ? (string) $row['completed_at'] : null,
            'created_at' => (string) $row['created_at'],
            'updated_at' => (string) $row['updated_at'],
        ], $statement->fetchAll(PDO::FETCH_ASSOC));
    }

    /** @return list<array<string,mixed>> */
    private function updateJobs(int $accountId): array
    {
        $statement = $this->database->pdo()->prepare(
            "SELECT j.id,j.public_id,j.status,j.current_stage,j.previous_version,j.target_version,
                    j.pre_update_backup_verified,j.attempts,j.started_at,j.completed_at,j.created_at,j.updated_at,
                    pd.public_id AS pod_public_id,d.hostname,r.public_id AS release_public_id,r.channel
             FROM update_jobs j
             JOIN pod_deployments pd ON pd.id=j.pod_deployment_id
             JOIN domain_registrations d ON d.id=pd.domain_registration_id
             JOIN software_releases r ON r.id=j.release_id
             WHERE j.account_id=:account AND j.target_type='pod'
             ORDER BY j.created_at DESC,j.id DESC LIMIT 40"
        );
        $statement->execute(['account' => $accountId]);
        $rows = [];
        $stepQuery = $this->database->pdo()->prepare(
            'SELECT stage,status,sequence_no,attempts,started_at,completed_at,rolled_back_at FROM update_steps WHERE job_id=:job ORDER BY sequence_no'
        );
        foreach ($statement->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $stepQuery->execute(['job' => (int) $row['id']]);
            $steps = array_map(static fn (array $step): array => [
                'stage' => (string) $step['stage'],
                'status' => (string) $step['status'],
                'sequence' => (int) $step['sequence_no'],
                'attempts' => (int) $step['attempts'],
                'started_at' => $step['started_at'] !== null ? (string) $step['started_at'] : null,
                'completed_at' => $step['completed_at'] !== null ? (string) $step['completed_at'] : null,
                'rolled_back_at' => $step['rolled_back_at'] !== null ? (string) $step['rolled_back_at'] : null,
            ], $stepQuery->fetchAll(PDO::FETCH_ASSOC));
            $rows[] = [
                'public_id' => (string) $row['public_id'],
                'pod_public_id' => (string) $row['pod_public_id'],
                'hostname' => (string) $row['hostname'],
                'release_public_id' => (string) $row['release_public_id'],
                'channel' => (string) $row['channel'],
                'status' => (string) $row['status'],
                'current_stage' => $row['current_stage'] !== null ? (string) $row['current_stage'] : null,
                'previous_version' => $row['previous_version'] !== null ? (string) $row['previous_version'] : null,
                'target_version' => (string) $row['target_version'],
                'pre_update_backup_verified' => (bool) $row['pre_update_backup_verified'],
                'attempts' => (int) $row['attempts'],
                'started_at' => $row['started_at'] !== null ? (string) $row['started_at'] : null,
                'completed_at' => $row['completed_at'] !== null ? (string) $row['completed_at'] : null,
                'created_at' => (string) $row['created_at'],
                'updated_at' => (string) $row['updated_at'],
                'steps' => $steps,
                'can_pause' => in_array($row['status'], ['queued', 'running'], true),
                'can_resume' => in_array($row['status'], ['paused', 'failed'], true),
            ];
        }
        return $rows;
    }

    /** @param list<array<string,mixed>> $pods @return array<string,list<array<string,mixed>>> */
    private function eligibleReleases(array $pods): array
    {
        $statement = $this->database->pdo()->query(
            "SELECT r.public_id,r.version,r.channel,r.emergency_override,r.published_at,
                    rr.percentage,rr.cohort_seed,rr.starts_at,rr.ends_at,
                    c.minimum_current_version,c.maximum_current_version
             FROM software_releases r
             JOIN software_products p ON p.id=r.product_id AND p.target_type='pod' AND p.status='active'
             JOIN release_rollouts rr ON rr.release_id=r.id AND rr.status='active'
             JOIN release_compatibility_rules c ON c.release_id=r.id
             WHERE r.status='published' AND r.manifest_hash IS NOT NULL AND r.manifest_signature IS NOT NULL
             ORDER BY r.published_at DESC,r.id DESC"
        );
        $catalog = $statement->fetchAll(PDO::FETCH_ASSOC);
        $result = [];
        foreach ($pods as $pod) {
            $current = (string) ($pod['installed_version'] ?? '');
            $result[(string) $pod['public_id']] = [];
            if ($current === '') continue;
            foreach ($catalog as $release) {
                if ($release['starts_at'] !== null && strtotime((string) $release['starts_at']) > time()) continue;
                if ($release['ends_at'] !== null && strtotime((string) $release['ends_at']) < time()) continue;
                if ($release['channel'] === 'beta' && $pod['update_channel'] !== 'beta') continue;
                if ($release['minimum_current_version'] !== null && $release['minimum_current_version'] !== '' && version_compare($current, (string) $release['minimum_current_version'], '<')) continue;
                if ($release['maximum_current_version'] !== null && $release['maximum_current_version'] !== '' && version_compare($current, (string) $release['maximum_current_version'], '>')) continue;
                if (version_compare($current, (string) $release['version'], '>=')) continue;
                $emergency = $release['channel'] === 'security' && (int) $release['emergency_override'] === 1;
                if (!$emergency) {
                    $bucket = hexdec(substr(hash('sha256', $release['cohort_seed'] . '|' . $pod['public_id']), 0, 8)) % 100;
                    if ($bucket >= (int) $release['percentage']) continue;
                }
                $result[(string) $pod['public_id']][] = [
                    'public_id' => (string) $release['public_id'],
                    'version' => (string) $release['version'],
                    'channel' => (string) $release['channel'],
                    'published_at' => $release['published_at'] !== null ? (string) $release['published_at'] : null,
                    'emergency' => $emergency,
                ];
            }
        }
        return $result;
    }
}

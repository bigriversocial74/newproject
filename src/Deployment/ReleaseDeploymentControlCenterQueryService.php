<?php

declare(strict_types=1);

namespace Vp3\Deployment;

use PDO;
use Vp3\Database;

final class ReleaseDeploymentControlCenterQueryService
{
    public function __construct(
        private readonly Database $database,
        private readonly PlatformOperatorAuthorizer $authorizer
    ) {
    }

    /** @return array<string,mixed> */
    public function snapshot(int $accountId, int $userId, string $role): array
    {
        $this->authorizer->assertOperator($accountId, $userId, $role);
        $pdo = $this->database->pdo();

        $candidates = $pdo->query(
            "SELECT public_id,release_version,commit_sha,schema_level,manifest_sha256,installer_sha256,
                    source_tree_sha256,source_file_count,migration_count,signing_key_id,candidate_status,verified_at
             FROM platform_release_candidates
             ORDER BY schema_level DESC,id DESC LIMIT 50"
        )->fetchAll(PDO::FETCH_ASSOC);

        $environments = $pdo->query(
            "SELECT e.public_id,e.environment_key,e.display_name,e.base_url,e.environment_status,
                    e.readiness_status,e.config_fingerprint,e.readiness_evidence_hash,
                    e.worker_last_seen_at,e.last_health_at,e.updated_at,
                    c.public_id AS current_candidate_public_id,c.release_version AS current_release_version,
                    c.commit_sha AS current_commit_sha
             FROM platform_deployment_environments e
             LEFT JOIN platform_release_candidates c ON c.id=e.current_candidate_id
             ORDER BY FIELD(e.environment_key,'staging','production'),e.id"
        )->fetchAll(PDO::FETCH_ASSOC);

        $windows = $pdo->prepare(
            "SELECT w.public_id,e.public_id AS environment_public_id,e.environment_key,
                    w.window_status,w.starts_at,w.ends_at,w.reason,
                    creator.public_id AS created_by_user_public_id,approver.public_id AS approved_by_user_public_id,
                    w.created_at,w.updated_at
             FROM platform_maintenance_windows w
             INNER JOIN platform_deployment_environments e ON e.id=w.environment_id
             INNER JOIN users creator ON creator.id=w.created_by_user_id
             LEFT JOIN users approver ON approver.id=w.approved_by_user_id
             WHERE w.account_scope=:account_scope
               AND (w.ends_at>=UTC_TIMESTAMP(6) OR w.window_status IN ('scheduled','open'))
             ORDER BY w.starts_at ASC LIMIT 50"
        );
        $windows->execute(['account_scope' => $accountId]);
        $windowRows = $windows->fetchAll(PDO::FETCH_ASSOC);

        $promotions = $pdo->prepare(
            "SELECT p.id,p.public_id,p.request_id,p.promotion_status,p.scheduled_for,p.backup_required,
                    p.health_required,p.failure_code,p.evidence_hash,p.requested_at,p.approved_at,
                    p.started_at,p.finished_at,p.created_at,p.updated_at,p.lease_expires_at,p.attempt_count,
                    c.public_id AS candidate_public_id,c.release_version,c.commit_sha,c.schema_level,
                    src.public_id AS source_environment_public_id,src.environment_key AS source_environment_key,
                    dst.public_id AS target_environment_public_id,dst.environment_key AS target_environment_key,
                    w.public_id AS maintenance_window_public_id,
                    requester.public_id AS requested_by_user_public_id,
                    approver.public_id AS approved_by_user_public_id,
                    p.deployment_run_public_id,p.backup_public_id
             FROM platform_release_promotions p
             INNER JOIN platform_release_candidates c ON c.id=p.release_candidate_id
             INNER JOIN platform_deployment_environments src ON src.id=p.source_environment_id
             INNER JOIN platform_deployment_environments dst ON dst.id=p.target_environment_id
             INNER JOIN users requester ON requester.id=p.requested_by_user_id
             LEFT JOIN users approver ON approver.id=p.approved_by_user_id
             LEFT JOIN platform_maintenance_windows w ON w.id=p.maintenance_window_id
             WHERE p.account_scope=:account_scope
             ORDER BY p.id DESC LIMIT 100"
        );
        $promotions->execute(['account_scope' => $accountId]);
        $promotionRows = $promotions->fetchAll(PDO::FETCH_ASSOC);
        foreach ($promotionRows as &$promotion) {
            $promotionId = (int) $promotion['id'];
            unset($promotion['id']);
            $promotion['event_chain_valid'] = $this->verifyEventChain($pdo, $promotionId);
            $promotion['steps'] = $this->steps($pdo, $promotionId);
        }
        unset($promotion);

        $health = $pdo->query(
            "SELECT h.public_id,e.public_id AS environment_public_id,e.environment_key,
                    c.public_id AS candidate_public_id,c.release_version,h.health_status,h.checks_json,
                    h.evidence_hash,h.captured_by,h.captured_at
             FROM platform_environment_health_snapshots h
             INNER JOIN platform_deployment_environments e ON e.id=h.environment_id
             LEFT JOIN platform_release_candidates c ON c.id=h.release_candidate_id
             WHERE h.id IN (
                 SELECT MAX(h2.id) FROM platform_environment_health_snapshots h2 GROUP BY h2.environment_id
             )
             ORDER BY e.environment_key"
        )->fetchAll(PDO::FETCH_ASSOC);
        foreach ($health as &$snapshot) {
            $decoded = json_decode((string) $snapshot['checks_json'], true);
            $snapshot['checks'] = is_array($decoded) ? $decoded : [];
            unset($snapshot['checks_json']);
        }
        unset($snapshot);

        $counts = [
            'verified_candidates' => $this->count($pdo, "SELECT COUNT(*) FROM platform_release_candidates WHERE candidate_status IN ('verified','approved')"),
            'pending_approvals' => $this->countPrepared($pdo, "SELECT COUNT(*) FROM platform_release_promotions WHERE account_scope=:account_scope AND promotion_status='requested'", $accountId),
            'queued_deployments' => $this->countPrepared($pdo, "SELECT COUNT(*) FROM platform_release_promotions WHERE account_scope=:account_scope AND promotion_status IN ('approved','scheduled','queued','deploying','rollback_queued','rolling_back')", $accountId),
            'failed_deployments' => $this->countPrepared($pdo, "SELECT COUNT(*) FROM platform_release_promotions WHERE account_scope=:account_scope AND promotion_status='failed'", $accountId),
        ];

        return [
            'operator' => ['role' => $role, 'owner_required_for_approval' => true],
            'summary' => $counts,
            'candidates' => $candidates,
            'environments' => $environments,
            'maintenance_windows' => $windowRows,
            'promotions' => $promotionRows,
            'health' => $health,
            'server_time_utc' => gmdate('Y-m-d H:i:s') . '.000000',
        ];
    }

    /** @return list<array<string,mixed>> */
    private function steps(PDO $pdo, int $promotionId): array
    {
        $statement = $pdo->prepare(
            "SELECT step_order,step_key,migration_path,step_status,evidence_hash,error_code,started_at,completed_at
             FROM platform_release_promotion_steps WHERE promotion_id=:promotion_id ORDER BY step_order,id"
        );
        $statement->execute(['promotion_id' => $promotionId]);
        return $statement->fetchAll(PDO::FETCH_ASSOC);
    }

    private function verifyEventChain(PDO $pdo, int $promotionId): bool
    {
        $statement = $pdo->prepare(
            'SELECT event_type,actor_user_id,event_result,metadata_hash,previous_hash,event_hash,occurred_at
             FROM platform_release_promotion_events WHERE promotion_id=:promotion_id ORDER BY id ASC'
        );
        $statement->execute(['promotion_id' => $promotionId]);
        $previous = null;
        foreach ($statement->fetchAll(PDO::FETCH_ASSOC) as $event) {
            $storedPrevious = $event['previous_hash'] === null ? null : (string) $event['previous_hash'];
            if ($storedPrevious !== $previous) {
                return false;
            }
            $expected = hash('sha256', implode('|', [
                $promotionId,
                (string) $event['event_type'],
                $event['actor_user_id'] === null ? '' : (string) $event['actor_user_id'],
                (string) $event['event_result'],
                (string) $event['metadata_hash'],
                $storedPrevious ?? '',
                (string) $event['occurred_at'],
            ]));
            if (!hash_equals($expected, (string) $event['event_hash'])) {
                return false;
            }
            $previous = (string) $event['event_hash'];
        }
        return true;
    }

    private function count(PDO $pdo, string $sql): int
    {
        return (int) $pdo->query($sql)->fetchColumn();
    }

    private function countPrepared(PDO $pdo, string $sql, int $accountId): int
    {
        $statement = $pdo->prepare($sql);
        $statement->execute(['account_scope' => $accountId]);
        return (int) $statement->fetchColumn();
    }
}

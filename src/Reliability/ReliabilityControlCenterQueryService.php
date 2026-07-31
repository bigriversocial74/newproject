<?php

declare(strict_types=1);

namespace Vp3\Reliability;

use PDO;
use RuntimeException;
use Vp3\Database;
use Vp3\Deployment\PlatformOperatorAuthorizer;

final class ReliabilityControlCenterQueryService
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
        $components = $this->components($pdo, $accountId, false);
        $messages = $this->messages($pdo, $accountId, false);
        $settings = $this->settings($pdo, $accountId);
        $windows = $this->maintenanceWindows($pdo, $accountId);
        $events = $this->statusEvents($pdo, $accountId, 80);

        $counts = [
            'components' => count($components),
            'operational' => 0,
            'degraded' => 0,
            'major_outage' => 0,
            'maintenance' => 0,
            'unknown' => 0,
            'open_incidents' => 0,
            'budget_warning' => 0,
            'budget_exhausted' => 0,
        ];
        foreach ($components as $component) {
            $status = (string) $component['current_status'];
            if (isset($counts[$status])) {
                $counts[$status]++;
            }
            if (($component['incident']['active'] ?? false) === true) {
                $counts['open_incidents']++;
            }
            $budgetStatus = (string) ($component['budget']['budget_status'] ?? 'healthy');
            if ($budgetStatus === 'warning') {
                $counts['budget_warning']++;
            } elseif ($budgetStatus === 'exhausted') {
                $counts['budget_exhausted']++;
            }
        }

        return [
            'metrics' => $counts,
            'overall_status' => $this->overallStatus($components),
            'components' => $components,
            'status_settings' => $settings,
            'status_messages' => $messages,
            'maintenance_windows' => $windows,
            'status_events' => $events,
            'public_status_url' => ($settings['public_slug'] ?? '') === ''
                ? null
                : '/status.php?status=' . rawurlencode((string) $settings['public_slug']),
            'generated_at' => gmdate('Y-m-d\TH:i:s\Z'),
        ];
    }

    /** @return array<string,mixed> */
    public function publicStatus(string $slug): array
    {
        $slug = strtolower(trim($slug));
        if (!preg_match('/^[a-z0-9][a-z0-9-]{2,79}$/', $slug)) {
            throw new RuntimeException('Public reliability status page was not found.');
        }
        $pdo = $this->database->pdo();
        $statement = $pdo->prepare(
            'SELECT account_scope,public_slug,page_title,page_description,show_history,updated_at
             FROM reliability_status_settings
             WHERE public_slug=:slug AND public_enabled=1 LIMIT 1'
        );
        $statement->execute(['slug' => $slug]);
        $settings = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($settings)) {
            throw new RuntimeException('Public reliability status page was not found.');
        }
        $accountId = (int) $settings['account_scope'];
        $components = $this->components($pdo, $accountId, true);
        $messages = $this->messages($pdo, $accountId, true);
        $events = (bool) $settings['show_history'] ? $this->statusEvents($pdo, $accountId, 30, true) : [];

        unset($settings['account_scope']);
        $settings['show_history'] = (bool) $settings['show_history'];
        return [
            'page' => $settings,
            'overall_status' => $this->overallStatus($components),
            'components' => $components,
            'messages' => $messages,
            'history' => $events,
            'generated_at' => gmdate('Y-m-d\TH:i:s\Z'),
        ];
    }

    /** @return list<array<string,mixed>> */
    private function components(PDO $pdo, int $accountId, bool $publicOnly): array
    {
        $sql =
            'SELECT c.id,c.public_id,c.component_key,c.display_name,c.component_type,c.visibility,
                    c.current_status,c.status_since,c.enabled,c.display_order,
                    e.public_id AS environment_public_id,e.environment_key,e.display_name AS environment_name,
                    rc.public_id AS release_candidate_public_id,rc.release_version,rc.commit_sha,
                    o.public_id AS objective_public_id,o.availability_target_bps,o.latency_target_ms,
                    o.evaluation_window_minutes,o.warning_burn_rate,o.critical_burn_rate,
                    o.consecutive_failure_threshold,o.recovery_success_threshold
             FROM reliability_components c
             INNER JOIN reliability_objectives o ON o.component_id=c.id
             LEFT JOIN platform_deployment_environments e ON e.id=c.environment_id
             LEFT JOIN platform_release_candidates rc ON rc.id=e.current_candidate_id
             WHERE c.account_scope=:account_id AND c.enabled=1';
        if ($publicOnly) {
            $sql .= " AND c.visibility='public'";
        }
        $sql .= ' ORDER BY c.display_order,c.display_name,c.id';
        $statement = $pdo->prepare($sql);
        $statement->execute(['account_id' => $accountId]);
        $rows = $statement->fetchAll(PDO::FETCH_ASSOC);
        $result = [];
        foreach ($rows as $row) {
            $componentId = (int) $row['id'];
            $probeStatement = $pdo->prepare(
                'SELECT public_id,probe_type,interval_seconds,timeout_ms,enabled,next_due_at,last_started_at,last_finished_at
                 FROM reliability_probes WHERE component_id=:component_id ORDER BY probe_type'
            );
            $probeStatement->execute(['component_id' => $componentId]);
            $probes = [];
            foreach ($probeStatement->fetchAll(PDO::FETCH_ASSOC) as $probe) {
                $probe['enabled'] = (bool) $probe['enabled'];
                $probes[] = $probe;
            }

            $latestResultStatement = $pdo->prepare(
                'SELECT r.public_id,r.result_status,r.latency_ms,r.value_numeric,r.error_code,r.observed_at,
                        rc.public_id AS release_candidate_public_id,rc.release_version
                 FROM reliability_probe_results r
                 LEFT JOIN platform_release_candidates rc ON rc.id=r.release_candidate_id
                 WHERE r.component_id=:component_id ORDER BY r.observed_at DESC,r.id DESC LIMIT 1'
            );
            $latestResultStatement->execute(['component_id' => $componentId]);
            $latestResult = $latestResultStatement->fetch(PDO::FETCH_ASSOC);
            $latestResult = is_array($latestResult) ? $latestResult : null;

            $budgetStatement = $pdo->prepare(
                'SELECT public_id,window_started_at,window_ended_at,total_probes,failed_probes,
                        availability_bps,budget_consumed_bps,burn_rate,budget_status,captured_at
                 FROM reliability_budget_snapshots
                 WHERE component_id=:component_id ORDER BY captured_at DESC,id DESC LIMIT 1'
            );
            $budgetStatement->execute(['component_id' => $componentId]);
            $budget = $budgetStatement->fetch(PDO::FETCH_ASSOC);
            $budget = is_array($budget) ? $budget : [
                'total_probes' => 0,
                'failed_probes' => 0,
                'availability_bps' => 10000,
                'budget_consumed_bps' => 0,
                'burn_rate' => '0.0000',
                'budget_status' => 'healthy',
                'captured_at' => null,
            ];

            $incidentStatement = $pdo->prepare(
                "SELECT oi.public_id,oi.severity,oi.status,oi.first_detected_at,oi.last_detected_at
                 FROM reliability_incident_links ril
                 INNER JOIN operational_incidents oi ON oi.id=ril.operational_incident_id
                 WHERE ril.component_id=:component_id AND ril.link_status='open' AND ril.active_marker=1 LIMIT 1"
            );
            $incidentStatement->execute(['component_id' => $componentId]);
            $incident = $incidentStatement->fetch(PDO::FETCH_ASSOC);
            $incident = is_array($incident)
                ? ['active' => true] + $incident
                : ['active' => false];

            $correlation = $this->deploymentCorrelation($pdo, $componentId, (int) ($row['environment_public_id'] !== null));
            $component = [
                'public_id' => (string) $row['public_id'],
                'component_key' => (string) $row['component_key'],
                'display_name' => (string) $row['display_name'],
                'component_type' => (string) $row['component_type'],
                'visibility' => (string) $row['visibility'],
                'current_status' => (string) $row['current_status'],
                'status_since' => (string) $row['status_since'],
                'display_order' => (int) $row['display_order'],
                'environment' => $row['environment_public_id'] === null ? null : [
                    'public_id' => (string) $row['environment_public_id'],
                    'environment_key' => (string) $row['environment_key'],
                    'display_name' => (string) $row['environment_name'],
                ],
                'release' => $row['release_candidate_public_id'] === null ? null : [
                    'public_id' => (string) $row['release_candidate_public_id'],
                    'version' => (string) $row['release_version'],
                    'commit_sha' => (string) $row['commit_sha'],
                ],
                'objective' => [
                    'public_id' => (string) $row['objective_public_id'],
                    'availability_target_bps' => (int) $row['availability_target_bps'],
                    'latency_target_ms' => $row['latency_target_ms'] === null ? null : (int) $row['latency_target_ms'],
                    'evaluation_window_minutes' => (int) $row['evaluation_window_minutes'],
                    'warning_burn_rate' => (float) $row['warning_burn_rate'],
                    'critical_burn_rate' => (float) $row['critical_burn_rate'],
                    'consecutive_failure_threshold' => (int) $row['consecutive_failure_threshold'],
                    'recovery_success_threshold' => (int) $row['recovery_success_threshold'],
                ],
                'probes' => $probes,
                'latest_result' => $latestResult,
                'budget' => $budget,
                'incident' => $incident,
                'deployment_correlation' => $correlation,
            ];
            if ($publicOnly) {
                unset(
                    $component['public_id'],
                    $component['component_key'],
                    $component['visibility'],
                    $component['environment'],
                    $component['release'],
                    $component['objective']['public_id'],
                    $component['objective']['warning_burn_rate'],
                    $component['objective']['critical_burn_rate'],
                    $component['objective']['consecutive_failure_threshold'],
                    $component['objective']['recovery_success_threshold'],
                    $component['probes'],
                    $component['incident']['public_id'],
                    $component['deployment_correlation']
                );
                if (is_array($component['latest_result'])) {
                    unset(
                        $component['latest_result']['public_id'],
                        $component['latest_result']['error_code'],
                        $component['latest_result']['release_candidate_public_id']
                    );
                }
                if (is_array($component['budget'])) {
                    unset($component['budget']['public_id'], $component['budget']['budget_consumed_bps']);
                }
            }
            $result[] = $component;
        }
        return $result;
    }

    /** @return array<string,mixed>|null */
    private function deploymentCorrelation(PDO $pdo, int $componentId, int $hasEnvironment): ?array
    {
        if ($hasEnvironment !== 1) {
            return null;
        }
        $statement = $pdo->prepare(
            "SELECT p.public_id,p.finished_at,c.public_id AS candidate_public_id,c.release_version
             FROM reliability_components rel
             INNER JOIN platform_release_promotions p ON p.target_environment_id=rel.environment_id
             INNER JOIN platform_release_candidates c ON c.id=p.release_candidate_id
             WHERE rel.id=:component_id AND p.promotion_status='completed' AND p.finished_at IS NOT NULL
             ORDER BY p.finished_at DESC,p.id DESC LIMIT 1"
        );
        $statement->execute(['component_id' => $componentId]);
        $promotion = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($promotion)) {
            return null;
        }
        $before = $pdo->prepare(
            "SELECT COUNT(*) AS total,SUM(result_status='failure') AS failed
             FROM reliability_probe_results
             WHERE component_id=:component_id AND observed_at>=DATE_SUB(:finished_start,INTERVAL 60 MINUTE)
               AND observed_at<:finished_end AND result_status IN ('success','failure')"
        );
        $before->execute([
            'component_id' => $componentId,
            'finished_start' => (string) $promotion['finished_at'],
            'finished_end' => (string) $promotion['finished_at'],
        ]);
        $beforeRow = $before->fetch(PDO::FETCH_ASSOC) ?: [];
        $after = $pdo->prepare(
            "SELECT COUNT(*) AS total,SUM(result_status='failure') AS failed
             FROM reliability_probe_results
             WHERE component_id=:component_id AND observed_at>=:finished
               AND observed_at<=DATE_ADD(:finished_after,INTERVAL 60 MINUTE)
               AND result_status IN ('success','failure')"
        );
        $after->execute([
            'component_id' => $componentId,
            'finished' => (string) $promotion['finished_at'],
            'finished_after' => (string) $promotion['finished_at'],
        ]);
        $afterRow = $after->fetch(PDO::FETCH_ASSOC) ?: [];
        return [
            'promotion_public_id' => (string) $promotion['public_id'],
            'candidate_public_id' => (string) $promotion['candidate_public_id'],
            'release_version' => (string) $promotion['release_version'],
            'deployed_at' => (string) $promotion['finished_at'],
            'before_failure_rate' => $this->failureRate($beforeRow),
            'after_failure_rate' => $this->failureRate($afterRow),
        ];
    }

    /** @param array<string,mixed> $row */
    private function failureRate(array $row): ?float
    {
        $total = (int) ($row['total'] ?? 0);
        if ($total < 1) {
            return null;
        }
        return round(((int) ($row['failed'] ?? 0) / $total) * 100, 2);
    }

    /** @return array<string,mixed> */
    private function settings(PDO $pdo, int $accountId): array
    {
        $statement = $pdo->prepare(
            'SELECT public_slug,page_title,page_description,public_enabled,show_history,created_at,updated_at
             FROM reliability_status_settings WHERE account_scope=:account_id LIMIT 1'
        );
        $statement->execute(['account_id' => $accountId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            return [
                'public_slug' => '',
                'page_title' => '',
                'page_description' => '',
                'public_enabled' => false,
                'show_history' => true,
            ];
        }
        $row['public_enabled'] = (bool) $row['public_enabled'];
        $row['show_history'] = (bool) $row['show_history'];
        return $row;
    }

    /** @return list<array<string,mixed>> */
    private function messages(PDO $pdo, int $accountId, bool $publicOnly): array
    {
        $sql =
            'SELECT m.public_id,m.title,m.message,m.message_status,m.starts_at,m.ends_at,m.created_at,m.updated_at,
                    c.public_id AS component_public_id,c.display_name AS component_name,c.visibility
             FROM reliability_status_messages m
             LEFT JOIN reliability_components c ON c.id=m.component_id
             WHERE m.account_scope=:account_id';
        if ($publicOnly) {
            $sql .= " AND m.message_status IN ('scheduled','published','resolved')
                      AND m.starts_at<=UTC_TIMESTAMP(6)
                      AND (m.ends_at IS NULL OR m.ends_at>=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 90 DAY))
                      AND (c.id IS NULL OR c.visibility='public')";
        }
        $sql .= ' ORDER BY m.starts_at DESC,m.id DESC LIMIT 100';
        $statement = $pdo->prepare($sql);
        $statement->execute(['account_id' => $accountId]);
        $rows = $statement->fetchAll(PDO::FETCH_ASSOC);
        if ($publicOnly) {
            foreach ($rows as &$row) {
                unset($row['public_id'], $row['component_public_id'], $row['visibility']);
            }
            unset($row);
        }
        return $rows;
    }

    /** @return list<array<string,mixed>> */
    private function maintenanceWindows(PDO $pdo, int $accountId): array
    {
        $statement = $pdo->prepare(
            "SELECT w.public_id,w.window_status,w.starts_at,w.ends_at,w.reason,
                    e.public_id AS environment_public_id,e.environment_key,e.display_name AS environment_name
             FROM platform_maintenance_windows w
             INNER JOIN platform_deployment_environments e ON e.id=w.environment_id
             WHERE w.account_scope=:account_id
               AND w.ends_at>=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 30 DAY)
             ORDER BY w.starts_at DESC LIMIT 50"
        );
        $statement->execute(['account_id' => $accountId]);
        return $statement->fetchAll(PDO::FETCH_ASSOC);
    }

    /** @return list<array<string,mixed>> */
    private function statusEvents(PDO $pdo, int $accountId, int $limit, bool $publicOnly = false): array
    {
        $sql =
            'SELECT c.public_id AS component_public_id,c.display_name,c.visibility,
                    e.previous_status,e.current_status,e.reason_code,e.occurred_at
             FROM reliability_status_events e
             INNER JOIN reliability_components c ON c.id=e.component_id
             WHERE c.account_scope=:account_id';
        if ($publicOnly) {
            $sql .= " AND c.visibility='public'";
        }
        $sql .= ' ORDER BY e.occurred_at DESC,e.id DESC LIMIT ' . max(1, min(200, $limit));
        $statement = $pdo->prepare($sql);
        $statement->execute(['account_id' => $accountId]);
        $rows = $statement->fetchAll(PDO::FETCH_ASSOC);
        if ($publicOnly) {
            foreach ($rows as &$row) {
                unset($row['component_public_id'], $row['visibility']);
            }
            unset($row);
        }
        return $rows;
    }

    /** @param list<array<string,mixed>> $components */
    private function overallStatus(array $components): string
    {
        $rank = ['operational' => 1, 'unknown' => 2, 'maintenance' => 3, 'degraded' => 4, 'major_outage' => 5];
        $status = $components === [] ? 'unknown' : 'operational';
        foreach ($components as $component) {
            $candidate = (string) ($component['current_status'] ?? 'unknown');
            if (($rank[$candidate] ?? 2) > ($rank[$status] ?? 2)) {
                $status = $candidate;
            }
        }
        return $status;
    }
}

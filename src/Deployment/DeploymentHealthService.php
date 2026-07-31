<?php

declare(strict_types=1);

namespace Vp3\Deployment;

use PDO;
use RuntimeException;
use Vp3\Database;

final class DeploymentHealthService
{
    private const WORKERS = [
        'workers/pod-provisioning.php',
        'workers/software-updates.php',
        'workers/backups.php',
        'workers/infrastructure.php',
        'workers/homeserver-monitor.php',
        'workers/operations.php',
        'workers/security-incidents.php',
    ];

    public function __construct(
        private readonly string $root,
        private readonly Database $database,
        private readonly ReleaseManifestService $releases
    ) {
    }

    /** @return array<string,mixed> */
    public function verify(string $requestId): array
    {
        $requestId = trim($requestId);
        if (!preg_match('/^[A-Za-z0-9._:-]{8,80}$/', $requestId)) {
            throw new RuntimeException('A valid deployment-health request ID is required.');
        }
        $pdo = $this->database->pdo();
        $release = $this->releases->build();
        $checks = [];

        $checks['database'] = ['ok' => (int) $pdo->query('SELECT 1')->fetchColumn() === 1];
        $storedMigrations = $pdo->query(
            'SELECT migration_path,migration_sha256 FROM platform_schema_migrations ORDER BY id ASC'
        )->fetchAll(PDO::FETCH_KEY_PAIR);
        $missing = [];
        $mismatched = [];
        foreach ($this->releases->migrationPaths() as $path) {
            $expected = $this->releases->migrationSha256($path);
            if (!isset($storedMigrations[$path])) {
                $missing[] = $path;
            } elseif (!hash_equals($expected, (string) $storedMigrations[$path])) {
                $mismatched[] = $path;
            }
        }
        $checks['schema'] = [
            'ok' => $missing === [] && $mismatched === [],
            'expected_count' => (int) $release['migration_count'],
            'stored_count' => count($storedMigrations),
            'missing' => $missing,
            'mismatched' => $mismatched,
        ];

        $activeRelease = $pdo->query(
            "SELECT release_version,commit_sha,schema_level,release_manifest_sha256,activated_at
             FROM platform_release_records WHERE release_status='active' ORDER BY id DESC LIMIT 1"
        )->fetch(PDO::FETCH_ASSOC);
        $checks['active_release'] = [
            'ok' => is_array($activeRelease)
                && hash_equals((string) $release['version'], (string) $activeRelease['release_version'])
                && hash_equals((string) $release['commit_sha'], (string) $activeRelease['commit_sha'])
                && hash_equals((string) $release['manifest_sha256'], (string) $activeRelease['release_manifest_sha256']),
            'release' => is_array($activeRelease) ? $activeRelease : null,
        ];

        $latestDeployment = $pdo->query(
            "SELECT public_id,operation,run_status,error_code,evidence_hash,started_at,finished_at
             FROM platform_deployment_runs ORDER BY id DESC LIMIT 1"
        )->fetch(PDO::FETCH_ASSOC);
        $checks['latest_deployment'] = [
            'ok' => is_array($latestDeployment) && in_array((string) $latestDeployment['run_status'], ['completed', 'rolled_back'], true),
            'run' => is_array($latestDeployment) ? $latestDeployment : null,
        ];

        $failedSteps = (int) $pdo->query(
            "SELECT COUNT(*) FROM platform_deployment_steps WHERE step_status='failed'"
        )->fetchColumn();
        $checks['failed_steps'] = ['ok' => $failedSteps === 0, 'count' => $failedSteps];

        $missingWorkers = [];
        $workerHashes = [];
        foreach (self::WORKERS as $worker) {
            $path = $this->root . '/' . $worker;
            if (!is_file($path) || !is_readable($path)) {
                $missingWorkers[] = $worker;
                continue;
            }
            $hash = hash_file('sha256', $path);
            if (!is_string($hash)) {
                $missingWorkers[] = $worker;
                continue;
            }
            $workerHashes[$worker] = $hash;
        }
        $checks['worker_entrypoints'] = [
            'ok' => $missingWorkers === [],
            'missing' => $missingWorkers,
            'sha256' => $workerHashes,
            'scheduler_contract' => 'Run each worker through the production scheduler with one stable VP3_WORKER_ID.',
        ];

        $failures = [];
        foreach ($checks as $name => $check) {
            if (($check['ok'] ?? false) !== true) {
                $failures[] = $name;
            }
        }
        $report = [
            'ok' => $failures === [],
            'release_version' => (string) $release['version'],
            'commit_sha' => (string) $release['commit_sha'],
            'checks' => $checks,
            'failures' => $failures,
        ];
        $evidence = hash('sha256', $this->releases->canonicalJson($report));

        $this->database->transaction(function (PDO $transaction) use ($requestId, $evidence, $report): void {
            $prior = $transaction->prepare(
                "SELECT evidence_hash,result FROM platform_deployment_receipts
                 WHERE request_id=:request_id AND action_type='platform_health_verify' LIMIT 1 FOR UPDATE"
            );
            $prior->execute(['request_id' => $requestId]);
            $row = $prior->fetch(PDO::FETCH_ASSOC);
            if (is_array($row)) {
                if (!hash_equals((string) $row['evidence_hash'], $evidence)
                    || !hash_equals((string) $row['result'], $report['ok'] ? 'success' : 'failure')) {
                    throw new RuntimeException('platform_health_request_conflict');
                }
                return;
            }
            $transaction->prepare(
                "INSERT INTO platform_deployment_receipts
                 (public_id,deployment_run_id,request_id,action_type,result,evidence_hash,created_at)
                 VALUES (:public_id,NULL,:request_id,'platform_health_verify',:result,:evidence_hash,:created_at)"
            )->execute([
                'public_id' => 'PLATFORM-RECEIPT-' . strtoupper(bin2hex(random_bytes(10))),
                'request_id' => $requestId,
                'result' => $report['ok'] ? 'success' : 'failure',
                'evidence_hash' => $evidence,
                'created_at' => gmdate('Y-m-d H:i:s') . '.000000',
            ]);
        });

        $report['checked_at'] = gmdate('Y-m-d H:i:s') . '.000000';
        $report['evidence_hash'] = $evidence;
        return $report;
    }
}

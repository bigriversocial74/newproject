<?php

declare(strict_types=1);

namespace Vp3\Deployment;

use PDO;
use RuntimeException;

final class DeploymentPreflightService
{
    /**
     * @param array<string,mixed> $applicationConfig
     * @param array<string,mixed> $deploymentConfig
     */
    public function __construct(
        private readonly string $root,
        private readonly array $applicationConfig,
        private readonly array $deploymentConfig,
        private readonly ReleaseManifestService $releases
    ) {
    }

    /** @return array<string,mixed> */
    public function inspect(PDO $pdo, bool $allowExampleConfig = false): array
    {
        $checks = [];
        $release = $this->releases->build();

        $minimumPhp = (string) ($release['minimum_php'] ?? '8.2.0');
        $checks['php_version'] = [
            'ok' => version_compare(PHP_VERSION, $minimumPhp, '>='),
            'actual' => PHP_VERSION,
            'minimum' => $minimumPhp,
        ];

        $requiredExtensions = ['pdo', 'pdo_mysql', 'json', 'mbstring', 'openssl', 'sodium', 'zip'];
        $missingExtensions = array_values(array_filter(
            $requiredExtensions,
            static fn (string $extension): bool => !extension_loaded($extension)
        ));
        $checks['php_extensions'] = ['ok' => $missingExtensions === [], 'missing' => $missingExtensions];

        $environment = strtolower(trim((string) ($this->applicationConfig['app']['env'] ?? '')));
        $configPath = $this->root . '/config/config.php';
        $checks['application_config'] = [
            'ok' => $allowExampleConfig || ($environment !== 'production' || is_file($configPath)),
            'environment' => $environment,
            'using_example' => !is_file($configPath),
        ];

        $baseUrl = (string) ($this->applicationConfig['app']['base_url'] ?? '');
        $checks['https_origin'] = [
            'ok' => $environment !== 'production' || $this->canonicalHttpsOrigin($baseUrl),
            'base_url' => $baseUrl,
        ];

        $serverVersion = (string) $pdo->query('SELECT VERSION()')->fetchColumn();
        $databaseEngine = stripos($serverVersion, 'mariadb') !== false ? 'mariadb' : 'mysql';
        $minimumDatabase = (string) (($release['supported_databases'][$databaseEngine] ?? '999.0.0'));
        $normalizedVersion = $this->databaseVersion($serverVersion);
        $checks['database_version'] = [
            'ok' => version_compare($normalizedVersion, $minimumDatabase, '>='),
            'engine' => $databaseEngine,
            'actual' => $serverVersion,
            'minimum' => $minimumDatabase,
        ];

        $timezone = (string) $pdo->query('SELECT @@session.time_zone')->fetchColumn();
        $checks['database_timezone'] = [
            'ok' => in_array(strtoupper($timezone), ['+00:00', 'UTC', 'SYSTEM'], true),
            'actual' => $timezone,
        ];

        $backupRoot = (string) ($this->deploymentConfig['backup_root'] ?? '');
        $checks['backup_root'] = $this->directoryCheck($backupRoot);
        $checks['mysqldump_binary'] = $this->binaryCheck((string) ($this->deploymentConfig['mysqldump_binary'] ?? ''));
        $checks['mysql_binary'] = $this->binaryCheck((string) ($this->deploymentConfig['mysql_binary'] ?? ''));

        $installer = (array) ($release['installer'] ?? []);
        $checks['installer'] = [
            'ok' => preg_match('/^[a-f0-9]{64}$/', (string) ($installer['sha256'] ?? '')) === 1
                && (int) ($installer['bytes'] ?? 0) > 0,
            'sha256' => (string) ($installer['sha256'] ?? ''),
            'bytes' => (int) ($installer['bytes'] ?? 0),
        ];

        $workerFiles = [
            'workers/operations.php',
            'workers/security-incidents.php',
        ];
        $missingWorkers = array_values(array_filter(
            $workerFiles,
            fn (string $path): bool => !is_file($this->root . '/' . $path) || !is_readable($this->root . '/' . $path)
        ));
        $checks['workers'] = ['ok' => $missingWorkers === [], 'missing' => $missingWorkers];

        $activeRun = null;
        if ($this->tableExists($pdo, 'platform_deployment_runs')) {
            $statement = $pdo->query(
                "SELECT public_id,operation,run_status,started_at
                 FROM platform_deployment_runs
                 WHERE run_status IN ('preflight','backing_up','applying','verifying','rolling_back')
                 ORDER BY id DESC LIMIT 1"
            );
            $row = $statement->fetch(PDO::FETCH_ASSOC);
            $activeRun = is_array($row) ? $row : null;
        }
        $checks['active_deployment'] = ['ok' => $activeRun === null, 'run' => $activeRun];

        $failures = [];
        foreach ($checks as $name => $check) {
            if (($check['ok'] ?? false) !== true) {
                $failures[] = $name;
            }
        }

        return [
            'ok' => $failures === [],
            'release' => [
                'version' => (string) $release['version'],
                'commit_sha' => (string) $release['commit_sha'],
                'schema_level' => (int) $release['schema_level'],
                'manifest_sha256' => (string) $release['manifest_sha256'],
            ],
            'checks' => $checks,
            'failures' => $failures,
        ];
    }

    /** @return array{ok:bool,path:string,free_bytes:int|null} */
    private function directoryCheck(string $path): array
    {
        $ok = str_starts_with($path, DIRECTORY_SEPARATOR);
        if ($ok && !is_dir($path)) {
            $parent = dirname($path);
            $ok = is_dir($parent) && is_writable($parent);
        } elseif ($ok) {
            $ok = is_writable($path);
        }
        $free = $ok ? disk_free_space(is_dir($path) ? $path : dirname($path)) : false;
        if ($free !== false && $free < 104857600) {
            $ok = false;
        }
        return ['ok' => $ok, 'path' => $path, 'free_bytes' => $free === false ? null : (int) $free];
    }

    /** @return array{ok:bool,path:string} */
    private function binaryCheck(string $path): array
    {
        return [
            'ok' => str_starts_with($path, DIRECTORY_SEPARATOR) && is_file($path) && is_executable($path),
            'path' => $path,
        ];
    }

    private function canonicalHttpsOrigin(string $url): bool
    {
        $parts = parse_url($url);
        return is_array($parts)
            && strtolower((string) ($parts['scheme'] ?? '')) === 'https'
            && isset($parts['host'])
            && !isset($parts['user'], $parts['pass'], $parts['query'], $parts['fragment'])
            && (($parts['path'] ?? '') === '' || ($parts['path'] ?? '') === '/');
    }

    private function databaseVersion(string $version): string
    {
        if (!preg_match('/(\d+\.\d+\.\d+)/', $version, $matches)) {
            throw new RuntimeException('Unable to parse the database server version.');
        }
        return $matches[1];
    }

    private function tableExists(PDO $pdo, string $table): bool
    {
        $statement = $pdo->prepare(
            'SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=:table'
        );
        $statement->execute(['table' => $table]);
        return (int) $statement->fetchColumn() === 1;
    }
}

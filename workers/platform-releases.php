<?php

declare(strict_types=1);

use Vp3\Database;
use Vp3\Deployment\DatabaseCommandService;
use Vp3\Deployment\DeploymentEnvironmentFingerprintService;
use Vp3\Deployment\DeploymentHealthService;
use Vp3\Deployment\DeploymentPreflightService;
use Vp3\Deployment\PlatformUpgradeService;
use Vp3\Deployment\ReleaseDeploymentWorkerService;
use Vp3\Deployment\ReleaseManifestService;

$root = dirname(__DIR__);
$container = require $root . '/bootstrap.php';
$applicationConfig = (array) $container['config'];
$releaseConfig = require $root . '/config/release.php';
$environment = strtolower((string) ($applicationConfig['app']['env'] ?? 'development'));
$defaultBackupRoot = $environment === 'production' ? '/srv/vp3/platform-backups' : sys_get_temp_dir() . '/vp3-platform-backups';
$targetDatabaseConfig = (array) $applicationConfig['database'];
$targetDatabaseConfig['dsn'] = (string) (getenv('VP3_PLATFORM_TARGET_DB_DSN') ?: $targetDatabaseConfig['dsn']);
$targetDatabaseConfig['username'] = (string) (getenv('VP3_PLATFORM_TARGET_DB_USERNAME') ?: $targetDatabaseConfig['username']);
$targetDatabaseConfig['password'] = (string) (getenv('VP3_PLATFORM_TARGET_DB_PASSWORD') ?: $targetDatabaseConfig['password']);
$targetApplicationConfig = $applicationConfig;
$targetApplicationConfig['database'] = $targetDatabaseConfig;
$targetApplicationConfig['app']['env'] = (string) (getenv('VP3_PLATFORM_TARGET_APP_ENV') ?: ($targetApplicationConfig['app']['env'] ?? ''));
$targetApplicationConfig['app']['base_url'] = rtrim((string) (getenv('VP3_PLATFORM_TARGET_BASE_URL') ?: ($targetApplicationConfig['app']['base_url'] ?? '')), '/');
$targetDatabase = new Database($targetDatabaseConfig);
$deploymentConfig = [
    'backup_root' => (string) (getenv('VP3_PLATFORM_BACKUP_ROOT') ?: $defaultBackupRoot),
    'mysqldump_binary' => (string) (getenv('VP3_PLATFORM_MYSQLDUMP_BINARY') ?: '/usr/bin/mysqldump'),
    'mysql_binary' => (string) (getenv('VP3_PLATFORM_MYSQL_BINARY') ?: '/usr/bin/mysql'),
    'lock_name' => (string) (getenv('VP3_PLATFORM_DEPLOYMENT_LOCK_NAME') ?: 'vp3-platform-deployment'),
    'maximum_backup_bytes' => max(1048576, (int) (getenv('VP3_PLATFORM_BACKUP_MAX_BYTES') ?: 5368709120)),
];
$releaseManifest = new ReleaseManifestService($root, $releaseConfig);
$preflight = new DeploymentPreflightService($root, $targetApplicationConfig, $deploymentConfig, $releaseManifest);
$commands = new DatabaseCommandService(
    $targetDatabaseConfig,
    (string) $deploymentConfig['mysqldump_binary'],
    (string) $deploymentConfig['mysql_binary'],
    (string) $deploymentConfig['backup_root'],
    (int) $deploymentConfig['maximum_backup_bytes']
);
$upgrades = new PlatformUpgradeService(
    $root,
    $targetDatabase,
    $deploymentConfig,
    $releaseManifest,
    $preflight,
    $commands
);
$health = new DeploymentHealthService($root, $targetDatabase, $releaseManifest);
$fingerprint = (new DeploymentEnvironmentFingerprintService())->fingerprint(
    $targetApplicationConfig,
    $targetDatabaseConfig,
    $releaseConfig,
    strtolower((string) (getenv('VP3_PLATFORM_ENVIRONMENT_KEY') ?: ''))
);
$worker = new ReleaseDeploymentWorkerService(
    $container['database'],
    $targetDatabase,
    $releaseManifest,
    $preflight,
    $upgrades,
    $health,
    $container['operational_incidents'],
    $fingerprint,
    max(300, min(7200, (int) (getenv('VP3_PLATFORM_RELEASE_LEASE_SECONDS') ?: 3600)))
);

$environmentKey = strtolower((string) (getenv('VP3_PLATFORM_ENVIRONMENT_KEY') ?: ''));
$workerId = (string) (getenv('VP3_PLATFORM_RELEASE_WORKER_ID') ?: (gethostname() . ':' . getmypid()));
$limit = max(1, min(10, (int) (getenv('VP3_PLATFORM_RELEASE_WORKER_LIMIT') ?: 1)));
$processed = 0;
try {
    while ($processed < $limit) {
        $result = $worker->processNext($environmentKey, $workerId);
        if ($result === null) {
            break;
        }
        fwrite(STDOUT, json_encode($result, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . PHP_EOL);
        $processed++;
    }
    fwrite(STDOUT, json_encode(['processed' => $processed, 'environment' => $environmentKey], JSON_THROW_ON_ERROR) . PHP_EOL);
} catch (Throwable $exception) {
    fwrite(STDERR, ($environment === 'production' ? 'Platform release worker failed. Review protected deployment evidence.' : $exception->getMessage()) . PHP_EOL);
    exit(1);
}

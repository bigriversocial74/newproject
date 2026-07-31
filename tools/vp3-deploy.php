<?php

declare(strict_types=1);

use Vp3\Database;
use Vp3\Deployment\DatabaseCommandService;
use Vp3\Deployment\DeploymentPreflightService;
use Vp3\Deployment\PlatformUpgradeService;
use Vp3\Deployment\ReleaseManifestService;

$root = dirname(__DIR__);
$autoload = $root . '/vendor/autoload.php';
if (is_file($autoload)) {
    require $autoload;
} else {
    spl_autoload_register(static function (string $class) use ($root): void {
        $prefix = 'Vp3\\';
        if (!str_starts_with($class, $prefix)) {
            return;
        }
        $path = $root . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($path)) {
            require $path;
        }
    });
}

$command = strtolower(trim((string) ($argv[1] ?? '')));
$options = [];
foreach (array_slice($argv, 2) as $argument) {
    if (!str_starts_with($argument, '--') || !str_contains($argument, '=')) {
        continue;
    }
    [$key, $value] = explode('=', substr($argument, 2), 2);
    $options[strtolower(trim($key))] = trim($value);
}

$respond = static function (array $document, int $exit = 0): never {
    fwrite(STDOUT, json_encode($document, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    exit($exit);
};

try {
    if (!in_array($command, ['preflight', 'manifest', 'install', 'upgrade', 'verify', 'rollback'], true)) {
        throw new RuntimeException(
            'Usage: php tools/vp3-deploy.php preflight|manifest|install|upgrade|verify|rollback '
            . '[--request-id=...] [--run=...] [--output=...]'
        );
    }

    $applicationConfigPath = $root . '/config/config.php';
    $usingExampleConfig = !is_file($applicationConfigPath);
    if ($usingExampleConfig) {
        $applicationConfigPath = $root . '/config/config-example.php';
    }
    $applicationConfig = require $applicationConfigPath;
    $releaseConfig = require $root . '/config/release.php';
    if (!is_array($applicationConfig) || !is_array($releaseConfig)) {
        throw new RuntimeException('VP3 deployment configuration did not return an array.');
    }

    $environment = strtolower((string) ($applicationConfig['app']['env'] ?? 'development'));
    $defaultBackupRoot = $environment === 'production'
        ? '/srv/vp3/platform-backups'
        : sys_get_temp_dir() . '/vp3-platform-backups';
    $deploymentConfig = [
        'backup_root' => (string) (getenv('VP3_PLATFORM_BACKUP_ROOT') ?: $defaultBackupRoot),
        'mysqldump_binary' => (string) (getenv('VP3_PLATFORM_MYSQLDUMP_BINARY') ?: '/usr/bin/mysqldump'),
        'mysql_binary' => (string) (getenv('VP3_PLATFORM_MYSQL_BINARY') ?: '/usr/bin/mysql'),
        'lock_name' => (string) (getenv('VP3_PLATFORM_DEPLOYMENT_LOCK_NAME') ?: 'vp3-platform-deployment'),
        'maximum_backup_bytes' => max(
            1048576,
            (int) (getenv('VP3_PLATFORM_BACKUP_MAX_BYTES') ?: 5368709120)
        ),
    ];

    $database = new Database((array) $applicationConfig['database']);
    $releaseManifest = new ReleaseManifestService($root, $releaseConfig);
    $preflight = new DeploymentPreflightService(
        $root,
        $applicationConfig,
        $deploymentConfig,
        $releaseManifest
    );
    $commands = new DatabaseCommandService(
        (array) $applicationConfig['database'],
        (string) $deploymentConfig['mysqldump_binary'],
        (string) $deploymentConfig['mysql_binary'],
        (string) $deploymentConfig['backup_root'],
        (int) $deploymentConfig['maximum_backup_bytes']
    );
    $upgrades = new PlatformUpgradeService(
        $root,
        $database,
        $deploymentConfig,
        $releaseManifest,
        $preflight,
        $commands
    );

    if ($command === 'manifest') {
        $manifest = $releaseManifest->build();
        $output = (string) ($options['output'] ?? '');
        if ($output !== '') {
            $outputPath = str_starts_with($output, DIRECTORY_SEPARATOR) ? $output : $root . '/' . ltrim($output, '/');
            $releaseManifest->write($manifest, $outputPath);
            $manifest['written_to'] = $outputPath;
        }
        $respond(['ok' => true, 'data' => $manifest]);
    }

    if ($command === 'preflight') {
        $report = $preflight->inspect($database->pdo(), $usingExampleConfig && $environment !== 'production');
        $respond(['ok' => (bool) $report['ok'], 'data' => $report], (bool) $report['ok'] ? 0 : 2);
    }

    if ($command === 'verify') {
        $result = $upgrades->verify();
        $respond(['ok' => (bool) $result['ok'], 'data' => $result], (bool) $result['ok'] ? 0 : 2);
    }

    $requestId = (string) ($options['request-id'] ?? getenv('VP3_DEPLOYMENT_REQUEST_ID') ?: '');
    if ($command === 'install') {
        if ($usingExampleConfig && $environment === 'production') {
            throw new RuntimeException('Production installation requires config/config.php.');
        }
        $respond(['ok' => true, 'data' => $upgrades->install($requestId)]);
    }
    if ($command === 'upgrade') {
        if ($usingExampleConfig && $environment === 'production') {
            throw new RuntimeException('Production upgrade requires config/config.php.');
        }
        $respond(['ok' => true, 'data' => $upgrades->upgrade($requestId)]);
    }

    $run = (string) ($options['run'] ?? '');
    $respond(['ok' => true, 'data' => $upgrades->rollback($run, $requestId)]);
} catch (Throwable $exception) {
    $message = trim($exception->getMessage());
    $errorCode = preg_replace('/[^a-zA-Z0-9._:-]+/', '_', strtolower($message)) ?: 'platform_deployment_failed';
    $respond([
        'ok' => false,
        'error' => [
            'code' => substr(trim($errorCode, '_'), 0, 100) ?: 'platform_deployment_failed',
            'message' => $environment === 'production'
                ? 'The platform deployment command did not complete. Review the protected deployment journal.'
                : substr($message, 0, 500),
        ],
    ], 1);
}

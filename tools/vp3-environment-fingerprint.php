<?php

declare(strict_types=1);

use Vp3\Deployment\DeploymentEnvironmentFingerprintService;

$root = dirname(__DIR__);
$autoload = $root . '/vendor/autoload.php';
if (is_file($autoload)) {
    require $autoload;
} else {
    spl_autoload_register(static function (string $class) use ($root): void {
        $prefix = 'Vp3\\';
        if (!str_starts_with($class, $prefix)) return;
        $path = $root . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($path)) require $path;
    });
}

try {
    $environmentKey = strtolower(trim((string) ($argv[1] ?? getenv('VP3_PLATFORM_ENVIRONMENT_KEY') ?: '')));
    $configPath = is_file($root . '/config/config.php')
        ? $root . '/config/config.php'
        : $root . '/config/config-example.php';
    $applicationConfig = require $configPath;
    $releaseConfig = require $root . '/config/release.php';
    if (!is_array($applicationConfig) || !is_array($releaseConfig)) {
        throw new RuntimeException('VP3 configuration did not return an array.');
    }
    $targetDatabaseConfig = (array) ($applicationConfig['database'] ?? []);
    $targetDatabaseConfig['dsn'] = (string) (getenv('VP3_PLATFORM_TARGET_DB_DSN') ?: ($targetDatabaseConfig['dsn'] ?? ''));
    $targetApplicationConfig = $applicationConfig;
    $targetApplicationConfig['database'] = $targetDatabaseConfig;
    $targetApplicationConfig['app']['env'] = (string) (getenv('VP3_PLATFORM_TARGET_APP_ENV')
        ?: ($targetApplicationConfig['app']['env'] ?? ''));
    $targetApplicationConfig['app']['base_url'] = rtrim((string) (getenv('VP3_PLATFORM_TARGET_BASE_URL')
        ?: ($targetApplicationConfig['app']['base_url'] ?? '')), '/');

    $service = new DeploymentEnvironmentFingerprintService();
    $fingerprint = $service->fingerprint(
        $targetApplicationConfig,
        $targetDatabaseConfig,
        $releaseConfig,
        $environmentKey
    );
    fwrite(STDOUT, json_encode([
        'ok' => true,
        'data' => [
            'environment_key' => $environmentKey,
            'base_url' => (string) $targetApplicationConfig['app']['base_url'],
            'config_fingerprint' => $fingerprint,
        ],
    ], JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
} catch (Throwable $exception) {
    fwrite(STDOUT, json_encode([
        'ok' => false,
        'error' => [
            'code' => 'platform_environment_fingerprint_failed',
            'message' => 'The non-secret platform environment fingerprint could not be generated.',
        ],
    ], JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT) . PHP_EOL);
    exit(1);
}

<?php

declare(strict_types=1);

use Vp3\Database;
use Vp3\Deployment\DeploymentHealthService;
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

try {
    $configPath = $root . '/config/config.php';
    if (!is_file($configPath)) {
        throw new RuntimeException('Deployment health verification requires config/config.php.');
    }
    $config = require $configPath;
    $release = require $root . '/config/release.php';
    if (!is_array($config) || !is_array($release)) {
        throw new RuntimeException('VP3 configuration did not return an array.');
    }
    $requestId = (string) (getenv('VP3_DEPLOYMENT_HEALTH_REQUEST_ID') ?: '');
    foreach (array_slice($argv, 1) as $argument) {
        if (str_starts_with($argument, '--request-id=')) {
            $requestId = substr($argument, 13);
        }
    }
    $database = new Database((array) $config['database']);
    $service = new DeploymentHealthService(
        $root,
        $database,
        new ReleaseManifestService($root, $release)
    );
    $report = $service->verify($requestId);
    fwrite(STDOUT, json_encode(['ok' => $report['ok'], 'data' => $report], JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    exit($report['ok'] ? 0 : 2);
} catch (Throwable $exception) {
    fwrite(STDOUT, json_encode([
        'ok' => false,
        'error' => [
            'code' => substr(trim((string) preg_replace('/[^a-z0-9._:-]+/', '_', strtolower($exception->getMessage())), '_'), 0, 100),
            'message' => 'Deployment health verification did not complete.',
        ],
    ], JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT) . PHP_EOL);
    exit(1);
}

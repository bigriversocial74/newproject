<?php

declare(strict_types=1);

use Vp3\Deployment\ReleaseCandidateRegistryService;
use Vp3\Deployment\ReleaseManifestService;

$root = dirname(__DIR__);
$container = require $root . '/bootstrap.php';
$releaseConfig = require $root . '/config/release.php';
$options = [];
foreach (array_slice($argv, 1) as $argument) {
    if (str_starts_with($argument, '--') && str_contains($argument, '=')) {
        [$key, $value] = explode('=', substr($argument, 2), 2);
        $options[strtolower(trim($key))] = trim($value);
    }
}
$respond = static function (array $document, int $exit = 0): never {
    fwrite(STDOUT, json_encode($document, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    exit($exit);
};
try {
    $releaseRoot = (string) (getenv('VP3_PLATFORM_RELEASE_OUTPUT_ROOT') ?: $root . '/var/platform-releases');
    $version = preg_replace('/[^A-Za-z0-9._-]+/', '-', (string) $releaseConfig['version']);
    $manifestPath = (string) ($options['manifest'] ?? $releaseRoot . '/' . $version . '/platform-release-manifest.json');
    $signaturePath = (string) ($options['signature'] ?? $releaseRoot . '/' . $version . '/platform-release-signature.json');
    $actorPublicId = (string) ($options['registered-by'] ?? '');
    $actorId = null;
    if ($actorPublicId !== '') {
        $statement = $container['database']->pdo()->prepare("SELECT id FROM users WHERE public_id=:public_id AND status='active' LIMIT 1");
        $statement->execute(['public_id' => $actorPublicId]);
        $resolved = $statement->fetchColumn();
        if ($resolved === false) throw new RuntimeException('The release registrar user was not found.');
        $actorId = (int) $resolved;
    }
    $releaseSection = (array) ($container['config']['releases'] ?? []);
    $registry = new ReleaseCandidateRegistryService(
        $container['database'],
        new ReleaseManifestService($root, $releaseConfig),
        $releaseRoot,
        (string) ($releaseSection['signing_public_key_base64'] ?? ''),
        (string) ($releaseSection['signing_key_id'] ?? '')
    );
    $respond(['ok' => true, 'data' => $registry->register($manifestPath, $signaturePath, $actorId)]);
} catch (Throwable $exception) {
    $respond(['ok' => false, 'error' => ['code' => 'release_candidate_registration_failed', 'message' => 'The signed release candidate was not registered.']], 1);
}

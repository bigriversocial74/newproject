<?php

declare(strict_types=1);

use Vp3\Deployment\PlatformReleaseSignatureService;
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
    $releaseConfig = require $root . '/config/release.php';
    $applicationConfigPath = is_file($root . '/config/config.php')
        ? $root . '/config/config.php'
        : $root . '/config/config-example.php';
    $applicationConfig = require $applicationConfigPath;
    if (!is_array($releaseConfig) || !is_array($applicationConfig)) {
        throw new RuntimeException('Release configuration did not return an array.');
    }

    $releaseSection = (array) ($applicationConfig['releases'] ?? []);
    $privateKey = (string) ($releaseSection['signing_private_key_base64']
        ?? getenv('RELEASE_SIGNING_PRIVATE_KEY_B64') ?: '');
    $publicKey = (string) ($releaseSection['signing_public_key_base64']
        ?? getenv('RELEASE_SIGNING_PUBLIC_KEY_B64') ?: '');
    $keyId = (string) ($releaseSection['signing_key_id']
        ?? getenv('RELEASE_SIGNING_KEY_ID') ?: '');
    $outputRoot = (string) (getenv('VP3_PLATFORM_RELEASE_OUTPUT_ROOT')
        ?: $root . '/var/platform-releases');
    if (!str_starts_with($outputRoot, DIRECTORY_SEPARATOR)) {
        throw new RuntimeException('VP3_PLATFORM_RELEASE_OUTPUT_ROOT must be an absolute path.');
    }

    $manifests = new ReleaseManifestService($root, $releaseConfig);
    $manifest = $manifests->build();
    $signer = new PlatformReleaseSignatureService($privateKey, $publicKey, $keyId);
    $signature = $signer->sign($manifest, $manifests);
    $signer->verify($manifest, $signature, $manifests);

    $version = preg_replace('/[^A-Za-z0-9._-]+/', '-', (string) $manifest['version']);
    $directory = rtrim($outputRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $version;
    if (!is_dir($directory) && !mkdir($directory, 0750, true) && !is_dir($directory)) {
        throw new RuntimeException('Unable to create the platform release output directory.');
    }
    @chmod($directory, 0750);
    $manifestPath = $directory . '/platform-release-manifest.json';
    $signaturePath = $directory . '/platform-release-signature.json';
    $manifests->write($manifest, $manifestPath);
    $writeJson = static function (string $path, string $json): void {
        $temporary = $path . '.tmp-' . bin2hex(random_bytes(5));
        if (file_put_contents($temporary, $json . "\n", LOCK_EX) === false) {
            @unlink($temporary);
            throw new RuntimeException('Unable to write the platform release signature.');
        }
        @chmod($temporary, 0640);
        if (!rename($temporary, $path)) {
            @unlink($temporary);
            throw new RuntimeException('Unable to publish the platform release signature atomically.');
        }
    };
    $writeJson($signaturePath, $manifests->canonicalJson($signature));

    fwrite(STDOUT, json_encode([
        'ok' => true,
        'data' => [
            'version' => $manifest['version'],
            'commit_sha' => $manifest['commit_sha'],
            'manifest_sha256' => $manifest['manifest_sha256'],
            'key_id' => $signature['key_id'],
            'manifest_path' => $manifestPath,
            'signature_path' => $signaturePath,
        ],
    ], JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
} catch (Throwable $exception) {
    fwrite(STDOUT, json_encode([
        'ok' => false,
        'error' => [
            'code' => substr(trim((string) preg_replace('/[^a-z0-9._:-]+/', '_', strtolower($exception->getMessage())), '_'), 0, 100),
            'message' => 'The signed platform release artifact was not created.',
        ],
    ], JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT) . PHP_EOL);
    exit(1);
}

<?php

declare(strict_types=1);

use Vp3\Http\HomeServerEndpoint;
use Vp3\Http\JsonResponse;

$container = require __DIR__ . '/_bootstrap.php';
HomeServerEndpoint::requireMethod('GET');
try {
    $grant = (string) ($_GET['grant'] ?? '');
    $artifact = $container['homeserver_control_plane']->consumeInstallerGrant($grant);
    $root = realpath((string) (getenv('VP3_HOMESERVER_ARTIFACT_ROOT') ?: dirname(__DIR__, 4) . '/storage/releases'));
    if ($root === false || !is_dir($root)) {
        throw new RuntimeException('VP3 HomeServer artifact storage is unavailable.');
    }
    $reference = str_replace('\\', '/', ltrim((string) $artifact['storage_reference'], '/'));
    if ($reference === '' || str_contains($reference, '..') || preg_match('#^[a-z]+://#i', $reference)) {
        throw new RuntimeException('The authorized installer reference is invalid.');
    }
    $path = realpath($root . DIRECTORY_SEPARATOR . $reference);
    if ($path === false || !is_file($path) || !str_starts_with($path, $root . DIRECTORY_SEPARATOR)) {
        throw new RuntimeException('The authorized installer file was not found.');
    }
    if (filesize($path) !== (int) $artifact['size_bytes'] || !hash_equals((string) $artifact['sha256'], hash_file('sha256', $path))) {
        throw new RuntimeException('The authorized installer failed integrity verification.');
    }
    header('Content-Type: application/vnd.microsoft.portable-executable');
    header('Content-Disposition: attachment; filename="' . addslashes((string) $artifact['file_name']) . '"');
    header('Content-Length: ' . (string) $artifact['size_bytes']);
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: private, no-store, max-age=0');
    $handle = fopen($path, 'rb');
    if ($handle === false) {
        throw new RuntimeException('The authorized installer could not be opened.');
    }
    while (!feof($handle)) {
        $chunk = fread($handle, 1024 * 1024);
        if ($chunk === false) {
            fclose($handle);
            throw new RuntimeException('The authorized installer could not be read.');
        }
        echo $chunk;
        flush();
    }
    fclose($handle);
    exit;
} catch (Throwable $exception) {
    if (!headers_sent()) {
        HomeServerEndpoint::sendException($exception);
    }
    exit;
}

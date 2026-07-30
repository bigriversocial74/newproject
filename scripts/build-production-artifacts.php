<?php

declare(strict_types=1);

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use ZipArchive;

$root = dirname(__DIR__);
$dist = $root . '/dist';

$removeTree = static function (string $path) use (&$removeTree): void {
    if (!file_exists($path) && !is_link($path)) {
        return;
    }
    if (is_link($path) || is_file($path)) {
        if (!unlink($path)) {
            throw new RuntimeException('Unable to remove prior production artifact: ' . $path);
        }
        return;
    }
    foreach (new FilesystemIterator($path, FilesystemIterator::SKIP_DOTS) as $item) {
        $removeTree($item->getPathname());
    }
    if (!rmdir($path)) {
        throw new RuntimeException('Unable to remove prior production artifact directory: ' . $path);
    }
};

$removeTree($dist);
if (!mkdir($dist, 0750, true) && !is_dir($dist)) {
    throw new RuntimeException('Unable to create the production artifact directory.');
}

$installerPath = $root . '/database/vp3-single-install.sql';
$installer = file($installerPath, FILE_IGNORE_NEW_LINES);
if (!is_array($installer)) {
    throw new RuntimeException('Unable to read the cumulative VP3 installer.');
}

$sql = [
    '-- VP3.me standalone production installer',
    '-- Generated from database/vp3-single-install.sql.',
    '-- Safe to import from any working directory.',
    '-- Do not edit this generated file directly.',
    'SET NAMES utf8mb4;',
    "SET time_zone = '+00:00';",
    '',
];
$migrationCount = 0;
foreach ($installer as $line) {
    if (!preg_match('/^\s*SOURCE\s+([^;]+);\s*$/i', $line, $matches)) {
        continue;
    }
    $relative = trim($matches[1], " \t\n\r\0\x0B'\"");
    $relative = str_replace('\\', '/', $relative);
    if ($relative === '' || str_starts_with($relative, '/') || str_contains($relative, '../')) {
        throw new RuntimeException('The cumulative installer contains an unsafe migration path.');
    }
    $source = $root . '/database/' . $relative;
    if (!is_file($source) || !is_readable($source)) {
        throw new RuntimeException('Cumulative migration is missing: ' . $relative);
    }
    $body = file_get_contents($source);
    if (!is_string($body)) {
        throw new RuntimeException('Unable to read cumulative migration: ' . $relative);
    }
    $sql[] = '-- BEGIN ' . $relative;
    $sql[] = rtrim($body);
    $sql[] = '-- END ' . $relative;
    $sql[] = '';
    $migrationCount++;
}
if ($migrationCount < 1) {
    throw new RuntimeException('The cumulative installer did not resolve any migrations.');
}

$sqlPath = $dist . '/vp3-production.sql';
$sqlBody = implode("\n", $sql) . "\n";
if (file_put_contents($sqlPath, $sqlBody, LOCK_EX) !== strlen($sqlBody)) {
    throw new RuntimeException('Unable to write the standalone production SQL installer.');
}
chmod($sqlPath, 0640);

$zipPath = $dist . '/vp3-production.zip';
$zip = new ZipArchive();
if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
    throw new RuntimeException('Unable to create the production ZIP package.');
}

$addFile = static function (ZipArchive $zip, string $source, string $destination): void {
    if (!is_file($source) || !is_readable($source)) {
        throw new RuntimeException('Production package source is not readable: ' . $source);
    }
    if (!$zip->addFile($source, str_replace('\\', '/', $destination))) {
        throw new RuntimeException('Unable to add a file to the production ZIP: ' . $destination);
    }
};
$addDirectory = static function (ZipArchive $zip, string $source, string $destination) use ($addFile): void {
    if (!is_dir($source)) {
        throw new RuntimeException('Production package directory is missing: ' . $source);
    }
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($source, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY
    );
    foreach ($iterator as $item) {
        if ($item->isLink()) {
            throw new RuntimeException('Production package source contains a symbolic link: ' . $item->getPathname());
        }
        if (!$item->isFile()) {
            continue;
        }
        $relative = ltrim(str_replace('\\', '/', substr($item->getPathname(), strlen($source))), '/');
        $addFile($zip, $item->getPathname(), rtrim($destination, '/') . '/' . $relative);
    }
};

foreach (['src', 'public', 'workers'] as $directory) {
    $addDirectory($zip, $root . '/' . $directory, $directory);
}
$addDirectory($zip, $root . '/database/migrations', 'database/migrations');
foreach (['bootstrap.php', 'composer.json'] as $file) {
    $addFile($zip, $root . '/' . $file, $file);
}
$addFile($zip, $root . '/config/config-example.php', 'config/config-example.php');
$addFile($zip, $sqlPath, 'database/vp3-production.sql');

$deploymentGuide = <<<'MD'
# VP3.me Production Deployment

1. Extract `vp3-production.zip` into the VP3 application root.
2. Import `database/vp3-production.sql` into the VP3 control-plane database.
3. Copy `config/config-example.php` to `config/config.php` outside source control.
4. Set the production database, mail, Stripe, signing, encryption, wildcard DNS/TLS, POD deployment, backup, and notification environment values.
5. Place the checksum-pinned customer POD release at `VP3_POD_RELEASE_ZIP`.
6. Run the provisioning, update, backup, and operations workers under the restricted service account.

The local POD provisioning worker creates the isolated tenant database and user, safely extracts the POD ZIP, generates the shared tenant configuration, activates the release, and verifies the deployment.
MD;
$guidePath = $dist . '/DEPLOYMENT.md';
file_put_contents($guidePath, $deploymentGuide . "\n", LOCK_EX);
$addFile($zip, $guidePath, 'DEPLOYMENT.md');

if (!$zip->close()) {
    throw new RuntimeException('Unable to finalize the production ZIP package.');
}
chmod($zipPath, 0640);

$verification = new ZipArchive();
if ($verification->open($zipPath) !== true) {
    throw new RuntimeException('The generated production ZIP cannot be reopened.');
}
$required = [
    'bootstrap.php',
    'composer.json',
    'config/config-example.php',
    'database/vp3-production.sql',
    'public/index.php',
    'DEPLOYMENT.md',
];
foreach ($required as $entry) {
    if ($verification->locateName($entry, ZipArchive::FL_NOCASE) === false) {
        throw new RuntimeException('The production ZIP is missing: ' . $entry);
    }
}
$forbiddenPatterns = [
    '#(^|/)\.env($|\.)#i',
    '#(^|/)config/config\.php$#i',
    '#(^|/)database\.json$#i',
    '#(^|/)owner-bootstrap\.json$#i',
    '#(^|/)\.git/#i',
    '#(^|/)tests/#i',
];
for ($index = 0; $index < $verification->numFiles; $index++) {
    $entry = (string) $verification->getNameIndex($index);
    foreach ($forbiddenPatterns as $pattern) {
        if (preg_match($pattern, $entry)) {
            throw new RuntimeException('The production ZIP contains a forbidden entry: ' . $entry);
        }
    }
}
$verification->close();

$checksums = [
    hash_file('sha256', $zipPath) . '  vp3-production.zip',
    hash_file('sha256', $sqlPath) . '  vp3-production.sql',
];
$checksumPath = $dist . '/SHA256SUMS.txt';
file_put_contents($checksumPath, implode("\n", $checksums) . "\n", LOCK_EX);

$manifest = [
    'schema' => 'vp3.production-artifacts.v1',
    'commit' => getenv('GITHUB_SHA') ?: 'local-build',
    'migration_count' => $migrationCount,
    'zip' => [
        'name' => basename($zipPath),
        'sha256' => hash_file('sha256', $zipPath),
        'size_bytes' => filesize($zipPath),
    ],
    'sql' => [
        'name' => basename($sqlPath),
        'sha256' => hash_file('sha256', $sqlPath),
        'size_bytes' => filesize($sqlPath),
    ],
];
$manifestPath = $dist . '/artifact-manifest.json';
file_put_contents(
    $manifestPath,
    json_encode($manifest, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n",
    LOCK_EX
);

fwrite(STDOUT, json_encode($manifest, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . PHP_EOL);

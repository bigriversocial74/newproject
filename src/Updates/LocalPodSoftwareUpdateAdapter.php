<?php

declare(strict_types=1);

namespace Vp3\Updates;

use FilesystemIterator;
use PDO;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use Throwable;
use Vp3\Backups\PortableLocalPodBackupAdapter;
use ZipArchive;

final class LocalPodSoftwareUpdateAdapter implements SoftwareUpdateAdapter
{
    private string $deploymentRoot;
    private string $configurationPath;
    private string $entrypointPath;
    private int $maximumArchiveFiles;
    private int $maximumArchiveBytes;
    private string $mysqlBinary;
    private string $databaseHost;
    private int $databasePort;
    private PDO $platformDatabase;
    private PortableLocalPodBackupAdapter $backups;

    /** @param array<string,mixed> $configuration */
    public function __construct(array $configuration)
    {
        $this->deploymentRoot = $this->absolutePath((string) ($configuration['deployment_root'] ?? ''), 'VP3_POD_DEPLOYMENT_ROOT');
        $this->configurationPath = $this->relativePath((string) ($configuration['configuration_path'] ?? 'config/config.php'), 'VP3_POD_CONFIGURATION_PATH');
        $this->entrypointPath = $this->relativePath((string) ($configuration['entrypoint_path'] ?? 'public/index.php'), 'VP3_POD_ENTRYPOINT_PATH');
        $this->maximumArchiveFiles = max(1, (int) ($configuration['maximum_archive_files'] ?? 20000));
        $this->maximumArchiveBytes = max(1048576, (int) ($configuration['maximum_archive_bytes'] ?? 1073741824));
        $this->mysqlBinary = $this->executable((string) ($configuration['mysql_binary'] ?? '/usr/bin/mysql'), 'VP3_MYSQL_BINARY');
        $this->databaseHost = trim((string) ($configuration['database_host'] ?? '127.0.0.1')) ?: '127.0.0.1';
        $this->databasePort = max(1, min(65535, (int) ($configuration['database_port'] ?? 3306)));
        $dsn = trim((string) ($configuration['platform_database_dsn'] ?? ''));
        $username = trim((string) ($configuration['platform_database_username'] ?? ''));
        $password = (string) ($configuration['platform_database_password'] ?? '');
        if ($dsn === '' || $username === '') {
            throw new RuntimeException('The VP3 platform database connection is required for local POD updates.');
        }
        $this->platformDatabase = new PDO($dsn, $username, $password, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        $this->backups = new PortableLocalPodBackupAdapter($configuration);
        if (!class_exists(ZipArchive::class)) {
            throw new RuntimeException('The PHP zip extension is required for local POD updates.');
        }
    }

    public function createPreUpdateBackup(array $target, array $release): array
    {
        $this->assertPodTarget($target);
        $created = $this->backups->createBackup($target, 'pre_update:' . (string) ($release['version'] ?? 'unknown'));
        $verified = $this->backups->verifyBackup($target, $created['reference'], $created['snapshot_hash']);
        if (($verified['verified'] ?? false) !== true) {
            throw new RuntimeException('The encrypted pre-update POD backup could not be verified.');
        }
        return [
            'reference' => $created['reference'],
            'hash' => $created['snapshot_hash'],
            'verified' => true,
        ];
    }

    public function executeStage(string $stage, array $target, array $release, array $job): array
    {
        $this->assertPodTarget($target);
        return match ($stage) {
            'downloading' => $this->downloadArtifact($target, $release, $job),
            'installing' => $this->installArtifact($target, $release, $job),
            'migrating' => $this->runMigrations($target, $job),
            'verifying' => $this->verifyUpdate($target, $release, $job),
            default => throw new RuntimeException('Unsupported local POD update stage: ' . $stage . '.'),
        };
    }

    public function rollback(array $target, array $release, array $job): array
    {
        $this->assertPodTarget($target);
        $reference = trim((string) ($job['pre_update_backup_reference'] ?? ''));
        $hash = strtolower(trim((string) ($job['pre_update_backup_hash'] ?? '')));
        if ($reference === '' || !preg_match('/^[a-f0-9]{64}$/', $hash)) {
            throw new RuntimeException('The update job has no verified encrypted rollback snapshot.');
        }
        $result = $this->backups->restoreBackup($target, $reference, $hash);
        if (($result['restored'] ?? false) !== true) {
            throw new RuntimeException('The encrypted POD rollback snapshot was not restored.');
        }
        $this->removeTree($this->jobWorkspace($target, $job));
        return ['restored' => true, 'verification_hash' => $result['verification_hash'] ?? hash('sha256', $hash . '|rollback')];
    }

    /** @return array<string,mixed> */
    private function downloadArtifact(array $target, array $release, array $job): array
    {
        $artifact = $this->artifact($release);
        $source = $this->absolutePath((string) $artifact['storage_reference'], 'release artifact storage reference');
        if (!is_file($source) || !is_readable($source)) {
            throw new RuntimeException('The local POD release artifact is not readable.');
        }
        $actualHash = hash_file('sha256', $source);
        if (!is_string($actualHash) || !hash_equals(strtolower((string) $artifact['sha256']), strtolower($actualHash))) {
            throw new RuntimeException('The local POD release artifact checksum does not match the release catalog.');
        }
        $actualSize = filesize($source);
        if (!is_int($actualSize) || $actualSize !== (int) $artifact['size_bytes'] || $actualSize > $this->maximumArchiveBytes) {
            throw new RuntimeException('The local POD release artifact size does not match the release catalog.');
        }
        $workspace = $this->jobWorkspace($target, $job);
        $this->ensureDirectory($workspace, 0700);
        $destination = $workspace . '/artifact.zip';
        $temporary = $destination . '.tmp-' . bin2hex(random_bytes(6));
        if (!copy($source, $temporary)) {
            throw new RuntimeException('Unable to stage the local POD release artifact.');
        }
        chmod($temporary, 0600);
        if (!rename($temporary, $destination)) {
            @unlink($temporary);
            throw new RuntimeException('Unable to activate the staged POD release artifact.');
        }
        return [
            'provider_request_id' => substr(hash('sha256', (string) $job['public_id'] . '|download|' . $actualHash), 0, 40),
            'artifact_sha256' => $actualHash,
        ];
    }

    /** @return array<string,mixed> */
    private function installArtifact(array $target, array $release, array $job): array
    {
        $workspace = $this->jobWorkspace($target, $job);
        $artifactPath = $workspace . '/artifact.zip';
        $artifact = $this->artifact($release);
        $expectedHash = strtolower((string) $artifact['sha256']);
        $actualHash = is_file($artifactPath) ? hash_file('sha256', $artifactPath) : false;
        if (!is_string($actualHash) || !hash_equals($expectedHash, strtolower($actualHash))) {
            throw new RuntimeException('The staged POD release artifact failed installation checksum validation.');
        }
        $deployment = $this->deploymentPath($target);
        $releaseName = $this->safeVersion((string) $release['version']) . '-' . substr($expectedHash, 0, 12);
        $releaseDirectory = $deployment . '/releases/' . $releaseName;
        $temporary = $deployment . '/releases/.update-' . bin2hex(random_bytes(8));
        if (!is_dir($releaseDirectory)) {
            $this->ensureDirectory($temporary, 0750);
            try {
                $this->extractArchive($artifactPath, $temporary);
                if (!is_file($temporary . '/' . $this->entrypointPath)) {
                    throw new RuntimeException('The update ZIP does not contain the configured POD entrypoint.');
                }
                $this->linkSharedConfiguration($deployment, $temporary);
                $this->atomicWrite($temporary . '/.vp3-release.json', $this->json([
                    'version' => (string) $release['version'],
                    'archive_sha256' => $expectedHash,
                    'release_public_id' => (string) $release['public_id'],
                    'installed_at' => gmdate(DATE_ATOM),
                ]), 0640);
                if (!rename($temporary, $releaseDirectory)) {
                    throw new RuntimeException('Unable to activate the extracted POD update release.');
                }
            } catch (Throwable $exception) {
                $this->removeTree($temporary);
                throw $exception;
            }
        }

        $current = $deployment . '/current';
        if (!is_link($current)) {
            throw new RuntimeException('The POD current-release link is missing before update installation.');
        }
        $prior = readlink($current);
        if (!is_string($prior) || $prior === '') {
            throw new RuntimeException('The POD current-release link cannot be read before update installation.');
        }
        $this->atomicWrite($workspace . '/previous-release.txt', $prior . "\n", 0600);
        unlink($current);
        if (!symlink($releaseDirectory, $current)) {
            @symlink($prior, $current);
            throw new RuntimeException('Unable to switch the POD current-release link to the update.');
        }
        return [
            'provider_request_id' => substr(hash('sha256', (string) $job['public_id'] . '|install|' . $expectedHash), 0, 40),
            'artifact_sha256' => $expectedHash,
        ];
    }

    /** @return array<string,mixed> */
    private function runMigrations(array $target, array $job): array
    {
        $deployment = $this->deploymentPath($target);
        $manifestPath = $deployment . '/current/vp3-update.json';
        if (!is_file($manifestPath)) {
            return ['migration_count' => 0, 'provider_request_id' => substr(hash('sha256', (string) $job['public_id'] . '|migrations|0'), 0, 40)];
        }
        $manifest = json_decode((string) file_get_contents($manifestPath), true, 32, JSON_THROW_ON_ERROR);
        $migrations = is_array($manifest) ? ($manifest['migrations'] ?? []) : [];
        if (!is_array($migrations) || count($migrations) > 200) {
            throw new RuntimeException('The POD update migration manifest is invalid.');
        }
        $state = $this->databaseState($deployment);
        $count = 0;
        foreach ($migrations as $migration) {
            if (!is_string($migration)) {
                throw new RuntimeException('A POD update migration path is invalid.');
            }
            $relative = $this->relativePath($migration, 'POD update migration path');
            if (!str_ends_with(strtolower($relative), '.sql')) {
                throw new RuntimeException('POD update migrations must be SQL files.');
            }
            $path = $deployment . '/current/' . $relative;
            if (!is_file($path) || !$this->isWithin($path, $deployment . '/current')) {
                throw new RuntimeException('A POD update migration file is missing.');
            }
            $this->runMysql($state, $path);
            $count++;
        }
        return ['migration_count' => $count, 'provider_request_id' => substr(hash('sha256', (string) $job['public_id'] . '|migrations|' . $count), 0, 40)];
    }

    /** @return array<string,mixed> */
    private function verifyUpdate(array $target, array $release, array $job): array
    {
        $deployment = $this->deploymentPath($target);
        $current = $deployment . '/current';
        $markerPath = $current . '/.vp3-release.json';
        $configuration = $current . '/' . $this->configurationPath;
        if (!is_link($current) || !is_file($current . '/' . $this->entrypointPath) || !is_file($configuration) || !is_file($markerPath)) {
            throw new RuntimeException('The updated POD release is incomplete.');
        }
        $marker = json_decode((string) file_get_contents($markerPath), true);
        $artifact = $this->artifact($release);
        if (!is_array($marker) || !hash_equals(strtolower((string) $artifact['sha256']), strtolower((string) ($marker['archive_sha256'] ?? '')))) {
            throw new RuntimeException('The updated POD release marker does not match the release artifact.');
        }
        $state = $this->databaseState($deployment);
        $pdo = new PDO(
            sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $this->databaseHost, $this->databasePort, $state['database_name']),
            (string) $state['database_username'],
            (string) $state['database_password'],
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]
        );
        $pdo->query('SELECT 1')->fetchColumn();
        return [
            'verified' => true,
            'provider_request_id' => substr(hash('sha256', (string) $job['public_id'] . '|verify|' . (string) $artifact['sha256']), 0, 40),
            'artifact_sha256' => (string) $artifact['sha256'],
        ];
    }

    /** @return array<string,mixed> */
    private function artifact(array $release): array
    {
        $releaseId = (int) ($release['id'] ?? 0);
        if ($releaseId < 1) {
            throw new RuntimeException('The POD release identity is invalid.');
        }
        $statement = $this->platformDatabase->prepare(
            "SELECT * FROM release_artifacts WHERE release_id=:release
             ORDER BY CASE WHEN platform='php' THEN 0 ELSE 1 END,
                      CASE WHEN architecture IN ('any','all','noarch') THEN 0 ELSE 1 END,id LIMIT 1"
        );
        $statement->execute(['release' => $releaseId]);
        $artifact = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($artifact) || !preg_match('/^[a-f0-9]{64}$/', strtolower((string) ($artifact['sha256'] ?? '')))) {
            throw new RuntimeException('The POD release has no valid local artifact.');
        }
        return $artifact;
    }

    /** @param array<string,mixed> $target */
    private function assertPodTarget(array $target): void
    {
        if (($target['target_type'] ?? '') !== 'pod') {
            throw new RuntimeException('The local POD update adapter does not execute private HomeServer updates.');
        }
        $this->deploymentPath($target);
    }

    /** @param array<string,mixed> $target */
    private function deploymentPath(array $target): string
    {
        $publicId = strtolower(trim((string) ($target['public_id'] ?? '')));
        if (!preg_match('/^pod-[a-z0-9]+$/', $publicId)) {
            throw new RuntimeException('The POD update target public ID is invalid.');
        }
        $path = rtrim($this->deploymentRoot, '/') . '/' . $publicId;
        if (!is_dir($path)) {
            throw new RuntimeException('The POD update target deployment directory does not exist.');
        }
        return $path;
    }

    /** @param array<string,mixed> $target @param array<string,mixed> $job */
    private function jobWorkspace(array $target, array $job): string
    {
        $jobId = (int) ($job['id'] ?? 0);
        if ($jobId < 1) {
            throw new RuntimeException('The POD update job identity is invalid.');
        }
        return $this->deploymentPath($target) . '/shared/.vp3/updates/job-' . $jobId;
    }

    private function linkSharedConfiguration(string $deployment, string $release): void
    {
        $shared = $deployment . '/shared/config/' . basename($this->configurationPath);
        if (!is_file($shared)) {
            throw new RuntimeException('The POD shared configuration is missing before update installation.');
        }
        $path = $release . '/' . $this->configurationPath;
        $this->ensureDirectory(dirname($path), 0750);
        if ((is_file($path) || is_link($path)) && !unlink($path)) {
            throw new RuntimeException('Unable to replace the update ZIP configuration placeholder.');
        }
        if (!symlink($shared, $path)) {
            throw new RuntimeException('Unable to link the updated POD release to shared configuration.');
        }
    }

    private function extractArchive(string $archivePath, string $destination): void
    {
        $archive = new ZipArchive();
        if ($archive->open($archivePath) !== true) {
            throw new RuntimeException('Unable to open the staged POD update ZIP.');
        }
        try {
            if ($archive->numFiles < 1 || $archive->numFiles > $this->maximumArchiveFiles) {
                throw new RuntimeException('The POD update ZIP contains an invalid number of files.');
            }
            $entries = [];
            $total = 0;
            for ($index = 0; $index < $archive->numFiles; $index++) {
                $stat = $archive->statIndex($index);
                if (!is_array($stat) || !isset($stat['name'])) {
                    throw new RuntimeException('Unable to inspect a POD update ZIP entry.');
                }
                $name = $this->safeArchivePath((string) $stat['name']);
                $total += max(0, (int) ($stat['size'] ?? 0));
                if ($total > $this->maximumArchiveBytes) {
                    throw new RuntimeException('The POD update ZIP exceeds the configured extracted-size limit.');
                }
                if ($this->zipEntryIsSymlink($archive, $index)) {
                    throw new RuntimeException('Symbolic links are not allowed inside a POD update ZIP.');
                }
                $entries[] = ['name' => $name, 'directory' => str_ends_with($name, '/')];
            }
            $root = $this->singleRoot($entries);
            foreach ($entries as $entry) {
                $relative = $entry['name'];
                if ($root !== null) {
                    if ($relative === $root . '/') {
                        continue;
                    }
                    $relative = substr($relative, strlen($root) + 1);
                }
                if ($relative === '') {
                    continue;
                }
                $target = $destination . '/' . rtrim($relative, '/');
                if (!$this->isWithin($target, $destination)) {
                    throw new RuntimeException('A POD update ZIP entry escapes the release directory.');
                }
                if ($entry['directory']) {
                    $this->ensureDirectory($target, 0750);
                    continue;
                }
                $this->ensureDirectory(dirname($target), 0750);
                $source = $archive->getStream($entry['name']);
                if (!is_resource($source)) {
                    throw new RuntimeException('Unable to read a POD update ZIP entry.');
                }
                $output = fopen($target, 'xb');
                if (!is_resource($output)) {
                    fclose($source);
                    throw new RuntimeException('Unable to create an extracted POD update file.');
                }
                try {
                    if (stream_copy_to_stream($source, $output) === false) {
                        throw new RuntimeException('Unable to extract a POD update file.');
                    }
                } finally {
                    fclose($source);
                    fclose($output);
                }
                chmod($target, 0640);
            }
        } finally {
            $archive->close();
        }
    }

    /** @param list<array{name:string,directory:bool}> $entries */
    private function singleRoot(array $entries): ?string
    {
        $root = null;
        foreach ($entries as $entry) {
            $trimmed = trim($entry['name'], '/');
            if ($trimmed === '') {
                continue;
            }
            $segments = explode('/', $trimmed);
            if (count($segments) < 2 && !$entry['directory']) {
                return null;
            }
            if ($root === null) {
                $root = $segments[0];
            } elseif ($root !== $segments[0]) {
                return null;
            }
        }
        return $root;
    }

    private function safeArchivePath(string $name): string
    {
        $name = str_replace('\\', '/', $name);
        if ($name === '' || str_contains($name, "\0") || str_starts_with($name, '/') || preg_match('/^[A-Za-z]:\//', $name)) {
            throw new RuntimeException('The POD update ZIP contains an unsafe path.');
        }
        foreach (explode('/', trim($name, '/')) as $segment) {
            if ($segment === '.' || $segment === '..') {
                throw new RuntimeException('The POD update ZIP contains a traversal path.');
            }
        }
        return $name;
    }

    private function zipEntryIsSymlink(ZipArchive $archive, int $index): bool
    {
        $system = 0;
        $attributes = 0;
        if (!$archive->getExternalAttributesIndex($index, $system, $attributes)) {
            return false;
        }
        return (($attributes >> 16) & 0170000) === 0120000;
    }

    /** @return array<string,mixed> */
    private function databaseState(string $deployment): array
    {
        $path = $deployment . '/shared/.vp3/database.json';
        $state = is_file($path) ? json_decode((string) file_get_contents($path), true) : null;
        if (!is_array($state)) {
            throw new RuntimeException('The POD database credential state is missing for update migration.');
        }
        foreach (['database_name', 'database_username', 'database_password'] as $key) {
            if (!isset($state[$key]) || !is_string($state[$key]) || $state[$key] === '') {
                throw new RuntimeException('The POD database credential state is incomplete for update migration.');
            }
        }
        return $state;
    }

    /** @param array<string,mixed> $state */
    private function runMysql(array $state, string $sqlPath): void
    {
        $command = [
            $this->mysqlBinary,
            '--host=' . $this->databaseHost,
            '--port=' . $this->databasePort,
            '--user=' . $state['database_username'],
            '--default-character-set=utf8mb4',
            (string) $state['database_name'],
        ];
        $environment = getenv();
        if (!is_array($environment)) {
            $environment = [];
        }
        $environment['MYSQL_PWD'] = (string) $state['database_password'];
        $process = proc_open($command, [
            0 => ['file', $sqlPath, 'rb'],
            1 => ['file', '/dev/null', 'wb'],
            2 => ['pipe', 'w'],
        ], $pipes, null, $environment, ['bypass_shell' => true]);
        if (!is_resource($process)) {
            throw new RuntimeException('Unable to start the POD update migration command.');
        }
        $error = isset($pipes[2]) && is_resource($pipes[2]) ? (stream_get_contents($pipes[2]) ?: '') : '';
        if (isset($pipes[2]) && is_resource($pipes[2])) {
            fclose($pipes[2]);
        }
        $exit = proc_close($process);
        if ($exit !== 0) {
            throw new RuntimeException('A POD update migration failed: ' . substr(trim($error), 0, 300));
        }
    }

    private function absolutePath(string $path, string $label): string
    {
        $path = trim($path);
        if ($path === '' || (!str_starts_with($path, '/') && !preg_match('/^[A-Za-z]:[\\\\\/]/', $path))) {
            throw new RuntimeException($label . ' must be an absolute path.');
        }
        return rtrim(str_replace('\\', '/', $path), '/');
    }

    private function executable(string $path, string $label): string
    {
        $path = $this->absolutePath($path, $label);
        if (!is_file($path) || !is_executable($path)) {
            throw new RuntimeException($label . ' must point to an executable file.');
        }
        return $path;
    }

    private function relativePath(string $path, string $label): string
    {
        $path = trim(str_replace('\\', '/', $path), '/');
        if ($path === '') {
            throw new RuntimeException($label . ' cannot be empty.');
        }
        foreach (explode('/', $path) as $segment) {
            if ($segment === '' || $segment === '.' || $segment === '..') {
                throw new RuntimeException($label . ' contains an unsafe path segment.');
            }
        }
        return $path;
    }

    private function safeVersion(string $version): string
    {
        $version = trim($version);
        if ($version === '' || !preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/', $version)) {
            throw new RuntimeException('The POD release version contains unsupported characters.');
        }
        return $version;
    }

    private function ensureDirectory(string $path, int $permissions): void
    {
        if (!is_dir($path) && !mkdir($path, $permissions, true) && !is_dir($path)) {
            throw new RuntimeException('Unable to create a local POD update directory.');
        }
    }

    private function atomicWrite(string $path, string $content, int $permissions): void
    {
        $this->ensureDirectory(dirname($path), 0750);
        $temporary = $path . '.tmp-' . bin2hex(random_bytes(6));
        if (file_put_contents($temporary, $content, LOCK_EX) !== strlen($content)) {
            @unlink($temporary);
            throw new RuntimeException('Unable to write local POD update metadata.');
        }
        chmod($temporary, $permissions);
        if (!rename($temporary, $path)) {
            @unlink($temporary);
            throw new RuntimeException('Unable to activate local POD update metadata.');
        }
    }

    private function removeTree(string $path): void
    {
        if (!file_exists($path) && !is_link($path)) {
            return;
        }
        if (is_link($path) || is_file($path)) {
            @unlink($path);
            return;
        }
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($iterator as $item) {
            $item->isLink() || $item->isFile() ? @unlink($item->getPathname()) : @rmdir($item->getPathname());
        }
        @rmdir($path);
    }

    private function isWithin(string $path, string $root): bool
    {
        $path = str_replace('\\', '/', $path);
        $root = rtrim(str_replace('\\', '/', $root), '/');
        return $path === $root || str_starts_with($path, $root . '/');
    }

    /** @param array<string,mixed> $value */
    private function json(array $value): string
    {
        return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT) . "\n";
    }
}

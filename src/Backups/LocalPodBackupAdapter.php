<?php

declare(strict_types=1);

namespace Vp3\Backups;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use Throwable;
use ZipArchive;

final class LocalPodBackupAdapter implements BackupProviderAdapter
{
    private const CHUNK_BYTES = 1048576;

    private string $deploymentRoot;
    private string $backupRoot;
    private string $encryptionKey;
    private string $mysqldumpBinary;
    private string $mysqlBinary;
    private string $databaseHost;
    private int $databasePort;
    private int $maximumBackupBytes;

    /** @param array<string,mixed> $configuration */
    public function __construct(array $configuration)
    {
        $this->deploymentRoot = $this->absolutePath((string) ($configuration['deployment_root'] ?? ''), 'VP3_POD_DEPLOYMENT_ROOT');
        $this->backupRoot = $this->absolutePath((string) ($configuration['backup_root'] ?? ''), 'VP3_LOCAL_BACKUP_ROOT');
        $encodedKey = trim((string) ($configuration['encryption_key_base64'] ?? ''));
        $key = base64_decode($encodedKey, true);
        if (!is_string($key) || strlen($key) !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES) {
            throw new RuntimeException('VP3_LOCAL_BACKUP_ENCRYPTION_KEY_B64 must decode to exactly 32 bytes.');
        }
        $this->encryptionKey = $key;
        $this->mysqldumpBinary = $this->executable((string) ($configuration['mysqldump_binary'] ?? '/usr/bin/mysqldump'), 'VP3_MYSQLDUMP_BINARY');
        $this->mysqlBinary = $this->executable((string) ($configuration['mysql_binary'] ?? '/usr/bin/mysql'), 'VP3_MYSQL_BINARY');
        $this->databaseHost = trim((string) ($configuration['database_host'] ?? '127.0.0.1')) ?: '127.0.0.1';
        $this->databasePort = max(1, min(65535, (int) ($configuration['database_port'] ?? 3306)));
        $this->maximumBackupBytes = max(1048576, (int) ($configuration['maximum_backup_bytes'] ?? 5368709120));
        if (!class_exists(ZipArchive::class)) {
            throw new RuntimeException('The PHP zip extension is required for local POD backups.');
        }
    }

    public function createBackup(array $target, string $purpose): array
    {
        $deployment = $this->deploymentPath($target);
        if (!is_dir($deployment)) {
            throw new RuntimeException('The local POD deployment directory does not exist.');
        }
        $state = $this->databaseState($deployment);
        $this->ensureDirectory($this->backupRoot, 0700);
        $reference = 'pod-' . strtolower((string) $target['public_id']) . '-' . gmdate('YmdHis') . '-' . bin2hex(random_bytes(8)) . '.vp3bak';
        $finalPath = $this->referencePath($reference);
        $workspace = $this->backupRoot . '/.tmp-' . bin2hex(random_bytes(8));
        $this->ensureDirectory($workspace, 0700);
        $sqlPath = $workspace . '/database.sql';
        $zipPath = $workspace . '/snapshot.zip';

        try {
            $this->dumpDatabase($state, $sqlPath);
            $manifest = $this->createArchive($deployment, $sqlPath, $zipPath, $target, $purpose);
            if (filesize($zipPath) > $this->maximumBackupBytes) {
                throw new RuntimeException('The local POD backup exceeds the configured maximum size.');
            }
            $this->encryptFile($zipPath, $finalPath);
            chmod($finalPath, 0600);
            $snapshotHash = hash_file('sha256', $finalPath);
            if (!is_string($snapshotHash)) {
                throw new RuntimeException('Unable to calculate the encrypted backup hash.');
            }
            return [
                'reference' => $reference,
                'snapshot_hash' => $snapshotHash,
                'size_bytes' => (int) filesize($finalPath),
                'provider_request_id' => substr(hash('sha256', $reference . '|' . $manifest['created_at']), 0, 40),
                'storage_class' => 'local-encrypted',
            ];
        } catch (Throwable $exception) {
            @unlink($finalPath);
            throw $exception;
        } finally {
            $this->removeTree($workspace);
        }
    }

    public function verifyBackup(array $target, string $providerReference, string $snapshotHash): array
    {
        $path = $this->referencePath($providerReference);
        $this->assertSnapshot($path, $snapshotHash);
        $workspace = $this->backupRoot . '/.verify-' . bin2hex(random_bytes(8));
        $this->ensureDirectory($workspace, 0700);
        $zipPath = $workspace . '/snapshot.zip';
        try {
            $this->decryptFile($path, $zipPath);
            $manifest = $this->readManifest($zipPath);
            $this->assertManifestTarget($manifest, $target);
            $verificationHash = hash('sha256', $snapshotHash . '|verified|' . hash('sha256', $this->json($manifest)));
            return [
                'verified' => true,
                'verification_hash' => $verificationHash,
                'metadata' => [
                    'verified' => true,
                    'size_bytes' => (int) filesize($path),
                    'storage_class' => 'local-encrypted',
                ],
            ];
        } finally {
            $this->removeTree($workspace);
        }
    }

    public function restoreBackup(array $target, string $providerReference, string $snapshotHash): array
    {
        $path = $this->referencePath($providerReference);
        $this->assertSnapshot($path, $snapshotHash);
        $deployment = $this->deploymentPath($target);
        $workspace = $this->backupRoot . '/.restore-' . bin2hex(random_bytes(8));
        $extracted = $workspace . '/extracted';
        $zipPath = $workspace . '/snapshot.zip';
        $this->ensureDirectory($extracted, 0700);

        try {
            $this->decryptFile($path, $zipPath);
            $manifest = $this->readManifest($zipPath);
            $this->assertManifestTarget($manifest, $target);
            $this->extractArchive($zipPath, $extracted);
            $restoredDeployment = $extracted . '/deployment';
            $sqlPath = $extracted . '/database.sql';
            if (!is_dir($restoredDeployment) || !is_file($sqlPath)) {
                throw new RuntimeException('The decrypted POD backup is incomplete.');
            }
            $state = $this->databaseState($restoredDeployment);
            $this->restoreDatabase($state, $sqlPath);
            $this->restoreCurrentLink($restoredDeployment, $manifest);

            $prior = $deployment . '.restore-prior-' . bin2hex(random_bytes(6));
            if (is_dir($deployment) && !rename($deployment, $prior)) {
                throw new RuntimeException('Unable to preserve the current POD deployment before restore.');
            }
            try {
                if (!rename($restoredDeployment, $deployment)) {
                    throw new RuntimeException('Unable to activate the restored POD deployment.');
                }
                $this->removeTree($prior);
            } catch (Throwable $exception) {
                if (!is_dir($deployment) && is_dir($prior)) {
                    @rename($prior, $deployment);
                }
                throw $exception;
            }

            $verificationHash = hash('sha256', $snapshotHash . '|restored|' . (string) ($manifest['deployment_public_id'] ?? ''));
            return [
                'restored' => true,
                'verification_hash' => $verificationHash,
                'metadata' => ['restored' => true, 'storage_class' => 'local-encrypted'],
            ];
        } finally {
            $this->removeTree($workspace);
        }
    }

    public function deleteBackup(array $target, string $providerReference, string $snapshotHash): array
    {
        $path = $this->referencePath($providerReference);
        $this->assertSnapshot($path, $snapshotHash);
        if (!unlink($path)) {
            throw new RuntimeException('Unable to delete the encrypted local POD backup.');
        }
        return [
            'deleted' => true,
            'receipt_hash' => hash('sha256', $providerReference . '|' . $snapshotHash . '|deleted'),
        ];
    }

    /** @param array<string,mixed> $target @return array<string,mixed> */
    private function createArchive(string $deployment, string $sqlPath, string $zipPath, array $target, string $purpose): array
    {
        $currentTarget = null;
        $current = $deployment . '/current';
        if (is_link($current)) {
            $linked = readlink($current);
            if (is_string($linked) && $linked !== '') {
                $currentTarget = basename($linked);
            }
        }
        $manifest = [
            'format' => 1,
            'target_type' => 'pod',
            'deployment_public_id' => (string) $target['public_id'],
            'purpose' => substr(trim($purpose), 0, 80),
            'current_release' => $currentTarget,
            'created_at' => gmdate(DATE_ATOM),
        ];

        $zip = new ZipArchive();
        if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            throw new RuntimeException('Unable to create the local POD backup ZIP.');
        }
        try {
            $zip->addFromString('manifest.json', $this->json($manifest));
            if (!$zip->addFile($sqlPath, 'database.sql')) {
                throw new RuntimeException('Unable to add the tenant database dump to the backup ZIP.');
            }
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($deployment, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );
            foreach ($iterator as $item) {
                $path = $item->getPathname();
                $relative = ltrim(str_replace('\\', '/', substr($path, strlen($deployment))), '/');
                if ($relative === '' || $relative === 'current' || str_starts_with($relative, 'current/')) {
                    continue;
                }
                $archiveName = 'deployment/' . $relative;
                if ($item->isLink()) {
                    throw new RuntimeException('Unexpected symbolic link inside the POD deployment backup source.');
                }
                if ($item->isDir()) {
                    $zip->addEmptyDir($archiveName);
                } elseif (!$zip->addFile($path, $archiveName)) {
                    throw new RuntimeException('Unable to add a POD deployment file to the backup ZIP.');
                }
            }
        } finally {
            $zip->close();
        }
        return $manifest;
    }

    /** @return array<string,mixed> */
    private function readManifest(string $zipPath): array
    {
        $zip = new ZipArchive();
        if ($zip->open($zipPath) !== true) {
            throw new RuntimeException('Unable to open the decrypted POD backup ZIP.');
        }
        try {
            $manifestJson = $zip->getFromName('manifest.json');
            if (!is_string($manifestJson)) {
                throw new RuntimeException('The decrypted POD backup has no manifest.');
            }
            $manifest = json_decode($manifestJson, true, 32, JSON_THROW_ON_ERROR);
            if (!is_array($manifest) || ($manifest['format'] ?? null) !== 1 || ($manifest['target_type'] ?? '') !== 'pod') {
                throw new RuntimeException('The decrypted POD backup manifest is invalid.');
            }
            if ($zip->locateName('database.sql') === false) {
                throw new RuntimeException('The decrypted POD backup has no database dump.');
            }
            return $manifest;
        } finally {
            $zip->close();
        }
    }

    /** @param array<string,mixed> $manifest @param array<string,mixed> $target */
    private function assertManifestTarget(array $manifest, array $target): void
    {
        if (!hash_equals(strtolower((string) $target['public_id']), strtolower((string) ($manifest['deployment_public_id'] ?? '')))) {
            throw new RuntimeException('The encrypted backup belongs to another POD deployment.');
        }
    }

    private function extractArchive(string $zipPath, string $destination): void
    {
        $zip = new ZipArchive();
        if ($zip->open($zipPath) !== true) {
            throw new RuntimeException('Unable to open the decrypted POD backup ZIP for restore.');
        }
        try {
            for ($index = 0; $index < $zip->numFiles; $index++) {
                $stat = $zip->statIndex($index);
                if (!is_array($stat) || !isset($stat['name'])) {
                    throw new RuntimeException('Unable to inspect an encrypted backup ZIP entry.');
                }
                $name = $this->safeArchivePath((string) $stat['name']);
                if ($name === 'manifest.json') {
                    continue;
                }
                $target = $destination . '/' . rtrim($name, '/');
                if (!$this->isWithin($target, $destination)) {
                    throw new RuntimeException('An encrypted backup ZIP entry escapes the restore directory.');
                }
                if (str_ends_with($name, '/')) {
                    $this->ensureDirectory($target, 0700);
                    continue;
                }
                $this->ensureDirectory(dirname($target), 0700);
                $source = $zip->getStream((string) $stat['name']);
                if (!is_resource($source)) {
                    throw new RuntimeException('Unable to read an encrypted backup ZIP entry.');
                }
                $output = fopen($target, 'xb');
                if (!is_resource($output)) {
                    fclose($source);
                    throw new RuntimeException('Unable to create a restored POD file.');
                }
                try {
                    if (stream_copy_to_stream($source, $output) === false) {
                        throw new RuntimeException('Unable to restore a POD backup file.');
                    }
                } finally {
                    fclose($source);
                    fclose($output);
                }
                chmod($target, str_ends_with($name, '.json') || str_ends_with($name, '.php') ? 0600 : 0640);
            }
        } finally {
            $zip->close();
        }
    }

    /** @param array<string,mixed> $manifest */
    private function restoreCurrentLink(string $deployment, array $manifest): void
    {
        $release = trim((string) ($manifest['current_release'] ?? ''));
        if ($release === '' || !preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/', $release)) {
            throw new RuntimeException('The POD backup does not identify a valid active release.');
        }
        $target = $deployment . '/releases/' . $release;
        if (!is_dir($target)) {
            throw new RuntimeException('The active release identified by the POD backup is missing.');
        }
        if (!symlink($target, $deployment . '/current')) {
            throw new RuntimeException('Unable to restore the POD current-release link.');
        }
    }

    /** @param array<string,mixed> $state */
    private function dumpDatabase(array $state, string $destination): void
    {
        $command = [
            $this->mysqldumpBinary,
            '--host=' . $this->databaseHost,
            '--port=' . $this->databasePort,
            '--user=' . $state['database_username'],
            '--single-transaction',
            '--routines',
            '--triggers',
            '--events',
            '--hex-blob',
            '--default-character-set=utf8mb4',
            '--skip-comments',
            (string) $state['database_name'],
        ];
        $this->runDatabaseCommand($command, (string) $state['database_password'], null, $destination);
    }

    /** @param array<string,mixed> $state */
    private function restoreDatabase(array $state, string $source): void
    {
        $command = [
            $this->mysqlBinary,
            '--host=' . $this->databaseHost,
            '--port=' . $this->databasePort,
            '--user=' . $state['database_username'],
            '--default-character-set=utf8mb4',
            (string) $state['database_name'],
        ];
        $this->runDatabaseCommand($command, (string) $state['database_password'], $source, null);
    }

    /** @param list<string> $command */
    private function runDatabaseCommand(array $command, string $databasePassword, ?string $stdinPath, ?string $stdoutPath): void
    {
        $descriptors = [
            0 => $stdinPath === null ? ['file', '/dev/null', 'rb'] : ['file', $stdinPath, 'rb'],
            1 => $stdoutPath === null ? ['file', '/dev/null', 'wb'] : ['file', $stdoutPath, 'wb'],
            2 => ['pipe', 'w'],
        ];
        $environment = getenv();
        if (!is_array($environment)) {
            $environment = [];
        }
        $environment['MYSQL_PWD'] = $databasePassword;
        $process = proc_open($command, $descriptors, $pipes, null, $environment, ['bypass_shell' => true]);
        if (!is_resource($process)) {
            throw new RuntimeException('Unable to start the configured database backup command.');
        }
        $error = '';
        try {
            if (isset($pipes[2]) && is_resource($pipes[2])) {
                $error = stream_get_contents($pipes[2]) ?: '';
                fclose($pipes[2]);
            }
            $exitCode = proc_close($process);
        } catch (Throwable $exception) {
            proc_terminate($process);
            throw $exception;
        }
        if ($exitCode !== 0) {
            throw new RuntimeException('The database backup command failed: ' . substr(trim($error), 0, 300));
        }
    }

    private function encryptFile(string $source, string $destination): void
    {
        $input = fopen($source, 'rb');
        $output = fopen($destination, 'xb');
        if (!is_resource($input) || !is_resource($output)) {
            if (is_resource($input)) fclose($input);
            if (is_resource($output)) fclose($output);
            throw new RuntimeException('Unable to open local POD backup encryption streams.');
        }
        try {
            [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($this->encryptionKey);
            fwrite($output, $header);
            $remaining = filesize($source);
            if (!is_int($remaining) || $remaining < 1) {
                throw new RuntimeException('The local POD backup archive is empty.');
            }
            while ($remaining > 0) {
                $length = min(self::CHUNK_BYTES, $remaining);
                $chunk = fread($input, $length);
                if (!is_string($chunk) || strlen($chunk) !== $length) {
                    throw new RuntimeException('Unable to read the local POD backup archive for encryption.');
                }
                $remaining -= $length;
                $tag = $remaining === 0
                    ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL
                    : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
                fwrite($output, sodium_crypto_secretstream_xchacha20poly1305_push($state, $chunk, '', $tag));
            }
        } finally {
            fclose($input);
            fclose($output);
        }
    }

    private function decryptFile(string $source, string $destination): void
    {
        $input = fopen($source, 'rb');
        $output = fopen($destination, 'xb');
        if (!is_resource($input) || !is_resource($output)) {
            if (is_resource($input)) fclose($input);
            if (is_resource($output)) fclose($output);
            throw new RuntimeException('Unable to open local POD backup decryption streams.');
        }
        try {
            $header = fread($input, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);
            if (!is_string($header) || strlen($header) !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES) {
                throw new RuntimeException('The encrypted POD backup header is invalid.');
            }
            $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $this->encryptionKey);
            $remaining = filesize($source) - SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES;
            $sawFinal = false;
            while ($remaining > 0) {
                $length = min(self::CHUNK_BYTES + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES, $remaining);
                $ciphertext = fread($input, $length);
                if (!is_string($ciphertext) || strlen($ciphertext) !== $length) {
                    throw new RuntimeException('Unable to read the encrypted POD backup.');
                }
                $remaining -= $length;
                $pulled = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $ciphertext);
                if (!is_array($pulled) || count($pulled) !== 2) {
                    throw new RuntimeException('The encrypted POD backup failed authentication.');
                }
                [$plaintext, $tag] = $pulled;
                if ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
                    if ($remaining !== 0) {
                        throw new RuntimeException('The encrypted POD backup ended before the final chunk.');
                    }
                    $sawFinal = true;
                }
                fwrite($output, $plaintext);
            }
            if (!$sawFinal) {
                throw new RuntimeException('The encrypted POD backup is missing its final authentication tag.');
            }
        } finally {
            fclose($input);
            fclose($output);
        }
    }

    private function assertSnapshot(string $path, string $snapshotHash): void
    {
        $snapshotHash = strtolower(trim($snapshotHash));
        if (!preg_match('/^[a-f0-9]{64}$/', $snapshotHash) || !is_file($path)) {
            throw new RuntimeException('The encrypted local POD backup reference is invalid.');
        }
        $actual = hash_file('sha256', $path);
        if (!is_string($actual) || !hash_equals($snapshotHash, strtolower($actual))) {
            throw new RuntimeException('The encrypted local POD backup hash does not match.');
        }
    }

    /** @param array<string,mixed> $target */
    private function deploymentPath(array $target): string
    {
        if (($target['target_type'] ?? '') !== 'pod') {
            throw new RuntimeException('The local POD backup adapter does not copy private HomeServer data into VP3 hosting.');
        }
        $publicId = strtolower(trim((string) ($target['public_id'] ?? '')));
        if (!preg_match('/^pod-[a-z0-9]+$/', $publicId)) {
            throw new RuntimeException('The POD backup target public ID is invalid.');
        }
        return rtrim($this->deploymentRoot, '/') . '/' . $publicId;
    }

    /** @return array<string,mixed> */
    private function databaseState(string $deployment): array
    {
        $path = $deployment . '/shared/.vp3/database.json';
        if (!is_file($path)) {
            throw new RuntimeException('The POD database credential state is missing.');
        }
        $state = json_decode((string) file_get_contents($path), true);
        if (!is_array($state)) {
            throw new RuntimeException('The POD database credential state is invalid.');
        }
        foreach (['database_name', 'database_username', 'database_password'] as $key) {
            if (!isset($state[$key]) || !is_string($state[$key]) || $state[$key] === '') {
                throw new RuntimeException('The POD database credential state is incomplete.');
            }
        }
        return $state;
    }

    private function referencePath(string $reference): string
    {
        if (!preg_match('/^pod-pod-[a-z0-9]+-[0-9]{14}-[a-f0-9]{16}\.vp3bak$/', $reference)) {
            throw new RuntimeException('The encrypted local POD backup reference is unsafe.');
        }
        return rtrim($this->backupRoot, '/') . '/' . $reference;
    }

    private function safeArchivePath(string $name): string
    {
        $name = str_replace('\\', '/', $name);
        if ($name === '' || str_contains($name, "\0") || str_starts_with($name, '/') || preg_match('/^[A-Za-z]:\//', $name)) {
            throw new RuntimeException('The encrypted backup contains an unsafe path.');
        }
        foreach (explode('/', trim($name, '/')) as $segment) {
            if ($segment === '.' || $segment === '..') {
                throw new RuntimeException('The encrypted backup contains a traversal path.');
            }
        }
        return $name;
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

    private function ensureDirectory(string $path, int $permissions): void
    {
        if (!is_dir($path) && !mkdir($path, $permissions, true) && !is_dir($path)) {
            throw new RuntimeException('Unable to create a local POD backup directory.');
        }
        chmod($path, $permissions);
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

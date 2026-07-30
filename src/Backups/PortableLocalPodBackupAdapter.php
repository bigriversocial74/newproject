<?php

declare(strict_types=1);

namespace Vp3\Backups;

use RuntimeException;

final class PortableLocalPodBackupAdapter implements BackupProviderAdapter
{
    private SymlinkAwareLocalPodBackupAdapter $inner;
    private DatabaseSchemaResetter $databaseSchemaResetter;
    private string $deploymentRoot;
    private string $configurationPath;

    /** @param array<string,mixed> $configuration */
    public function __construct(array $configuration)
    {
        $backupRoot = (string) ($configuration['backup_root'] ?? '');
        $configuredDumpBinary = (string) ($configuration['mysqldump_binary'] ?? '/usr/bin/mysqldump');
        $configuration['mysqldump_binary'] = DatabaseDumpBinaryResolver::resolve($configuredDumpBinary, $backupRoot);
        $this->inner = new SymlinkAwareLocalPodBackupAdapter($configuration);
        $this->deploymentRoot = $this->absolutePath((string) ($configuration['deployment_root'] ?? ''));
        $this->configurationPath = $this->relativePath((string) ($configuration['configuration_path'] ?? 'config/config.php'));
        $this->databaseSchemaResetter = new DatabaseSchemaResetter(
            trim((string) ($configuration['database_host'] ?? '127.0.0.1')) ?: '127.0.0.1',
            max(1, min(65535, (int) ($configuration['database_port'] ?? 3306)))
        );
    }

    public function createBackup(array $target, string $purpose): array
    {
        return $this->inner->createBackup($target, $purpose);
    }

    public function verifyBackup(array $target, string $providerReference, string $snapshotHash): array
    {
        return $this->inner->verifyBackup($target, $providerReference, $snapshotHash);
    }

    public function restoreBackup(array $target, string $providerReference, string $snapshotHash): array
    {
        $verification = $this->inner->verifyBackup($target, $providerReference, $snapshotHash);
        if (($verification['verified'] ?? false) !== true) {
            throw new RuntimeException('The encrypted POD backup was not verified before restore.');
        }

        $deployment = $this->deploymentPath($target);
        $this->databaseSchemaResetter->reset($this->databaseState($deployment));
        $result = $this->inner->restoreBackup($target, $providerReference, $snapshotHash);

        $current = $deployment . '/current';
        if (!is_link($current)) {
            throw new RuntimeException('The restored POD current-release link is missing.');
        }
        $priorTarget = readlink($current);
        if (!is_string($priorTarget) || $priorTarget === '') {
            throw new RuntimeException('The restored POD current-release link cannot be read.');
        }
        $releaseName = basename($priorTarget);
        if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/', $releaseName)) {
            throw new RuntimeException('The restored POD release name is invalid.');
        }
        $releaseTarget = $deployment . '/releases/' . $releaseName;
        if (!is_dir($releaseTarget)) {
            throw new RuntimeException('The restored POD active release directory is missing.');
        }
        unlink($current);
        if (!symlink($releaseTarget, $current)) {
            throw new RuntimeException('Unable to rewrite the restored POD current-release link.');
        }

        $sharedConfiguration = $deployment . '/shared/config/' . basename($this->configurationPath);
        $releaseConfiguration = $current . '/' . $this->configurationPath;
        if (!is_file($sharedConfiguration) || !is_dir(dirname($releaseConfiguration))) {
            throw new RuntimeException('The restored POD shared configuration structure is incomplete.');
        }
        if ((is_file($releaseConfiguration) || is_link($releaseConfiguration)) && !unlink($releaseConfiguration)) {
            throw new RuntimeException('Unable to remove the relocated POD configuration link.');
        }
        if (!symlink($sharedConfiguration, $releaseConfiguration)) {
            throw new RuntimeException('Unable to rewrite the restored POD shared-configuration link.');
        }
        if (!is_file($releaseConfiguration)) {
            throw new RuntimeException('The rewritten POD shared-configuration link is not readable.');
        }

        return $result + [
            'portable_links_verified' => true,
            'database_schema_reset' => true,
        ];
    }

    public function deleteBackup(array $target, string $providerReference, string $snapshotHash): array
    {
        return $this->inner->deleteBackup($target, $providerReference, $snapshotHash);
    }

    /** @param array<string,mixed> $target */
    private function deploymentPath(array $target): string
    {
        if (($target['target_type'] ?? '') !== 'pod') {
            throw new RuntimeException('The hosted backup adapter does not restore private HomeServer content.');
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
            throw new RuntimeException('The active POD database credential state is missing before restore.');
        }
        $state = json_decode((string) file_get_contents($path), true);
        if (!is_array($state)) {
            throw new RuntimeException('The active POD database credential state is invalid before restore.');
        }
        foreach (['database_name', 'database_username', 'database_password'] as $key) {
            if (!isset($state[$key]) || !is_string($state[$key]) || $state[$key] === '') {
                throw new RuntimeException('The active POD database credential state is incomplete before restore.');
            }
        }
        return $state;
    }

    private function absolutePath(string $path): string
    {
        $path = trim($path);
        if ($path === '' || (!str_starts_with($path, '/') && !preg_match('/^[A-Za-z]:[\\\\\/]/', $path))) {
            throw new RuntimeException('The POD deployment root must be an absolute path.');
        }
        return rtrim(str_replace('\\', '/', $path), '/');
    }

    private function relativePath(string $path): string
    {
        $path = trim(str_replace('\\', '/', $path), '/');
        if ($path === '') {
            throw new RuntimeException('The POD configuration path cannot be empty.');
        }
        foreach (explode('/', $path) as $segment) {
            if ($segment === '' || $segment === '.' || $segment === '..') {
                throw new RuntimeException('The POD configuration path is unsafe.');
            }
        }
        return $path;
    }
}

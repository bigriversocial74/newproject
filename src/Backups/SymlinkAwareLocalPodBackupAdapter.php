<?php

declare(strict_types=1);

namespace Vp3\Backups;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use Throwable;

final class SymlinkAwareLocalPodBackupAdapter implements BackupProviderAdapter
{
    private string $deploymentRoot;
    private string $configurationPath;

    /** @param array<string,mixed> $configuration */
    public function __construct(private readonly array $configuration)
    {
        $this->deploymentRoot = $this->absolutePath((string) ($configuration['deployment_root'] ?? ''));
        $this->configurationPath = $this->relativePath((string) ($configuration['configuration_path'] ?? 'config/config.php'));
    }

    public function createBackup(array $target, string $purpose): array
    {
        $workspace = $this->workspace();
        try {
            $this->copyForBackup($this->actualDeployment($target), $workspace . '/' . $this->publicId($target));
            return $this->inner($workspace)->createBackup($target, $purpose);
        } finally {
            $this->removeTree($workspace);
        }
    }

    public function verifyBackup(array $target, string $providerReference, string $snapshotHash): array
    {
        $workspace = $this->workspace();
        try {
            return $this->inner($workspace)->verifyBackup($target, $providerReference, $snapshotHash);
        } finally {
            $this->removeTree($workspace);
        }
    }

    public function restoreBackup(array $target, string $providerReference, string $snapshotHash): array
    {
        $workspace = $this->workspace();
        $publicId = $this->publicId($target);
        try {
            $result = $this->inner($workspace)->restoreBackup($target, $providerReference, $snapshotHash);
            $restored = $workspace . '/' . $publicId;
            if (!is_dir($restored)) {
                throw new RuntimeException('The local backup engine did not produce a restored POD deployment.');
            }
            $this->relocateCurrentLink($restored);
            $this->restoreConfigurationLink($restored);
            $actual = $this->actualDeployment($target);
            $prior = $actual . '.backup-restore-prior-' . bin2hex(random_bytes(6));
            if (is_dir($actual) && !rename($actual, $prior)) {
                throw new RuntimeException('Unable to preserve the current POD before activating the restored backup.');
            }
            try {
                if (!rename($restored, $actual)) {
                    throw new RuntimeException('Unable to activate the restored POD backup on the deployment filesystem.');
                }
                $this->removeTree($prior);
            } catch (Throwable $exception) {
                if (!is_dir($actual) && is_dir($prior)) {
                    @rename($prior, $actual);
                }
                throw $exception;
            }
            return $result;
        } finally {
            $this->removeTree($workspace);
        }
    }

    public function deleteBackup(array $target, string $providerReference, string $snapshotHash): array
    {
        $workspace = $this->workspace();
        try {
            return $this->inner($workspace)->deleteBackup($target, $providerReference, $snapshotHash);
        } finally {
            $this->removeTree($workspace);
        }
    }

    private function inner(string $workspace): LocalPodBackupAdapter
    {
        return new LocalPodBackupAdapter(array_replace($this->configuration, ['deployment_root' => $workspace]));
    }

    private function workspace(): string
    {
        $workspace = rtrim($this->deploymentRoot, '/') . '/.vp3-backup-work-' . bin2hex(random_bytes(8));
        if (!mkdir($workspace, 0700, true) && !is_dir($workspace)) {
            throw new RuntimeException('Unable to create the POD backup normalization workspace.');
        }
        return $workspace;
    }

    private function copyForBackup(string $source, string $destination): void
    {
        if (!is_dir($source)) {
            throw new RuntimeException('The POD deployment does not exist for backup normalization.');
        }
        if (!mkdir($destination, 0700, true) && !is_dir($destination)) {
            throw new RuntimeException('Unable to create the normalized POD backup source.');
        }
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($source, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($iterator as $item) {
            $path = $item->getPathname();
            $relative = ltrim(str_replace('\\', '/', substr($path, strlen($source))), '/');
            $target = $destination . '/' . $relative;
            if ($item->isLink()) {
                $linked = readlink($path);
                if (!is_string($linked) || $linked === '') {
                    throw new RuntimeException('Unable to inspect a POD deployment symbolic link.');
                }
                if ($relative === 'current') {
                    if (!symlink($linked, $target)) {
                        throw new RuntimeException('Unable to normalize the POD current-release link.');
                    }
                    continue;
                }
                if (str_ends_with($relative, '/' . $this->configurationPath) || $relative === $this->configurationPath) {
                    $content = file_get_contents($path);
                    if (!is_string($content)) {
                        throw new RuntimeException('Unable to normalize the shared POD configuration link.');
                    }
                    $this->ensureDirectory(dirname($target), 0700);
                    if (file_put_contents($target, $content, LOCK_EX) !== strlen($content)) {
                        throw new RuntimeException('Unable to copy the shared POD configuration into the encrypted backup source.');
                    }
                    chmod($target, 0600);
                    continue;
                }
                throw new RuntimeException('An unsupported symbolic link exists inside the POD deployment.');
            }
            if ($item->isDir()) {
                $this->ensureDirectory($target, 0700);
            } elseif ($item->isFile()) {
                $this->ensureDirectory(dirname($target), 0700);
                if (!copy($path, $target)) {
                    throw new RuntimeException('Unable to copy a POD deployment file into the encrypted backup source.');
                }
                chmod($target, 0600);
            }
        }
    }

    private function relocateCurrentLink(string $deployment): void
    {
        $current = $deployment . '/current';
        if (!is_link($current)) {
            throw new RuntimeException('The restored POD current-release link is missing before relocation.');
        }
        $linked = readlink($current);
        if (!is_string($linked) || $linked === '') {
            throw new RuntimeException('The restored POD current-release link cannot be read before relocation.');
        }
        $releaseName = basename($linked);
        if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/', $releaseName)) {
            throw new RuntimeException('The restored POD current-release name is invalid.');
        }
        $release = $deployment . '/releases/' . $releaseName;
        if (!is_dir($release)) {
            throw new RuntimeException('The restored POD current-release directory is missing.');
        }
        unlink($current);
        if (!symlink($release, $current)) {
            throw new RuntimeException('Unable to relocate the restored POD current-release link.');
        }
    }

    private function restoreConfigurationLink(string $deployment): void
    {
        $current = $deployment . '/current';
        $shared = $deployment . '/shared/config/' . basename($this->configurationPath);
        $releaseConfiguration = $current . '/' . $this->configurationPath;
        if (!is_file($shared) || !is_dir(dirname($releaseConfiguration))) {
            throw new RuntimeException('The restored POD backup does not contain its shared configuration structure.');
        }
        if ((is_file($releaseConfiguration) || is_link($releaseConfiguration)) && !unlink($releaseConfiguration)) {
            throw new RuntimeException('Unable to replace the restored release configuration.');
        }
        if (!symlink($shared, $releaseConfiguration)) {
            throw new RuntimeException('Unable to restore the active release shared-configuration link.');
        }
    }

    /** @param array<string,mixed> $target */
    private function actualDeployment(array $target): string
    {
        return rtrim($this->deploymentRoot, '/') . '/' . $this->publicId($target);
    }

    /** @param array<string,mixed> $target */
    private function publicId(array $target): string
    {
        if (($target['target_type'] ?? '') !== 'pod') {
            throw new RuntimeException('VP3 does not copy private HomeServer data into the hosted POD backup adapter.');
        }
        $publicId = strtolower(trim((string) ($target['public_id'] ?? '')));
        if (!preg_match('/^pod-[a-z0-9]+$/', $publicId)) {
            throw new RuntimeException('The POD backup target public ID is invalid.');
        }
        return $publicId;
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

    private function ensureDirectory(string $path, int $permissions): void
    {
        if (!is_dir($path) && !mkdir($path, $permissions, true) && !is_dir($path)) {
            throw new RuntimeException('Unable to create a POD backup normalization directory.');
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
}

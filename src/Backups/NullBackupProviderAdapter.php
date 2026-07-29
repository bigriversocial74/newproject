<?php

declare(strict_types=1);

namespace Vp3\Backups;

use RuntimeException;

final class NullBackupProviderAdapter implements BackupProviderAdapter
{
    public function createBackup(array $target, string $purpose): array
    {
        throw new RuntimeException('No backup provider is configured to create a backup.');
    }

    public function verifyBackup(array $target, string $providerReference, string $snapshotHash): array
    {
        throw new RuntimeException('No backup provider is configured to verify a backup.');
    }

    public function restoreBackup(array $target, string $providerReference, string $snapshotHash): array
    {
        throw new RuntimeException('No backup provider is configured to restore a backup.');
    }

    public function deleteBackup(array $target, string $providerReference, string $snapshotHash): array
    {
        throw new RuntimeException('No backup provider is configured to delete a backup.');
    }
}

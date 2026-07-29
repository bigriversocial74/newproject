<?php

declare(strict_types=1);

namespace Vp3\Backups;

interface BackupProviderAdapter
{
    /** @param array<string,mixed> $target @return array{reference:string,snapshot_hash:string,size_bytes:int} */
    public function createBackup(array $target, string $purpose): array;

    /** @param array<string,mixed> $target @return array{verified:bool,verification_hash:string,metadata?:array<string,mixed>} */
    public function verifyBackup(array $target, string $providerReference, string $snapshotHash): array;

    /** @param array<string,mixed> $target @return array{restored:bool,verification_hash:string,metadata?:array<string,mixed>} */
    public function restoreBackup(array $target, string $providerReference, string $snapshotHash): array;

    /** @param array<string,mixed> $target @return array{deleted:bool,receipt_hash:string} */
    public function deleteBackup(array $target, string $providerReference, string $snapshotHash): array;
}

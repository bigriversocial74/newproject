<?php

declare(strict_types=1);

namespace Vp3\Updates;

interface SoftwareUpdateAdapter
{
    /** @param array<string,mixed> $target @param array<string,mixed> $release @return array{reference:string,hash:string,verified:bool} */
    public function createPreUpdateBackup(array $target, array $release): array;

    /** @param array<string,mixed> $target @param array<string,mixed> $release @param array<string,mixed> $job @return array<string,mixed> */
    public function executeStage(string $stage, array $target, array $release, array $job): array;

    /** @param array<string,mixed> $target @param array<string,mixed> $release @param array<string,mixed> $job @return array<string,mixed> */
    public function rollback(array $target, array $release, array $job): array;
}

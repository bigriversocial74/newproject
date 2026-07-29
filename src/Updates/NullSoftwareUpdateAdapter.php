<?php

declare(strict_types=1);

namespace Vp3\Updates;

use RuntimeException;

final class NullSoftwareUpdateAdapter implements SoftwareUpdateAdapter
{
    public function createPreUpdateBackup(array $target, array $release): array
    {
        throw new RuntimeException('No software update provider is configured to create a pre-update backup.');
    }

    public function executeStage(string $stage, array $target, array $release, array $job): array
    {
        throw new RuntimeException('No software update provider is configured for stage ' . $stage . '.');
    }

    public function rollback(array $target, array $release, array $job): array
    {
        throw new RuntimeException('No software update provider is configured for rollback.');
    }
}

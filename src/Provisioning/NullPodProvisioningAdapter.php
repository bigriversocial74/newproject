<?php

declare(strict_types=1);

namespace Vp3\Provisioning;

use RuntimeException;

final class NullPodProvisioningAdapter implements PodProvisioningAdapter
{
    public function executeStage(string $stage, array $deployment): array
    {
        throw new RuntimeException('No POD provisioning provider is configured for stage ' . $stage . '.');
    }

    public function rollbackStage(string $stage, array $deployment): array
    {
        throw new RuntimeException('No POD provisioning provider is configured for rollback stage ' . $stage . '.');
    }

    public function readConfiguration(array $deployment): array
    {
        throw new RuntimeException('No POD provisioning provider is configured to read configuration.');
    }

    public function buildConfiguration(array $deployment): array
    {
        throw new RuntimeException('No POD provisioning provider is configured to build configuration.');
    }

    public function writeConfiguration(array $deployment, array $configuration): array
    {
        throw new RuntimeException('No POD provisioning provider is configured to write configuration.');
    }
}

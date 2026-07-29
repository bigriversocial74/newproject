<?php

declare(strict_types=1);

namespace Vp3\Provisioning;

interface PodProvisioningAdapter
{
    /** @param array<string,mixed> $deployment @return array<string,mixed> */
    public function executeStage(string $stage, array $deployment): array;

    /** @param array<string,mixed> $deployment @return array<string,mixed> */
    public function rollbackStage(string $stage, array $deployment): array;

    /** @param array<string,mixed> $deployment @return array<string,mixed> */
    public function readConfiguration(array $deployment): array;

    /** @param array<string,mixed> $deployment @return array<string,mixed> */
    public function buildConfiguration(array $deployment): array;

    /** @param array<string,mixed> $deployment @param array<string,mixed> $configuration @return array<string,mixed> */
    public function writeConfiguration(array $deployment, array $configuration): array;
}

<?php

declare(strict_types=1);

namespace Vp3\Infrastructure;

interface HostingProviderAdapter
{
    /** @param array<string,mixed> $authContext @param array<string,mixed> $deployment @return array<string,mixed> */
    public function allocateHosting(array $authContext, array $deployment): array;

    /** @param array<string,mixed> $authContext @return array<string,mixed> */
    public function verifyHosting(array $authContext, string $providerReference): array;

    /** @param array<string,mixed> $authContext @return array<string,mixed> */
    public function releaseHosting(array $authContext, string $providerReference): array;
}

<?php

declare(strict_types=1);

namespace Vp3\Infrastructure;

use RuntimeException;

final class NullInfrastructureProviderAdapter implements HostingProviderAdapter, DnsProviderAdapter, CertificateProviderAdapter
{
    public function allocateHosting(array $authContext, array $deployment): array
    {
        throw new RuntimeException('No hosting provider adapter is configured.');
    }

    public function verifyHosting(array $authContext, string $providerReference): array
    {
        throw new RuntimeException('No hosting provider adapter is configured for verification.');
    }

    public function releaseHosting(array $authContext, string $providerReference): array
    {
        throw new RuntimeException('No hosting provider adapter is configured for release.');
    }

    public function upsertRecord(array $authContext, string $hostname, string $recordType, string $recordValue): array
    {
        throw new RuntimeException('No DNS provider adapter is configured.');
    }

    public function verifyRecord(array $authContext, string $providerReference, string $hostname, string $recordType, string $recordValue): array
    {
        throw new RuntimeException('No DNS provider adapter is configured for verification.');
    }

    public function removeRecord(array $authContext, string $providerReference): array
    {
        throw new RuntimeException('No DNS provider adapter is configured for removal.');
    }

    public function requestCertificate(array $authContext, string $hostname): array
    {
        throw new RuntimeException('No certificate provider adapter is configured.');
    }

    public function verifyCertificate(array $authContext, string $providerReference, string $hostname): array
    {
        throw new RuntimeException('No certificate provider adapter is configured for verification.');
    }

    public function revokeCertificate(array $authContext, string $providerReference): array
    {
        throw new RuntimeException('No certificate provider adapter is configured for revocation.');
    }
}

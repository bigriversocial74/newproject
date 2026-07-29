<?php

declare(strict_types=1);

namespace Vp3\Infrastructure;

interface CertificateProviderAdapter
{
    /** @param array<string,mixed> $authContext @return array<string,mixed> */
    public function requestCertificate(array $authContext, string $hostname): array;

    /** @param array<string,mixed> $authContext @return array<string,mixed> */
    public function verifyCertificate(array $authContext, string $providerReference, string $hostname): array;

    /** @param array<string,mixed> $authContext @return array<string,mixed> */
    public function revokeCertificate(array $authContext, string $providerReference): array;
}

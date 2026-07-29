<?php

declare(strict_types=1);

namespace Vp3\Infrastructure;

interface DnsProviderAdapter
{
    /** @param array<string,mixed> $authContext @return array<string,mixed> */
    public function upsertRecord(array $authContext, string $hostname, string $recordType, string $recordValue): array;

    /** @param array<string,mixed> $authContext @return array<string,mixed> */
    public function verifyRecord(array $authContext, string $providerReference, string $hostname, string $recordType, string $recordValue): array;

    /** @param array<string,mixed> $authContext @return array<string,mixed> */
    public function removeRecord(array $authContext, string $providerReference): array;
}

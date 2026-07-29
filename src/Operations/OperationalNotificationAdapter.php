<?php

declare(strict_types=1);

namespace Vp3\Operations;

interface OperationalNotificationAdapter
{
    /** @param array<string,mixed> $destination @param array<string,mixed> $payload @return array<string,mixed> */
    public function deliver(array $destination, array $payload): array;
}

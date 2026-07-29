<?php

declare(strict_types=1);

namespace Vp3\Operations;

use RuntimeException;

final class NullOperationalNotificationAdapter implements OperationalNotificationAdapter
{
    public function deliver(array $destination, array $payload): array
    {
        throw new RuntimeException('No operational notification adapter is configured.');
    }
}

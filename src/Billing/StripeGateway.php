<?php

declare(strict_types=1);

namespace Vp3\Billing;

interface StripeGateway
{
    /** @param array<string,mixed> $parameters @return array<string,mixed> */
    public function createCheckoutSession(array $parameters, string $idempotencyKey): array;

    /** @param array<string,mixed> $parameters @return array<string,mixed> */
    public function createPortalSession(array $parameters, string $idempotencyKey): array;
}

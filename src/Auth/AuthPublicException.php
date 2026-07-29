<?php

declare(strict_types=1);

namespace Vp3\Auth;

use RuntimeException;

final class AuthPublicException extends RuntimeException
{
    public function __construct(
        private readonly string $publicCode,
        private readonly string $publicMessage,
        private readonly int $httpStatus = 422
    ) {
        parent::__construct($publicMessage);
    }

    public function publicCode(): string
    {
        return $this->publicCode;
    }

    public function publicMessage(): string
    {
        return $this->publicMessage;
    }

    public function httpStatus(): int
    {
        return $this->httpStatus;
    }
}

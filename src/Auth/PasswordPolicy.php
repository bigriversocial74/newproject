<?php

declare(strict_types=1);

namespace Vp3\Auth;

use InvalidArgumentException;

final class PasswordPolicy
{
    public function __construct(private readonly int $minimumLength = 12)
    {
    }

    public function assertValid(string $password): void
    {
        $errors = [];

        if (mb_strlen($password) < $this->minimumLength) {
            $errors[] = sprintf('Password must be at least %d characters.', $this->minimumLength);
        }
        if (!preg_match('/[a-z]/', $password)) {
            $errors[] = 'Password must contain a lowercase letter.';
        }
        if (!preg_match('/[A-Z]/', $password)) {
            $errors[] = 'Password must contain an uppercase letter.';
        }
        if (!preg_match('/\d/', $password)) {
            $errors[] = 'Password must contain a number.';
        }

        if ($errors !== []) {
            throw new InvalidArgumentException(implode(' ', $errors));
        }
    }
}

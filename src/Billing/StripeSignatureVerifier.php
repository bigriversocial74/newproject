<?php

declare(strict_types=1);

namespace Vp3\Billing;

use InvalidArgumentException;
use RuntimeException;

final class StripeSignatureVerifier
{
    public function __construct(
        private readonly string $webhookSecret,
        private readonly int $toleranceSeconds = 300
    ) {
    }

    /** @return array<string,mixed> */
    public function verifyAndDecode(string $payload, string $signatureHeader, ?int $now = null): array
    {
        if ($this->webhookSecret === '') {
            throw new RuntimeException('Stripe webhook secret is not configured.');
        }
        if ($payload === '' || trim($signatureHeader) === '') {
            throw new InvalidArgumentException('Stripe webhook payload and signature are required.');
        }

        $timestamp = null;
        $signatures = [];
        foreach (explode(',', $signatureHeader) as $part) {
            [$key, $value] = array_pad(explode('=', trim($part), 2), 2, null);
            if ($key === 't' && is_string($value) && ctype_digit($value)) {
                $timestamp = (int) $value;
            }
            if ($key === 'v1' && is_string($value) && preg_match('/^[a-f0-9]{64}$/i', $value) === 1) {
                $signatures[] = strtolower($value);
            }
        }
        if ($timestamp === null || $signatures === []) {
            throw new RuntimeException('Stripe webhook signature header is malformed.');
        }

        $clock = $now ?? time();
        if (abs($clock - $timestamp) > $this->toleranceSeconds) {
            throw new RuntimeException('Stripe webhook signature timestamp is outside the allowed tolerance.');
        }

        $expected = hash_hmac('sha256', $timestamp . '.' . $payload, $this->webhookSecret);
        $valid = false;
        foreach ($signatures as $signature) {
            $valid = hash_equals($expected, $signature) || $valid;
        }
        if (!$valid) {
            throw new RuntimeException('Stripe webhook signature is invalid.');
        }

        $event = json_decode($payload, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($event) || !is_string($event['id'] ?? null) || !is_string($event['type'] ?? null)) {
            throw new RuntimeException('Stripe webhook event envelope is invalid.');
        }
        return $event;
    }
}

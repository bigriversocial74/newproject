<?php

declare(strict_types=1);

namespace Vp3\Billing;

use RuntimeException;

final class StripeApiClient implements StripeGateway
{
    public function __construct(
        private readonly string $secretKey,
        private readonly string $apiBase = 'https://api.stripe.com/v1',
        private readonly int $timeoutSeconds = 20
    ) {
    }

    public function createCheckoutSession(array $parameters, string $idempotencyKey): array
    {
        return $this->post('/checkout/sessions', $parameters, $idempotencyKey);
    }

    public function createPortalSession(array $parameters, string $idempotencyKey): array
    {
        return $this->post('/billing_portal/sessions', $parameters, $idempotencyKey);
    }

    /** @param array<string,mixed> $parameters @return array<string,mixed> */
    private function post(string $path, array $parameters, string $idempotencyKey): array
    {
        if ($this->secretKey === '') {
            throw new RuntimeException('Stripe secret key is not configured.');
        }
        if ($idempotencyKey === '') {
            throw new RuntimeException('Stripe idempotency key is required.');
        }

        $body = http_build_query($this->flatten($parameters), '', '&', PHP_QUERY_RFC3986);
        $headers = [
            'Authorization: Bearer ' . $this->secretKey,
            'Content-Type: application/x-www-form-urlencoded',
            'Idempotency-Key: ' . $idempotencyKey,
            'User-Agent: VP3.me/1.0',
        ];

        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => implode("\r\n", $headers),
                'content' => $body,
                'timeout' => $this->timeoutSeconds,
                'ignore_errors' => true,
            ],
        ]);
        $response = @file_get_contents(rtrim($this->apiBase, '/') . $path, false, $context);
        if ($response === false) {
            throw new RuntimeException('Stripe API request failed.');
        }

        $statusCode = $this->statusCode($http_response_header ?? []);
        $decoded = json_decode($response, true);
        if (!is_array($decoded)) {
            throw new RuntimeException('Stripe API returned invalid JSON.');
        }
        if ($statusCode < 200 || $statusCode >= 300) {
            $message = $decoded['error']['message'] ?? 'Stripe API rejected the request.';
            throw new RuntimeException(is_string($message) ? $message : 'Stripe API rejected the request.');
        }

        return $decoded;
    }

    /** @param array<string,mixed> $input @return array<string,scalar|null> */
    private function flatten(array $input, string $prefix = ''): array
    {
        $output = [];
        foreach ($input as $key => $value) {
            $name = $prefix === '' ? (string) $key : $prefix . '[' . $key . ']';
            if (is_array($value)) {
                $output += $this->flatten($value, $name);
                continue;
            }
            if (is_bool($value)) {
                $output[$name] = $value ? 'true' : 'false';
                continue;
            }
            if ($value === null || is_scalar($value)) {
                $output[$name] = $value;
            }
        }
        return $output;
    }

    /** @param list<string> $headers */
    private function statusCode(array $headers): int
    {
        foreach ($headers as $header) {
            if (preg_match('/^HTTP\/\S+\s+(\d{3})/', $header, $matches) === 1) {
                return (int) $matches[1];
            }
        }
        return 0;
    }
}

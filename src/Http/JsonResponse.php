<?php

declare(strict_types=1);

namespace Vp3\Http;

final class JsonResponse
{
    /** @param array<string,mixed> $payload */
    public static function send(array $payload, int $status = 200): never
    {
        if (PublicResponseGuard::enabled()) {
            $payload = PublicResponseGuard::sanitize($payload);
            PublicResponseGuard::assertSafe($payload);
        }

        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        echo json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        exit;
    }
}

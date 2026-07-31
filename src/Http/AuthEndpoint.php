<?php

declare(strict_types=1);

namespace Vp3\Http;

use InvalidArgumentException;
use JsonException;
use RuntimeException;
use Throwable;
use Vp3\Auth\AuthPublicException;

final class AuthEndpoint
{
    private static ?AuthRequestIntegrity $requestIntegrity = null;

    public static function configureRequestIntegrity(AuthRequestIntegrity $requestIntegrity): void
    {
        self::$requestIntegrity = $requestIntegrity;
    }

    public static function requireMethod(string $method): void
    {
        PublicResponseGuard::enable();
        if (strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')) !== strtoupper($method)) {
            JsonResponse::send(['error' => ['code' => 'method_not_allowed', 'message' => $method . ' required.']], 405);
        }
        if (self::$requestIntegrity === null) {
            JsonResponse::send([
                'error' => [
                    'code' => 'request_integrity_unavailable',
                    'message' => 'Request validation is temporarily unavailable.',
                ],
            ], 503);
        }
        try {
            self::$requestIntegrity->assertTrusted($_SERVER);
        } catch (Throwable $exception) {
            self::sendException($exception);
        }
    }

    /** @return array<string,mixed> */
    public static function payload(): array
    {
        try {
            $payload = json_decode((string) file_get_contents('php://input'), true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new AuthPublicException('invalid_json', 'The request body is not valid JSON.', 400);
        }
        if (!is_array($payload)) {
            throw new AuthPublicException('invalid_json', 'The request body is not valid JSON.', 400);
        }
        return $payload;
    }

    /** @param array<string,mixed> $payload */
    public static function csrf(array $payload): string
    {
        $header = (string) ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
        return $header !== '' ? $header : (string) ($payload['csrf_token'] ?? '');
    }

    public static function ip(): string
    {
        return (string) ($_SERVER['REMOTE_ADDR'] ?? '');
    }

    public static function userAgent(): string
    {
        return (string) ($_SERVER['HTTP_USER_AGENT'] ?? '');
    }

    public static function sendException(Throwable $exception): never
    {
        if ($exception instanceof AuthPublicException) {
            JsonResponse::send([
                'error' => [
                    'code' => $exception->publicCode(),
                    'message' => $exception->publicMessage(),
                ],
            ], $exception->httpStatus());
        }
        if ($exception instanceof InvalidArgumentException) {
            JsonResponse::send(['error' => ['code' => 'validation_failed', 'message' => 'The supplied information is invalid.']], 422);
        }
        if ($exception instanceof RuntimeException && $exception->getMessage() === 'Invalid CSRF token.') {
            JsonResponse::send(['error' => ['code' => 'csrf_rejected', 'message' => 'The security token is invalid or expired.']], 403);
        }
        JsonResponse::send(['error' => ['code' => 'request_failed', 'message' => 'Unable to complete the request.']], 500);
    }
}

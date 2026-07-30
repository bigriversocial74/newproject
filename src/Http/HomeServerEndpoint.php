<?php

declare(strict_types=1);

namespace Vp3\Http;

use JsonException;
use RuntimeException;
use Throwable;
use Vp3\Auth\AuthPublicException;
use Vp3\ControlCenter\PublicAccountIdentityResolver;

final class HomeServerEndpoint
{
    public const MAX_JSON_BYTES = 65536;

    public static function requireMethod(string $method): void
    {
        if (strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')) !== strtoupper($method)) {
            JsonResponse::send(['error' => ['code' => 'method_not_allowed', 'message' => $method . ' required.']], 405);
        }
    }

    /** @return array<string,mixed> */
    public static function payload(): array
    {
        $length = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
        if ($length > self::MAX_JSON_BYTES) {
            JsonResponse::send(['error' => ['code' => 'request_too_large', 'message' => 'The request body is too large.']], 413);
        }
        $body = (string) file_get_contents('php://input', false, null, 0, self::MAX_JSON_BYTES + 1);
        if (strlen($body) > self::MAX_JSON_BYTES) {
            JsonResponse::send(['error' => ['code' => 'request_too_large', 'message' => 'The request body is too large.']], 413);
        }
        try {
            $payload = json_decode($body, true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            JsonResponse::send(['error' => ['code' => 'invalid_json', 'message' => 'The request body is not valid JSON.']], 400);
        }
        if (!is_array($payload)) {
            JsonResponse::send(['error' => ['code' => 'invalid_json', 'message' => 'The request body is not valid JSON.']], 400);
        }
        return $payload;
    }

    public static function bearerCredential(): string
    {
        $header = trim((string) ($_SERVER['HTTP_AUTHORIZATION'] ?? ''));
        if (!preg_match('/^Bearer\s+([A-Za-z0-9_-]{32,256})$/', $header, $matches)) {
            JsonResponse::send(['error' => ['code' => 'device_authentication_required', 'message' => 'A valid HomeServer device credential is required.']], 401);
        }
        return $matches[1];
    }

    public static function requestId(array $payload): string
    {
        $value = trim((string) ($_SERVER['HTTP_X_REQUEST_ID'] ?? ($payload['request_id'] ?? '')));
        if (!preg_match('/^[A-Za-z0-9._:-]{8,64}$/', $value)) {
            JsonResponse::send(['error' => ['code' => 'request_id_required', 'message' => 'A valid request ID is required.']], 400);
        }
        return $value;
    }

    public static function idempotencyKey(array $payload): string
    {
        $value = trim((string) ($_SERVER['HTTP_IDEMPOTENCY_KEY'] ?? ($payload['idempotency_key'] ?? '')));
        if (!preg_match('/^[A-Za-z0-9._:-]{8,128}$/', $value)) {
            JsonResponse::send(['error' => ['code' => 'idempotency_key_required', 'message' => 'A valid idempotency key is required.']], 400);
        }
        return $value;
    }

    /** @return array{account_id:int,account_public_id:string,user:array<string,mixed>,session:array<string,mixed>} */
    public static function accountContext(array $container, array $payload): array
    {
        $current = $container['authentication_context']->requireCurrent(AuthEndpoint::ip(), AuthEndpoint::userAgent());
        $container['session']->assertCsrf(AuthEndpoint::csrf($payload));
        if (array_key_exists('account_id', $payload)) {
            throw new AuthPublicException(
                'account_public_identity_required',
                'Use the public VP3 account identity for HomeServer Control Center requests.',
                400
            );
        }
        $resolver = new PublicAccountIdentityResolver($container['database']);
        $resolved = $resolver->resolve(
            (int) $current['user']['id'],
            isset($payload['account_public_id']) ? (string) $payload['account_public_id'] : null,
            ['customer_owner', 'customer_admin']
        );
        return [
            'account_id' => $resolved['account_id'],
            'account_public_id' => $resolved['account_public_id'],
            'user' => $current['user'],
            'session' => $current['session'],
        ];
    }

    public static function sendException(Throwable $exception): never
    {
        if ($exception instanceof AuthPublicException) {
            AuthEndpoint::sendException($exception);
        }
        if ($exception instanceof RuntimeException) {
            $message = $exception->getMessage();
            $status = str_contains(strtolower($message), 'credential') ? 401 : 422;
            if (str_contains(strtolower($message), 'not found')) {
                $status = 404;
            } elseif (str_contains(strtolower($message), 'suspended') || str_contains(strtolower($message), 'revoked') || str_contains(strtolower($message), 'eligible') || str_contains(strtolower($message), 'membership')) {
                $status = 403;
            }
            JsonResponse::send(['error' => ['code' => 'homeserver_request_rejected', 'message' => $message]], $status);
        }
        JsonResponse::send(['error' => ['code' => 'homeserver_request_failed', 'message' => 'Unable to complete the HomeServer request.']], 500);
    }
}

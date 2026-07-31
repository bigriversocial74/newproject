<?php

declare(strict_types=1);

namespace Vp3\Http;

use InvalidArgumentException;
use JsonException;
use Throwable;
use Vp3\Auth\AuthPublicException;
use Vp3\ControlCenter\PublicAccountIdentityResolver;

final class ControlCenterEndpoint
{
    public const MAX_JSON_BYTES = 65536;

    private static ?BrowserRequestIntegrity $requestIntegrity = null;

    public static function configureRequestIntegrity(BrowserRequestIntegrity $requestIntegrity): void
    {
        self::$requestIntegrity = $requestIntegrity;
    }

    public static function requireMethod(string $method): void
    {
        PublicResponseGuard::enable();
        $requiredMethod = strtoupper($method);
        if (strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')) !== $requiredMethod) {
            JsonResponse::send(['error' => ['code' => 'method_not_allowed', 'message' => $requiredMethod . ' required.']], 405);
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
            self::$requestIntegrity->assertTrustedMutation($_SERVER, $requiredMethod);
        } catch (Throwable $exception) {
            self::sendException($exception);
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

    /** @return array{account_id:int,account_public_id:string,role:string,user:array<string,mixed>,session:array<string,mixed>} */
    public static function accountContext(array $container, array $payload): array
    {
        return self::accountContextForRoles($container, $payload, ['customer_owner', 'customer_admin']);
    }

    /**
     * @param array<string,mixed> $container
     * @param array<string,mixed> $payload
     * @param list<string> $allowedRoles
     * @return array{account_id:int,account_public_id:string,role:string,user:array<string,mixed>,session:array<string,mixed>}
     */
    public static function accountContextForRoles(array $container, array $payload, array $allowedRoles): array
    {
        PublicResponseGuard::enable();
        $current = $container['authentication_context']->requireCurrent(AuthEndpoint::ip(), AuthEndpoint::userAgent());
        $container['session']->assertCsrf(AuthEndpoint::csrf($payload));
        if (array_key_exists('account_id', $payload)) {
            throw new AuthPublicException(
                'account_public_identity_required',
                'Use the public VP3 account identity for Control Center requests.',
                400
            );
        }
        $resolver = new PublicAccountIdentityResolver($container['database']);
        $resolved = $resolver->resolve(
            (int) $current['user']['id'],
            isset($payload['account_public_id']) ? (string) $payload['account_public_id'] : null,
            $allowedRoles
        );
        return [
            'account_id' => $resolved['account_id'],
            'account_public_id' => $resolved['account_public_id'],
            'role' => $resolved['role'],
            'user' => $current['user'],
            'session' => $current['session'],
        ];
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

    public static function sendException(Throwable $exception): never
    {
        if ($exception instanceof AuthPublicException) {
            AuthEndpoint::sendException($exception);
        }
        if ($exception instanceof InvalidArgumentException || $exception instanceof \RuntimeException) {
            $message = $exception->getMessage();
            $status = str_contains(strtolower($message), 'not found') ? 404 : 422;
            if (str_contains(strtolower($message), 'membership') || str_contains(strtolower($message), 'eligible') || str_contains(strtolower($message), 'permission')) {
                $status = 403;
            }
            JsonResponse::send(['error' => ['code' => 'control_center_request_rejected', 'message' => $message]], $status);
        }
        JsonResponse::send(['error' => ['code' => 'control_center_request_failed', 'message' => 'Unable to complete the control center request.']], 500);
    }
}

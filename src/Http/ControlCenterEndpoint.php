<?php

declare(strict_types=1);

namespace Vp3\Http;

use InvalidArgumentException;
use JsonException;
use RuntimeException;
use Throwable;
use Vp3\Auth\AuthPublicException;

final class ControlCenterEndpoint
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

    /** @return array{account_id:int,user:array<string,mixed>,session:array<string,mixed>} */
    public static function accountContext(array $container, array $payload): array
    {
        $current = $container['authentication_context']->requireCurrent(AuthEndpoint::ip(), AuthEndpoint::userAgent());
        $container['session']->assertCsrf(AuthEndpoint::csrf($payload));
        $requestedAccountId = max(0, (int) ($payload['account_id'] ?? 0));
        $sql = "SELECT account_id FROM account_users WHERE user_id=:user AND status='active'
                AND role IN ('owner','administrator')";
        $parameters = ['user' => (int) $current['user']['id']];
        if ($requestedAccountId > 0) {
            $sql .= ' AND account_id=:account';
            $parameters['account'] = $requestedAccountId;
        }
        $sql .= ' ORDER BY account_id LIMIT 1';
        $statement = $container['database']->pdo()->prepare($sql);
        $statement->execute($parameters);
        $accountId = (int) $statement->fetchColumn();
        if ($accountId < 1) {
            throw new RuntimeException('An active VP3 account owner or administrator membership is required.');
        }
        return ['account_id' => $accountId, 'user' => $current['user'], 'session' => $current['session']];
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
        if ($exception instanceof InvalidArgumentException || $exception instanceof RuntimeException) {
            $message = $exception->getMessage();
            $status = str_contains(strtolower($message), 'not found') ? 404 : 422;
            if (str_contains(strtolower($message), 'membership') || str_contains(strtolower($message), 'eligible')) {
                $status = 403;
            }
            JsonResponse::send(['error' => ['code' => 'control_center_request_rejected', 'message' => $message]], $status);
        }
        JsonResponse::send(['error' => ['code' => 'control_center_request_failed', 'message' => 'Unable to complete the control center request.']], 500);
    }
}

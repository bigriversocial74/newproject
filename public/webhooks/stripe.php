<?php

declare(strict_types=1);

use Vp3\Billing\StripeWebhookService;

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

$requestId = trim((string) ($_SERVER['HTTP_X_REQUEST_ID'] ?? ''));
if ($requestId === '') {
    $requestId = 'REQ-' . strtoupper(bin2hex(random_bytes(12)));
}
header('X-Request-ID: ' . $requestId);

try {
    $services = require dirname(__DIR__, 2) . '/bootstrap.php';
    $handler = $services['stripe_webhooks'] ?? null;
    if (!$handler instanceof StripeWebhookService) {
        throw new RuntimeException('Stripe webhook service is unavailable.');
    }
    $payload = file_get_contents('php://input');
    if (!is_string($payload)) {
        throw new RuntimeException('Stripe webhook payload could not be read.');
    }
    $signature = (string) ($_SERVER['HTTP_STRIPE_SIGNATURE'] ?? '');
    $result = $handler->handle($payload, $signature, $requestId);
    http_response_code(200);
    echo json_encode(['ok' => true, 'request_id' => $requestId, 'data' => $result], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
} catch (\Throwable $exception) {
    http_response_code(400);
    echo json_encode([
        'ok' => false,
        'request_id' => $requestId,
        'error' => ['code' => 'stripe_webhook_rejected', 'message' => 'The Stripe webhook could not be accepted.'],
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
}

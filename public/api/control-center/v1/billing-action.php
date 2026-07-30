<?php

declare(strict_types=1);

use Vp3\Http\ControlCenterEndpoint;
use Vp3\Http\JsonResponse;

$container = require __DIR__ . '/_bootstrap.php';
ControlCenterEndpoint::requireMethod('POST');

try {
    $payload = ControlCenterEndpoint::payload();
    $account = ControlCenterEndpoint::accountContext(
        $container,
        $payload,
        ['customer_owner', 'customer_admin', 'billing_manager']
    );
    $action = strtolower(trim((string) ($payload['action'] ?? '')));
    $requestId = ControlCenterEndpoint::requestId($payload);
    $idempotencyKey = ControlCenterEndpoint::idempotencyKey($payload);
    $baseUrl = rtrim((string) ($container['config']['app']['base_url'] ?? ''), '/');
    $scheme = strtolower((string) parse_url($baseUrl, PHP_URL_SCHEME));
    if ($scheme !== 'https') {
        throw new RuntimeException('Secure billing is temporarily unavailable.');
    }

    $billingPage = $baseUrl . '/billing.php?account_id=' . $account['account_id'];
    if ($action === 'checkout') {
        $planPublicId = trim((string) ($payload['plan_public_id'] ?? ''));
        if (!preg_match('/^[A-Za-z0-9._:-]{3,64}$/', $planPublicId)) {
            throw new RuntimeException('A valid billing plan is required.');
        }
        $statement = $container['database']->pdo()->prepare(
            "SELECT p.id
             FROM plans p
             JOIN stripe_price_mappings sp ON sp.plan_id=p.id AND sp.active=1
             WHERE p.public_id=:public AND p.status='active'
             ORDER BY sp.id DESC LIMIT 1"
        );
        $statement->execute(['public' => $planPublicId]);
        $planId = (int) $statement->fetchColumn();
        if ($planId < 1) {
            throw new RuntimeException('The selected billing plan is not available for checkout.');
        }
        try {
            $result = $container['stripe_checkout']->createCheckoutSession(
                $account['account_id'],
                $planId,
                $billingPage . '&checkout=success',
                $billingPage . '&checkout=canceled',
                $requestId,
                $idempotencyKey
            );
        } catch (RuntimeException $exception) {
            if (str_contains($exception->getMessage(), 'idempotency key was reused')) {
                throw $exception;
            }
            throw new RuntimeException('Secure billing checkout could not be created.');
        }
        $url = trustedStripeRedirect($result['url'] ?? null, 'checkout.stripe.com');
        JsonResponse::send(['data' => [
            'action' => 'checkout',
            'public_id' => (string) $result['public_id'],
            'url' => $url,
            'status' => (string) $result['status'],
            'replayed' => (bool) $result['replayed'],
        ]]);
    }

    if ($action === 'portal') {
        try {
            $result = $container['stripe_checkout']->createPortalSession(
                $account['account_id'],
                $billingPage,
                $requestId,
                $idempotencyKey
            );
        } catch (RuntimeException $exception) {
            if (str_contains($exception->getMessage(), 'Stripe customer is required')) {
                throw new RuntimeException('The secure billing portal is not available until billing is activated for this account.');
            }
            if (str_contains($exception->getMessage(), 'idempotency key was reused')) {
                throw $exception;
            }
            throw new RuntimeException('The secure billing portal could not be opened.');
        }
        $url = trustedStripeRedirect($result['url'] ?? null, 'billing.stripe.com');
        JsonResponse::send(['data' => [
            'action' => 'portal',
            'public_id' => (string) $result['public_id'],
            'url' => $url,
            'replayed' => (bool) $result['replayed'],
        ]]);
    }

    throw new RuntimeException('The requested billing action is not supported.');
} catch (Throwable $exception) {
    ControlCenterEndpoint::sendException($exception);
}

function trustedStripeRedirect(mixed $value, string $expectedHost): string
{
    if (!is_string($value) || trim($value) === '') {
        throw new RuntimeException('The billing provider did not return a secure redirect.');
    }
    $url = trim($value);
    $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
    $host = strtolower((string) parse_url($url, PHP_URL_HOST));
    if ($scheme !== 'https' || $host !== strtolower($expectedHost)) {
        throw new RuntimeException('The billing provider returned an untrusted redirect.');
    }
    return $url;
}

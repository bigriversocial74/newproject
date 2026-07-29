<?php

declare(strict_types=1);

namespace Vp3\Licensing;

use DateTimeImmutable;
use PDO;
use RuntimeException;
use Vp3\Database;

final class DomainLicenseBundleService
{
    public function __construct(private readonly Database $database)
    {
    }

    /**
     * @return array{domain_id:int,domain_public_id:string,hostname:string,pod_license_id:int,pod_license_public_id:string,homeserver_license_id:int,homeserver_license_public_id:string}
     */
    public function activateDomainBundle(
        int $accountId,
        int $subscriptionId,
        string $label,
        string $requestId,
        string $idempotencyKey
    ): array {
        $label = strtolower(trim($label));
        $requestId = trim($requestId);
        $idempotencyKey = trim($idempotencyKey);

        if (!preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/', $label)) {
            throw new RuntimeException('The Domain label is invalid.');
        }
        if ($requestId === '' || $idempotencyKey === '') {
            throw new RuntimeException('Request ID and idempotency key are required.');
        }

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $subscriptionId,
            $label,
            $requestId,
            $idempotencyKey
        ): array {
            $subscription = $pdo->prepare(
                'SELECT s.id, s.account_id, s.plan_id, s.status
                 FROM subscriptions s
                 WHERE s.id = :subscription_id AND s.account_id = :account_id
                 LIMIT 1 FOR UPDATE'
            );
            $subscription->execute(['subscription_id' => $subscriptionId, 'account_id' => $accountId]);
            $subscriptionRow = $subscription->fetch();
            if (!$subscriptionRow || !in_array($subscriptionRow['status'], ['trialing', 'active', 'grace'], true)) {
                throw new RuntimeException('An eligible subscription is required.');
            }

            $existingEvent = $pdo->prepare(
                'SELECT metadata_json FROM domain_license_events
                 WHERE event_type = :event_type AND idempotency_key = :idempotency_key
                 LIMIT 1'
            );
            $existingEvent->execute([
                'event_type' => 'domain_bundle_activated',
                'idempotency_key' => $idempotencyKey,
            ]);
            $existingMetadata = $existingEvent->fetchColumn();
            if (is_string($existingMetadata) && $existingMetadata !== '') {
                $decoded = json_decode($existingMetadata, true, 16, JSON_THROW_ON_ERROR);
                if (is_array($decoded)) {
                    return $decoded;
                }
            }

            $hostname = $label . '.vp3.me';
            $now = new DateTimeImmutable('now');
            $domainPublicId = 'DOM-' . strtoupper(bin2hex(random_bytes(8)));

            $domain = $pdo->prepare(
                'INSERT INTO domain_registrations
                 (public_id, account_id, subscription_id, label, hostname, status, routing_status, ssl_status, registered_at, created_at, updated_at)
                 VALUES
                 (:public_id, :account_id, :subscription_id, :label, :hostname, :status, :routing_status, :ssl_status, :registered_at, :created_at, :updated_at)'
            );
            $domain->execute([
                'public_id' => $domainPublicId,
                'account_id' => $accountId,
                'subscription_id' => $subscriptionId,
                'label' => $label,
                'hostname' => $hostname,
                'status' => 'active',
                'routing_status' => 'pending',
                'ssl_status' => 'pending',
                'registered_at' => $now->format('Y-m-d H:i:s'),
                'created_at' => $now->format('Y-m-d H:i:s'),
                'updated_at' => $now->format('Y-m-d H:i:s'),
            ]);
            $domainId = (int) $pdo->lastInsertId();

            $licenses = [];
            foreach (['pod' => 'LIC-POD-', 'homeserver' => 'LIC-HS-'] as $productType => $prefix) {
                $publicId = $prefix . strtoupper(bin2hex(random_bytes(8)));
                $insert = $pdo->prepare(
                    'INSERT INTO licenses
                     (public_id, account_id, subscription_id, domain_registration_id, product_type, status, starts_at, created_at, updated_at)
                     VALUES
                     (:public_id, :account_id, :subscription_id, :domain_registration_id, :product_type, :status, :starts_at, :created_at, :updated_at)'
                );
                $insert->execute([
                    'public_id' => $publicId,
                    'account_id' => $accountId,
                    'subscription_id' => $subscriptionId,
                    'domain_registration_id' => $domainId,
                    'product_type' => $productType,
                    'status' => 'active',
                    'starts_at' => $now->format('Y-m-d H:i:s'),
                    'created_at' => $now->format('Y-m-d H:i:s'),
                    'updated_at' => $now->format('Y-m-d H:i:s'),
                ]);
                $licenseId = (int) $pdo->lastInsertId();

                $copyEntitlements = $pdo->prepare(
                    'INSERT INTO license_entitlements
                     (license_id, entitlement_key, value_type, value_json, source_plan_id, effective_at, created_at, updated_at)
                     SELECT :license_id, entitlement_key, value_type, value_json, plan_id, :effective_at, :created_at, :updated_at
                     FROM plan_entitlements WHERE plan_id = :plan_id'
                );
                $copyEntitlements->execute([
                    'license_id' => $licenseId,
                    'effective_at' => $now->format('Y-m-d H:i:s'),
                    'created_at' => $now->format('Y-m-d H:i:s'),
                    'updated_at' => $now->format('Y-m-d H:i:s'),
                    'plan_id' => $subscriptionRow['plan_id'],
                ]);

                $licenses[$productType] = ['id' => $licenseId, 'public_id' => $publicId];
            }

            $result = [
                'domain_id' => $domainId,
                'domain_public_id' => $domainPublicId,
                'hostname' => $hostname,
                'pod_license_id' => $licenses['pod']['id'],
                'pod_license_public_id' => $licenses['pod']['public_id'],
                'homeserver_license_id' => $licenses['homeserver']['id'],
                'homeserver_license_public_id' => $licenses['homeserver']['public_id'],
            ];

            $event = $pdo->prepare(
                'INSERT INTO domain_license_events
                 (request_id, idempotency_key, account_id, domain_registration_id, event_type, result, metadata_json, created_at)
                 VALUES
                 (:request_id, :idempotency_key, :account_id, :domain_registration_id, :event_type, :result, :metadata_json, :created_at)'
            );
            $event->execute([
                'request_id' => $requestId,
                'idempotency_key' => $idempotencyKey,
                'account_id' => $accountId,
                'domain_registration_id' => $domainId,
                'event_type' => 'domain_bundle_activated',
                'result' => 'success',
                'metadata_json' => json_encode($result, JSON_THROW_ON_ERROR),
                'created_at' => $now->format('Y-m-d H:i:s'),
            ]);

            return $result;
        });
    }
}

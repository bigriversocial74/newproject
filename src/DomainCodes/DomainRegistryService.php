<?php

declare(strict_types=1);

namespace Vp3\DomainCodes;

use DateTimeImmutable;
use InvalidArgumentException;
use PDO;
use RuntimeException;
use Vp3\Catalog\PlanCatalogService;
use Vp3\Database;

final class DomainRegistryService
{
    private const DOMAIN_SUFFIX = '.vp3.me';

    /** @var list<string> */
    private const ROUTING_STATES = ['pending', 'active', 'degraded', 'disabled'];

    /** @var list<string> */
    private const SSL_STATES = ['pending', 'active', 'renewing', 'failed', 'disabled'];

    public function __construct(private readonly Database $database)
    {
    }

    /** @return array{label:string,hostname:string,available:bool} */
    public function availability(string $label): array
    {
        $label = $this->normalizeLabel($label);
        $hostname = $label . self::DOMAIN_SUFFIX;
        $statement = $this->database->pdo()->prepare(
            'SELECT id FROM domain_registrations WHERE hostname = :hostname LIMIT 1'
        );
        $statement->execute(['hostname' => $hostname]);

        return [
            'label' => $label,
            'hostname' => $hostname,
            'available' => !$statement->fetchColumn(),
        ];
    }

    /** @return array{domain_id:int,domain_public_id:string,hostname:string,status:string,reserved_until:string} */
    public function reserveDomain(
        int $accountId,
        int $subscriptionId,
        string $label,
        DateTimeImmutable $reservedUntil,
        string $requestId,
        string $idempotencyKey
    ): array {
        $label = $this->normalizeLabel($label);
        $this->assertRequestIdentity($accountId, $requestId, $idempotencyKey);
        $now = new DateTimeImmutable('now');
        if ($reservedUntil <= $now || $reservedUntil > $now->modify('+30 days')) {
            throw new InvalidArgumentException('The reservation expiration must be within the next 30 days.');
        }

        $payload = [
            'account_id' => $accountId,
            'subscription_id' => $subscriptionId,
            'label' => $label,
            'reserved_until' => $reservedUntil->format(DATE_ATOM),
        ];

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $subscriptionId,
            $label,
            $reservedUntil,
            $requestId,
            $idempotencyKey,
            $payload,
            $now
        ): array {
            $replay = $this->beginReceipt(
                $pdo,
                $accountId,
                'domain.reserve',
                $idempotencyKey,
                $requestId,
                $payload
            );
            if ($replay !== null) {
                return $replay;
            }

            $this->activeSubscription($pdo, $accountId, $subscriptionId, true);
            $hostname = $label . self::DOMAIN_SUFFIX;
            $this->assertHostnameAvailable($pdo, $hostname);

            $publicId = 'DOM-' . strtoupper(bin2hex(random_bytes(8)));
            $statement = $pdo->prepare(
                'INSERT INTO domain_registrations
                 (public_id, account_id, subscription_id, label, hostname, status, routing_status, ssl_status,
                  reserved_until, created_at, updated_at)
                 VALUES
                 (:public_id, :account_id, :subscription_id, :label, :hostname, :status, :routing_status, :ssl_status,
                  :reserved_until, :created_at, :updated_at)'
            );
            $statement->execute([
                'public_id' => $publicId,
                'account_id' => $accountId,
                'subscription_id' => $subscriptionId,
                'label' => $label,
                'hostname' => $hostname,
                'status' => 'reserved',
                'routing_status' => 'pending',
                'ssl_status' => 'pending',
                'reserved_until' => $reservedUntil->format('Y-m-d H:i:s'),
                'created_at' => $now->format('Y-m-d H:i:s'),
                'updated_at' => $now->format('Y-m-d H:i:s'),
            ]);
            $domainId = (int) $pdo->lastInsertId();
            $result = [
                'domain_id' => $domainId,
                'domain_public_id' => $publicId,
                'hostname' => $hostname,
                'status' => 'reserved',
                'reserved_until' => $reservedUntil->format(DATE_ATOM),
            ];

            $this->recordEvent($pdo, $accountId, $domainId, $requestId, 'domain_reserved', $result);
            $this->completeReceipt($pdo, $accountId, 'domain.reserve', $idempotencyKey, $domainId, $result);

            return $result;
        });
    }

    /**
     * @return array{domain_id:int,domain_public_id:string,hostname:string,entitlement_bundle_id:int,entitlement_bundle_public_id:string,pod_license_id:int,pod_license_public_id:string,homeserver_license_id:int,homeserver_license_public_id:string}
     */
    public function registerAndActivate(
        int $accountId,
        int $subscriptionId,
        string $label,
        string $requestId,
        string $idempotencyKey
    ): array {
        $label = $this->normalizeLabel($label);
        $this->assertRequestIdentity($accountId, $requestId, $idempotencyKey);
        $payload = [
            'account_id' => $accountId,
            'subscription_id' => $subscriptionId,
            'label' => $label,
        ];

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $subscriptionId,
            $label,
            $requestId,
            $idempotencyKey,
            $payload
        ): array {
            $replay = $this->beginReceipt(
                $pdo,
                $accountId,
                'domain.register_activate',
                $idempotencyKey,
                $requestId,
                $payload
            );
            if ($replay !== null) {
                return $replay;
            }

            $subscription = $this->activeSubscription($pdo, $accountId, $subscriptionId, true);
            $hostname = $label . self::DOMAIN_SUFFIX;
            $this->assertHostnameAvailable($pdo, $hostname);
            $now = new DateTimeImmutable('now');
            $domainPublicId = 'DOM-' . strtoupper(bin2hex(random_bytes(8)));
            $statement = $pdo->prepare(
                'INSERT INTO domain_registrations
                 (public_id, account_id, subscription_id, label, hostname, status, routing_status, ssl_status,
                  registered_at, renews_at, expires_at, created_at, updated_at)
                 VALUES
                 (:public_id, :account_id, :subscription_id, :label, :hostname, :status, :routing_status, :ssl_status,
                  :registered_at, :renews_at, :expires_at, :created_at, :updated_at)'
            );
            $statement->execute([
                'public_id' => $domainPublicId,
                'account_id' => $accountId,
                'subscription_id' => $subscriptionId,
                'label' => $label,
                'hostname' => $hostname,
                'status' => 'active',
                'routing_status' => 'pending',
                'ssl_status' => 'pending',
                'registered_at' => $now->format('Y-m-d H:i:s'),
                'renews_at' => $subscription['current_period_ends_at'],
                'expires_at' => $subscription['current_period_ends_at'],
                'created_at' => $now->format('Y-m-d H:i:s'),
                'updated_at' => $now->format('Y-m-d H:i:s'),
            ]);
            $domainId = (int) $pdo->lastInsertId();
            $licenses = $this->createEntitlementBundleAndLicenses(
                $pdo,
                $accountId,
                $subscriptionId,
                $domainId,
                (int) $subscription['plan_id'],
                $subscription['current_period_ends_at'],
                $now
            );
            $result = [
                'domain_id' => $domainId,
                'domain_public_id' => $domainPublicId,
                'hostname' => $hostname,
                ...$licenses,
            ];

            $this->recordEvent($pdo, $accountId, $domainId, $requestId, 'domain_bundle_activated', $result);
            $this->completeReceipt(
                $pdo,
                $accountId,
                'domain.register_activate',
                $idempotencyKey,
                $domainId,
                $result
            );

            return $result;
        });
    }

    /**
     * @return array{domain_id:int,domain_public_id:string,hostname:string,entitlement_bundle_id:int,entitlement_bundle_public_id:string,pod_license_id:int,pod_license_public_id:string,homeserver_license_id:int,homeserver_license_public_id:string}
     */
    public function activateReservedDomain(
        int $accountId,
        string $domainPublicId,
        string $requestId,
        string $idempotencyKey
    ): array {
        $this->assertRequestIdentity($accountId, $requestId, $idempotencyKey);
        $domainPublicId = trim($domainPublicId);
        if ($domainPublicId === '') {
            throw new InvalidArgumentException('The Domain identity is required.');
        }
        $payload = ['account_id' => $accountId, 'domain_public_id' => $domainPublicId];

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $domainPublicId,
            $requestId,
            $idempotencyKey,
            $payload
        ): array {
            $replay = $this->beginReceipt(
                $pdo,
                $accountId,
                'domain.activate_reserved',
                $idempotencyKey,
                $requestId,
                $payload
            );
            if ($replay !== null) {
                return $replay;
            }

            $domain = $this->domainForAccount($pdo, $accountId, $domainPublicId, true);
            if ($domain['status'] !== 'reserved') {
                throw new RuntimeException('Only a reserved Domain may be activated.');
            }
            $now = new DateTimeImmutable('now');
            if ($domain['reserved_until'] === null || new DateTimeImmutable($domain['reserved_until']) <= $now) {
                throw new RuntimeException('The Domain reservation has expired.');
            }
            $this->assertNoActiveHold($pdo, (int) $domain['id']);
            $subscription = $this->activeSubscription(
                $pdo,
                $accountId,
                (int) $domain['subscription_id'],
                true
            );
            $licenses = $this->createEntitlementBundleAndLicenses(
                $pdo,
                $accountId,
                (int) $domain['subscription_id'],
                (int) $domain['id'],
                (int) $subscription['plan_id'],
                $subscription['current_period_ends_at'],
                $now
            );

            $update = $pdo->prepare(
                'UPDATE domain_registrations
                 SET status = :status, registered_at = :registered_at, reserved_until = NULL,
                     renews_at = :renews_at, expires_at = :expires_at, updated_at = :updated_at
                 WHERE id = :id'
            );
            $update->execute([
                'status' => 'active',
                'registered_at' => $now->format('Y-m-d H:i:s'),
                'renews_at' => $subscription['current_period_ends_at'],
                'expires_at' => $subscription['current_period_ends_at'],
                'updated_at' => $now->format('Y-m-d H:i:s'),
                'id' => $domain['id'],
            ]);
            $result = [
                'domain_id' => (int) $domain['id'],
                'domain_public_id' => (string) $domain['public_id'],
                'hostname' => (string) $domain['hostname'],
                ...$licenses,
            ];
            $this->recordEvent(
                $pdo,
                $accountId,
                (int) $domain['id'],
                $requestId,
                'reserved_domain_activated',
                $result
            );
            $this->completeReceipt(
                $pdo,
                $accountId,
                'domain.activate_reserved',
                $idempotencyKey,
                (int) $domain['id'],
                $result
            );

            return $result;
        });
    }

    /** @return array{domain_public_id:string,status:string,renews_at:string,expires_at:string} */
    public function renewDomain(
        int $accountId,
        string $domainPublicId,
        DateTimeImmutable $renewsAt,
        DateTimeImmutable $expiresAt,
        string $requestId,
        string $idempotencyKey
    ): array {
        $this->assertRequestIdentity($accountId, $requestId, $idempotencyKey);
        if ($expiresAt < $renewsAt) {
            throw new InvalidArgumentException('The Domain expiration cannot precede renewal.');
        }
        $payload = [
            'account_id' => $accountId,
            'domain_public_id' => trim($domainPublicId),
            'renews_at' => $renewsAt->format(DATE_ATOM),
            'expires_at' => $expiresAt->format(DATE_ATOM),
        ];

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $domainPublicId,
            $renewsAt,
            $expiresAt,
            $requestId,
            $idempotencyKey,
            $payload
        ): array {
            $replay = $this->beginReceipt(
                $pdo,
                $accountId,
                'domain.renew',
                $idempotencyKey,
                $requestId,
                $payload
            );
            if ($replay !== null) {
                return $replay;
            }
            $domain = $this->domainForAccount($pdo, $accountId, trim($domainPublicId), true);
            if (!in_array($domain['status'], ['active', 'grace'], true)) {
                throw new RuntimeException('The Domain is not eligible for renewal.');
            }
            $this->assertNoActiveHold($pdo, (int) $domain['id']);
            $this->activeSubscription($pdo, $accountId, (int) $domain['subscription_id'], true);
            $now = new DateTimeImmutable('now');
            $update = $pdo->prepare(
                'UPDATE domain_registrations
                 SET status = :status, renews_at = :renews_at, expires_at = :expires_at,
                     suspended_at = NULL, updated_at = :updated_at
                 WHERE id = :id'
            );
            $update->execute([
                'status' => 'active',
                'renews_at' => $renewsAt->format('Y-m-d H:i:s'),
                'expires_at' => $expiresAt->format('Y-m-d H:i:s'),
                'updated_at' => $now->format('Y-m-d H:i:s'),
                'id' => $domain['id'],
            ]);
            $this->setLicenseState(
                $pdo,
                (int) $domain['id'],
                'active',
                $now,
                $renewsAt,
                $expiresAt
            );
            $result = [
                'domain_public_id' => (string) $domain['public_id'],
                'status' => 'active',
                'renews_at' => $renewsAt->format(DATE_ATOM),
                'expires_at' => $expiresAt->format(DATE_ATOM),
            ];
            $this->recordEvent($pdo, $accountId, (int) $domain['id'], $requestId, 'domain_renewed', $result);
            $this->completeReceipt(
                $pdo,
                $accountId,
                'domain.renew',
                $idempotencyKey,
                (int) $domain['id'],
                $result
            );

            return $result;
        });
    }

    /** @return array{domain_public_id:string,status:string} */
    public function suspendDomain(
        int $accountId,
        string $domainPublicId,
        string $requestId,
        string $idempotencyKey,
        string $reason
    ): array {
        $reason = trim($reason);
        if ($reason === '' || mb_strlen($reason) > 500) {
            throw new InvalidArgumentException('A valid suspension reason is required.');
        }

        return $this->transitionDomainState(
            $accountId,
            $domainPublicId,
            'suspended',
            'domain.suspend',
            'domain_suspended',
            $requestId,
            $idempotencyKey,
            ['reason' => $reason]
        );
    }

    /** @return array{domain_public_id:string,status:string} */
    public function expireDomain(
        int $accountId,
        string $domainPublicId,
        string $requestId,
        string $idempotencyKey
    ): array {
        return $this->transitionDomainState(
            $accountId,
            $domainPublicId,
            'expired',
            'domain.expire',
            'domain_expired',
            $requestId,
            $idempotencyKey,
            []
        );
    }

    /** @return array{domain_public_id:string,status:string} */
    public function releaseDomain(
        int $accountId,
        string $domainPublicId,
        string $requestId,
        string $idempotencyKey
    ): array {
        return $this->transitionDomainState(
            $accountId,
            $domainPublicId,
            'released',
            'domain.release',
            'domain_released',
            $requestId,
            $idempotencyKey,
            []
        );
    }

    /** @return array{hold_public_id:string,domain_public_id:string,status:string} */
    public function placeAdministrativeHold(
        int $accountId,
        string $domainPublicId,
        string $reason,
        string $requestId,
        string $idempotencyKey,
        ?int $actorId = null
    ): array {
        $reason = trim($reason);
        if ($reason === '' || mb_strlen($reason) > 500) {
            throw new InvalidArgumentException('A valid administrative-hold reason is required.');
        }
        $this->assertRequestIdentity($accountId, $requestId, $idempotencyKey);
        $payload = [
            'account_id' => $accountId,
            'domain_public_id' => trim($domainPublicId),
            'reason' => $reason,
            'actor_id' => $actorId,
        ];

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $domainPublicId,
            $reason,
            $requestId,
            $idempotencyKey,
            $actorId,
            $payload
        ): array {
            $replay = $this->beginReceipt(
                $pdo,
                $accountId,
                'domain.hold.place',
                $idempotencyKey,
                $requestId,
                $payload
            );
            if ($replay !== null) {
                return $replay;
            }
            $domain = $this->domainForAccount($pdo, $accountId, trim($domainPublicId), true);
            if (in_array($domain['status'], ['released', 'transferred'], true)) {
                throw new RuntimeException('The Domain cannot be placed on hold.');
            }
            $now = new DateTimeImmutable('now');
            $holdPublicId = 'HOLD-' . strtoupper(bin2hex(random_bytes(8)));
            $insert = $pdo->prepare(
                'INSERT INTO domain_admin_holds
                 (public_id, domain_registration_id, account_id, status, reason, placed_by_actor_id,
                  placed_at, created_at, updated_at)
                 VALUES
                 (:public_id, :domain_id, :account_id, :status, :reason, :actor_id,
                  :placed_at, :created_at, :updated_at)'
            );
            $insert->execute([
                'public_id' => $holdPublicId,
                'domain_id' => $domain['id'],
                'account_id' => $accountId,
                'status' => 'active',
                'reason' => $reason,
                'actor_id' => $actorId,
                'placed_at' => $now->format('Y-m-d H:i:s'),
                'created_at' => $now->format('Y-m-d H:i:s'),
                'updated_at' => $now->format('Y-m-d H:i:s'),
            ]);
            $this->updateDomainAndLicenseState($pdo, (int) $domain['id'], 'suspended', $now);
            $result = [
                'hold_public_id' => $holdPublicId,
                'domain_public_id' => (string) $domain['public_id'],
                'status' => 'active',
            ];
            $this->recordEvent($pdo, $accountId, (int) $domain['id'], $requestId, 'domain_hold_placed', [
                'hold_public_id' => $holdPublicId,
                'reason' => $reason,
            ]);
            $this->completeReceipt(
                $pdo,
                $accountId,
                'domain.hold.place',
                $idempotencyKey,
                (int) $domain['id'],
                $result
            );

            return $result;
        });
    }

    /** @return array{hold_public_id:string,domain_public_id:string,status:string,domain_status:string} */
    public function releaseAdministrativeHold(
        int $accountId,
        string $holdPublicId,
        string $requestId,
        string $idempotencyKey,
        ?int $actorId = null
    ): array {
        $this->assertRequestIdentity($accountId, $requestId, $idempotencyKey);
        $holdPublicId = trim($holdPublicId);
        if ($holdPublicId === '') {
            throw new InvalidArgumentException('The hold identity is required.');
        }
        $payload = ['account_id' => $accountId, 'hold_public_id' => $holdPublicId, 'actor_id' => $actorId];

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $holdPublicId,
            $requestId,
            $idempotencyKey,
            $actorId,
            $payload
        ): array {
            $replay = $this->beginReceipt(
                $pdo,
                $accountId,
                'domain.hold.release',
                $idempotencyKey,
                $requestId,
                $payload
            );
            if ($replay !== null) {
                return $replay;
            }
            $statement = $pdo->prepare(
                'SELECT h.id, h.domain_registration_id, h.status, d.public_id, d.subscription_id
                 FROM domain_admin_holds h
                 JOIN domain_registrations d ON d.id = h.domain_registration_id
                 WHERE h.public_id = :public_id AND h.account_id = :account_id
                 LIMIT 1 FOR UPDATE'
            );
            $statement->execute(['public_id' => $holdPublicId, 'account_id' => $accountId]);
            $hold = $statement->fetch(PDO::FETCH_ASSOC);
            if (!is_array($hold)) {
                throw new RuntimeException('The administrative hold was not found.');
            }
            if ($hold['status'] !== 'active') {
                throw new RuntimeException('The administrative hold is not active.');
            }
            $now = new DateTimeImmutable('now');
            $update = $pdo->prepare(
                'UPDATE domain_admin_holds
                 SET status = :status, released_by_actor_id = :actor_id,
                     released_at = :released_at, updated_at = :updated_at
                 WHERE id = :id'
            );
            $update->execute([
                'status' => 'released',
                'actor_id' => $actorId,
                'released_at' => $now->format('Y-m-d H:i:s'),
                'updated_at' => $now->format('Y-m-d H:i:s'),
                'id' => $hold['id'],
            ]);
            $remaining = $pdo->prepare(
                'SELECT COUNT(*) FROM domain_admin_holds
                 WHERE domain_registration_id = :domain_id AND status = :status'
            );
            $remaining->execute(['domain_id' => $hold['domain_registration_id'], 'status' => 'active']);
            $domainStatus = 'suspended';
            if ((int) $remaining->fetchColumn() === 0) {
                $subscription = $pdo->prepare(
                    'SELECT status, current_period_ends_at FROM subscriptions
                     WHERE id = :id AND account_id = :account_id LIMIT 1 FOR UPDATE'
                );
                $subscription->execute([
                    'id' => $hold['subscription_id'],
                    'account_id' => $accountId,
                ]);
                $subscriptionRow = $subscription->fetch(PDO::FETCH_ASSOC);
                if (!is_array($subscriptionRow)) {
                    throw new RuntimeException('The linked subscription could not be resolved.');
                }
                $domainStatus = match ((string) $subscriptionRow['status']) {
                    'active' => 'active',
                    'grace' => 'grace',
                    default => 'suspended',
                };
                $this->updateDomainAndLicenseState(
                    $pdo,
                    (int) $hold['domain_registration_id'],
                    $domainStatus,
                    $now,
                    is_string($subscriptionRow['current_period_ends_at'])
                        ? $subscriptionRow['current_period_ends_at']
                        : null
                );
            }
            $result = [
                'hold_public_id' => $holdPublicId,
                'domain_public_id' => (string) $hold['public_id'],
                'status' => 'released',
                'domain_status' => $domainStatus,
            ];
            $this->recordEvent(
                $pdo,
                $accountId,
                (int) $hold['domain_registration_id'],
                $requestId,
                'domain_hold_released',
                ['hold_public_id' => $holdPublicId, 'domain_status' => $domainStatus]
            );
            $this->completeReceipt(
                $pdo,
                $accountId,
                'domain.hold.release',
                $idempotencyKey,
                (int) $hold['domain_registration_id'],
                $result
            );

            return $result;
        });
    }

    /** @return array{alias_public_id:string,domain_public_id:string,alias_hostname:string,status:string} */
    public function addAlias(
        int $accountId,
        string $domainPublicId,
        string $aliasHostname,
        string $requestId,
        string $idempotencyKey
    ): array {
        $this->assertRequestIdentity($accountId, $requestId, $idempotencyKey);
        $aliasHostname = $this->normalizeHostname($aliasHostname);
        if (str_ends_with($aliasHostname, self::DOMAIN_SUFFIX)) {
            throw new InvalidArgumentException('VP3-managed hostnames cannot be used as custom aliases.');
        }
        $payload = [
            'account_id' => $accountId,
            'domain_public_id' => trim($domainPublicId),
            'alias_hostname' => $aliasHostname,
        ];

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $domainPublicId,
            $aliasHostname,
            $requestId,
            $idempotencyKey,
            $payload
        ): array {
            $replay = $this->beginReceipt(
                $pdo,
                $accountId,
                'domain.alias.add',
                $idempotencyKey,
                $requestId,
                $payload
            );
            if ($replay !== null) {
                return $replay;
            }
            $domain = $this->domainForAccount($pdo, $accountId, trim($domainPublicId), true);
            if (!in_array($domain['status'], ['active', 'grace'], true)) {
                throw new RuntimeException('The Domain cannot accept aliases in its current state.');
            }
            $this->assertNoActiveHold($pdo, (int) $domain['id']);
            if ($aliasHostname === $domain['hostname']) {
                throw new RuntimeException('The primary Domain hostname cannot be added as an alias.');
            }
            $limit = $this->integerEntitlement($pdo, (int) $domain['id'], 'custom_domain_alias_limit');
            $count = $pdo->prepare(
                'SELECT COUNT(*) FROM domain_aliases
                 WHERE domain_registration_id = :domain_id AND status <> :removed'
            );
            $count->execute(['domain_id' => $domain['id'], 'removed' => 'removed']);
            if ((int) $count->fetchColumn() >= $limit) {
                throw new RuntimeException('The Domain alias entitlement limit has been reached.');
            }
            $now = new DateTimeImmutable('now');
            $publicId = 'ALIAS-' . strtoupper(bin2hex(random_bytes(8)));
            $insert = $pdo->prepare(
                'INSERT INTO domain_aliases
                 (public_id, domain_registration_id, account_id, alias_hostname, status, routing_status, ssl_status,
                  created_at, updated_at)
                 VALUES
                 (:public_id, :domain_id, :account_id, :alias_hostname, :status, :routing_status, :ssl_status,
                  :created_at, :updated_at)'
            );
            $insert->execute([
                'public_id' => $publicId,
                'domain_id' => $domain['id'],
                'account_id' => $accountId,
                'alias_hostname' => $aliasHostname,
                'status' => 'pending',
                'routing_status' => 'pending',
                'ssl_status' => 'pending',
                'created_at' => $now->format('Y-m-d H:i:s'),
                'updated_at' => $now->format('Y-m-d H:i:s'),
            ]);
            $result = [
                'alias_public_id' => $publicId,
                'domain_public_id' => (string) $domain['public_id'],
                'alias_hostname' => $aliasHostname,
                'status' => 'pending',
            ];
            $this->recordEvent($pdo, $accountId, (int) $domain['id'], $requestId, 'domain_alias_added', $result);
            $this->completeReceipt(
                $pdo,
                $accountId,
                'domain.alias.add',
                $idempotencyKey,
                (int) $domain['id'],
                $result
            );

            return $result;
        });
    }

    /** @return array{redirect_public_id:string,domain_public_id:string,source_path:string,target_url:string,http_status:int,status:string} */
    public function addRedirect(
        int $accountId,
        string $domainPublicId,
        string $sourcePath,
        string $targetUrl,
        int $httpStatus,
        string $requestId,
        string $idempotencyKey
    ): array {
        $this->assertRequestIdentity($accountId, $requestId, $idempotencyKey);
        $sourcePath = trim($sourcePath);
        $targetUrl = trim($targetUrl);
        if (!str_starts_with($sourcePath, '/') || mb_strlen($sourcePath) > 1024) {
            throw new InvalidArgumentException('The redirect source path is invalid.');
        }
        if (filter_var($targetUrl, FILTER_VALIDATE_URL) === false || mb_strlen($targetUrl) > 2048) {
            throw new InvalidArgumentException('The redirect target URL is invalid.');
        }
        if (!in_array($httpStatus, [301, 302, 307, 308], true)) {
            throw new InvalidArgumentException('The redirect HTTP status is invalid.');
        }
        $payload = [
            'account_id' => $accountId,
            'domain_public_id' => trim($domainPublicId),
            'source_path' => $sourcePath,
            'target_url' => $targetUrl,
            'http_status' => $httpStatus,
        ];

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $domainPublicId,
            $sourcePath,
            $targetUrl,
            $httpStatus,
            $requestId,
            $idempotencyKey,
            $payload
        ): array {
            $replay = $this->beginReceipt(
                $pdo,
                $accountId,
                'domain.redirect.add',
                $idempotencyKey,
                $requestId,
                $payload
            );
            if ($replay !== null) {
                return $replay;
            }
            $domain = $this->domainForAccount($pdo, $accountId, trim($domainPublicId), true);
            if (!in_array($domain['status'], ['active', 'grace'], true)) {
                throw new RuntimeException('The Domain cannot accept redirects in its current state.');
            }
            $this->assertNoActiveHold($pdo, (int) $domain['id']);
            $now = new DateTimeImmutable('now');
            $publicId = 'REDIR-' . strtoupper(bin2hex(random_bytes(8)));
            $insert = $pdo->prepare(
                'INSERT INTO domain_redirects
                 (public_id, domain_registration_id, account_id, source_path, source_path_hash, target_url, http_status, status,
                  created_at, updated_at)
                 VALUES
                 (:public_id, :domain_id, :account_id, :source_path, :source_path_hash, :target_url, :http_status, :status,
                  :created_at, :updated_at)'
            );
            $insert->execute([
                'public_id' => $publicId,
                'domain_id' => $domain['id'],
                'account_id' => $accountId,
                'source_path' => $sourcePath,
                'source_path_hash' => hash('sha256', $sourcePath),
                'target_url' => $targetUrl,
                'http_status' => $httpStatus,
                'status' => 'active',
                'created_at' => $now->format('Y-m-d H:i:s'),
                'updated_at' => $now->format('Y-m-d H:i:s'),
            ]);
            $result = [
                'redirect_public_id' => $publicId,
                'domain_public_id' => (string) $domain['public_id'],
                'source_path' => $sourcePath,
                'target_url' => $targetUrl,
                'http_status' => $httpStatus,
                'status' => 'active',
            ];
            $this->recordEvent($pdo, $accountId, (int) $domain['id'], $requestId, 'domain_redirect_added', $result);
            $this->completeReceipt(
                $pdo,
                $accountId,
                'domain.redirect.add',
                $idempotencyKey,
                (int) $domain['id'],
                $result
            );

            return $result;
        });
    }

    /** @return array{domain_public_id:string,routing_status:string,ssl_status:string} */
    public function updateRoutingAndSslStatus(
        int $accountId,
        string $domainPublicId,
        string $routingStatus,
        string $sslStatus,
        string $requestId,
        string $idempotencyKey
    ): array {
        if (!in_array($routingStatus, self::ROUTING_STATES, true)) {
            throw new InvalidArgumentException('The routing status is invalid.');
        }
        if (!in_array($sslStatus, self::SSL_STATES, true)) {
            throw new InvalidArgumentException('The SSL status is invalid.');
        }
        $this->assertRequestIdentity($accountId, $requestId, $idempotencyKey);
        $payload = [
            'account_id' => $accountId,
            'domain_public_id' => trim($domainPublicId),
            'routing_status' => $routingStatus,
            'ssl_status' => $sslStatus,
        ];

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $domainPublicId,
            $routingStatus,
            $sslStatus,
            $requestId,
            $idempotencyKey,
            $payload
        ): array {
            $replay = $this->beginReceipt(
                $pdo,
                $accountId,
                'domain.routing_ssl.update',
                $idempotencyKey,
                $requestId,
                $payload
            );
            if ($replay !== null) {
                return $replay;
            }
            $domain = $this->domainForAccount($pdo, $accountId, trim($domainPublicId), true);
            $now = new DateTimeImmutable('now');
            $update = $pdo->prepare(
                'UPDATE domain_registrations
                 SET routing_status = :routing_status, ssl_status = :ssl_status, updated_at = :updated_at
                 WHERE id = :id'
            );
            $update->execute([
                'routing_status' => $routingStatus,
                'ssl_status' => $sslStatus,
                'updated_at' => $now->format('Y-m-d H:i:s'),
                'id' => $domain['id'],
            ]);
            $result = [
                'domain_public_id' => (string) $domain['public_id'],
                'routing_status' => $routingStatus,
                'ssl_status' => $sslStatus,
            ];
            $this->recordEvent(
                $pdo,
                $accountId,
                (int) $domain['id'],
                $requestId,
                'domain_routing_ssl_updated',
                $result
            );
            $this->completeReceipt(
                $pdo,
                $accountId,
                'domain.routing_ssl.update',
                $idempotencyKey,
                (int) $domain['id'],
                $result
            );

            return $result;
        });
    }

    public function generateTransferToken(): string
    {
        return bin2hex(random_bytes(32));
    }

    /** @return array{transfer_public_id:string,domain_public_id:string,status:string,expires_at:string} */
    public function requestTransfer(
        int $accountId,
        string $domainPublicId,
        ?int $targetAccountId,
        string $transferToken,
        DateTimeImmutable $expiresAt,
        string $requestId,
        string $idempotencyKey
    ): array {
        $this->assertRequestIdentity($accountId, $requestId, $idempotencyKey);
        if (!preg_match('/^[a-f0-9]{64}$/', $transferToken)) {
            throw new InvalidArgumentException('The transfer token must be a secure 64-character hexadecimal value.');
        }
        if ($targetAccountId !== null && ($targetAccountId < 1 || $targetAccountId === $accountId)) {
            throw new InvalidArgumentException('The transfer target account is invalid.');
        }
        $now = new DateTimeImmutable('now');
        if ($expiresAt <= $now || $expiresAt > $now->modify('+14 days')) {
            throw new InvalidArgumentException('The transfer expiration must be within the next 14 days.');
        }
        $payload = [
            'account_id' => $accountId,
            'domain_public_id' => trim($domainPublicId),
            'target_account_id' => $targetAccountId,
            'token_hash' => hash('sha256', $transferToken),
            'expires_at' => $expiresAt->format(DATE_ATOM),
        ];

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $domainPublicId,
            $targetAccountId,
            $transferToken,
            $expiresAt,
            $requestId,
            $idempotencyKey,
            $payload,
            $now
        ): array {
            $replay = $this->beginReceipt(
                $pdo,
                $accountId,
                'domain.transfer.request',
                $idempotencyKey,
                $requestId,
                $payload
            );
            if ($replay !== null) {
                return $replay;
            }
            $domain = $this->domainForAccount($pdo, $accountId, trim($domainPublicId), true);
            if ($domain['status'] !== 'active') {
                throw new RuntimeException('Only an active Domain may be transferred.');
            }
            $this->assertNoActiveHold($pdo, (int) $domain['id']);
            if ($targetAccountId !== null) {
                $target = $pdo->prepare('SELECT id FROM accounts WHERE id = :id AND status = :status LIMIT 1');
                $target->execute(['id' => $targetAccountId, 'status' => 'active']);
                if (!$target->fetchColumn()) {
                    throw new RuntimeException('The transfer target account is unavailable.');
                }
            }
            $pending = $pdo->prepare(
                'SELECT id FROM domain_transfer_requests
                 WHERE domain_registration_id = :domain_id AND status = :status LIMIT 1 FOR UPDATE'
            );
            $pending->execute(['domain_id' => $domain['id'], 'status' => 'pending']);
            if ($pending->fetchColumn()) {
                throw new RuntimeException('A pending transfer already exists for this Domain.');
            }
            $publicId = 'XFER-' . strtoupper(bin2hex(random_bytes(8)));
            $insert = $pdo->prepare(
                'INSERT INTO domain_transfer_requests
                 (public_id, domain_registration_id, source_account_id, target_account_id, token_hash, status,
                  expires_at, created_at, updated_at)
                 VALUES
                 (:public_id, :domain_id, :source_account_id, :target_account_id, :token_hash, :status,
                  :expires_at, :created_at, :updated_at)'
            );
            $insert->execute([
                'public_id' => $publicId,
                'domain_id' => $domain['id'],
                'source_account_id' => $accountId,
                'target_account_id' => $targetAccountId,
                'token_hash' => hash('sha256', $transferToken),
                'status' => 'pending',
                'expires_at' => $expiresAt->format('Y-m-d H:i:s'),
                'created_at' => $now->format('Y-m-d H:i:s'),
                'updated_at' => $now->format('Y-m-d H:i:s'),
            ]);
            $transferId = (int) $pdo->lastInsertId();
            $activeTransfer = $pdo->prepare(
                'INSERT INTO domain_transfer_active (domain_registration_id, transfer_request_id, created_at)
                 VALUES (:domain_id, :transfer_request_id, :created_at)'
            );
            $activeTransfer->execute([
                'domain_id' => $domain['id'],
                'transfer_request_id' => $transferId,
                'created_at' => $now->format('Y-m-d H:i:s'),
            ]);
            $result = [
                'transfer_public_id' => $publicId,
                'domain_public_id' => (string) $domain['public_id'],
                'status' => 'pending',
                'expires_at' => $expiresAt->format(DATE_ATOM),
            ];
            $this->recordEvent(
                $pdo,
                $accountId,
                (int) $domain['id'],
                $requestId,
                'domain_transfer_requested',
                $result
            );
            $this->completeReceipt(
                $pdo,
                $accountId,
                'domain.transfer.request',
                $idempotencyKey,
                (int) $domain['id'],
                $result
            );

            return $result;
        });
    }

    /**
     * @param array<string,mixed> $metadata
     * @return array{domain_public_id:string,status:string}
     */
    private function transitionDomainState(
        int $accountId,
        string $domainPublicId,
        string $toStatus,
        string $operation,
        string $eventType,
        string $requestId,
        string $idempotencyKey,
        array $metadata
    ): array {
        $this->assertRequestIdentity($accountId, $requestId, $idempotencyKey);
        $domainPublicId = trim($domainPublicId);
        $payload = [
            'account_id' => $accountId,
            'domain_public_id' => $domainPublicId,
            'to_status' => $toStatus,
            'metadata' => $metadata,
        ];

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $domainPublicId,
            $toStatus,
            $operation,
            $eventType,
            $requestId,
            $idempotencyKey,
            $metadata,
            $payload
        ): array {
            $replay = $this->beginReceipt(
                $pdo,
                $accountId,
                $operation,
                $idempotencyKey,
                $requestId,
                $payload
            );
            if ($replay !== null) {
                return $replay;
            }
            $domain = $this->domainForAccount($pdo, $accountId, $domainPublicId, true);
            if (in_array($domain['status'], ['released', 'transferred'], true)) {
                throw new RuntimeException('The Domain is in a terminal state.');
            }
            $now = new DateTimeImmutable('now');
            $this->updateDomainAndLicenseState($pdo, (int) $domain['id'], $toStatus, $now);
            $result = ['domain_public_id' => (string) $domain['public_id'], 'status' => $toStatus];
            $this->recordEvent(
                $pdo,
                $accountId,
                (int) $domain['id'],
                $requestId,
                $eventType,
                [...$result, ...$metadata]
            );
            $this->completeReceipt(
                $pdo,
                $accountId,
                $operation,
                $idempotencyKey,
                (int) $domain['id'],
                $result
            );

            return $result;
        });
    }

    /** @return array<string,mixed>|null */
    private function beginReceipt(
        PDO $pdo,
        int $accountId,
        string $operation,
        string $idempotencyKey,
        string $requestId,
        array $payload
    ): ?array {
        $requestHash = hash(
            'sha256',
            json_encode($this->canonicalize($payload), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)
        );
        $now = (new DateTimeImmutable('now'))->format('Y-m-d H:i:s');
        $insert = $pdo->prepare(
            'INSERT IGNORE INTO domain_request_receipts
             (account_id, operation, idempotency_key, request_id, request_hash, status, created_at)
             VALUES
             (:account_id, :operation, :idempotency_key, :request_id, :request_hash, :status, :created_at)'
        );
        $insert->execute([
            'account_id' => $accountId,
            'operation' => $operation,
            'idempotency_key' => $idempotencyKey,
            'request_id' => $requestId,
            'request_hash' => $requestHash,
            'status' => 'processing',
            'created_at' => $now,
        ]);
        if ($insert->rowCount() === 1) {
            return null;
        }

        $select = $pdo->prepare(
            'SELECT request_hash, status, response_json
             FROM domain_request_receipts
             WHERE account_id = :account_id AND operation = :operation AND idempotency_key = :idempotency_key
             LIMIT 1 FOR UPDATE'
        );
        $select->execute([
            'account_id' => $accountId,
            'operation' => $operation,
            'idempotency_key' => $idempotencyKey,
        ]);
        $receipt = $select->fetch(PDO::FETCH_ASSOC);
        if (!is_array($receipt)) {
            throw new RuntimeException('The idempotency receipt could not be resolved.');
        }
        if (!hash_equals((string) $receipt['request_hash'], $requestHash)) {
            throw new RuntimeException('The idempotency key was reused with a different request payload.');
        }
        if ($receipt['status'] !== 'completed' || !is_string($receipt['response_json'])) {
            throw new RuntimeException('The idempotent operation is already in progress.');
        }
        $decoded = json_decode($receipt['response_json'], true, 64, JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new RuntimeException('The idempotency receipt response is invalid.');
        }

        return $decoded;
    }

    /** @param array<string,mixed> $response */
    private function completeReceipt(
        PDO $pdo,
        int $accountId,
        string $operation,
        string $idempotencyKey,
        int $domainId,
        array $response
    ): void {
        $statement = $pdo->prepare(
            'UPDATE domain_request_receipts
             SET domain_registration_id = :domain_id, status = :status,
                 response_json = :response_json, completed_at = :completed_at
             WHERE account_id = :account_id AND operation = :operation AND idempotency_key = :idempotency_key'
        );
        $statement->execute([
            'domain_id' => $domainId,
            'status' => 'completed',
            'response_json' => json_encode($response, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            'completed_at' => (new DateTimeImmutable('now'))->format('Y-m-d H:i:s'),
            'account_id' => $accountId,
            'operation' => $operation,
            'idempotency_key' => $idempotencyKey,
        ]);
        if ($statement->rowCount() !== 1) {
            throw new RuntimeException('The idempotency receipt could not be completed.');
        }
    }

    /**
     * @return array{plan_id:int,current_period_ends_at:?string}
     */
    private function activeSubscription(PDO $pdo, int $accountId, int $subscriptionId, bool $lock): array
    {
        $sql =
            'SELECT s.plan_id, s.current_period_ends_at
             FROM subscriptions s
             JOIN plans p ON p.id = s.plan_id
             WHERE s.id = :subscription_id
               AND s.account_id = :account_id
               AND s.status = :subscription_status
               AND p.status = :plan_status
             LIMIT 1' . ($lock ? ' FOR UPDATE' : '');
        $statement = $pdo->prepare($sql);
        $statement->execute([
            'subscription_id' => $subscriptionId,
            'account_id' => $accountId,
            'subscription_status' => 'active',
            'plan_status' => 'active',
        ]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('An active subscription owned by the account is required.');
        }

        return [
            'plan_id' => (int) $row['plan_id'],
            'current_period_ends_at' => is_string($row['current_period_ends_at'])
                ? $row['current_period_ends_at']
                : null,
        ];
    }

    /** @return array<string,mixed> */
    private function domainForAccount(PDO $pdo, int $accountId, string $publicId, bool $lock): array
    {
        $statement = $pdo->prepare(
            'SELECT id, public_id, account_id, subscription_id, label, hostname, status,
                    routing_status, ssl_status, reserved_until, renews_at, expires_at
             FROM domain_registrations
             WHERE public_id = :public_id AND account_id = :account_id
             LIMIT 1' . ($lock ? ' FOR UPDATE' : '')
        );
        $statement->execute(['public_id' => $publicId, 'account_id' => $accountId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('The Domain was not found for this account.');
        }

        return $row;
    }

    private function assertHostnameAvailable(PDO $pdo, string $hostname): void
    {
        $statement = $pdo->prepare(
            'SELECT id FROM domain_registrations WHERE hostname = :hostname LIMIT 1 FOR UPDATE'
        );
        $statement->execute(['hostname' => $hostname]);
        if ($statement->fetchColumn()) {
            throw new RuntimeException('The Domain is not available.');
        }
    }

    /**
     * @return array{entitlement_bundle_id:int,entitlement_bundle_public_id:string,pod_license_id:int,pod_license_public_id:string,homeserver_license_id:int,homeserver_license_public_id:string}
     */
    private function createEntitlementBundleAndLicenses(
        PDO $pdo,
        int $accountId,
        int $subscriptionId,
        int $domainId,
        int $planId,
        ?string $periodEnd,
        DateTimeImmutable $now
    ): array {
        $entitlements = $pdo->prepare(
            'SELECT entitlement_key, value_type, value_json
             FROM plan_entitlements WHERE plan_id = :plan_id ORDER BY entitlement_key'
        );
        $entitlements->execute(['plan_id' => $planId]);
        $rows = $entitlements->fetchAll(PDO::FETCH_ASSOC);
        $keys = array_map(static fn (array $row): string => (string) $row['entitlement_key'], $rows);
        $missing = array_values(array_diff(PlanCatalogService::REQUIRED_ENTITLEMENTS, $keys));
        if ($missing !== []) {
            throw new RuntimeException('The active plan is missing required entitlements: ' . implode(', ', $missing));
        }

        $snapshot = [];
        foreach ($rows as $row) {
            $snapshot[(string) $row['entitlement_key']] = [
                'value_type' => (string) $row['value_type'],
                'value' => json_decode((string) $row['value_json'], true, 32, JSON_THROW_ON_ERROR),
            ];
        }
        $snapshotHash = hash(
            'sha256',
            json_encode($this->canonicalize($snapshot), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)
        );
        $bundlePublicId = 'BUNDLE-' . strtoupper(bin2hex(random_bytes(8)));
        $bundle = $pdo->prepare(
            'INSERT INTO entitlement_bundles
             (public_id, account_id, subscription_id, domain_registration_id, plan_id, snapshot_hash, created_at, updated_at)
             VALUES
             (:public_id, :account_id, :subscription_id, :domain_id, :plan_id, :snapshot_hash, :created_at, :updated_at)'
        );
        $bundle->execute([
            'public_id' => $bundlePublicId,
            'account_id' => $accountId,
            'subscription_id' => $subscriptionId,
            'domain_id' => $domainId,
            'plan_id' => $planId,
            'snapshot_hash' => $snapshotHash,
            'created_at' => $now->format('Y-m-d H:i:s'),
            'updated_at' => $now->format('Y-m-d H:i:s'),
        ]);
        $bundleId = (int) $pdo->lastInsertId();

        $licenses = [];
        foreach (['pod' => 'LIC-POD-', 'homeserver' => 'LIC-HS-'] as $productType => $prefix) {
            $publicId = $prefix . strtoupper(bin2hex(random_bytes(8)));
            $insert = $pdo->prepare(
                'INSERT INTO licenses
                 (public_id, account_id, subscription_id, domain_registration_id, entitlement_bundle_id,
                  product_type, status, starts_at, renews_at, expires_at, created_at, updated_at)
                 VALUES
                 (:public_id, :account_id, :subscription_id, :domain_id, :bundle_id,
                  :product_type, :status, :starts_at, :renews_at, :expires_at, :created_at, :updated_at)'
            );
            $insert->execute([
                'public_id' => $publicId,
                'account_id' => $accountId,
                'subscription_id' => $subscriptionId,
                'domain_id' => $domainId,
                'bundle_id' => $bundleId,
                'product_type' => $productType,
                'status' => 'active',
                'starts_at' => $now->format('Y-m-d H:i:s'),
                'renews_at' => $periodEnd,
                'expires_at' => $periodEnd,
                'created_at' => $now->format('Y-m-d H:i:s'),
                'updated_at' => $now->format('Y-m-d H:i:s'),
            ]);
            $licenseId = (int) $pdo->lastInsertId();
            $copy = $pdo->prepare(
                'INSERT INTO license_entitlements
                 (license_id, entitlement_key, value_type, value_json, source_plan_id, effective_at, created_at, updated_at)
                 SELECT :license_id, entitlement_key, value_type, value_json, plan_id,
                        :effective_at, :created_at, :updated_at
                 FROM plan_entitlements WHERE plan_id = :plan_id'
            );
            $copy->execute([
                'license_id' => $licenseId,
                'effective_at' => $now->format('Y-m-d H:i:s'),
                'created_at' => $now->format('Y-m-d H:i:s'),
                'updated_at' => $now->format('Y-m-d H:i:s'),
                'plan_id' => $planId,
            ]);
            $licenses[$productType] = ['id' => $licenseId, 'public_id' => $publicId];
        }

        return [
            'entitlement_bundle_id' => $bundleId,
            'entitlement_bundle_public_id' => $bundlePublicId,
            'pod_license_id' => $licenses['pod']['id'],
            'pod_license_public_id' => $licenses['pod']['public_id'],
            'homeserver_license_id' => $licenses['homeserver']['id'],
            'homeserver_license_public_id' => $licenses['homeserver']['public_id'],
        ];
    }

    private function assertNoActiveHold(PDO $pdo, int $domainId): void
    {
        $statement = $pdo->prepare(
            'SELECT id FROM domain_admin_holds
             WHERE domain_registration_id = :domain_id AND status = :status LIMIT 1'
        );
        $statement->execute(['domain_id' => $domainId, 'status' => 'active']);
        if ($statement->fetchColumn()) {
            throw new RuntimeException('The Domain is under an administrative hold.');
        }
    }

    private function integerEntitlement(PDO $pdo, int $domainId, string $key): int
    {
        $statement = $pdo->prepare(
            'SELECT le.value_json
             FROM license_entitlements le
             JOIN licenses l ON l.id = le.license_id
             WHERE l.domain_registration_id = :domain_id
               AND l.product_type = :product_type
               AND le.entitlement_key = :entitlement_key
             LIMIT 1'
        );
        $statement->execute([
            'domain_id' => $domainId,
            'product_type' => 'pod',
            'entitlement_key' => $key,
        ]);
        $value = $statement->fetchColumn();
        if (!is_string($value)) {
            throw new RuntimeException('The required Domain entitlement is unavailable.');
        }
        $decoded = json_decode($value, true, 16, JSON_THROW_ON_ERROR);
        if (!is_int($decoded) || $decoded < 0) {
            throw new RuntimeException('The Domain entitlement is invalid.');
        }

        return $decoded;
    }

    private function updateDomainAndLicenseState(
        PDO $pdo,
        int $domainId,
        string $domainStatus,
        DateTimeImmutable $now,
        ?string $periodEnd = null
    ): void {
        $routingStatus = in_array($domainStatus, ['expired', 'released', 'transferred'], true)
            ? 'disabled'
            : null;
        $sslStatus = in_array($domainStatus, ['expired', 'released', 'transferred'], true)
            ? 'disabled'
            : null;
        $update = $pdo->prepare(
            'UPDATE domain_registrations
             SET status = :status,
                 routing_status = COALESCE(:routing_status, routing_status),
                 ssl_status = COALESCE(:ssl_status, ssl_status),
                 suspended_at = :suspended_at,
                 released_at = :released_at,
                 updated_at = :updated_at
             WHERE id = :id'
        );
        $update->execute([
            'status' => $domainStatus,
            'routing_status' => $routingStatus,
            'ssl_status' => $sslStatus,
            'suspended_at' => $domainStatus === 'suspended' ? $now->format('Y-m-d H:i:s') : null,
            'released_at' => $domainStatus === 'released' ? $now->format('Y-m-d H:i:s') : null,
            'updated_at' => $now->format('Y-m-d H:i:s'),
            'id' => $domainId,
        ]);

        $licenseStatus = match ($domainStatus) {
            'active' => 'active',
            'grace' => 'grace',
            'suspended' => 'suspended',
            'expired' => 'expired',
            'released', 'transferred' => 'terminated',
            default => null,
        };
        if ($licenseStatus !== null) {
            $this->setLicenseState($pdo, $domainId, $licenseStatus, $now, null, $periodEnd);
        }
        if (in_array($domainStatus, ['released', 'transferred'], true)) {
            $pdo->prepare(
                'UPDATE domain_aliases SET status = :status, routing_status = :routing_status,
                 ssl_status = :ssl_status, updated_at = :updated_at WHERE domain_registration_id = :domain_id'
            )->execute([
                'status' => 'removed',
                'routing_status' => 'disabled',
                'ssl_status' => 'disabled',
                'updated_at' => $now->format('Y-m-d H:i:s'),
                'domain_id' => $domainId,
            ]);
            $pdo->prepare(
                'UPDATE domain_redirects SET status = :status, updated_at = :updated_at
                 WHERE domain_registration_id = :domain_id'
            )->execute([
                'status' => 'removed',
                'updated_at' => $now->format('Y-m-d H:i:s'),
                'domain_id' => $domainId,
            ]);
        }
    }

    private function setLicenseState(
        PDO $pdo,
        int $domainId,
        string $licenseStatus,
        DateTimeImmutable $now,
        ?DateTimeImmutable $renewsAt = null,
        DateTimeImmutable|string|null $expiresAt = null
    ): void {
        $expiresValue = $expiresAt instanceof DateTimeImmutable
            ? $expiresAt->format('Y-m-d H:i:s')
            : $expiresAt;
        $statement = $pdo->prepare(
            'UPDATE licenses
             SET status = :status,
                 renews_at = COALESCE(:renews_at, renews_at),
                 expires_at = COALESCE(:expires_at, expires_at),
                 suspended_at = :suspended_at,
                 terminated_at = :terminated_at,
                 updated_at = :updated_at
             WHERE domain_registration_id = :domain_id'
        );
        $statement->execute([
            'status' => $licenseStatus,
            'renews_at' => $renewsAt?->format('Y-m-d H:i:s'),
            'expires_at' => $expiresValue,
            'suspended_at' => $licenseStatus === 'suspended' ? $now->format('Y-m-d H:i:s') : null,
            'terminated_at' => $licenseStatus === 'terminated' ? $now->format('Y-m-d H:i:s') : null,
            'updated_at' => $now->format('Y-m-d H:i:s'),
            'domain_id' => $domainId,
        ]);
    }

    /** @param array<string,mixed> $metadata */
    private function recordEvent(
        PDO $pdo,
        int $accountId,
        int $domainId,
        string $requestId,
        string $eventType,
        array $metadata
    ): void {
        $statement = $pdo->prepare(
            'INSERT INTO domain_events
             (request_id, account_id, domain_registration_id, event_type, result, metadata_json, created_at)
             VALUES
             (:request_id, :account_id, :domain_id, :event_type, :result, :metadata_json, :created_at)'
        );
        $statement->execute([
            'request_id' => $requestId,
            'account_id' => $accountId,
            'domain_id' => $domainId,
            'event_type' => $eventType,
            'result' => 'success',
            'metadata_json' => json_encode($metadata, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            'created_at' => (new DateTimeImmutable('now'))->format('Y-m-d H:i:s'),
        ]);
    }

    private function normalizeLabel(string $label): string
    {
        $label = strtolower(trim($label));
        if (!preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/', $label)) {
            throw new InvalidArgumentException('The Domain label is invalid.');
        }

        return $label;
    }

    private function normalizeHostname(string $hostname): string
    {
        $hostname = strtolower(rtrim(trim($hostname), '.'));
        if (mb_strlen($hostname) > 253 || !preg_match(
            '/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/',
            $hostname
        )) {
            throw new InvalidArgumentException('The alias hostname is invalid.');
        }

        return $hostname;
    }

    private function assertRequestIdentity(int $accountId, string $requestId, string $idempotencyKey): void
    {
        if ($accountId < 1 || trim($requestId) === '' || trim($idempotencyKey) === '') {
            throw new InvalidArgumentException('The request identity is invalid.');
        }
        if (mb_strlen($requestId) > 64 || mb_strlen($idempotencyKey) > 128) {
            throw new InvalidArgumentException('The request identity exceeds the supported length.');
        }
    }

    private function canonicalize(mixed $value): mixed
    {
        if (!is_array($value)) {
            return $value;
        }

        if (!array_is_list($value)) {
            ksort($value);
        }
        foreach ($value as $key => $item) {
            $value[$key] = $this->canonicalize($item);
        }

        return $value;
    }
}

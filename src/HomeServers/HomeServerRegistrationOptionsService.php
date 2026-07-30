<?php

declare(strict_types=1);

namespace Vp3\HomeServers;

use PDO;
use RuntimeException;
use Vp3\Database;

final class HomeServerRegistrationOptionsService
{
    public function __construct(private readonly Database $database)
    {
    }

    /** @return list<array<string,mixed>> */
    public function eligibleLicenses(int $accountId): array
    {
        if ($accountId < 1) {
            throw new RuntimeException('A valid VP3 account is required.');
        }

        $statement = $this->database->pdo()->prepare(
            "SELECT l.id,l.public_id,l.status,l.renews_at,l.expires_at,
                    d.public_id AS domain_public_id,d.hostname,d.status AS domain_status,
                    s.public_id AS subscription_public_id,s.status AS subscription_status,
                    p.name AS plan_name,p.code AS plan_code
             FROM licenses l
             JOIN domain_registrations d ON d.id=l.domain_registration_id AND d.account_id=l.account_id
             JOIN subscriptions s ON s.id=l.subscription_id AND s.account_id=l.account_id
             JOIN plans p ON p.id=s.plan_id
             LEFT JOIN homeserver_devices hs ON hs.license_id=l.id AND hs.status<>'revoked'
             WHERE l.account_id=:account
               AND l.product_type='homeserver'
               AND l.status IN ('active','grace')
               AND s.status IN ('trialing','active','grace')
               AND d.status IN ('active','grace')
               AND hs.id IS NULL
             ORDER BY d.hostname,l.id"
        );
        $statement->execute(['account' => $accountId]);

        return array_map(static fn (array $row): array => [
            'license_id' => (int) $row['id'],
            'license_public_id' => (string) $row['public_id'],
            'status' => (string) $row['status'],
            'renews_at' => $row['renews_at'] !== null ? (string) $row['renews_at'] : null,
            'expires_at' => $row['expires_at'] !== null ? (string) $row['expires_at'] : null,
            'domain_public_id' => (string) $row['domain_public_id'],
            'hostname' => (string) $row['hostname'],
            'domain_status' => (string) $row['domain_status'],
            'subscription_public_id' => (string) $row['subscription_public_id'],
            'subscription_status' => (string) $row['subscription_status'],
            'plan_name' => (string) $row['plan_name'],
            'plan_code' => (string) $row['plan_code'],
        ], $statement->fetchAll(PDO::FETCH_ASSOC));
    }
}

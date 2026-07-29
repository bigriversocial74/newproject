<?php

declare(strict_types=1);

namespace Vp3\Licensing;

use DateTimeImmutable;
use InvalidArgumentException;
use PDO;
use RuntimeException;
use Vp3\Database;

final class LicenseLifecycleService
{
    /** @var list<string> */
    private const STATES = ['active', 'grace', 'suspended', 'expired', 'terminated'];

    public function __construct(private readonly Database $database)
    {
    }

    /**
     * @return array{domain_public_id:string,entitlement_bundle_id:int,pod_license_public_id:string,homeserver_license_public_id:string,status:string}
     */
    public function assertPairedBundle(int $accountId, string $domainPublicId): array
    {
        $statement = $this->database->pdo()->prepare(
            'SELECT d.public_id AS domain_public_id,
                    MIN(l.entitlement_bundle_id) AS bundle_min,
                    MAX(l.entitlement_bundle_id) AS bundle_max,
                    SUM(l.product_type = :pod) AS pod_count,
                    SUM(l.product_type = :homeserver) AS homeserver_count,
                    MAX(CASE WHEN l.product_type = :pod_case THEN l.public_id END) AS pod_public_id,
                    MAX(CASE WHEN l.product_type = :homeserver_case THEN l.public_id END) AS homeserver_public_id,
                    MIN(l.status) AS status_min,
                    MAX(l.status) AS status_max,
                    COUNT(*) AS license_count
             FROM domain_registrations d
             JOIN licenses l ON l.domain_registration_id = d.id
             WHERE d.account_id = :account_id AND d.public_id = :domain_public_id
             GROUP BY d.id, d.public_id'
        );
        $statement->execute([
            'pod' => 'pod',
            'homeserver' => 'homeserver',
            'pod_case' => 'pod',
            'homeserver_case' => 'homeserver',
            'account_id' => $accountId,
            'domain_public_id' => trim($domainPublicId),
        ]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('The Domain license pair was not found.');
        }
        if (
            (int) $row['license_count'] !== 2
            || (int) $row['pod_count'] !== 1
            || (int) $row['homeserver_count'] !== 1
            || (int) $row['bundle_min'] !== (int) $row['bundle_max']
            || $row['status_min'] !== $row['status_max']
        ) {
            throw new RuntimeException('The Domain license pair is inconsistent.');
        }

        return [
            'domain_public_id' => (string) $row['domain_public_id'],
            'entitlement_bundle_id' => (int) $row['bundle_min'],
            'pod_license_public_id' => (string) $row['pod_public_id'],
            'homeserver_license_public_id' => (string) $row['homeserver_public_id'],
            'status' => (string) $row['status_min'],
        ];
    }

    /** @return array{domain_public_id:string,status:string,license_count:int} */
    public function transitionForDomain(
        int $accountId,
        string $domainPublicId,
        string $status,
        string $requestId
    ): array {
        if ($accountId < 1 || trim($domainPublicId) === '' || trim($requestId) === '') {
            throw new InvalidArgumentException('The license transition identity is invalid.');
        }
        if (!in_array($status, self::STATES, true)) {
            throw new InvalidArgumentException('The license status is invalid.');
        }

        return $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $domainPublicId,
            $status,
            $requestId
        ): array {
            $domain = $pdo->prepare(
                'SELECT id, public_id FROM domain_registrations
                 WHERE account_id = :account_id AND public_id = :public_id
                 LIMIT 1 FOR UPDATE'
            );
            $domain->execute(['account_id' => $accountId, 'public_id' => trim($domainPublicId)]);
            $row = $domain->fetch(PDO::FETCH_ASSOC);
            if (!is_array($row)) {
                throw new RuntimeException('The Domain was not found for this account.');
            }
            $licenseRows = $pdo->prepare(
                'SELECT id FROM licenses WHERE domain_registration_id = :domain_id FOR UPDATE'
            );
            $licenseRows->execute(['domain_id' => $row['id']]);
            if (count($licenseRows->fetchAll(PDO::FETCH_COLUMN)) !== 2) {
                throw new RuntimeException('The Domain does not have exactly two licenses.');
            }
            $now = new DateTimeImmutable('now');
            $update = $pdo->prepare(
                'UPDATE licenses
                 SET status = :status,
                     suspended_at = :suspended_at,
                     terminated_at = :terminated_at,
                     updated_at = :updated_at
                 WHERE domain_registration_id = :domain_id'
            );
            $update->execute([
                'status' => $status,
                'suspended_at' => $status === 'suspended' ? $now->format('Y-m-d H:i:s') : null,
                'terminated_at' => $status === 'terminated' ? $now->format('Y-m-d H:i:s') : null,
                'updated_at' => $now->format('Y-m-d H:i:s'),
                'domain_id' => $row['id'],
            ]);
            $event = $pdo->prepare(
                'INSERT INTO domain_events
                 (request_id, account_id, domain_registration_id, event_type, result, metadata_json, created_at)
                 VALUES
                 (:request_id, :account_id, :domain_id, :event_type, :result, :metadata_json, :created_at)'
            );
            $event->execute([
                'request_id' => trim($requestId),
                'account_id' => $accountId,
                'domain_id' => $row['id'],
                'event_type' => 'domain_license_state_changed',
                'result' => 'success',
                'metadata_json' => json_encode(['status' => $status], JSON_THROW_ON_ERROR),
                'created_at' => $now->format('Y-m-d H:i:s'),
            ]);

            return [
                'domain_public_id' => (string) $row['public_id'],
                'status' => $status,
                'license_count' => $update->rowCount(),
            ];
        });
    }
}

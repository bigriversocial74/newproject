<?php

declare(strict_types=1);

namespace Vp3\Licensing;

use Vp3\Database;
use Vp3\DomainCodes\DomainRegistryService;

final class DomainLicenseBundleService
{
    private readonly DomainRegistryService $domains;

    public function __construct(Database $database)
    {
        $this->domains = new DomainRegistryService($database);
    }

    /**
     * @return array{domain_id:int,domain_public_id:string,hostname:string,entitlement_bundle_id:int,entitlement_bundle_public_id:string,pod_license_id:int,pod_license_public_id:string,homeserver_license_id:int,homeserver_license_public_id:string}
     */
    public function activateDomainBundle(
        int $accountId,
        int $subscriptionId,
        string $label,
        string $requestId,
        string $idempotencyKey
    ): array {
        return $this->domains->registerAndActivate(
            $accountId,
            $subscriptionId,
            $label,
            $requestId,
            $idempotencyKey
        );
    }
}

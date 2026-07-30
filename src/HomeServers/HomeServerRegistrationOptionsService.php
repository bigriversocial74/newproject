<?php

declare(strict_types=1);

namespace Vp3\HomeServers;

use Vp3\Database;

final class HomeServerRegistrationOptionsService
{
    private readonly HomeServerLicenseIdentityResolver $licenses;

    public function __construct(Database $database)
    {
        $this->licenses = new HomeServerLicenseIdentityResolver($database);
    }

    /** @return list<array<string,mixed>> */
    public function eligibleLicenses(int $accountId): array
    {
        return $this->licenses->eligibleLicenses($accountId);
    }
}

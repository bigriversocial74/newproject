<?php

declare(strict_types=1);

use Vp3\Billing\SubscriptionLifecycleService;
use Vp3\Catalog\PlanCatalogService;
use Vp3\Database;
use Vp3\DomainCodes\DomainRegistryService;
use Vp3\Licensing\DomainLicenseBundleService;
use Vp3\Licensing\LicenseLifecycleService;

$projectRoot = dirname(__DIR__);
$autoload = $projectRoot . '/vendor/autoload.php';
if (is_file($autoload)) {
    require $autoload;
} else {
    spl_autoload_register(static function (string $class) use ($projectRoot): void {
        $prefix = 'Vp3\\';
        if (!str_starts_with($class, $prefix)) {
            return;
        }

        $path = $projectRoot . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($path)) {
            require $path;
        }
    });
}

$dsn = getenv('VP3_TEST_DSN') ?: '';
$username = getenv('VP3_TEST_DB_USER') ?: 'root';
$password = getenv('VP3_TEST_DB_PASSWORD') ?: '';
if ($dsn === '') {
    fwrite(STDERR, "VP3_TEST_DSN is required.\n");
    exit(1);
}

$database = new Database([
    'dsn' => $dsn,
    'username' => $username,
    'password' => $password,
    'options' => [
        \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
        \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
        \PDO::ATTR_EMULATE_PREPARES => false,
    ],
]);
$pdo = $database->pdo();
$plans = new PlanCatalogService($database);
$subscriptions = new SubscriptionLifecycleService($database);
$domains = new DomainRegistryService($database);
$bundles = new DomainLicenseBundleService($database);
$licenses = new LicenseLifecycleService($database);
$failures = [];

$expectException = static function (callable $callback, string $message) use (&$failures): void {
    try {
        $callback();
        $failures[] = $message;
    } catch (\Throwable) {
        // Expected.
    }
};

$createAccount = static function (string $name) use ($pdo): int {
    $now = (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s');
    $publicId = 'VP3-T3-' . strtoupper(bin2hex(random_bytes(5)));
    $statement = $pdo->prepare(
        'INSERT INTO accounts (public_id, account_type, status, display_name, created_at, updated_at)
         VALUES (:public_id, :type, :status, :display_name, :created_at, :updated_at)'
    );
    $statement->execute([
        'public_id' => $publicId,
        'type' => 'individual',
        'status' => 'active',
        'display_name' => $name,
        'created_at' => $now,
        'updated_at' => $now,
    ]);

    return (int) $pdo->lastInsertId();
};

try {
    $accountA = $createAccount('Phase Three Account A');
    $accountB = $createAccount('Phase Three Account B');

    $planId = (int) $pdo->query("SELECT id FROM plans WHERE code = 'standard' AND status = 'active' LIMIT 1")->fetchColumn();
    if ($planId < 1) {
        $failures[] = 'The active standard plan seed is missing.';
    } else {
        try {
            $plans->assertRequiredEntitlements($planId);
        } catch (\Throwable $exception) {
            $failures[] = 'The standard plan is incomplete: ' . $exception->getMessage();
        }
        $entitlementCount = $pdo->prepare('SELECT COUNT(*) FROM plan_entitlements WHERE plan_id = :plan_id');
        $entitlementCount->execute(['plan_id' => $planId]);
        if ((int) $entitlementCount->fetchColumn() !== count(PlanCatalogService::REQUIRED_ENTITLEMENTS)) {
            $failures[] = 'The standard plan does not contain exactly the required entitlement set.';
        }
    }

    $periodStart = new \DateTimeImmutable('now');
    $periodEnd = $periodStart->modify('+1 month');
    $subscriptionA = $subscriptions->create(
        $accountA,
        $planId,
        'active',
        'REQ-SUB-A-' . strtoupper(bin2hex(random_bytes(5))),
        $periodStart,
        $periodEnd
    );
    $subscriptionB = $subscriptions->create(
        $accountB,
        $planId,
        'active',
        'REQ-SUB-B-' . strtoupper(bin2hex(random_bytes(5))),
        $periodStart,
        $periodEnd
    );
    $inactiveSubscription = $subscriptions->create(
        $accountA,
        $planId,
        'canceled',
        'REQ-SUB-C-' . strtoupper(bin2hex(random_bytes(5))),
        $periodStart,
        $periodEnd
    );

    $expectException(
        static fn () => $domains->availability('invalid_label'),
        'An invalid Domain label was accepted.'
    );

    $reservedLabel = 'reserve-' . strtolower(bin2hex(random_bytes(4)));
    $availability = $domains->availability($reservedLabel);
    if ($availability['available'] !== true) {
        $failures[] = 'A new Domain label was not reported as available.';
    }

    $reserveRequestId = 'REQ-RES-' . strtoupper(bin2hex(random_bytes(6)));
    $reserveIdempotency = 'IDEM-RES-' . strtoupper(bin2hex(random_bytes(6)));
    $reserved = $domains->reserveDomain(
        $accountA,
        $subscriptionA['id'],
        $reservedLabel,
        (new \DateTimeImmutable('now'))->modify('+2 hours'),
        $reserveRequestId,
        $reserveIdempotency
    );
    $reservedReplay = $domains->reserveDomain(
        $accountA,
        $subscriptionA['id'],
        $reservedLabel,
        new \DateTimeImmutable($reserved['reserved_until']),
        $reserveRequestId,
        $reserveIdempotency
    );
    if ($reservedReplay !== $reserved) {
        $failures[] = 'The Domain reservation idempotent replay did not return the original result.';
    }
    if ($domains->availability($reservedLabel)['available'] !== false) {
        $failures[] = 'A reserved Domain remained available.';
    }
    $reservedLicenseCount = $pdo->prepare('SELECT COUNT(*) FROM licenses WHERE domain_registration_id = :domain_id');
    $reservedLicenseCount->execute(['domain_id' => $reserved['domain_id']]);
    if ((int) $reservedLicenseCount->fetchColumn() !== 0) {
        $failures[] = 'A reservation created licenses before activation.';
    }

    $expectException(
        static fn () => $domains->activateReservedDomain(
            $accountB,
            $reserved['domain_public_id'],
            'REQ-XACCOUNT-' . strtoupper(bin2hex(random_bytes(5))),
            'IDEM-XACCOUNT-' . strtoupper(bin2hex(random_bytes(5)))
        ),
        'Cross-account Domain activation was not rejected.'
    );

    $activationRequestId = 'REQ-ACT-' . strtoupper(bin2hex(random_bytes(6)));
    $activationIdempotency = 'IDEM-ACT-' . strtoupper(bin2hex(random_bytes(6)));
    $activated = $domains->activateReservedDomain(
        $accountA,
        $reserved['domain_public_id'],
        $activationRequestId,
        $activationIdempotency
    );
    $activatedReplay = $domains->activateReservedDomain(
        $accountA,
        $reserved['domain_public_id'],
        $activationRequestId,
        $activationIdempotency
    );
    if ($activatedReplay !== $activated) {
        $failures[] = 'Reserved Domain activation replay did not return the original result.';
    }

    $pair = $licenses->assertPairedBundle($accountA, $activated['domain_public_id']);
    if ($pair['entitlement_bundle_id'] !== $activated['entitlement_bundle_id']) {
        $failures[] = 'The POD and HomeServer licenses are not linked to the same entitlement bundle.';
    }
    $products = $pdo->prepare(
        'SELECT product_type, entitlement_bundle_id FROM licenses
         WHERE domain_registration_id = :domain_id ORDER BY product_type'
    );
    $products->execute(['domain_id' => $activated['domain_id']]);
    $productRows = $products->fetchAll();
    $productTypes = array_column($productRows, 'product_type');
    sort($productTypes);
    if (count($productRows) !== 2 || $productTypes !== ['homeserver', 'pod']) {
        $failures[] = 'The active Domain does not have exactly one POD and one HomeServer license.';
    }
    if (count(array_unique(array_map('intval', array_column($productRows, 'entitlement_bundle_id')))) !== 1) {
        $failures[] = 'The paired licenses reference different entitlement bundles.';
    }
    $copiedEntitlements = $pdo->prepare(
        'SELECT COUNT(*) FROM license_entitlements le
         JOIN licenses l ON l.id = le.license_id
         WHERE l.domain_registration_id = :domain_id'
    );
    $copiedEntitlements->execute(['domain_id' => $activated['domain_id']]);
    if ((int) $copiedEntitlements->fetchColumn() !== count(PlanCatalogService::REQUIRED_ENTITLEMENTS) * 2) {
        $failures[] = 'The complete entitlement snapshot was not copied to both licenses.';
    }

    $expectException(
        static fn () => $domains->reserveDomain(
            $accountA,
            $subscriptionA['id'],
            'different-' . strtolower(bin2hex(random_bytes(3))),
            (new \DateTimeImmutable('now'))->modify('+2 hours'),
            $reserveRequestId,
            $reserveIdempotency
        ),
        'Idempotency payload mismatch was not rejected.'
    );

    $directLabel = 'direct-' . strtolower(bin2hex(random_bytes(4)));
    $directRequestId = 'REQ-DIRECT-' . strtoupper(bin2hex(random_bytes(5)));
    $directIdempotency = 'IDEM-DIRECT-' . strtoupper(bin2hex(random_bytes(5)));
    $direct = $bundles->activateDomainBundle(
        $accountA,
        $subscriptionA['id'],
        $directLabel,
        $directRequestId,
        $directIdempotency
    );
    $directReplay = $bundles->activateDomainBundle(
        $accountA,
        $subscriptionA['id'],
        $directLabel,
        $directRequestId,
        $directIdempotency
    );
    if ($directReplay !== $direct) {
        $failures[] = 'Direct Domain bundle replay did not return the original result.';
    }

    $expectException(
        static fn () => $bundles->activateDomainBundle(
            $accountA,
            $subscriptionA['id'],
            $directLabel,
            'REQ-DUP-' . strtoupper(bin2hex(random_bytes(5))),
            'IDEM-DUP-' . strtoupper(bin2hex(random_bytes(5)))
        ),
        'Duplicate Domain ownership was not rejected.'
    );
    $expectException(
        static fn () => $bundles->activateDomainBundle(
            $accountA,
            $subscriptionB['id'],
            'cross-sub-' . strtolower(bin2hex(random_bytes(3))),
            'REQ-CROSS-SUB-' . strtoupper(bin2hex(random_bytes(5))),
            'IDEM-CROSS-SUB-' . strtoupper(bin2hex(random_bytes(5)))
        ),
        'A subscription owned by another account was accepted.'
    );
    $expectException(
        static fn () => $bundles->activateDomainBundle(
            $accountA,
            $inactiveSubscription['id'],
            'inactive-' . strtolower(bin2hex(random_bytes(3))),
            'REQ-INACTIVE-' . strtoupper(bin2hex(random_bytes(5))),
            'IDEM-INACTIVE-' . strtoupper(bin2hex(random_bytes(5)))
        ),
        'An inactive subscription was accepted for Domain activation.'
    );

    $newRenewal = (new \DateTimeImmutable('now'))->modify('+30 days');
    $newExpiration = $newRenewal->modify('+2 days');
    $renewed = $domains->renewDomain(
        $accountA,
        $activated['domain_public_id'],
        $newRenewal,
        $newExpiration,
        'REQ-RENEW-' . strtoupper(bin2hex(random_bytes(5))),
        'IDEM-RENEW-' . strtoupper(bin2hex(random_bytes(5)))
    );
    if ($renewed['status'] !== 'active') {
        $failures[] = 'Domain renewal did not preserve active state.';
    }
    $licenseDates = $pdo->prepare(
        'SELECT COUNT(*) FROM licenses
         WHERE domain_registration_id = :domain_id AND status = :status
           AND renews_at = :renews_at AND expires_at = :expires_at'
    );
    $licenseDates->execute([
        'domain_id' => $activated['domain_id'],
        'status' => 'active',
        'renews_at' => $newRenewal->format('Y-m-d H:i:s'),
        'expires_at' => $newExpiration->format('Y-m-d H:i:s'),
    ]);
    if ((int) $licenseDates->fetchColumn() !== 2) {
        $failures[] = 'Domain renewal did not synchronize both license dates.';
    }

    $routing = $domains->updateRoutingAndSslStatus(
        $accountA,
        $activated['domain_public_id'],
        'active',
        'active',
        'REQ-ROUTE-' . strtoupper(bin2hex(random_bytes(5))),
        'IDEM-ROUTE-' . strtoupper(bin2hex(random_bytes(5)))
    );
    if ($routing['routing_status'] !== 'active' || $routing['ssl_status'] !== 'active') {
        $failures[] = 'Routing and SSL status were not updated.';
    }

    $alias = $domains->addAlias(
        $accountA,
        $activated['domain_public_id'],
        'alias-' . strtolower(bin2hex(random_bytes(4))) . '.example.com',
        'REQ-ALIAS-' . strtoupper(bin2hex(random_bytes(5))),
        'IDEM-ALIAS-' . strtoupper(bin2hex(random_bytes(5)))
    );
    if ($alias['status'] !== 'pending') {
        $failures[] = 'Domain alias creation did not begin in pending state.';
    }
    $redirect = $domains->addRedirect(
        $accountA,
        $activated['domain_public_id'],
        '/legacy-' . strtolower(bin2hex(random_bytes(3))),
        'https://example.com/new-location',
        301,
        'REQ-REDIR-' . strtoupper(bin2hex(random_bytes(5))),
        'IDEM-REDIR-' . strtoupper(bin2hex(random_bytes(5)))
    );
    if ($redirect['http_status'] !== 301 || $redirect['status'] !== 'active') {
        $failures[] = 'Domain redirect creation failed.';
    }

    $hold = $domains->placeAdministrativeHold(
        $accountA,
        $activated['domain_public_id'],
        'Phase 3 certification hold',
        'REQ-HOLD-' . strtoupper(bin2hex(random_bytes(5))),
        'IDEM-HOLD-' . strtoupper(bin2hex(random_bytes(5)))
    );
    $heldStates = $pdo->prepare(
        'SELECT d.status AS domain_status, MIN(l.status) AS license_min, MAX(l.status) AS license_max
         FROM domain_registrations d JOIN licenses l ON l.domain_registration_id = d.id
         WHERE d.id = :domain_id GROUP BY d.id, d.status'
    );
    $heldStates->execute(['domain_id' => $activated['domain_id']]);
    $held = $heldStates->fetch();
    if (!is_array($held) || $held['domain_status'] !== 'suspended' || $held['license_min'] !== 'suspended' || $held['license_max'] !== 'suspended') {
        $failures[] = 'Administrative hold did not suspend the Domain and both licenses.';
    }
    $expectException(
        static fn () => $domains->renewDomain(
            $accountA,
            $activated['domain_public_id'],
            $newRenewal->modify('+1 month'),
            $newExpiration->modify('+1 month'),
            'REQ-HOLD-RENEW-' . strtoupper(bin2hex(random_bytes(5))),
            'IDEM-HOLD-RENEW-' . strtoupper(bin2hex(random_bytes(5)))
        ),
        'A Domain under administrative hold was renewed.'
    );
    $releasedHold = $domains->releaseAdministrativeHold(
        $accountA,
        $hold['hold_public_id'],
        'REQ-HOLD-REL-' . strtoupper(bin2hex(random_bytes(5))),
        'IDEM-HOLD-REL-' . strtoupper(bin2hex(random_bytes(5)))
    );
    if ($releasedHold['domain_status'] !== 'active') {
        $failures[] = 'Releasing the final administrative hold did not reactivate the Domain.';
    }

    $transferToken = $domains->generateTransferToken();
    $transfer = $domains->requestTransfer(
        $accountA,
        $activated['domain_public_id'],
        $accountB,
        $transferToken,
        (new \DateTimeImmutable('now'))->modify('+2 days'),
        'REQ-XFER-' . strtoupper(bin2hex(random_bytes(5))),
        'IDEM-XFER-' . strtoupper(bin2hex(random_bytes(5)))
    );
    if ($transfer['status'] !== 'pending') {
        $failures[] = 'Domain transfer foundation did not create a pending request.';
    }
    $storedTransfer = $pdo->prepare(
        'SELECT token_hash FROM domain_transfer_requests WHERE public_id = :public_id LIMIT 1'
    );
    $storedTransfer->execute(['public_id' => $transfer['transfer_public_id']]);
    $storedTokenHash = $storedTransfer->fetchColumn();
    if (!is_string($storedTokenHash) || $storedTokenHash !== hash('sha256', $transferToken) || $storedTokenHash === $transferToken) {
        $failures[] = 'The transfer token was not stored exclusively as a secure hash.';
    }
    $activeTransferCount = $pdo->prepare(
        'SELECT COUNT(*) FROM domain_transfer_active WHERE domain_registration_id = :domain_id'
    );
    $activeTransferCount->execute(['domain_id' => $activated['domain_id']]);
    if ((int) $activeTransferCount->fetchColumn() !== 1) {
        $failures[] = 'The active transfer guard was not created.';
    }
    $receiptResponse = $pdo->prepare(
        'SELECT response_json FROM domain_request_receipts
         WHERE account_id = :account_id AND operation = :operation AND idempotency_key LIKE :prefix LIMIT 1'
    );
    $receiptResponse->execute([
        'account_id' => $accountA,
        'operation' => 'domain.transfer.request',
        'prefix' => 'IDEM-XFER-%',
    ]);
    $receiptJson = $receiptResponse->fetchColumn();
    if (is_string($receiptJson) && str_contains($receiptJson, $transferToken)) {
        $failures[] = 'A raw transfer token was persisted in an idempotency receipt.';
    }

    $suspended = $domains->suspendDomain(
        $accountA,
        $activated['domain_public_id'],
        'REQ-SUSP-' . strtoupper(bin2hex(random_bytes(5))),
        'IDEM-SUSP-' . strtoupper(bin2hex(random_bytes(5))),
        'Certification suspension'
    );
    if ($suspended['status'] !== 'suspended') {
        $failures[] = 'Domain suspension failed.';
    }
    $expired = $domains->expireDomain(
        $accountA,
        $activated['domain_public_id'],
        'REQ-EXP-' . strtoupper(bin2hex(random_bytes(5))),
        'IDEM-EXP-' . strtoupper(bin2hex(random_bytes(5)))
    );
    if ($expired['status'] !== 'expired') {
        $failures[] = 'Domain expiration failed.';
    }
    $expiredLicenses = $pdo->prepare(
        'SELECT COUNT(*) FROM licenses WHERE domain_registration_id = :domain_id AND status = :status'
    );
    $expiredLicenses->execute(['domain_id' => $activated['domain_id'], 'status' => 'expired']);
    if ((int) $expiredLicenses->fetchColumn() !== 2) {
        $failures[] = 'Domain expiration did not expire both licenses.';
    }

    $released = $domains->releaseDomain(
        $accountA,
        $direct['domain_public_id'],
        'REQ-REL-' . strtoupper(bin2hex(random_bytes(5))),
        'IDEM-REL-' . strtoupper(bin2hex(random_bytes(5)))
    );
    if ($released['status'] !== 'released') {
        $failures[] = 'Domain release failed.';
    }
    $terminatedLicenses = $pdo->prepare(
        'SELECT COUNT(*) FROM licenses WHERE domain_registration_id = :domain_id AND status = :status'
    );
    $terminatedLicenses->execute(['domain_id' => $direct['domain_id'], 'status' => 'terminated']);
    if ((int) $terminatedLicenses->fetchColumn() !== 2) {
        $failures[] = 'Domain release did not terminate both licenses.';
    }

    $pastDue = $subscriptions->transition(
        $accountB,
        $subscriptionB['id'],
        'past_due',
        'REQ-SUB-PD-' . strtoupper(bin2hex(random_bytes(5)))
    );
    $grace = $subscriptions->transition(
        $accountB,
        $subscriptionB['id'],
        'grace',
        'REQ-SUB-GR-' . strtoupper(bin2hex(random_bytes(5))),
        (new \DateTimeImmutable('now'))->modify('+7 days')
    );
    $recovered = $subscriptions->transition(
        $accountB,
        $subscriptionB['id'],
        'active',
        'REQ-SUB-REC-' . strtoupper(bin2hex(random_bytes(5)))
    );
    if ($pastDue['status'] !== 'past_due' || $grace['status'] !== 'grace' || $recovered['status'] !== 'active') {
        $failures[] = 'Subscription lifecycle transitions failed.';
    }
    $expectException(
        static fn () => $subscriptions->transition(
            $accountB,
            $subscriptionB['id'],
            'trialing',
            'REQ-SUB-INVALID-' . strtoupper(bin2hex(random_bytes(5)))
        ),
        'An invalid subscription lifecycle transition was accepted.'
    );

    $eventCount = $pdo->prepare('SELECT COUNT(*) FROM domain_events WHERE account_id = :account_id');
    $eventCount->execute(['account_id' => $accountA]);
    if ((int) $eventCount->fetchColumn() < 12) {
        $failures[] = 'Domain event history is incomplete.';
    }
    $hostnameCount = $pdo->prepare('SELECT COUNT(*) FROM domain_registrations WHERE hostname = :hostname');
    $hostnameCount->execute(['hostname' => $direct['hostname']]);
    if ((int) $hostnameCount->fetchColumn() !== 1) {
        $failures[] = 'The unique Domain hostname contract was violated.';
    }
} catch (\Throwable $exception) {
    $failures[] = get_class($exception) . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL);
    exit(1);
}

echo "Phase 3 Domain registry, plans, subscriptions, lifecycle, and paired-license certification passed.\n";

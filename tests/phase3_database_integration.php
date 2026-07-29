<?php

declare(strict_types=1);

use DateTimeImmutable;
use PDO;
use Throwable;
use Vp3\Database;
use Vp3\Licensing\DomainLicenseBundleService;

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
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ],
]);
$pdo = $database->pdo();
$service = new DomainLicenseBundleService($database);
$failures = [];

try {
    $now = new DateTimeImmutable('now');
    $accountPublicId = 'VP3-T3-' . strtoupper(bin2hex(random_bytes(5)));
    $pdo->prepare(
        'INSERT INTO accounts (public_id, account_type, status, display_name, created_at, updated_at)
         VALUES (:public_id, :type, :status, :display_name, :created_at, :updated_at)'
    )->execute([
        'public_id' => $accountPublicId,
        'type' => 'individual',
        'status' => 'active',
        'display_name' => 'Phase Three Account',
        'created_at' => $now->format('Y-m-d H:i:s'),
        'updated_at' => $now->format('Y-m-d H:i:s'),
    ]);
    $accountId = (int) $pdo->lastInsertId();

    $planId = (int) $pdo->query("SELECT id FROM plans WHERE code='standard' LIMIT 1")->fetchColumn();
    if ($planId < 1) {
        $failures[] = 'Standard plan seed is missing.';
    }

    $subscriptionPublicId = 'SUB-' . strtoupper(bin2hex(random_bytes(8)));
    $pdo->prepare(
        'INSERT INTO subscriptions
         (public_id, account_id, plan_id, status, starts_at, current_period_starts_at, current_period_ends_at, created_at, updated_at)
         VALUES
         (:public_id, :account_id, :plan_id, :status, :starts_at, :period_start, :period_end, :created_at, :updated_at)'
    )->execute([
        'public_id' => $subscriptionPublicId,
        'account_id' => $accountId,
        'plan_id' => $planId,
        'status' => 'active',
        'starts_at' => $now->format('Y-m-d H:i:s'),
        'period_start' => $now->format('Y-m-d H:i:s'),
        'period_end' => $now->modify('+1 month')->format('Y-m-d H:i:s'),
        'created_at' => $now->format('Y-m-d H:i:s'),
        'updated_at' => $now->format('Y-m-d H:i:s'),
    ]);
    $subscriptionId = (int) $pdo->lastInsertId();

    $label = 'phase3-' . strtolower(bin2hex(random_bytes(4)));
    $requestId = 'REQ-' . strtoupper(bin2hex(random_bytes(8)));
    $idempotencyKey = 'IDEM-' . strtoupper(bin2hex(random_bytes(8)));
    $bundle = $service->activateDomainBundle($accountId, $subscriptionId, $label, $requestId, $idempotencyKey);

    $licenseCount = $pdo->prepare('SELECT COUNT(*) FROM licenses WHERE domain_registration_id = :domain_id');
    $licenseCount->execute(['domain_id' => $bundle['domain_id']]);
    if ((int) $licenseCount->fetchColumn() !== 2) {
        $failures[] = 'An active Domain did not receive exactly two licenses.';
    }

    $products = $pdo->prepare('SELECT product_type FROM licenses WHERE domain_registration_id = :domain_id ORDER BY product_type');
    $products->execute(['domain_id' => $bundle['domain_id']]);
    $productTypes = array_column($products->fetchAll(), 'product_type');
    sort($productTypes);
    if ($productTypes !== ['homeserver', 'pod']) {
        $failures[] = 'The Domain license bundle does not contain one POD and one HomeServer license.';
    }

    $entitlementCount = $pdo->prepare(
        'SELECT COUNT(*) FROM license_entitlements le
         JOIN licenses l ON l.id = le.license_id
         WHERE l.domain_registration_id = :domain_id'
    );
    $entitlementCount->execute(['domain_id' => $bundle['domain_id']]);
    if ((int) $entitlementCount->fetchColumn() < 14) {
        $failures[] = 'Plan entitlements were not copied to both licenses.';
    }

    $replayed = $service->activateDomainBundle($accountId, $subscriptionId, $label, $requestId, $idempotencyKey);
    if ($replayed !== $bundle) {
        $failures[] = 'Idempotent Domain bundle retry did not return the original result.';
    }

    $duplicateCount = $pdo->prepare('SELECT COUNT(*) FROM domain_registrations WHERE hostname = :hostname');
    $duplicateCount->execute(['hostname' => $bundle['hostname']]);
    if ((int) $duplicateCount->fetchColumn() !== 1) {
        $failures[] = 'Idempotent retry created a duplicate Domain registration.';
    }

    $duplicateRejected = false;
    try {
        $service->activateDomainBundle(
            $accountId,
            $subscriptionId,
            $label,
            'REQ-' . strtoupper(bin2hex(random_bytes(8))),
            'IDEM-' . strtoupper(bin2hex(random_bytes(8)))
        );
    } catch (Throwable) {
        $duplicateRejected = true;
    }
    if (!$duplicateRejected) {
        $failures[] = 'A second ownership claim for the same Domain label was not rejected.';
    }

    $otherAccountRejected = false;
    try {
        $service->activateDomainBundle(
            $accountId + 999999,
            $subscriptionId,
            'other-' . strtolower(bin2hex(random_bytes(4))),
            'REQ-' . strtoupper(bin2hex(random_bytes(8))),
            'IDEM-' . strtoupper(bin2hex(random_bytes(8)))
        );
    } catch (Throwable) {
        $otherAccountRejected = true;
    }
    if (!$otherAccountRejected) {
        $failures[] = 'Subscription ownership enforcement failed.';
    }
} catch (Throwable $exception) {
    $failures[] = get_class($exception) . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL);
    exit(1);
}

echo "Phase 3 Domain, plan, subscription, and paired-license certification passed.\n";

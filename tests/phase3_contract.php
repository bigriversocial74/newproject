<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$autoload = $root . '/vendor/autoload.php';
if (is_file($autoload)) {
    require $autoload;
} else {
    spl_autoload_register(static function (string $class) use ($root): void {
        $prefix = 'Vp3\\';
        if (!str_starts_with($class, $prefix)) {
            return;
        }
        $path = $root . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($path)) {
            require $path;
        }
    });
}

$failures = [];
$migrationPath = $root . '/database/migrations/20260729_phase3_domain_plans_licenses.sql';
$migration = file_get_contents($migrationPath);
if (!is_string($migration)) {
    $failures[] = 'The Phase 3 migration could not be read.';
    $migration = '';
}

foreach ([
    'plans',
    'plan_entitlements',
    'subscriptions',
    'subscription_events',
    'domain_registrations',
    'entitlement_bundles',
    'licenses',
    'license_entitlements',
    'domain_admin_holds',
    'domain_aliases',
    'domain_redirects',
    'domain_transfer_requests',
    'domain_transfer_active',
    'domain_request_receipts',
    'domain_events',
] as $table) {
    if (!str_contains($migration, 'CREATE TABLE IF NOT EXISTS ' . $table)) {
        $failures[] = 'Missing Phase 3 table: ' . $table;
    }
}

foreach (\Vp3\Catalog\PlanCatalogService::REQUIRED_ENTITLEMENTS as $key) {
    if (!str_contains($migration, "'" . $key . "'")) {
        $failures[] = 'Missing required entitlement seed: ' . $key;
    }
}

$requiredMethods = [
    \Vp3\DomainCodes\DomainRegistryService::class => [
        'availability',
        'reserveDomain',
        'registerAndActivate',
        'activateReservedDomain',
        'renewDomain',
        'suspendDomain',
        'expireDomain',
        'releaseDomain',
        'placeAdministrativeHold',
        'releaseAdministrativeHold',
        'addAlias',
        'addRedirect',
        'updateRoutingAndSslStatus',
        'requestTransfer',
    ],
    \Vp3\Billing\SubscriptionLifecycleService::class => ['create', 'transition'],
    \Vp3\Licensing\LicenseLifecycleService::class => ['assertPairedBundle', 'transitionForDomain'],
    \Vp3\Licensing\DomainLicenseBundleService::class => ['activateDomainBundle'],
];
foreach ($requiredMethods as $class => $methods) {
    $reflection = new \ReflectionClass($class);
    foreach ($methods as $method) {
        if (!$reflection->hasMethod($method) || !$reflection->getMethod($method)->isPublic()) {
            $failures[] = 'Missing public Phase 3 method: ' . $class . '::' . $method;
        }
    }
}

$installer = file_get_contents($root . '/database/vp3-single-install.sql');
if (!is_string($installer) || !str_contains($installer, '20260729_phase3_domain_plans_licenses.sql')) {
    $failures[] = 'The cumulative VP3 installer does not include Phase 3.';
}

if ($failures !== []) {
    fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL);
    exit(1);
}

echo "Phase 3 static contract certification passed.\n";

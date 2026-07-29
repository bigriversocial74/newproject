<?php

declare(strict_types=1);

use Vp3\Auth\AccountSecurityService;
use Vp3\Auth\AuthService;
use Vp3\Auth\PasswordPolicy;
use Vp3\Billing\BillingGraceService;
use Vp3\Billing\StripeApiClient;
use Vp3\Billing\StripeCatalogService;
use Vp3\Billing\StripeCheckoutService;
use Vp3\Billing\StripeSignatureVerifier;
use Vp3\Billing\StripeWebhookService;
use Vp3\Billing\SubscriptionLifecycleService;
use Vp3\Catalog\PlanCatalogService;
use Vp3\Database;
use Vp3\Deployments\PodHealthService;
use Vp3\DomainCodes\DomainRegistryService;
use Vp3\Http\SessionManager;
use Vp3\Licensing\DomainLicenseBundleService;
use Vp3\Licensing\LicenseLifecycleService;
use Vp3\Provisioning\NullPodProvisioningAdapter;
use Vp3\Provisioning\PodProvisioningService;
use Vp3\Provisioning\ProtectedConfigurationMerger;

$autoload = __DIR__ . '/vendor/autoload.php';
if (!is_file($autoload)) {
    spl_autoload_register(static function (string $class): void {
        $prefix = 'Vp3\\';
        if (!str_starts_with($class, $prefix)) {
            return;
        }
        $path = __DIR__ . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($path)) {
            require $path;
        }
    });
} else {
    require $autoload;
}

$configFile = __DIR__ . '/config/config.php';
if (!is_file($configFile)) {
    $configFile = __DIR__ . '/config/config-example.php';
}
$config = require $configFile;

$database = new Database($config['database']);
$passwordPolicy = new PasswordPolicy((int) $config['auth']['password_min_length']);
$auth = new AuthService($database, $passwordPolicy);
$accountSecurity = new AccountSecurityService($database, $passwordPolicy);
$planCatalog = new PlanCatalogService($database);
$subscriptionLifecycle = new SubscriptionLifecycleService($database);
$domainRegistry = new DomainRegistryService($database);
$domainLicenseBundles = new DomainLicenseBundleService($database);
$licenseLifecycle = new LicenseLifecycleService($database);
$stripeGateway = new StripeApiClient(
    (string) $config['stripe']['secret_key'],
    (string) $config['stripe']['api_base']
);
$stripeSignatureVerifier = new StripeSignatureVerifier(
    (string) $config['stripe']['webhook_secret'],
    (int) $config['stripe']['signature_tolerance_seconds']
);
$stripeCatalog = new StripeCatalogService($database);
$stripeCheckout = new StripeCheckoutService($database, $stripeGateway);
$stripeWebhooks = new StripeWebhookService($database, $stripeSignatureVerifier, (int) $config['stripe']['grace_days']);
$billingGrace = new BillingGraceService($database);
$podProvisioningAdapter = new NullPodProvisioningAdapter();
$podProvisioning = new PodProvisioningService(
    $database,
    $podProvisioningAdapter,
    new ProtectedConfigurationMerger(),
    (array) $config['provisioning']['protected_configuration_paths']
);
$podHealth = new PodHealthService($database);
$session = new SessionManager([
    'name' => (string) $config['app']['session_name'],
    'secure' => (bool) $config['app']['session_secure'],
]);

return [
    'config' => $config,
    'database' => $database,
    'auth' => $auth,
    'account_security' => $accountSecurity,
    'plan_catalog' => $planCatalog,
    'subscription_lifecycle' => $subscriptionLifecycle,
    'domain_registry' => $domainRegistry,
    'domain_license_bundles' => $domainLicenseBundles,
    'license_lifecycle' => $licenseLifecycle,
    'stripe_gateway' => $stripeGateway,
    'stripe_signature_verifier' => $stripeSignatureVerifier,
    'stripe_catalog' => $stripeCatalog,
    'stripe_checkout' => $stripeCheckout,
    'stripe_webhooks' => $stripeWebhooks,
    'billing_grace' => $billingGrace,
    'pod_provisioning_adapter' => $podProvisioningAdapter,
    'pod_provisioning' => $podProvisioning,
    'pod_health' => $podHealth,
    'session' => $session,
];

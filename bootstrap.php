<?php

declare(strict_types=1);
use Vp3\Auth\AccountSecurityService;
use Vp3\Auth\AuthenticationContext;
use Vp3\Auth\AuthAuditService;
use Vp3\Auth\AuthRuntimeConfigurationValidator;
use Vp3\Auth\AuthSecretCipher;
use Vp3\Auth\AuthService;
use Vp3\Auth\DatabaseSessionService;
use Vp3\Auth\Mail\MailAdapterFactory;
use Vp3\Auth\MfaService;
use Vp3\Auth\PasswordChangeService;
use Vp3\Auth\PasswordPolicy;
use Vp3\Auth\TeamSecurityService;
use Vp3\Backups\BackupMetadataCipher;
use Vp3\Backups\BackupService;
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
use Vp3\HomeServers\HomeServerLeaseSigner;
use Vp3\HomeServers\HomeServerRegistryService;
use Vp3\Http\AuthEndpoint;
use Vp3\Http\AuthRequestIntegrity;
use Vp3\Http\SessionManager;
use Vp3\Infrastructure\InfrastructureProviderService;
use Vp3\Infrastructure\ProviderSecretCipher;
use Vp3\Licensing\DomainLicenseBundleService;
use Vp3\Licensing\LicenseLifecycleService;
use Vp3\Operations\OperationalAuditService;
use Vp3\Operations\OperationalIncidentService;
use Vp3\Operations\OperationalNotificationService;
use Vp3\Operations\OperationsControlCenterActionService;
use Vp3\Operations\OperationsControlCenterQueryService;
use Vp3\Operations\OperationsMonitorService;
use Vp3\Operations\OperationsReadinessService;
use Vp3\Operations\OperationsSecretCipher;
use Vp3\Provisioning\PodProvisioningService;
use Vp3\Provisioning\ProtectedConfigurationMerger;
use Vp3\Releases\ReleaseCatalogService;
use Vp3\Releases\ReleaseManifestSigner;
use Vp3\Runtime\AdapterFactory;
use Vp3\Runtime\RuntimeConfigurationValidator;
use Vp3\Updates\SoftwareUpdateService;

$autoload = __DIR__ . '/vendor/autoload.php';
if (!is_file($autoload)) {
    spl_autoload_register(static function (string $class): void {
        $prefix = 'Vp3\\';
        if (!str_starts_with($class, $prefix)) return;
        $path = __DIR__ . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($path)) require $path;
    });
} else {
    require $autoload;
}

$configFile = __DIR__ . '/config/config.php';
$usingExampleConfig = !is_file($configFile);
if ($usingExampleConfig) $configFile = __DIR__ . '/config/config-example.php';
$config = require $configFile;
$runtimeConfigurationValidator = new RuntimeConfigurationValidator();
$runtimeConfigurationValidator->validate($config, $usingExampleConfig);
$authRuntimeConfigurationValidator = new AuthRuntimeConfigurationValidator();
$authRuntimeConfigurationValidator->validate($config, $usingExampleConfig);
$environment = strtolower((string) $config['app']['env']);
$queueLeaseSeconds = (int) $config['queue']['lease_seconds'];
$authRequestIntegrity = new AuthRequestIntegrity((string) $config['app']['base_url'], $environment);
AuthEndpoint::configureRequestIntegrity($authRequestIntegrity);

$database = new Database($config['database']);
$passwordPolicy = new PasswordPolicy((int) $config['auth']['password_min_length']);
$authAudit = new AuthAuditService($database);
$mailAdapter = MailAdapterFactory::create((array) $config['mail'], $environment);
$authConfig = array_merge((array) $config['auth'], ['base_url' => (string) $config['app']['base_url']]);
$session = new SessionManager(['name' => (string) $config['app']['session_name'], 'secure' => (bool) $config['app']['session_secure']]);
$databaseSessions = new DatabaseSessionService(
    $database,
    (int) $config['auth']['session_inactivity_ttl_seconds'],
    (int) $config['auth']['session_absolute_ttl_seconds'],
    $authAudit
);
$authenticationContext = new AuthenticationContext($session, $databaseSessions);
$passwordChanges = new PasswordChangeService($database, $passwordPolicy, $authAudit);
$auth = new AuthService($database, $passwordPolicy, $mailAdapter, $authConfig, $authAudit);
$accountSecurity = new AccountSecurityService($database, $passwordPolicy, $mailAdapter, $authConfig, $authAudit);
$authSecretCipher = new AuthSecretCipher(
    (string) ($config['auth']['secret_encryption_key_base64'] ?? getenv('AUTH_SECRET_ENCRYPTION_KEY_B64') ?: ''),
    (string) ($config['auth']['secret_encryption_key_id'] ?? getenv('AUTH_SECRET_ENCRYPTION_KEY_ID') ?: 'auth-aes256gcm-v1')
);
$mfa = new MfaService(
    $database,
    $authSecretCipher,
    $authAudit,
    (int) ($config['auth']['mfa_challenge_ttl_seconds'] ?? 300),
    (int) ($config['auth']['mfa_recovery_code_count'] ?? 10)
);
$teamSecurity = new TeamSecurityService(
    $database,
    $mailAdapter,
    $authAudit,
    (string) $config['app']['base_url'],
    (int) ($config['auth']['team_invitation_ttl_seconds'] ?? 604800)
);
$planCatalog = new PlanCatalogService($database);
$subscriptionLifecycle = new SubscriptionLifecycleService($database);
$domainRegistry = new DomainRegistryService($database);
$domainLicenseBundles = new DomainLicenseBundleService($database);
$licenseLifecycle = new LicenseLifecycleService($database);
$stripeGateway = new StripeApiClient((string) $config['stripe']['secret_key'], (string) $config['stripe']['api_base']);
$stripeSignatureVerifier = new StripeSignatureVerifier((string) $config['stripe']['webhook_secret'], (int) $config['stripe']['signature_tolerance_seconds']);
$stripeCatalog = new StripeCatalogService($database);
$stripeCheckout = new StripeCheckoutService($database, $stripeGateway);
$stripeWebhooks = new StripeWebhookService($database, $stripeSignatureVerifier, (int) $config['stripe']['grace_days']);
$billingGrace = new BillingGraceService($database);
$podProvisioningAdapter = AdapterFactory::provisioning((string) $config['provisioning']['provider_driver'], $environment);
$podProvisioning = new PodProvisioningService($database, $podProvisioningAdapter, new ProtectedConfigurationMerger(), (array) $config['provisioning']['protected_configuration_paths'], $queueLeaseSeconds);
$podHealth = new PodHealthService($database);
$homeServerLeaseSigner = new HomeServerLeaseSigner(
    (string) $config['homeserver']['lease_signing_private_key_base64'],
    (string) $config['homeserver']['lease_signing_public_key_base64'],
    (string) $config['homeserver']['lease_signing_key_id']
);
$homeServers = new HomeServerRegistryService($database, $homeServerLeaseSigner, (int) $config['homeserver']['pairing_ttl_seconds'], (int) $config['homeserver']['lease_ttl_seconds']);
$releaseManifestSigner = new ReleaseManifestSigner(
    (string) $config['releases']['signing_private_key_base64'],
    (string) $config['releases']['signing_public_key_base64'],
    (string) $config['releases']['signing_key_id']
);
$releaseCatalog = new ReleaseCatalogService($database, $releaseManifestSigner);
$softwareUpdateAdapter = AdapterFactory::updates((string) $config['releases']['update_provider_driver'], $environment);
$softwareUpdates = new SoftwareUpdateService($database, $softwareUpdateAdapter, $queueLeaseSeconds);
$backupProviderAdapter = AdapterFactory::backups((string) $config['backups']['provider_driver'], $environment);
$backupMetadataCipher = new BackupMetadataCipher((string) $config['backups']['metadata_encryption_key_base64'], (string) $config['backups']['metadata_encryption_key_id']);
$backups = new BackupService($database, $backupProviderAdapter, $backupMetadataCipher, (float) $config['backups']['warning_threshold_percent'], (float) $config['backups']['critical_threshold_percent'], $queueLeaseSeconds);
$infrastructureConfig = (array) ($config['infrastructure'] ?? []);
$providerSecretCipher = new ProviderSecretCipher(
    (string) ($infrastructureConfig['secret_encryption_key_base64'] ?? getenv('PROVIDER_SECRET_ENCRYPTION_KEY_B64') ?: ''),
    (string) ($infrastructureConfig['secret_encryption_key_id'] ?? getenv('PROVIDER_SECRET_ENCRYPTION_KEY_ID') ?: 'provider-aes256gcm-v1')
);
$infrastructureAdapters = AdapterFactory::infrastructure((string) ($infrastructureConfig['provider_driver'] ?? 'null'), $environment);
$infrastructure = new InfrastructureProviderService($database, $providerSecretCipher, $infrastructureAdapters['hosting'], $infrastructureAdapters['dns'], $infrastructureAdapters['certificate'], $queueLeaseSeconds);
$operationsConfig = (array) ($config['operations'] ?? []);
$operationsSecretCipher = new OperationsSecretCipher(
    (string) ($operationsConfig['secret_encryption_key_base64'] ?? getenv('OPERATIONS_SECRET_ENCRYPTION_KEY_B64') ?: ''),
    (string) ($operationsConfig['secret_encryption_key_id'] ?? getenv('OPERATIONS_SECRET_ENCRYPTION_KEY_ID') ?: 'operations-aes256gcm-v1')
);
$operationalNotificationAdapter = AdapterFactory::notifications((string) ($operationsConfig['notification_driver'] ?? 'null'), $environment);
$operationalAudit = new OperationalAuditService($database);
$operationalNotifications = new OperationalNotificationService($database, $operationsSecretCipher, $operationalNotificationAdapter, $operationalAudit, $queueLeaseSeconds);
$operationalIncidents = new OperationalIncidentService($database, $operationalAudit, $operationalNotifications);
$operationsMonitor = new OperationsMonitorService($database, $operationalIncidents, $operationalAudit, (int) ($operationsConfig['pod_offline_after_minutes'] ?? 10), (int) ($operationsConfig['homeserver_offline_after_minutes'] ?? 10));
$operations = new OperationsReadinessService($database, $operationalAudit, $operationalNotifications, $operationalIncidents, $operationsMonitor);
$operationsControlCenterQuery = new OperationsControlCenterQueryService($database);
$operationsControlCenterActions = new OperationsControlCenterActionService(
    $database,
    $operationalAudit,
    $operationalNotifications,
    $operationsSecretCipher
);

return [
    'config' => $config,
    'runtime_configuration_validator' => $runtimeConfigurationValidator,
    'auth_runtime_configuration_validator' => $authRuntimeConfigurationValidator,
    'auth_request_integrity' => $authRequestIntegrity,
    'database' => $database,
    'auth_audit' => $authAudit,
    'mail_adapter' => $mailAdapter,
    'auth' => $auth,
    'account_security' => $accountSecurity,
    'auth_secret_cipher' => $authSecretCipher,
    'mfa' => $mfa,
    'team_security' => $teamSecurity,
    'database_sessions' => $databaseSessions,
    'authentication_context' => $authenticationContext,
    'password_changes' => $passwordChanges,
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
    'homeserver_lease_signer' => $homeServerLeaseSigner,
    'homeservers' => $homeServers,
    'release_manifest_signer' => $releaseManifestSigner,
    'release_catalog' => $releaseCatalog,
    'software_update_adapter' => $softwareUpdateAdapter,
    'software_updates' => $softwareUpdates,
    'backup_provider_adapter' => $backupProviderAdapter,
    'backup_metadata_cipher' => $backupMetadataCipher,
    'backups' => $backups,
    'provider_secret_cipher' => $providerSecretCipher,
    'infrastructure_provider_adapter' => $infrastructureAdapters['hosting'],
    'infrastructure_provider_adapters' => $infrastructureAdapters,
    'infrastructure' => $infrastructure,
    'operations_secret_cipher' => $operationsSecretCipher,
    'operational_notification_adapter' => $operationalNotificationAdapter,
    'operational_audit' => $operationalAudit,
    'operational_notifications' => $operationalNotifications,
    'operational_incidents' => $operationalIncidents,
    'operations_monitor' => $operationsMonitor,
    'operations' => $operations,
    'operations_control_center_query' => $operationsControlCenterQuery,
    'operations_control_center_actions' => $operationsControlCenterActions,
    'session' => $session,
];

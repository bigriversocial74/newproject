<?php

declare(strict_types=1);

use Vp3\ControlCenter\AccountControlCenterQueryService;
use Vp3\Database;

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

$dsn = getenv('VP3_TEST_DSN') ?: '';
if ($dsn === '') {
    fwrite(STDERR, "VP3_TEST_DSN is required.\n");
    exit(1);
}
$database = new Database([
    'dsn' => $dsn,
    'username' => getenv('VP3_TEST_DB_USER') ?: 'root',
    'password' => getenv('VP3_TEST_DB_PASSWORD') ?: '',
    'options' => [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => true,
    ],
]);
$pdo = $database->pdo();
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

try {
    $token = strtolower(bin2hex(random_bytes(6)));
    $now = gmdate('Y-m-d H:i:s');
    $periodEnd = gmdate('Y-m-d H:i:s', time() + 2592000);
    $planId = (int) $pdo->query("SELECT id FROM plans WHERE code='standard' LIMIT 1")->fetchColumn();
    if ($planId < 1) {
        throw new RuntimeException('VP3 Standard plan seed is missing.');
    }

    $createEstate = static function (string $suffix, bool $withRuntime) use ($pdo, $token, $now, $periodEnd, $planId): array {
        $upper = strtoupper($token . '-' . $suffix);
        $pdo->prepare(
            "INSERT INTO accounts (public_id,account_type,status,display_name,created_at,updated_at)
             VALUES (:public,'individual','active',:name,:now,:now)"
        )->execute(['public' => 'VP3-P15-' . $upper, 'name' => 'Phase 15 ' . $suffix, 'now' => $now]);
        $accountId = (int) $pdo->lastInsertId();

        $pdo->prepare(
            "INSERT INTO subscriptions
             (public_id,account_id,plan_id,status,starts_at,current_period_starts_at,current_period_ends_at,created_at,updated_at)
             VALUES (:public,:account,:plan,'active',:now,:now,:ends,:now,:now)"
        )->execute([
            'public' => 'SUB-P15-' . $upper,
            'account' => $accountId,
            'plan' => $planId,
            'now' => $now,
            'ends' => $periodEnd,
        ]);
        $subscriptionId = (int) $pdo->lastInsertId();

        $label = 'phase15-' . $token . '-' . $suffix;
        $domainPublicId = 'DOM-P15-' . $upper;
        $pdo->prepare(
            "INSERT INTO domain_registrations
             (public_id,account_id,subscription_id,label,hostname,status,routing_status,ssl_status,registered_at,renews_at,expires_at,created_at,updated_at)
             VALUES (:public,:account,:subscription,:label,:hostname,'active','active','active',:now,:ends,:ends,:now,:now)"
        )->execute([
            'public' => $domainPublicId,
            'account' => $accountId,
            'subscription' => $subscriptionId,
            'label' => $label,
            'hostname' => $label . '.vp3.me',
            'now' => $now,
            'ends' => $periodEnd,
        ]);
        $domainId = (int) $pdo->lastInsertId();

        $pdo->prepare(
            "INSERT INTO entitlement_bundles
             (public_id,account_id,subscription_id,domain_registration_id,plan_id,snapshot_hash,created_at,updated_at)
             VALUES (:public,:account,:subscription,:domain,:plan,:hash,:now,:now)"
        )->execute([
            'public' => 'BUNDLE-P15-' . $upper,
            'account' => $accountId,
            'subscription' => $subscriptionId,
            'domain' => $domainId,
            'plan' => $planId,
            'hash' => hash('sha256', 'bundle-' . $upper),
            'now' => $now,
        ]);
        $bundleId = (int) $pdo->lastInsertId();

        $insertLicense = $pdo->prepare(
            "INSERT INTO licenses
             (public_id,account_id,subscription_id,domain_registration_id,entitlement_bundle_id,product_type,status,starts_at,renews_at,expires_at,created_at,updated_at)
             VALUES (:public,:account,:subscription,:domain,:bundle,:product,'active',:now,:ends,:ends,:now,:now)"
        );
        $insertLicense->execute([
            'public' => 'PODL-P15-' . $upper,
            'account' => $accountId,
            'subscription' => $subscriptionId,
            'domain' => $domainId,
            'bundle' => $bundleId,
            'product' => 'pod',
            'now' => $now,
            'ends' => $periodEnd,
        ]);
        $podLicenseId = (int) $pdo->lastInsertId();
        $insertLicense->execute([
            'public' => 'HSL-P15-' . $upper,
            'account' => $accountId,
            'subscription' => $subscriptionId,
            'domain' => $domainId,
            'bundle' => $bundleId,
            'product' => 'homeserver',
            'now' => $now,
            'ends' => $periodEnd,
        ]);
        $homeServerLicenseId = (int) $pdo->lastInsertId();

        $result = [
            'account' => $accountId,
            'subscription' => $subscriptionId,
            'domain' => $domainId,
            'domain_public' => $domainPublicId,
            'hostname' => $label . '.vp3.me',
            'pod_license' => $podLicenseId,
            'homeserver_license' => $homeServerLicenseId,
        ];

        if (!$withRuntime) {
            return $result;
        }

        $podPublicId = 'POD-P15-' . $upper;
        $pdo->prepare(
            "INSERT INTO pod_deployments
             (public_id,account_id,subscription_id,domain_registration_id,license_id,status,installation_fingerprint,
              installed_version,update_channel,storage_usage_bytes,storage_allowance_bytes,last_heartbeat_at,routing_status,
              ssl_status,backup_status,license_status,activated_at,created_at,updated_at)
             VALUES (:public,:account,:subscription,:domain,:license,'active',:fingerprint,'15.0.0','stable',1048576,1073741824,
                     :now,'active','active','verified','active',:now,:now,:now)"
        )->execute([
            'public' => $podPublicId,
            'account' => $accountId,
            'subscription' => $subscriptionId,
            'domain' => $domainId,
            'license' => $podLicenseId,
            'fingerprint' => hash('sha256', 'pod-' . $upper),
            'now' => $now,
        ]);
        $deploymentId = (int) $pdo->lastInsertId();
        $pdo->prepare(
            "INSERT INTO pod_provisioning_jobs
             (public_id,deployment_id,account_id,job_type,status,current_stage,attempts,max_attempts,idempotency_key,request_id,
              available_at,started_at,completed_at,created_at,updated_at)
             VALUES (:public,:deployment,:account,'provision','completed','deployment_active',1,5,:idempotency,:request,
                     :now,:now,:now,:now,:now)"
        )->execute([
            'public' => 'JOB-P15-' . $upper,
            'deployment' => $deploymentId,
            'account' => $accountId,
            'idempotency' => 'phase15-job-' . $token . '-' . $suffix,
            'request' => 'REQ-P15-' . $upper,
            'now' => $now,
        ]);

        $devicePublicId = 'HS-P15-' . $upper;
        $pdo->prepare(
            "INSERT INTO homeserver_devices
             (public_id,account_id,subscription_id,domain_registration_id,license_id,device_fingerprint,credential_hash,status,
              pairing_status,software_version,mcp_version,update_channel,frontend_limit,paired_frontend_count,last_heartbeat_at,
              paired_at,created_at,updated_at)
             VALUES (:public,:account,:subscription,:domain,:license,:fingerprint,:credential,'online','paired','0.1.4','1.0.0',
                     'stable',2,1,:now,:now,:now,:now)"
        )->execute([
            'public' => $devicePublicId,
            'account' => $accountId,
            'subscription' => $subscriptionId,
            'domain' => $domainId,
            'license' => $homeServerLicenseId,
            'fingerprint' => hash('sha256', 'homeserver-' . $upper),
            'credential' => hash('sha256', 'credential-' . $upper),
            'now' => $now,
        ]);

        $pdo->prepare(
            "INSERT INTO operational_incidents
             (public_id,account_scope,incident_key,source_type,source_id,severity,status,active_marker,monitor_managed,title,
              summary_hash,evidence_hash,occurrence_count,first_detected_at,last_detected_at,created_at,updated_at)
             VALUES (:public,:account,:incident_key,'pod_deployment',:source,'critical','open',1,1,'Phase 15 test incident',
                     :summary,:evidence,1,:now,:now,:now,:now)"
        )->execute([
            'public' => 'INC-P15-' . $upper,
            'account' => $accountId,
            'incident_key' => hash('sha256', 'incident-' . $upper),
            'source' => $deploymentId,
            'summary' => hash('sha256', 'summary-' . $upper),
            'evidence' => hash('sha256', 'evidence-' . $upper),
            'now' => $now,
        ]);

        return $result + ['deployment' => $deploymentId, 'pod_public' => $podPublicId, 'homeserver_public' => $devicePublicId];
    };

    $owned = $createEstate('owned', true);
    $other = $createEstate('other', false);
    $query = new AccountControlCenterQueryService($database);

    $snapshot = $query->snapshot($owned['account']);
    $assert($snapshot['account']['id'] === $owned['account'], 'Snapshot returned the wrong account.');
    $assert($snapshot['metrics']['domains_total'] === 1 && $snapshot['metrics']['domains_active'] === 1, 'Domain metrics are incorrect.');
    $assert($snapshot['metrics']['pods_total'] === 1 && $snapshot['metrics']['pods_active'] === 1, 'POD metrics are incorrect.');
    $assert($snapshot['metrics']['homeservers_total'] === 1 && $snapshot['metrics']['homeservers_online'] === 1, 'HomeServer metrics are incorrect.');
    $assert($snapshot['metrics']['open_incidents'] === 1 && $snapshot['metrics']['critical_incidents'] === 1, 'Incident metrics are incorrect.');
    $assert(count($snapshot['domains']) === 1 && $snapshot['domains'][0]['hostname'] === $owned['hostname'], 'Domain snapshot returned incorrect account data.');
    $assert(count($snapshot['pods']) === 1 && $snapshot['pods'][0]['public_id'] === $owned['pod_public'], 'POD snapshot returned incorrect account data.');
    $assert(($snapshot['pods'][0]['latest_job']['status'] ?? null) === 'completed', 'POD snapshot omitted latest worker state.');
    $assert(count($snapshot['homeservers']['devices']) === 1 && $snapshot['homeservers']['devices'][0]['device_public_id'] === $owned['homeserver_public'], 'HomeServer snapshot returned incorrect account data.');
    $assert(count($snapshot['attention']) === 1 && $snapshot['attention'][0]['title'] === 'Phase 15 test incident', 'Prioritized attention list is incorrect.');

    $forbiddenKeys = [
        'credential_hash', 'device_fingerprint', 'installation_fingerprint', 'destination_ciphertext',
        'hosting_reference', 'database_reference', 'configuration_hash', 'token_hash', 'code_hash',
    ];
    $walk = static function (array $value) use (&$walk, $forbiddenKeys, $assert): void {
        foreach ($value as $key => $item) {
            $assert(!in_array((string) $key, $forbiddenKeys, true), 'Unified snapshot exposed forbidden key ' . $key . '.');
            if (is_array($item)) {
                $walk($item);
            }
        }
    };
    $walk($snapshot);

    $otherSnapshot = $query->snapshot($other['account']);
    $assert(count($otherSnapshot['domains']) === 1 && $otherSnapshot['domains'][0]['hostname'] === $other['hostname'], 'Second account snapshot returned incorrect Domain data.');
    $assert($otherSnapshot['metrics']['pods_total'] === 0, 'Second account received a cross-account POD.');
    $assert($otherSnapshot['metrics']['homeservers_total'] === 0, 'Second account received a cross-account HomeServer.');
    $assert($otherSnapshot['metrics']['open_incidents'] === 0, 'Second account received a cross-account incident.');
    $otherJson = json_encode($otherSnapshot, JSON_THROW_ON_ERROR);
    $assert(!str_contains($otherJson, $owned['hostname']), 'Cross-account Domain data leaked into the second account.');
    $assert(!str_contains($otherJson, $owned['pod_public']), 'Cross-account POD data leaked into the second account.');
    $assert(!str_contains($otherJson, $owned['homeserver_public']), 'Cross-account HomeServer data leaked into the second account.');
} catch (Throwable $exception) {
    $failures[] = $exception::class . ': ' . $exception->getMessage();
}

if ($failures !== []) {
    fwrite(STDERR, implode("\n", $failures) . "\n");
    exit(1);
}

echo "Phase 15 unified control center database integration passed.\n";

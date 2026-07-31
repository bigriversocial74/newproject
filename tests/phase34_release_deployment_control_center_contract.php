<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) $failures[] = $message;
};
$read = static function (string $path) use ($root, &$failures): string {
    $absolute = $root . '/' . $path;
    if (!is_file($absolute)) {
        $failures[] = 'Missing Phase 34 file: ' . $path;
        return '';
    }
    $content = file_get_contents($absolute);
    if (!is_string($content)) {
        $failures[] = 'Unable to read Phase 34 file: ' . $path;
        return '';
    }
    return $content;
};

$migration = $read('database/migrations/20260731_phase34_release_deployment_control_center.sql');
$manifest = $read('database/single-install-manifest.txt');
$release = $read('config/release.php');
$releaseManifest = $read('src/Deployment/ReleaseManifestService.php');
$authorizer = $read('src/Deployment/PlatformOperatorAuthorizer.php');
$grant = $read('src/Deployment/PlatformOperatorGrantService.php');
$registry = $read('src/Deployment/ReleaseCandidateRegistryService.php');
$fingerprint = $read('src/Deployment/DeploymentEnvironmentFingerprintService.php');
$actions = $read('src/Deployment/ReleaseDeploymentControlCenterActionService.php');
$query = $read('src/Deployment/ReleaseDeploymentControlCenterQueryService.php');
$worker = $read('src/Deployment/ReleaseDeploymentWorkerService.php');
$workerCli = $read('workers/platform-releases.php');
$page = $read('public/releases.php');
$endpoint = $read('public/api/control-center/v1/release-deployment-action.php');
$overview = $read('public/api/control-center/v1/release-deployment-overview.php');
$javascript = $read('public/assets/release-deployment.js');
$nav = $read('src/ControlCenter/ControlCenterPage.php');
$grantCli = $read('tools/vp3-grant-platform-operator.php');
$registerCli = $read('tools/vp3-register-release-candidate.php');
$fingerprintCli = $read('tools/vp3-environment-fingerprint.php');

foreach ([
    'platform_operator_accounts',
    'platform_release_candidates',
    'platform_deployment_environments',
    'platform_maintenance_windows',
    'platform_release_promotions',
    'platform_release_promotion_events',
    'platform_release_promotion_steps',
    'platform_environment_health_snapshots',
    'platform_release_control_receipts',
] as $table) {
    $assert(str_contains($migration, 'CREATE TABLE IF NOT EXISTS ' . $table), 'Phase 34 migration is missing ' . $table . '.');
}
$assert(str_contains($migration, 'source_tree_sha256 CHAR(64)'), 'Release candidates omit the signed source-tree identity.');
$assert(str_contains($migration, 'source_file_count INT UNSIGNED'), 'Release candidates omit source file counts.');
$assert(str_contains($migration, 'deployment_run_public_id VARCHAR(40)'), 'Promotion records omit target deployment public identities.');
$assert(str_contains($migration, 'backup_public_id VARCHAR(40)'), 'Promotion records omit target backup public identities.');
$assert(!str_contains($migration, 'FOREIGN KEY (deployment_run_public_id)'), 'The central control plane is coupled to a target deployment ledger.');
$assert(!str_contains($migration, 'FOREIGN KEY (backup_public_id)'), 'The central control plane is coupled to a target backup ledger.');
$assert(str_contains($migration, 'account_scope BIGINT UNSIGNED NOT NULL'), 'Phase 34 account authority is not persisted.');
$assert(str_contains($migration, 'UNIQUE KEY uq_platform_window_request (account_scope, request_id)'), 'Maintenance-window replay is not account scoped.');
$assert(str_contains($migration, 'UNIQUE KEY uq_platform_control_receipt_request (account_scope, request_id, action_type)'), 'Control receipts are not account scoped.');
$assert(str_contains($migration, 'lease_expires_at DATETIME(6)'), 'Promotion workers lack recoverable leases.');
$assert(str_contains($migration, 'worker_id_hash CHAR(64)'), 'Promotion workers lack privacy-safe worker identities.');

$entries = array_values(array_filter(array_map('trim', explode("\n", $manifest)), static fn (string $line): bool => $line !== '' && !str_starts_with($line, '#')));
$phase34Migration = 'migrations/20260731_phase34_release_deployment_control_center.sql';
$assert(in_array($phase34Migration, $entries, true), 'Phase 34 migration is missing from the ordered installer manifest.');
$releaseConfig = require $root . '/config/release.php';
$assert(($releaseConfig['format'] ?? null) === 'vp3-platform-release-v2', 'The platform release format no longer retains the Phase 34 signed-manifest contract.');
$assert(version_compare((string) ($releaseConfig['version'] ?? '0.0.0'), '34.0.0', '>='), 'The current release identity predates Phase 34.');
$assert((int) ($releaseConfig['schema_level'] ?? 0) >= 34, 'The current schema level predates Phase 34.');
$assert(($releaseConfig['migration_tail'] ?? null) === end($entries), 'The current release migration tail does not match the ordered installer manifest.');
$assert(str_contains($releaseManifest, "'application_source'"), 'Signed platform manifests omit the application source identity.');
$assert(str_contains($releaseManifest, 'sourceDocuments'), 'Release source-tree hashing is not deterministic.');
$assert(str_contains($releaseManifest, 'is_link'), 'Release source-tree hashing does not reject symlinks.');

$assert(str_contains($authorizer, 'platform_operator_accounts'), 'Release authority does not require an explicit platform-operator grant.');
$assert(str_contains($authorizer, "po.operator_status='active'"), 'Revoked platform-operator grants remain usable.');
$assert(str_contains($grant, 'public function grant('), 'Operator grant service is missing its grant boundary.');
$assert(str_contains($grant, 'public function revoke('), 'Operator grant service is missing its revocation boundary.');
$assert(str_contains($grant, "'_platform_operator'"), 'Operator grant receipts are not action-specific.');
$assert(str_contains($grantCli, 'GRANT_PLATFORM_OPERATOR'), 'Operator grants lack an explicit CLI confirmation boundary.');
$assert(str_contains($grantCli, 'REVOKE_PLATFORM_OPERATOR'), 'Operator revocation lacks an explicit CLI confirmation boundary.');

$assert(str_contains($registry, 'sodium_crypto_sign_verify_detached'), 'Release candidates are not verified with Ed25519.');
$assert(str_contains($registry, 'source_tree_sha256'), 'Release candidate registration omits the signed source tree.');
$assert(str_contains($registry, 'artifact_root_hash'), 'Release artifact locations are not represented by privacy-safe hashes.');
$assert(str_contains($registerCli, 'VP3_PLATFORM_RELEASE_OUTPUT_ROOT'), 'Release registration lacks a bounded artifact root.');
$assert(str_contains($fingerprint, 'canonicalJson'), 'Environment configuration fingerprints are not canonical.');
$assert(!str_contains($fingerprint, "'password' =>"), 'Environment fingerprints include database passwords.');
$assert(str_contains($fingerprintCli, 'config_fingerprint'), 'Environment fingerprint CLI does not return the fingerprint.');

$assert(str_contains($actions, 'approvePromotion'), 'Production promotions lack an approval action.');
$assert(str_contains($actions, 'requested_by_user_id'), 'Production approval does not enforce requester separation.');
$assert(str_contains($actions, 'platform.approve_release_promotion'), 'Production promotion does not consume action-bound reauthentication.');
$assert(str_contains($actions, 'platform.rollback_release'), 'Rollback does not consume action-bound reauthentication.');
$assert(str_contains($actions, 'approved_by_user_id'), 'Maintenance windows do not retain owner approval.');
$assert(str_contains($actions, "hash_equals('staging'"), 'Production promotion does not require staging evidence.');
$assert(str_contains($query, 'verifyEventChain'), 'Promotion event evidence is not chain verified.');
$assert(str_contains($query, 'platform_release_promotion_steps'), 'Target deployment steps are not surfaced centrally.');

foreach (['VP3_PLATFORM_TARGET_DB_DSN', 'VP3_PLATFORM_TARGET_DB_USERNAME', 'VP3_PLATFORM_TARGET_DB_PASSWORD'] as $variable) {
    $assert(str_contains($workerCli, $variable), 'Target database isolation is missing ' . $variable . '.');
}
$assert(str_contains($worker, 'lease_expires_at'), 'Release workers do not use recoverable leases.');
$assert(str_contains($worker, 'configuration_fingerprint'), 'Release workers do not compare non-secret environment configuration.');
$assert(str_contains($worker, "'application_source'"), 'Release workers do not verify the signed source tree.');
$assert(str_contains($worker, 'recordTargetRun'), 'Target deployment and backup identities are not copied before health verification.');
$assert(str_contains($worker, 'open('), 'Deployment failures do not escalate through Operations incidents.');

$assert(str_contains($page, "'Releases & Deployments'"), 'Release Control Center page is missing.');
$assert(str_contains($page, 'config_fingerprint'), 'Environment configuration fingerprint is not required by the UI.');
$assert(str_contains($endpoint, 'begin_promotion_reauthentication'), 'Production approval lacks a browser reauthentication start boundary.');
$assert(str_contains($endpoint, 'queue_rollback'), 'Rollback is not exposed through the protected action endpoint.');
$assert(str_contains($overview, 'ReleaseDeploymentControlCenterQueryService'), 'Release overview does not use the account-scoped read model.');
$assert(str_contains($javascript, 'textContent'), 'Release UI does not use DOM-safe text rendering.');
$assert(!str_contains($javascript, 'innerHTML'), 'Release UI uses unsafe HTML rendering.');
$assert(str_contains($nav, "'releases' => ['/releases.php', 'Releases & Deployments']"), 'Control Center navigation omits Releases & Deployments.');

$installer = $read('database/vp3-single-install.sql');
$assert(!preg_match('/^[[:space:]]*SOURCE[[:space:]]/mi', $installer), 'Standalone installer contains SOURCE directives.');

if ($failures !== []) {
    fwrite(STDERR, "Phase 34 Release & Deployment Control Center contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

fwrite(STDOUT, "Phase 34 Release & Deployment Control Center contract passed.\n");

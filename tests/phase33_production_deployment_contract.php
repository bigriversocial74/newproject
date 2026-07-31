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
        $failures[] = 'Missing Phase 33 file: ' . $path;
        return '';
    }
    $content = file_get_contents($absolute);
    if (!is_string($content)) {
        $failures[] = 'Unable to read Phase 33 file: ' . $path;
        return '';
    }
    return $content;
};

$migration = $read('database/migrations/20260731_phase33_production_deployment_upgrade.sql');
$manifest = $read('database/single-install-manifest.txt');
$release = $read('config/release.php');
$releaseService = $read('src/Deployment/ReleaseManifestService.php');
$preflight = $read('src/Deployment/DeploymentPreflightService.php');
$commands = $read('src/Deployment/DatabaseCommandService.php');
$upgrade = $read('src/Deployment/PlatformUpgradeService.php');
$cli = $read('tools/vp3-deploy.php');

foreach ([
    'platform_schema_migrations',
    'platform_release_records',
    'platform_deployment_runs',
    'platform_deployment_backups',
    'platform_deployment_steps',
    'platform_deployment_receipts',
] as $table) {
    $assert(str_contains($migration, 'CREATE TABLE IF NOT EXISTS ' . $table), 'Phase 33 migration is missing ' . $table . '.');
}
$assert(str_contains($migration, 'UNIQUE KEY uq_platform_deployment_request'), 'Deployment request replay is not constrained.');
$assert(str_contains($migration, 'file_path_hash CHAR(64)'), 'Backup paths are not represented by privacy-safe hashes.');
$assert(str_contains($migration, "ENUM('install','upgrade','verify','rollback')"), 'Deployment operation states are incomplete.');
$entries = array_values(array_filter(
    array_map('trim', explode("\n", $manifest)),
    static fn (string $line): bool => $line !== '' && !str_starts_with($line, '#')
));
$phase33 = array_search('migrations/20260731_phase33_production_deployment_upgrade.sql', $entries, true);
$phase32 = array_search('migrations/20260731_phase32_security_incident_automation.sql', $entries, true);
$assert($phase33 !== false, 'Phase 33 is missing from the cumulative installer manifest.');
$assert($phase32 !== false && $phase33 > $phase32, 'Phase 33 no longer follows its Phase 32 prerequisite.');

$assert(str_contains($release, "'minimum_php' => '8.2.0'"), 'The retained minimum PHP release contract changed.');
if (preg_match("/'schema_level'\\s*=>\\s*(\\d+)/", $release, $matches) === 1) {
    $assert((int) $matches[1] >= 33, 'The current release schema level regressed below Phase 33.');
} else {
    $failures[] = 'The current release schema level could not be verified.';
}
$assert(str_contains($releaseService, 'manifest_sha256'), 'Release manifests are not self-identifying.');
$assert(str_contains($releaseService, 'canonicalJson'), 'Release manifests are not canonicalized.');
$assert(str_contains($releaseService, 'migrationSha256'), 'Release manifests do not expose migration checksums.');
$assert(str_contains($releaseService, 'rename($temporary, $path)'), 'Release manifest publication is not atomic.');

foreach (['php_version', 'php_extensions', 'database_version', 'database_timezone', 'backup_root', 'active_deployment'] as $check) {
    $assert(str_contains($preflight, "'" . $check . "'"), 'Preflight is missing ' . $check . '.');
}
$assert(str_contains($preflight, 'disk_free_space'), 'Preflight does not enforce backup disk capacity.');
$assert(str_contains($preflight, 'canonicalHttpsOrigin'), 'Production URL readiness is not validated.');

$assert(str_contains($commands, "'MYSQL_PWD'"), 'Database passwords are not isolated from command arguments.');
$assert(!str_contains($commands, '--password='), 'Database passwords are exposed on the process command line.');
$assert(str_contains($commands, "'--single-transaction'"), 'Database backups are not transaction-consistent.');
$assert(str_contains($commands, "'--add-drop-table'"), 'Database backups cannot replace prior tables during restore.');
$assert(str_contains($commands, "hash_file('sha256'"), 'Database backup checksums are not verified.');
$assert(str_contains($commands, 'DROP TABLE IF EXISTS'), 'Rollback does not remove post-backup schema additions.');
$assert(str_contains($commands, '@chmod($path, 0600)'), 'Backup files are not restricted to the deployment user.');

$assert(str_contains($upgrade, 'SELECT GET_LOCK'), 'Deployments do not acquire a database advisory lock.');
$assert(str_contains($upgrade, 'SELECT RELEASE_LOCK'), 'Deployment locks are not released.');
$assert(str_contains($upgrade, 'createBackup'), 'Upgrades do not require a database backup.');
$assert(str_contains($upgrade, 'baselinePhase32'), 'Existing Phase 32 databases are not reconciled.');
$assert(str_contains($upgrade, 'applyPendingMigrations'), 'Ordered pending migrations are not applied.');
$assert(str_contains($upgrade, 'platform_migration_checksum_changed'), 'Changed applied migrations are not rejected.');
$assert(str_contains($upgrade, 'verifyCurrentRelease'), 'Deployments do not run post-upgrade smoke verification.');
$assert(str_contains($upgrade, 'restoreBackup'), 'Failed upgrades do not invoke automatic restore.');
$assert(str_contains($upgrade, 'writeJournal'), 'Pre-ledger upgrade evidence is not journaled to protected storage.');
$assert(str_contains($upgrade, 'platform_deployment_receipts'), 'Deployment actions are not replay-safe.');

foreach (['preflight', 'manifest', 'install', 'upgrade', 'verify', 'rollback'] as $command) {
    $assert(str_contains($cli, "'" . $command . "'"), 'Deployment CLI is missing ' . $command . '.');
}
$assert(str_contains($cli, 'JSON_PRETTY_PRINT'), 'Deployment CLI does not return structured JSON.');
$assert(str_contains($cli, 'VP3_DEPLOYMENT_REQUEST_ID'), 'Deployment CLI lacks a protected request identity input.');
$assert(str_contains($cli, 'VP3_PLATFORM_BACKUP_ROOT'), 'Deployment CLI lacks an explicit backup root boundary.');

if ($failures !== []) {
    fwrite(STDERR, "Phase 33 production deployment contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

fwrite(STDOUT, "Phase 33 production deployment contract passed.\n");

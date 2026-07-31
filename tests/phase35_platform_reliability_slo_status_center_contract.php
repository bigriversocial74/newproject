<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$read = static function (string $path) use ($root): string {
    $content = file_get_contents($root . '/' . $path);
    if (!is_string($content)) throw new RuntimeException('Unable to read ' . $path);
    return $content;
};
$assert = static function (bool $condition, string $message): void {
    if (!$condition) throw new RuntimeException($message);
};

$release = require $root . '/config/release.php';
$assert(($release['version'] ?? null) === '35.0.0', 'Phase 35 release version is not active.');
$assert((int) ($release['schema_level'] ?? 0) === 35, 'Phase 35 schema level is not active.');
$assert(($release['migration_tail'] ?? null) === 'migrations/20260731_phase35_platform_reliability_slo_status_center.sql', 'Phase 35 migration tail is incorrect.');

$manifest = array_values(array_filter(array_map('trim', file($root . '/database/single-install-manifest.txt', FILE_IGNORE_NEW_LINES) ?: []), static fn (string $line): bool => $line !== '' && !str_starts_with($line, '#')));
$assert(end($manifest) === 'migrations/20260731_phase35_platform_reliability_slo_status_center.sql', 'Phase 35 migration is not the final ordered migration.');
$assert(count($manifest) >= 26, 'Phase 35 migration manifest did not advance.');

$migration = $read('database/migrations/20260731_phase35_platform_reliability_slo_status_center.sql');
foreach ([
    'reliability_components',
    'reliability_objectives',
    'reliability_probes',
    'reliability_probe_results',
    'reliability_budget_snapshots',
    'reliability_incident_links',
    'reliability_status_events',
    'reliability_status_settings',
    'reliability_status_messages',
    'reliability_action_receipts',
] as $table) {
    $assert(str_contains($migration, 'CREATE TABLE IF NOT EXISTS ' . $table), 'Missing Phase 35 table ' . $table);
}
$assert(str_contains($migration, "result_status ENUM('success','failure','maintenance')"), 'Maintenance observations are not represented.');
$assert(str_contains($migration, 'UNIQUE KEY uq_reliability_incident_active'), 'Reliability incident serialization is missing.');
$assert(str_contains($migration, 'previous_hash CHAR(64)') && str_contains($migration, 'event_hash CHAR(64)'), 'Tamper-evident status events are missing.');

$action = $read('src/Reliability/ReliabilityControlCenterActionService.php');
$query = $read('src/Reliability/ReliabilityControlCenterQueryService.php');
$executor = $read('src/Reliability/ReliabilityProbeExecutor.php');
$worker = $read('src/Reliability/ReliabilityWorkerService.php');
$assert(str_contains($action, 'PlatformOperatorAuthorizer'), 'Reliability actions do not enforce platform operator authority.');
$assert(str_contains($action, 'reliability_request_conflict'), 'Reliability request replay conflict detection is missing.');
$assert(str_contains($action, "unset(\$row['account_scope']") && str_contains($action, "unset(\$row['target_value']"), 'Reliability browser responses are not explicitly scrubbed.');
$assert(str_contains($query, "c.visibility='public'"), 'Public status visibility filtering is missing.');
$assert(!str_contains($query, 'target_value'), 'Reliability query service exposes protected probe targets.');
$assert(str_contains($query, 'deploymentCorrelation'), 'Release-to-reliability correlation is missing.');
$assert(str_contains($executor, "'http' =>") && str_contains($executor, "'dns' =>") && str_contains($executor, "'ssl' =>"), 'Synthetic network probes are incomplete.');
$assert(str_contains($executor, "'database' =>") && str_contains($executor, "'worker' =>") && str_contains($executor, "'queue' =>") && str_contains($executor, "'storage' =>"), 'Internal reliability probes are incomplete.');
$assert(str_contains($worker, 'platform_maintenance_windows'), 'Phase 34 maintenance synchronization is missing.');
$assert(str_contains($worker, 'OperationalIncidentService'), 'Reliability-to-Operations incident automation is missing.');
$assert(str_contains($worker, 'consecutive_failure_threshold') && str_contains($worker, 'recovery_success_threshold'), 'False-positive and recovery thresholds are missing.');
$assert(str_contains($worker, 'reliability_budget_snapshots') && str_contains($worker, 'burn_rate'), 'Error-budget evaluation is missing.');
$assert(str_contains($worker, 'previousHash') && str_contains($worker, 'eventHash'), 'Status transition chaining is missing.');
$assert(str_contains($worker, "result_status IN ('success','failure')"), 'Maintenance observations are not excluded from error budgets.');

$overview = $read('public/api/control-center/v1/reliability-overview.php');
$endpoint = $read('public/api/control-center/v1/reliability-action.php');
foreach ([$overview, $endpoint] as $source) {
    $assert(str_contains($source, "ControlCenterEndpoint::requireMethod('POST')"), 'Reliability API is not POST-only.');
    $assert(str_contains($source, "['customer_owner', 'customer_admin']"), 'Reliability API role boundary is incomplete.');
}
$assert(str_contains($endpoint, 'ControlCenterEndpoint::requestId'), 'Reliability actions do not enforce request identities.');

$page = $read('public/reliability.php');
$publicPage = $read('public/status.php');
$javascript = $read('public/assets/reliability.js');
$controlCenter = $read('src/ControlCenter/ControlCenterPage.php');
$assert(str_contains($page, "'Reliability & Status'") && str_contains($page, "'reliability'"), 'Reliability Control Center page is not wired.');
$assert(str_contains($controlCenter, "'reliability' => ['/reliability.php', 'Reliability & Status']"), 'Reliability navigation is missing.');
$assert(str_contains($controlCenter, '/assets/reliability.css'), 'Reliability Control Center stylesheet is missing.');
$assert(str_contains($publicPage, "Cache-Control: public, max-age=30"), 'Public status caching boundary is missing.');
$assert(str_contains($publicPage, "Content-Security-Policy"), 'Public status CSP is missing.');
foreach (['innerHTML', 'localStorage', 'sessionStorage', 'document.write'] as $unsafe) {
    $assert(!str_contains($javascript, $unsafe), 'Reliability JavaScript contains unsafe browser persistence or rendering: ' . $unsafe);
}
$assert(str_contains($javascript, "credentials: 'same-origin'") && str_contains($javascript, "'X-CSRF-Token'"), 'Reliability browser requests are not session/CSRF protected.');
$assert(str_contains($javascript, 'replaceChildren'), 'Reliability browser rendering does not use DOM-safe replacement.');

$workerEntrypoint = $read('workers/reliability.php');
$assert(str_contains($workerEntrypoint, 'VP3_RELIABILITY_WORKER_ID'), 'Reliability worker identity configuration is missing.');
$assert(str_contains($workerEntrypoint, 'VP3_RELIABILITY_MAX_PER_RUN'), 'Reliability worker bounded-run control is missing.');

$documentation = $read('docs/vp3-platform-backend/22-PHASE35-PLATFORM-RELIABILITY-SLO-STATUS-CENTER.md');
foreach (['error budget', 'maintenance', 'public status', 'incident', 'worker'] as $term) {
    $assert(str_contains(strtolower($documentation), $term), 'Phase 35 documentation is missing ' . $term . '.');
}

fwrite(STDOUT, "Phase 35 reliability, SLO, incident automation and public-status contract passed.\n");

<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

foreach ([
    'database/migrations/20260729_phase10_operations_readiness.sql',
    'src/Operations/OperationsSecretCipher.php',
    'src/Operations/OperationalNotificationAdapter.php',
    'src/Operations/NullOperationalNotificationAdapter.php',
    'src/Operations/OperationalAuditService.php',
    'src/Operations/OperationalNotificationService.php',
    'src/Operations/OperationalIncidentService.php',
    'src/Operations/OperationsMonitorService.php',
    'src/Operations/OperationsReadinessService.php',
    'workers/operations.php',
] as $file) {
    $assert(is_file($root . '/' . $file), 'Missing Phase 10 file: ' . $file);
}

$migration = file_get_contents($root . '/database/migrations/20260729_phase10_operations_readiness.sql') ?: '';
foreach ([
    'operational_health_signals', 'operational_incidents', 'operational_incident_events',
    'operational_notification_channels', 'operational_notifications', 'operational_notification_receipts',
    'operational_audit_heads', 'operational_audit_chain', 'operational_monitor_runs', 'operational_readiness_assessments',
    'operational_readiness_checks', 'operational_request_receipts',
] as $table) {
    $assert(str_contains($migration, 'CREATE TABLE IF NOT EXISTS ' . $table), 'Missing operations table: ' . $table);
}
foreach (['destination_ciphertext', 'destination_nonce', 'destination_tag', 'event_status', 'previous_chain_hash', 'chain_hash'] as $column) {
    $assert(str_contains($migration, $column), 'Missing Phase 10 safety field: ' . $column);
}
foreach (['notification_body', 'customer_content', 'conversation_content', 'backup_content', 'plaintext_destination'] as $forbidden) {
    $assert(!str_contains(strtolower($migration), $forbidden), 'Forbidden customer or plaintext content field exists: ' . $forbidden);
}

$cipher = file_get_contents($root . '/src/Operations/OperationsSecretCipher.php') ?: '';
$assert(str_contains($cipher, 'aes-256-gcm'), 'Operations destination encryption is missing.');
$service = file_get_contents($root . '/src/Operations/OperationsReadinessService.php') ?: '';
foreach ([
    'saveNotificationChannel', 'recordHealthSignal', 'openIncident', 'acknowledgeIncident',
    'resolveIncident', 'runMonitoringPass', 'processNextNotification', 'assessReadiness', 'verifyAuditChain',
] as $method) {
    $assert(str_contains($service, 'function ' . $method), 'Missing Phase 10 lifecycle operation: ' . $method);
}
$assert(str_contains($service, '$blockers += $findingCount'), 'Readiness blockers are not aggregated by actual finding count.');
$assert(str_contains($service, '$warnings += $findingCount'), 'Readiness warnings are not aggregated by actual finding count.');
$notificationService = file_get_contents($root . '/src/Operations/OperationalNotificationService.php') ?: '';
$incidentService = file_get_contents($root . '/src/Operations/OperationalIncidentService.php') ?: '';
$monitorService = file_get_contents($root . '/src/Operations/OperationsMonitorService.php') ?: '';
$auditService = file_get_contents($root . '/src/Operations/OperationalAuditService.php') ?: '';
$combined = $service . $notificationService . $incidentService . $monitorService . $auditService;
foreach (['FOR UPDATE SKIP LOCKED', 'event_status', 'monitor_managed', 'appendWithPdo', 'operational_audit_heads', 'resolveRecovered'] as $contract) {
    $assert(str_contains($combined, $contract), 'Missing Phase 10 reliability contract: ' . $contract);
}
$assert(str_contains($notificationService, "'status' => (string) \$notification['event_status']"), 'Notification payload does not use immutable queued event status.');
$assert(str_contains($notificationService, "locked_at<DATE_SUB(UTC_TIMESTAMP(),INTERVAL 15 MINUTE)"), 'Stale notification claims are not recovered.');
$infrastructureService = file_get_contents($root . '/src/Infrastructure/InfrastructureProviderService.php') ?: '';
$assert(str_contains($infrastructureService, 'Infrastructure provider verification failed for stage:'), 'Retained Phase 9 provider verification enforcement is missing.');

$installer = file_get_contents($root . '/database/vp3-single-install.sql') ?: '';
$assert(str_contains($installer, '20260729_phase10_operations_readiness.sql'), 'Phase 10 migration is missing from the cumulative installer.');
$config = file_get_contents($root . '/config/config-example.php') ?: '';
foreach (['OPERATIONS_SECRET_ENCRYPTION_KEY_B64', 'OPERATIONS_SECRET_ENCRYPTION_KEY_ID', 'VP3_OPERATIONS_NOTIFICATION_DRIVER'] as $setting) {
    $assert(str_contains($config, $setting), 'Missing Phase 10 production configuration: ' . $setting);
}
$bootstrap = file_get_contents($root . '/bootstrap.php') ?: '';
foreach (['OperationsSecretCipher', 'NullOperationalNotificationAdapter', 'OperationsReadinessService', "'operations' => \$operations"] as $wiring) {
    $assert(str_contains($bootstrap, $wiring), 'Missing Phase 10 bootstrap wiring: ' . $wiring);
}

if ($failures !== []) {
    fwrite(STDERR, "Phase 10 contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 10 operations readiness and security contract certification passed.\n");

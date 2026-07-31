<?php

declare(strict_types=1);

use Vp3\Security\SecurityAlertPreferenceService;
use Vp3\Security\SecurityAuditService;
use Vp3\Security\SecurityIncidentAutomationService;

$services = require dirname(__DIR__) . '/bootstrap.php';
$operations = $services['operations'] ?? null;
if (!$operations instanceof \Vp3\Operations\OperationsReadinessService) {
    fwrite(STDERR, "Operations readiness service is unavailable.\n");
    exit(1);
}

$workerId = getenv('VP3_OPERATIONS_WORKER_ID') ?: (gethostname() . ':' . getmypid());
$mode = strtolower((string) (getenv('VP3_OPERATIONS_MODE') ?: 'all'));
$limit = max(1, min(100, (int) (getenv('VP3_OPERATIONS_NOTIFICATION_LIMIT') ?: 25)));
$securityLimit = max(1, min(200, (int) (getenv('VP3_SECURITY_INCIDENT_LIMIT') ?: 50)));

if (in_array($mode, ['all', 'monitor'], true)) {
    fwrite(STDOUT, json_encode($operations->runMonitoringPass($workerId), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . PHP_EOL);
}

if (in_array($mode, ['all', 'security', 'security-incidents'], true)) {
    $database = $services['database'] ?? null;
    $incidents = $services['operational_incidents'] ?? null;
    if (!$database instanceof \Vp3\Database || !$incidents instanceof \Vp3\Operations\OperationalIncidentService) {
        fwrite(STDERR, "Security incident automation dependencies are unavailable.\n");
        exit(1);
    }
    $audit = new SecurityAuditService($database);
    $preferences = new SecurityAlertPreferenceService($database, $incidents, $audit);
    $security = new SecurityIncidentAutomationService($database, $incidents, $preferences, $audit);
    fwrite(STDOUT, json_encode(
        $security->runPass((string) $workerId, $securityLimit),
        JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES
    ) . PHP_EOL);
}

if (in_array($mode, ['all', 'notifications'], true)) {
    for ($processed = 0; $processed < $limit; $processed++) {
        $result = $operations->processNextNotification($workerId);
        if ($result === null) {
            break;
        }
        fwrite(STDOUT, json_encode($result, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    }
}
if (in_array($mode, ['all', 'readiness'], true)) {
    fwrite(STDOUT, json_encode($operations->assessReadiness('worker', 0), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . PHP_EOL);
}

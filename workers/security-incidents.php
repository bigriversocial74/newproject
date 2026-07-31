<?php

declare(strict_types=1);

use Vp3\Security\SecurityAlertPreferenceService;
use Vp3\Security\SecurityAuditService;
use Vp3\Security\SecurityIncidentAutomationService;

$services = require dirname(__DIR__) . '/bootstrap.php';
$database = $services['database'] ?? null;
$incidents = $services['operational_incidents'] ?? null;
if (!$database instanceof \Vp3\Database || !$incidents instanceof \Vp3\Operations\OperationalIncidentService) {
    fwrite(STDERR, "Security incident automation dependencies are unavailable.\n");
    exit(1);
}

$workerId = getenv('VP3_SECURITY_INCIDENT_WORKER_ID') ?: (gethostname() . ':' . getmypid());
$limit = max(1, min(200, (int) (getenv('VP3_SECURITY_INCIDENT_LIMIT') ?: 50)));
$audit = new SecurityAuditService($database);
$preferences = new SecurityAlertPreferenceService($database, $incidents, $audit);
$automation = new SecurityIncidentAutomationService($database, $incidents, $preferences, $audit);

try {
    fwrite(STDOUT, json_encode(
        $automation->runPass((string) $workerId, $limit),
        JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES
    ) . PHP_EOL);
} catch (Throwable $exception) {
    fwrite(STDERR, json_encode([
        'error' => $exception::class,
        'message_hash' => hash('sha256', $exception->getMessage()),
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    exit(1);
}

<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};
$read = static function (string $path) use ($root, &$failures): string {
    $full = $root . '/' . $path;
    if (!is_file($full)) {
        $failures[] = 'Missing Phase 32 file: ' . $path;
        return '';
    }
    $content = file_get_contents($full);
    if (!is_string($content)) {
        $failures[] = 'Unable to read Phase 32 file: ' . $path;
        return '';
    }
    return $content;
};

$migration = $read('database/migrations/20260731_phase32_security_incident_automation.sql');
$manifest = $read('database/single-install-manifest.txt');
$response = $read('src/Security/SecurityIncidentResponseService.php');
$proof = $read('src/Security/SecurityReauthenticationProofService.php');
$preferences = $read('src/Security/SecurityAlertPreferenceService.php');
$automation = $read('src/Security/SecurityIncidentAutomationService.php');
$resolution = $read('src/Security/SecurityIncidentResolutionService.php');
$query = $read('src/Security/SecurityCenterQueryService.php');
$endpoint = $read('public/api/control-center/v1/security-response-action.php');
$overview = $read('public/api/control-center/v1/security-center-overview.php');
$page = $read('public/security-center.php');
$script = $read('public/assets/security-center.js');
$style = $read('public/assets/security-center.css');
$worker = $read('workers/security-incidents.php');
$operationsWorker = $read('workers/operations.php');
$assignmentProof = $read('tests/phase32_assignment_replay_database_integration.php');

foreach (['security_incident_cases', 'security_incident_notes', 'security_alert_preferences', 'security_response_actions'] as $table) {
    $assert(str_contains($migration, 'CREATE TABLE IF NOT EXISTS ' . $table), 'Phase 32 migration is missing ' . $table . '.');
}
$assert(str_contains($migration, 'automatic_promotion_enabled TINYINT(1) NOT NULL DEFAULT 0'), 'Automatic promotion is not independently opt-in.');
$assert(str_contains($migration, 'idx_security_alert_automatic'), 'Automatic promotion policy lacks an efficient worker index.');
$manifestEntries = array_values(array_filter(array_map('trim', explode("\n", $manifest)), static fn (string $line): bool => $line !== '' && !str_starts_with($line, '#')));
$assert(str_contains($manifest, 'migrations/20260731_phase32_security_incident_automation.sql'), 'Phase 32 migration is absent from the standalone installer manifest.');
$phase32Index = array_search('migrations/20260731_phase32_security_incident_automation.sql', $manifestEntries, true);
$assert($phase32Index !== false, 'Phase 32 migration is absent from the ordered installer manifest.');
if ($phase32Index !== false && isset($manifestEntries[$phase32Index + 1])) {
    $assert($manifestEntries[$phase32Index + 1] === 'migrations/20260731_phase33_production_deployment_upgrade.sql', 'Phase 32 is not immediately followed by the Phase 33 deployment migration.');
}

$assert(str_contains($response, 'qualifiesForIncident'), 'Security event qualification is not centralized.');
$assert(str_contains($response, "['high', 'critical']"), 'High and critical audit events are not incident eligible.');
$assert(str_contains($response, "['failure', 'denied']"), 'Failed and denied audit events are not incident eligible.');
$assert(str_contains($response, "=== 'integrity'"), 'Request-integrity events are not incident eligible.');
$assert(str_contains($response, "'security_audit'"), 'Security events are not promoted through the operational incident service.');
$assert(str_contains($response, 'OperationsSecretCipher'), 'Security analyst notes are not encrypted.');
$assert(str_contains($response, 'security_incident_notes'), 'Encrypted security notes are not persisted.');
$assert(!str_contains($response, 'note_plaintext'), 'Security note plaintext is persisted by name.');
$assert(str_contains($response, "'support_member'"), 'Assigned support responders are not represented in the response boundary.');
$assert(str_contains($response, 'assignmentReplayMatches'), 'Case-assignment replays are not authenticated against case and responder identities.');
$assert(str_contains($response, 'security_response_request_conflict'), 'Conflicting request-ID reuse is not rejected.');
$assert(str_contains($response, 'security_case_resolved'), 'Resolved security cases can still be reassigned.');
$assert(str_contains($response, 'security.emergency_revoke_sessions'), 'Emergency session revocation is not context-bound to reauthentication.');
$assert(str_contains($response, "revocation_reason='security_incident_response'"), 'Emergency session revocation lacks an explicit reason.');
$assert(str_contains($response, 'revoked_by_user_id=:actor_user_id'), 'Emergency session revocation does not preserve the acting administrator.');
$assert(str_contains($response, 'security_response_actions'), 'Security response actions are not idempotently receipted.');

$assert(str_contains($proof, 'password_verify'), 'Sensitive-action reauthentication does not verify the current password.');
$assert(str_contains($proof, 'requiresMfa'), 'Sensitive-action reauthentication does not inspect MFA state.');
$assert(str_contains($proof, 'completeChallenge'), 'Enabled MFA is not completed before satisfying reauthentication.');
$assert(str_contains($proof, 'SecurityReauthenticationService'), 'Password and MFA proof is not bound to the Phase 30 one-time challenge.');

$assert(str_contains($preferences, 'automatic_promotion_enabled'), 'Alert preferences do not persist explicit automatic promotion state.');
$assert(str_contains($preferences, 'notify_on_promotion'), 'Promotion notification preference is not persisted.');
$assert(str_contains($preferences, 'notify_on_emergency_action'), 'Emergency notification preference is not persisted.');
$assert(str_contains($preferences, 'suppressPromotionNotifications'), 'Disabled promotion alerts are not removed from the Operations queue.');
$assert(str_contains($preferences, "source_type='security_response_action'"), 'Emergency alert routing is not idempotent by source response action.');
$assert(str_contains($preferences, "'security_response_action'"), 'Emergency response alerts are not routed through Operations incidents.');

$assert(str_contains($automation, 'p.automatic_promotion_enabled=1'), 'The automatic worker ignores the explicit account opt-in boundary.');
$assert(str_contains($automation, 'FOR UPDATE'), 'Automatic event promotion does not lock its policy and evidence rows.');
$assert(str_contains($automation, "'automatic_promote_event'"), 'Automatic event promotion lacks an immutable response receipt.');
$assert(str_contains($automation, 'worker_id_hash'), 'Automatic promotion exposes or omits worker identity evidence.');
foreach (["security.incident.%", "security.response.%", "security.reauthentication.%"] as $excludedNamespace) {
    $assert(str_contains($automation, $excludedNamespace), 'Automatic promotion does not exclude internal namespace ' . $excludedNamespace . '.');
}
$assert(str_contains($automation, "security.alert_preferences.updated"), 'Automatic promotion can recursively promote policy-update evidence.');
$assert(str_contains($worker, 'VP3_SECURITY_INCIDENT_WORKER_ID'), 'The dedicated automatic promotion worker has no stable worker identity configuration.');
$assert(str_contains($worker, 'SecurityIncidentAutomationService'), 'The dedicated worker bypasses the Phase 32 automation service.');
$assert(str_contains($operationsWorker, "['all', 'security', 'security-incidents']"), 'The retained Operations worker does not schedule Phase 32 promotion.');
$assert(str_contains($operationsWorker, 'SecurityIncidentAutomationService'), 'The retained Operations worker bypasses the Phase 32 automation service.');
$assert(strpos($operationsWorker, 'runPass(') < strpos($operationsWorker, 'processNextNotification('), 'Security promotion does not run before same-pass notification delivery.');

$assert(str_contains($resolution, "'security.resolve_incident_case'"), 'Case closure is not context-bound to sensitive-action reauthentication.');
$assert(str_contains($resolution, '$this->reauthentication->consume('), 'Case closure does not consume a one-time reauthentication challenge.');
$assert(str_contains($resolution, '$this->incidents->resolve('), 'Security case closure does not resolve the linked operational incident.');
$assert(str_contains($resolution, "case_status='resolved'"), 'Security case closure does not persist resolved state.');
$assert(str_contains($resolution, "'resolve_case'"), 'Case resolution lacks an immutable response receipt.');
$assert(str_contains($resolution, 'resolutionEvidence'), 'Resolution replays are not bound to canonical resolution evidence.');
$assert(str_contains($resolution, 'hash_equals((string) $prior[\'evidence_hash\'], $expected)'), 'Resolution replay does not authenticate the stored evidence hash.');

$assert(str_contains($query, 'securityCases'), 'The Security Center does not expose Phase 32 cases.');
$assert(str_contains($query, 'responders'), 'The Security Center does not expose eligible responders.');
$assert(str_contains($query, 'security_incident_notes'), 'The Security Center does not load encrypted analyst notes.');
$assert(str_contains($query, '$this->cipher->decrypt('), 'Authorized managers cannot authenticate and read encrypted case notes.');
$assert(str_contains($query, 'SELECT automatic_promotion_enabled,minimum_risk'), 'The direct Security Center policy snapshot omits the explicit promotion flag.');
$assert(str_contains($query, "'automatic_promotion_enabled' => (bool) \$row['automatic_promotion_enabled']"), 'The direct Security Center policy snapshot infers opt-in from row existence.');
$assert(str_contains($query, 'recentResponseActions'), 'The Security Center omits immutable response history.');
$assert(str_contains($overview, 'SecurityAlertPreferenceService'), 'The Security Center overview does not return explicit policy state.');

$assert(str_contains($endpoint, "ControlCenterEndpoint::requireMethod('POST')"), 'Security response endpoint is not POST-only.');
$assert(str_contains($endpoint, "['customer_owner', 'customer_admin', 'support_member']"), 'Security response endpoint does not preserve responder role routing.');
$assert(str_contains($endpoint, 'ControlCenterEndpoint::requestId'), 'Security response mutations do not require request identities.');
$assert(str_contains($endpoint, "'assigned' => \$response->assignCase("), 'The assignment endpoint hides exact-replay state.');
$assert(str_contains($endpoint, 'AuthEndpoint::ip()'), 'Reauthentication is not bound to the current client network identity.');
$assert(str_contains($endpoint, 'AuthEndpoint::userAgent()'), 'Reauthentication is not bound to the current user agent.');
foreach (['save_alert_preferences', 'begin_case_resolution_reauthentication', 'complete_case_resolution_reauthentication', 'resolve_case'] as $action) {
    $assert(str_contains($endpoint, "case '" . $action . "':"), 'Security response endpoint is missing ' . $action . '.');
}
$assert(str_contains($endpoint, 'routeEmergencyAction'), 'Emergency response does not invoke alert routing.');

$assert(str_contains($assignmentProof, 'security_response_request_conflict'), 'Native assignment proof omits conflicting responder request-ID reuse.');
$assert(str_contains($assignmentProof, 'security_case_resolved'), 'Native assignment proof omits resolved-case rejection.');
$assert(str_contains($assignmentProof, 'Assignment replay created duplicate immutable receipts.'), 'Native assignment proof omits duplicate-receipt detection.');

$assert(str_contains($page, 'Security Cases &amp; Responders'), 'Security Center omits the case and responder surface.');
$assert(str_contains($page, 'Security Alert Policy'), 'Security Center omits policy controls.');
$assert(str_contains($page, 'security-reauth-dialog'), 'Security Center omits the sensitive-action reauthentication dialog.');
$assert(str_contains($script, "credentials: 'same-origin'"), 'Security Center actions do not use same-origin credentials.');
$assert(!str_contains($script, 'localStorage') && !str_contains($script, 'sessionStorage'), 'Security Center persists sensitive state in browser storage.');
$assert(!str_contains($script, '.innerHTML'), 'Security Center renders server data through innerHTML.');
$assert(str_contains($script, 'collectReauthentication'), 'Security Center does not collect password and MFA proof through a dedicated dialog.');
$assert(str_contains($script, 'emergency_revoke_sessions'), 'Security Center omits emergency session revocation controls.');
$assert(str_contains($script, 'resolve_case'), 'Security Center omits reauthenticated case resolution.');
$assert(str_contains($style, '.security-case-card'), 'Security Center stylesheet omits case presentation.');
$assert(str_contains($style, '.security-dialog'), 'Security Center stylesheet omits reauthentication presentation.');

if ($failures !== []) {
    fwrite(STDERR, "Phase 32 security incident automation contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

fwrite(STDOUT, "Phase 32 security incident automation contract passed.\n");

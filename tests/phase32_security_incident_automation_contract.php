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
$endpoint = $read('public/api/control-center/v1/security-response-action.php');

foreach (['security_incident_cases', 'security_incident_notes', 'security_alert_preferences', 'security_response_actions'] as $table) {
    $assert(str_contains($migration, 'CREATE TABLE IF NOT EXISTS ' . $table), 'Phase 32 migration is missing ' . $table . '.');
}
$manifestEntries = array_values(array_filter(array_map('trim', explode("\n", $manifest)), static fn (string $line): bool => $line !== '' && !str_starts_with($line, '#')));
$assert(str_contains($manifest, 'migrations/20260731_phase32_security_incident_automation.sql'), 'Phase 32 migration is absent from the standalone installer manifest.');
$assert(end($manifestEntries) === 'migrations/20260731_phase32_security_incident_automation.sql', 'Phase 32 is not the current final migration in the standalone installer manifest.');
$assert(str_contains($response, 'qualifiesForIncident'), 'Security event qualification is not centralized.');
$assert(str_contains($response, "['high', 'critical']"), 'High and critical audit events are not incident eligible.');
$assert(str_contains($response, "['failure', 'denied']"), 'Failed and denied audit events are not incident eligible.');
$assert(str_contains($response, "=== 'integrity'"), 'Request-integrity events are not incident eligible.');
$assert(str_contains($response, "'security_audit'"), 'Security events are not promoted through the operational incident service.');
$assert(str_contains($response, 'OperationsSecretCipher'), 'Security analyst notes are not encrypted.');
$assert(str_contains($response, 'security_incident_notes'), 'Encrypted security notes are not persisted.');
$assert(!str_contains($response, 'note_plaintext'), 'Security note plaintext is persisted by name.');
$assert(str_contains($response, "'support_member'"), 'Assigned support responders are not represented in the response boundary.');
$assert(str_contains($response, 'security.emergency_revoke_sessions'), 'Emergency session revocation is not context-bound to reauthentication.');
$assert(str_contains($response, "revocation_reason='security_incident_response'"), 'Emergency session revocation lacks an explicit reason.');
$assert(str_contains($response, 'revoked_by_user_id=:actor_user_id'), 'Emergency session revocation does not preserve the acting administrator.');
$assert(str_contains($response, 'security_response_actions'), 'Security response actions are not idempotently receipted.');
$assert(str_contains($proof, 'password_verify'), 'Sensitive-action reauthentication does not verify the current password.');
$assert(str_contains($proof, 'requiresMfa'), 'Sensitive-action reauthentication does not inspect MFA state.');
$assert(str_contains($proof, 'completeChallenge'), 'Enabled MFA is not completed before satisfying reauthentication.');
$assert(str_contains($proof, 'SecurityReauthenticationService'), 'Password and MFA proof is not bound to the Phase 30 one-time challenge.');
$assert(str_contains($endpoint, "ControlCenterEndpoint::requireMethod('POST')"), 'Security response endpoint is not POST-only.');
$assert(str_contains($endpoint, "['customer_owner', 'customer_admin', 'support_member']"), 'Security response endpoint does not preserve responder role routing.');
$assert(str_contains($endpoint, 'ControlCenterEndpoint::requestId'), 'Security response mutations do not require request identities.');
$assert(str_contains($endpoint, 'AuthEndpoint::ip()'), 'Reauthentication is not bound to the current client network identity.');
$assert(str_contains($endpoint, 'AuthEndpoint::userAgent()'), 'Reauthentication is not bound to the current user agent.');

if ($failures !== []) {
    fwrite(STDERR, "Phase 32 security incident automation contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}

fwrite(STDOUT, "Phase 32 security incident automation contract passed.\n");

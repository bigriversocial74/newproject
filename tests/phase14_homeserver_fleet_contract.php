<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};
$read = static function (string $path) use ($root): string {
    $content = file_get_contents($root . '/' . $path);
    if ($content === false) {
        throw new RuntimeException('Unable to read ' . $path);
    }
    return $content;
};

$service = $read('src/HomeServers/HomeServerFleetQueryService.php');
$endpoint = $read('public/api/homeserver/v1/fleet.php');

$assert(str_contains($endpoint, "HomeServerEndpoint::requireMethod('POST')"), 'Fleet endpoint is not POST-only.');
$assert(str_contains($endpoint, 'HomeServerEndpoint::accountContext'), 'Fleet endpoint does not enforce authenticated account ownership and CSRF.');
$assert(str_contains($service, 'WHERE d.account_id=:account'), 'Fleet query is not account scoped.');
$assert(str_contains($service, 'homeserver_entitlement_leases'), 'Fleet response omits lease evidence.');
$assert(str_contains($service, 'homeserver_update_receipts_v1'), 'Fleet response omits update receipt evidence.');
$assert(str_contains($service, 'homeserver_control_plane_events'), 'Fleet response omits bounded operational event counts.');
$assert(!str_contains($service, 'credential_hash'), 'Fleet service exposes or queries a device credential hash.');
$assert(!str_contains($service, 'code_hash'), 'Fleet service exposes or queries a pairing or transfer code hash.');
$assert(!str_contains($service, 'token_hash'), 'Fleet service exposes or queries an installer grant token hash.');
$assert(!str_contains($service, "'device_fingerprint' =>"), 'Fleet response exposes the device fingerprint.');
$assert(str_contains($service, "'event_count_24h'"), 'Fleet response does not bound operational event counts to the recent window.');

if ($failures !== []) {
    fwrite(STDERR, implode("\n", $failures) . "\n");
    exit(1);
}

echo "Phase 14 HomeServer fleet contract passed.\n";

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
$options = $read('src/HomeServers/HomeServerRegistrationOptionsService.php');
$endpoint = $read('public/api/homeserver/v1/fleet.php');
$optionsEndpoint = $read('public/api/homeserver/v1/registration-options.php');
$page = $read('public/homeservers.php');
$pageContext = $read('src/ControlCenter/AccountPageContext.php');
$pageShell = $read('src/ControlCenter/ControlCenterPage.php');
$client = $read('public/assets/homeserver-fleet.js');
$transferClient = $read('public/assets/homeserver-transfer-accept.js');

$assert(str_contains($endpoint, "HomeServerEndpoint::requireMethod('POST')"), 'Fleet endpoint is not POST-only.');
$assert(str_contains($endpoint, 'HomeServerEndpoint::accountContext'), 'Fleet endpoint does not enforce authenticated account ownership and CSRF.');
$assert(str_contains($optionsEndpoint, 'HomeServerEndpoint::accountContext'), 'Registration options are not account authenticated.');
$assert(str_contains($service, 'WHERE d.account_id=:account'), 'Fleet query is not account scoped.');
$assert(str_contains($service, 'homeserver_entitlement_leases'), 'Fleet response omits lease evidence.');
$assert(str_contains($service, 'homeserver_update_receipts_v1'), 'Fleet response omits update receipt evidence.');
$assert(str_contains($service, 'homeserver_control_plane_events'), 'Fleet response omits bounded operational event counts.');
$assert(!str_contains($service, 'credential_hash'), 'Fleet service exposes or queries a device credential hash.');
$assert(!str_contains($service, 'code_hash'), 'Fleet service exposes or queries a pairing or transfer code hash.');
$assert(!str_contains($service, 'token_hash'), 'Fleet service exposes or queries an installer grant token hash.');
$assert(!str_contains($service, "'device_fingerprint' =>"), 'Fleet response exposes the device fingerprint.');
$assert(str_contains($service, "'event_count_24h'"), 'Fleet response does not bound operational event counts to the recent window.');
$assert(str_contains($options, "hs.status<>'revoked'"), 'Eligible-license query does not exclude occupied licenses.');
$assert(str_contains($options, 'hs.id IS NULL'), 'Eligible-license query does not require an unoccupied license.');
$assert(str_contains($options, "l.product_type='homeserver'"), 'Eligible-license query can return non-HomeServer licenses.');
$assert(str_contains($pageContext, "role IN ('customer_owner','customer_admin')"), 'Fleet page context does not require a customer owner or administrator role.');
$assert(str_contains($pageShell, "header('Cache-Control: no-store')"), 'Shared fleet page shell does not disable response caching.');
$assert(str_contains($pageShell, 'Content-Security-Policy'), 'Shared fleet page shell does not enforce a restrictive content security policy.');
$assert(str_contains($page, 'AccountPageContext::resolve'), 'Fleet page is not using the shared authenticated account context.');
$assert(str_contains($page, "'homeservers'"), 'Fleet page is not registered in the shared control center navigation state.');
$assert(str_contains($client, '/api/homeserver/v1/register.php'), 'Fleet client cannot register a HomeServer.');
$assert(str_contains($client, '/api/homeserver/v1/replace.php'), 'Fleet client cannot replace a HomeServer.');
$assert(str_contains($client, '/api/homeserver/v1/transfer-request.php'), 'Fleet client cannot request a transfer.');
$assert(str_contains($transferClient, '/api/homeserver/v1/transfer-accept.php'), 'Fleet client cannot accept a transfer.');
$assert(str_contains($client, 'oneTimeBundle'), 'Registration and replacement credentials are not treated as one-time values.');
$assert(str_contains($client, 'bundle.account_id'), 'Registration and replacement bundles are not bound to their issuing account.');
$assert(str_contains($transferClient, 'bundleAccountId'), 'Transferred activation bundles are not bound to the destination account.');
$assert(str_contains($transferClient, 'Transferred HomeServer activation bundle'), 'Transfer credentials are not presented through a one-time activation flow.');
$assert(!str_contains($client, 'localStorage') && !str_contains($client, 'sessionStorage'), 'Fleet client persists one-time activation data in browser storage.');
$assert(!str_contains($transferClient, 'localStorage') && !str_contains($transferClient, 'sessionStorage'), 'Transfer client persists one-time activation data in browser storage.');
$assert(!str_contains($page, '$exception->getMessage()'), 'Fleet authentication page leaks internal exception messages.');

if ($failures !== []) {
    fwrite(STDERR, implode("\n", $failures) . "\n");
    exit(1);
}

echo "Phase 14 HomeServer fleet contract passed.\n";

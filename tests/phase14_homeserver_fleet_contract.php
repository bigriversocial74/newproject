<?php

declare(strict_types=1);
$root = dirname(__DIR__);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void { if (!$condition) $failures[] = $message; };
$read = static function (string $path) use ($root): string {
    $content = file_get_contents($root . '/' . $path);
    if ($content === false) throw new RuntimeException('Unable to read ' . $path);
    return $content;
};
$service = $read('src/HomeServers/HomeServerFleetQueryService.php');
$options = $read('src/HomeServers/HomeServerRegistrationOptionsService.php');
$licenseResolver = $read('src/HomeServers/HomeServerLicenseIdentityResolver.php');
$endpoint = $read('public/api/homeserver/v1/fleet.php');
$optionsEndpoint = $read('public/api/homeserver/v1/registration-options.php');
$page = $read('public/homeservers.php');
$pageContext = $read('src/ControlCenter/AccountPageContext.php');
$pageShell = $read('src/ControlCenter/ControlCenterPage.php');
$client = $read('public/assets/homeserver-fleet.js');
$transferClient = $read('public/assets/homeserver-transfer-accept.js');
$registerEndpoint = $read('public/api/homeserver/v1/register.php');
$transferEndpoint = $read('public/api/homeserver/v1/transfer-request.php');
$acceptEndpoint = $read('public/api/homeserver/v1/transfer-accept.php');

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
$assert(str_contains($options, 'HomeServerLicenseIdentityResolver'), 'Registration options bypass the shared public license resolver.');
$assert(str_contains($licenseResolver, "hs.status<>'revoked'"), 'Eligible-license query does not exclude occupied licenses.');
$assert(str_contains($licenseResolver, 'hs.id IS NULL'), 'Eligible-license query does not require an unoccupied license.');
$assert(str_contains($licenseResolver, "l.product_type='homeserver'"), 'Eligible-license query can return non-HomeServer licenses.');
$assert(!str_contains($licenseResolver, "'license_id' =>"), 'Eligible-license output exposes an internal ID.');
$assert(str_contains($pageContext, "'customer_owner', 'customer_admin'"), 'Fleet page context does not require owner/admin roles.');
$assert(str_contains($pageShell, "header('Cache-Control: no-store')"), 'Shared fleet page shell does not disable response caching.');
$assert(str_contains($pageShell, 'Content-Security-Policy'), 'Shared fleet page shell does not enforce a restrictive CSP.');
$assert(str_contains($page, 'AccountPageContext::resolve'), 'Fleet page is not using the shared authenticated account context.');
$assert(str_contains($page, "'homeservers'"), 'Fleet page is not registered in navigation.');
$assert(str_contains($page, 'data-account-public-id'), 'Fleet page does not expose the selected public account identity.');
$assert(!str_contains($page, 'data-account-id='), 'Fleet page still exposes an internal account ID.');
$assert(str_contains($client, '/api/homeserver/v1/register.php'), 'Fleet client cannot register a HomeServer.');
$assert(str_contains($client, '/api/homeserver/v1/replace.php'), 'Fleet client cannot replace a HomeServer.');
$assert(str_contains($client, '/api/homeserver/v1/transfer-request.php'), 'Fleet client cannot request a transfer.');
$assert(str_contains($transferClient, '/api/homeserver/v1/transfer-accept.php'), 'Fleet client cannot accept a transfer.');
$assert(str_contains($client, 'oneTimeBundle'), 'Registration and replacement credentials are not one-time values.');
$assert(str_contains($client, 'bundle.account_public_id') && str_contains($client, 'bundle.license_public_id'), 'Activation bundles are not bound to public account/license identities.');
$assert(str_contains($transferClient, 'bundleAccountPublicId') && str_contains($transferClient, 'bundle.license_public_id'), 'Transferred bundles are not bound to public account/license identities.');
$assert(str_contains($transferClient, 'Transferred HomeServer activation bundle'), 'Transfer credentials lack a one-time activation flow.');
$assert(str_contains($registerEndpoint, "unset(\$result['device_id'])") && str_contains($registerEndpoint, "'account_public_id'") && str_contains($registerEndpoint, "'license_public_id'"), 'Registration response exposes internal identity.');
$assert(str_contains($acceptEndpoint, "unset(\$result['license_id'])") && str_contains($acceptEndpoint, "'account_public_id'") && str_contains($acceptEndpoint, "'license_public_id'"), 'Transfer acceptance response exposes internal identity.');
$assert(str_contains($transferEndpoint, 'target_account_public_id') && !str_contains($transferEndpoint, "payload['target_account_id']"), 'Transfer target still uses a numeric account identity.');
foreach ([$client, $transferClient] as $browser) {
    $assert(!str_contains($browser, 'account_id') && !str_contains($browser, 'license_id') && !str_contains($browser, 'target_license_id'), 'Fleet browser code carries numeric account/license identity fields.');
    $assert(!str_contains($browser, 'localStorage') && !str_contains($browser, 'sessionStorage'), 'Fleet browser persists one-time activation data.');
}
$assert(!str_contains($page, '$exception->getMessage()'), 'Fleet authentication page leaks internal exception messages.');

if ($failures !== []) { fwrite(STDERR, implode("\n", $failures) . "\n"); exit(1); }
echo "Phase 14 HomeServer fleet contract passed.\n";

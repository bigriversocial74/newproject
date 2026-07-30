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

$context = $read('src/ControlCenter/AccountPageContext.php');
$shell = $read('src/ControlCenter/ControlCenterPage.php');
$query = $read('src/ControlCenter/AccountControlCenterQueryService.php');
$endpoint = $read('src/Http/ControlCenterEndpoint.php');
$overview = $read('public/api/control-center/v1/overview.php');
$domainAction = $read('public/api/control-center/v1/domain-action.php');
$podAction = $read('public/api/control-center/v1/pod-action.php');
$dashboard = $read('public/dashboard.php');
$domains = $read('public/domains.php');
$pods = $read('public/pods.php');
$homeservers = $read('public/homeservers.php');
$client = $read('public/assets/control-center.js');
$shellClient = $read('public/assets/control-center-shell.js');
$fleetClient = $read('public/assets/homeserver-fleet.js');
$transferClient = $read('public/assets/homeserver-transfer-accept.js');
$styles = $read('public/assets/control-center.css');

$assert(str_contains($context, "role IN ('owner','administrator')"), 'Shared account context does not require an owner or administrator role.');
$assert(str_contains($context, "a.status='active'"), 'Shared account context does not require an active account.');
$assert(str_contains($context, 'AuthPublicException'), 'Account membership failure is not represented as a public access error.');
$assert(str_contains($shell, "'dashboard' => ['/dashboard.php'"), 'Shared shell does not expose the Dashboard route.');
$assert(str_contains($shell, "'domains' => ['/domains.php'"), 'Shared shell does not expose the Domains route.');
$assert(str_contains($shell, "'pods' => ['/pods.php'"), 'Shared shell does not expose the POD route.');
$assert(str_contains($shell, "'homeservers' => ['/homeservers.php'"), 'Shared shell does not expose the HomeServer route.');
$assert(str_contains($shell, "header('Cache-Control: no-store')"), 'Control Center pages are cacheable.');
$assert(str_contains($shell, 'Content-Security-Policy'), 'Control Center pages do not enforce a content security policy.');
$assert(str_contains($shell, "frame-ancestors 'none'"), 'Control Center pages can be framed.');
$assert(str_contains($shell, 'http_response_code($exception->httpStatus())'), 'Control Center access pages do not preserve the safe public HTTP status.');
$assert(str_contains($shell, '$exception->publicMessage()'), 'Control Center access pages do not render the safe public access message.');

foreach ([$overview, $domainAction, $podAction] as $apiFile) {
    $assert(str_contains($apiFile, "ControlCenterEndpoint::requireMethod('POST')"), 'A Phase 15 API endpoint is not POST-only.');
    $assert(str_contains($apiFile, 'ControlCenterEndpoint::accountContext'), 'A Phase 15 API endpoint is not account authenticated and CSRF protected.');
}
$assert(str_contains($endpoint, 'MAX_JSON_BYTES = 65536'), 'Control Center JSON requests are not bounded.');
$assert(str_contains($endpoint, "role IN ('owner','administrator')"), 'Control Center API account context permits unsupported roles.');
$assert(str_contains($endpoint, 'InvalidArgumentException'), 'Control Center API does not return stable validation errors.');

$assert(str_contains($query, 'WHERE s.account_id=:account'), 'Subscription query is not account scoped.');
$assert(str_contains($query, 'WHERE d.account_id=:account'), 'Domain query is not account scoped.');
$assert(str_contains($query, 'WHERE pd.account_id=:account'), 'POD query is not account scoped.');
$assert(str_contains($query, 'WHERE account_scope=:account'), 'Incident query is not account scoped.');
$assert(str_contains($query, 'HomeServerFleetQueryService'), 'Unified account snapshot omits the certified HomeServer fleet read model.');
$assert(!str_contains($query, 'credential_hash'), 'Unified read model queries a device credential hash.');
$assert(!str_contains($query, 'device_fingerprint'), 'Unified read model queries a HomeServer fingerprint.');
$assert(!str_contains($query, 'destination_ciphertext'), 'Unified read model queries an encrypted notification destination.');
$assert(!str_contains($query, 'hosting_reference'), 'Unified read model exposes a hosting provider reference.');
$assert(!str_contains($query, 'database_reference'), 'Unified read model exposes a database provider reference.');
$assert(!str_contains($query, 'configuration_hash'), 'Unified read model exposes protected POD configuration evidence.');

$assert(str_contains($domainAction, "'register' => \$service->registerAndActivate"), 'Domain UI cannot register and activate the paired license bundle.');
$assert(str_contains($domainAction, "'activate_reserved' => \$service->activateReservedDomain"), 'Domain UI cannot activate a reservation.');
$assert(str_contains($domainAction, "'suspend' => \$service->suspendDomain"), 'Domain UI cannot perform non-destructive suspension.');
$assert(str_contains($domainAction, "!== 'RELEASE'"), 'Domain release is not protected by an exact confirmation.');
$assert(str_contains($podAction, "\$service->enqueue("), 'POD provisioning does not use the durable queue.');
$assert(str_contains($podAction, "\$service->enqueueRollback("), 'POD rollback does not use the durable queue.');
$assert(str_contains($podAction, "!== 'ROLLBACK'"), 'POD rollback is not protected by an exact confirmation.');
$assert(!str_contains($podAction, 'processNext('), 'POD worker execution occurs inside the web request.');

foreach ([$dashboard, $domains, $pods, $homeservers] as $pageFile) {
    $assert(str_contains($pageFile, 'AccountPageContext::resolve'), 'A Control Center page bypasses the shared authenticated account context.');
    $assert(str_contains($pageFile, 'ControlCenterPage::renderStart'), 'A Control Center page bypasses the shared shell.');
    $assert(str_contains($pageFile, 'catch (AuthPublicException $exception)'), 'A Control Center page does not isolate safe public access failures.');
    $assert(str_contains($pageFile, 'ControlCenterPage::renderAccessFailure'), 'A Control Center page does not use the shared safe access renderer.');
    $assert(!str_contains($pageFile, 'catch (Throwable)'), 'A Control Center page catches every operational failure as an access failure.');
    $assert(!str_contains($pageFile, '$exception->getMessage()'), 'A Control Center page leaks internal authentication exception details.');
}
$assert(str_contains($dashboard, 'dashboard-attention'), 'Dashboard omits prioritized attention items.');
$assert(str_contains($domains, 'domain-register-form'), 'Domain page omits Domain registration.');
$assert(str_contains($pods, 'pod-provision-form'), 'POD page omits queued provisioning.');
$assert(str_contains($homeservers, 'data-homeserver-fleet'), 'HomeServer page lost the certified fleet module.');

$assert(str_contains($client, 'cache: "no-store"'), 'Control Center API client permits browser caching.');
$assert(str_contains($client, 'body.account_id = accountId'), 'Control Center client does not force the selected account after caller payload construction.');
$assert(str_contains($client, 'body.csrf_token = csrfToken'), 'Control Center client does not force the current CSRF token after caller payload construction.');
$assert(str_contains($client, '{ request: true, idempotency: true }'), 'Idempotent lifecycle actions do not carry request and idempotency identities.');
$assert(str_contains($client, 'A suspension reason is required.'), 'Domain suspension can be submitted without a reason.');
$assert(str_contains($client, '<progress class='), 'POD storage usage does not use a CSP-compatible progress element.');
$assert(!str_contains($client, 'style='), 'Control Center client emits an inline style under a strict CSP.');
$assert(!str_contains($client, 'localStorage') && !str_contains($client, 'sessionStorage'), 'Control Center persists account or lifecycle data in browser storage.');
$assert(!str_contains($shellClient, 'localStorage') && !str_contains($shellClient, 'sessionStorage'), 'Shared shell persists account selection in browser storage.');
$assert(!str_contains($fleetClient, 'localStorage') && !str_contains($fleetClient, 'sessionStorage'), 'HomeServer fleet persists one-time credentials in browser storage.');
$assert(!str_contains($transferClient, 'localStorage') && !str_contains($transferClient, 'sessionStorage'), 'HomeServer transfer persists one-time credentials in browser storage.');
$assert(str_contains($styles, '@media(max-width:820px)'), 'Unified control center does not include a responsive navigation breakpoint.');

if ($failures !== []) {
    fwrite(STDERR, implode("\n", $failures) . "\n");
    exit(1);
}

echo "Phase 15 unified control center contract passed.\n";

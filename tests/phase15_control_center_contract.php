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

$context = $read('src/ControlCenter/AccountPageContext.php');
$resolver = $read('src/ControlCenter/PublicAccountIdentityResolver.php');
$shell = $read('src/ControlCenter/ControlCenterPage.php');
$query = $read('src/ControlCenter/AccountControlCenterQueryService.php');
$endpoint = $read('src/Http/ControlCenterEndpoint.php');
$overview = $read('public/api/control-center/v1/overview.php');
$domainAction = $read('public/api/control-center/v1/domain-action.php');
$podAction = $read('public/api/control-center/v1/pod-action.php');
$lifecycleAction = $read('src/Lifecycle/DomainPodLifecycleActionService.php');
$rollbackAction = $read('src/Lifecycle/PodRollbackLifecycleService.php');
$dashboard = $read('public/dashboard.php');
$domains = $read('public/domains.php');
$pods = $read('public/pods.php');
$homeservers = $read('public/homeservers.php');
$client = $read('public/assets/control-center.js');
$shellClient = $read('public/assets/control-center-shell.js');
$fleetClient = $read('public/assets/homeserver-fleet.js');
$transferClient = $read('public/assets/homeserver-transfer-accept.js');
$styles = $read('public/assets/control-center.css');

$assert(str_contains($context, "'customer_owner', 'customer_admin'"), 'Shared account context does not retain owner/admin roles.');
$assert(str_contains($resolver, "a.status='active'") && str_contains($resolver, "au.status='active'"), 'Shared account context does not require active account and membership state.');
$assert(str_contains($context, 'AuthPublicException'), 'Account membership failure is not a public access error.');
$assert(str_contains($context, "\$_GET['account']"), 'Shared account context does not route by public account identity.');
$assert(str_contains($resolver, "hash_equals((string) \$membership['public_id'], \$requestedPublicId)"), 'Page routing does not compare public account identities safely.');
$assert(str_contains($shell, "'dashboard' => ['/dashboard.php'"), 'Shared shell does not expose Dashboard.');
$assert(str_contains($shell, "'domains' => ['/domains.php'"), 'Shared shell does not expose Domains.');
$assert(str_contains($shell, "'pods' => ['/pods.php'"), 'Shared shell does not expose PODs.');
$assert(str_contains($shell, "'homeservers' => ['/homeservers.php'"), 'Shared shell does not expose HomeServers.');
$assert(str_contains($shell, '?account='), 'Shared shell does not emit public account routes.');
$assert(str_contains($shell, 'data-account-public-id'), 'Shared shell omits the public account data boundary.');
$assert(!str_contains($shell, 'data-account-id='), 'Shared shell exposes internal account IDs.');
$assert(!str_contains($shell, '?account_id='), 'Shared shell emits numeric account routes.');
$assert(str_contains($shell, "header('Cache-Control: no-store')"), 'Control Center pages are cacheable.');
$assert(str_contains($shell, 'Content-Security-Policy'), 'Control Center pages lack CSP.');
$assert(str_contains($shell, "frame-ancestors 'none'"), 'Control Center pages can be framed.');
$assert(str_contains($shell, 'http_response_code($exception->httpStatus())'), 'Access pages lose public HTTP status.');
$assert(str_contains($shell, '$exception->publicMessage()'), 'Access pages do not render safe public messages.');

foreach ([$overview, $domainAction, $podAction] as $apiFile) {
    $assert(str_contains($apiFile, "ControlCenterEndpoint::requireMethod('POST')"), 'A Phase 15 API endpoint is not POST-only.');
    $assert(str_contains($apiFile, 'ControlCenterEndpoint::accountContext'), 'A Phase 15 API endpoint is not account authenticated.');
}
$assert(str_contains($endpoint, 'MAX_JSON_BYTES = 65536'), 'Control Center JSON requests are not bounded.');
$assert(str_contains($endpoint, 'account_public_id'), 'Control Center API does not resolve public account identities.');
$assert(str_contains($endpoint, "array_key_exists('account_id', \$payload)"), 'Control Center API does not reject legacy numeric account payloads.');
$assert(str_contains($endpoint, 'new PublicAccountIdentityResolver'), 'Control Center API bypasses the shared public account resolver.');
$assert(str_contains($resolver, "JOIN accounts a ON a.id=au.account_id"), 'Control Center API does not resolve public identity server-side.');
$assert(str_contains($endpoint, 'InvalidArgumentException'), 'Control Center API lacks stable validation errors.');

$assert(str_contains($query, 'WHERE s.account_id=:account'), 'Subscription query is not account scoped.');
$assert(str_contains($query, 'WHERE d.account_id=:account'), 'Domain query is not account scoped.');
$assert(str_contains($query, 'WHERE pd.account_id=:account'), 'POD query is not account scoped.');
$assert(str_contains($query, 'WHERE account_scope=:account'), 'Incident query is not account scoped.');
$assert(str_contains($query, 'HomeServerFleetQueryService'), 'Unified snapshot omits HomeServer fleet.');
foreach (['credential_hash','device_fingerprint','destination_ciphertext','hosting_reference','database_reference','configuration_hash'] as $forbidden) {
    $assert(!str_contains($query, $forbidden), 'Unified read model exposes forbidden field ' . $forbidden . '.');
}

$assert(str_contains($domainAction, "'register' => \$service->registerDomain") && str_contains($lifecycleAction, 'registerAndActivate('), 'Domain registration bundle is unavailable.');
$assert(str_contains($domainAction, "'activate_reserved' => \$service->activateReservedDomain") && str_contains($lifecycleAction, 'activateReservedDomain('), 'Domain reservation activation is unavailable.');
$assert(str_contains($domainAction, "'suspend' => \$service->suspendDomain") && str_contains($lifecycleAction, 'suspendDomain('), 'Domain suspension is unavailable.');
$assert(str_contains($lifecycleAction, "!== 'RELEASE'"), 'Domain release lacks exact confirmation.');
$assert(str_contains($podAction, "'provision' => \$service->provisionPod") && str_contains($lifecycleAction, '$this->pods->enqueue('), 'POD provisioning bypasses durable queue.');
$assert(str_contains($podAction, "'rollback' => \$rollback->enqueue") && str_contains($rollbackAction, '$this->pods->enqueueRollback('), 'POD rollback bypasses durable queue.');
$assert(str_contains($rollbackAction, "!== 'ROLLBACK'"), 'POD rollback lacks exact confirmation.');
$assert(!str_contains($podAction, 'processNext('), 'POD worker execution occurs in web request.');

foreach ([$dashboard, $domains, $pods, $homeservers] as $pageFile) {
    $assert(str_contains($pageFile, 'AccountPageContext::resolve'), 'A Control Center page bypasses shared account context.');
    $assert(str_contains($pageFile, 'ControlCenterPage::renderStart'), 'A Control Center page bypasses shared shell.');
    $assert(str_contains($pageFile, 'catch (AuthPublicException $exception)'), 'A Control Center page does not isolate access failures.');
    $assert(str_contains($pageFile, 'ControlCenterPage::renderAccessFailure'), 'A Control Center page lacks safe access renderer.');
    $assert(!str_contains($pageFile, 'catch (Throwable)'), 'A page catches operational failures as access failures.');
    $assert(!str_contains($pageFile, '$exception->getMessage()'), 'A page leaks authentication exception details.');
}
$assert(str_contains($dashboard, 'dashboard-attention'), 'Dashboard omits attention items.');
$assert(str_contains($domains, 'domain-register-form'), 'Domain page omits registration.');
$assert(str_contains($pods, 'pod-provision-form'), 'POD page omits provisioning.');
$assert(str_contains($homeservers, 'data-homeserver-fleet'), 'HomeServer page lost fleet module.');

$assert(str_contains($client, 'cache: "no-store"'), 'Control Center client permits caching.');
$assert(str_contains($client, 'body.account_public_id = accountPublicId'), 'Control Center client does not force public account identity.');
$assert(!str_contains($client, 'body.account_id') && !str_contains($client, 'dataset.accountId'), 'Control Center client still uses numeric account identity.');
$assert(str_contains($client, 'body.csrf_token = csrfToken'), 'Control Center client does not force CSRF.');
$assert(str_contains($client, '{ request: true, idempotency: true }'), 'Idempotent actions omit identities.');
$assert(str_contains($client, 'A suspension reason is required.'), 'Domain suspension accepts no reason.');
$assert(str_contains($client, '<progress class='), 'POD storage usage lacks CSP-compatible progress.');
$assert(!str_contains($client, 'style='), 'Control Center client emits inline style.');
$assert(str_contains($shellClient, 'url.searchParams.set("account", picker.value)'), 'Account switcher does not use public routing.');
$assert(!str_contains($shellClient, 'url.searchParams.set("account_id"') && !str_contains($shellClient, 'url.searchParams.set("account_public_id"'), 'Account switcher actively emits a legacy account route.');
$assert(str_contains($shellClient, 'url.searchParams.delete("account_id")'), 'Account switcher does not remove legacy numeric account routing.');
foreach ([$client, $shellClient, $fleetClient, $transferClient] as $browserFile) {
    $assert(!str_contains($browserFile, 'localStorage') && !str_contains($browserFile, 'sessionStorage'), 'Control Center persists sensitive browser state.');
}
$assert(str_contains($styles, '@media(max-width:820px)'), 'Unified Control Center lacks responsive navigation.');

if ($failures !== []) { fwrite(STDERR, implode("\n", $failures) . "\n"); exit(1); }
echo "Phase 15 unified control center contract passed.\n";

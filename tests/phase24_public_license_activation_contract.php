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

$required = [
    'src/HomeServers/HomeServerLicenseIdentityResolver.php',
    'src/HomeServers/HomeServerRegistrationOptionsService.php',
    'public/api/homeserver/v1/registration-options.php',
    'public/api/homeserver/v1/register.php',
    'public/api/homeserver/v1/transfer-accept.php',
    'public/assets/homeserver-fleet.js',
    'public/assets/homeserver-transfer-accept.js',
    'tests/phase24_public_license_activation_database_integration.php',
];
foreach ($required as $path) $assert(is_file($root . '/' . $path), 'Missing Phase 24 file ' . $path . '.');

$resolver = $read('src/HomeServers/HomeServerLicenseIdentityResolver.php');
$options = $read('src/HomeServers/HomeServerRegistrationOptionsService.php');
$optionsEndpoint = $read('public/api/homeserver/v1/registration-options.php');
$register = $read('public/api/homeserver/v1/register.php');
$accept = $read('public/api/homeserver/v1/transfer-accept.php');
$fleet = $read('public/assets/homeserver-fleet.js');
$transfer = $read('public/assets/homeserver-transfer-accept.js');
$controlPlane = $read('src/HomeServers/HomeServerControlPlaneService.php');

foreach (["l.product_type='homeserver'", "l.status IN ('active','grace')", "s.status IN ('trialing','active','grace')", "d.status IN ('active','grace')", "hs.status<>'revoked'", 'hs.id IS NULL'] as $needle) {
    $assert(str_contains($resolver, $needle), 'Public license resolver is missing eligibility rule ' . $needle . '.');
}
$assert(str_contains($resolver, 'license_identity_invalid'), 'Malformed license identities lack a stable public error.');
$assert(str_contains($resolver, 'license_not_eligible'), 'Ineligible licenses lack a stable public error.');
$assert(str_contains($resolver, "'license_public_id' =>"), 'Eligible licenses omit their public identity.');
$assert(!str_contains($resolver, "'license_id' =>"), 'Eligible license output exposes an internal ID.');
$assert(str_contains($options, 'HomeServerLicenseIdentityResolver'), 'Registration options bypass the shared license resolver.');
$assert(str_contains($optionsEndpoint, "'account_public_id'"), 'Registration options omit the public account identity.');
$assert(!str_contains($optionsEndpoint, "'account_id' =>"), 'Registration options expose an internal account ID.');

foreach ([[$register, 'license_id', 'license_public_id'], [$accept, 'target_license_id', 'target_license_public_id']] as [$endpoint, $legacy, $public]) {
    $assert(str_contains($endpoint, "array_key_exists('{$legacy}', \$payload)"), 'Endpoint does not reject legacy numeric field ' . $legacy . '.');
    $assert(str_contains($endpoint, 'license_public_identity_required'), 'Endpoint lacks the stable legacy license error.');
    $assert(str_contains($endpoint, "payload['{$public}']"), 'Endpoint does not read public license field ' . $public . '.');
    $assert(str_contains($endpoint, 'HomeServerLicenseIdentityResolver'), 'Endpoint bypasses the public license resolver.');
}
$assert(str_contains($register, "unset(\$result['device_id'])") && str_contains($register, "'license_public_id'"), 'Registration response is not public-license-only.');
$assert(str_contains($accept, "unset(\$result['license_id'])") && str_contains($accept, "'license_public_id'"), 'Transfer response is not public-license-only.');
$assert(str_contains($controlPlane, 'registerDevice(') && str_contains($controlPlane, 'acceptTransfer('), 'Certified control-plane operations were removed.');

foreach ([$fleet, $transfer] as $browser) {
    $assert(str_contains($browser, 'license_public_id'), 'HomeServer browser flow omits public license identity.');
    foreach (['license_id:', 'target_license_id:', '.license_id', '.target_license_id', 'Number(license.license_public_id)', 'Number(option.license_public_id)'] as $forbidden) {
        $assert(!str_contains($browser, $forbidden), 'HomeServer browser flow contains forbidden numeric license pattern ' . $forbidden . '.');
    }
    $assert(!str_contains($browser, 'localStorage') && !str_contains($browser, 'sessionStorage'), 'HomeServer browser flow persists activation data.');
}
$assert(str_contains($fleet, 'license_public_id: licensePublicId'), 'Registration browser request does not send the public license identity.');
$assert(str_contains($transfer, 'target_license_public_id: licensePublicId'), 'Transfer acceptance does not send the public license identity.');

if ($failures !== []) {
    fwrite(STDERR, "Phase 24 public license activation contract failures:\n- " . implode("\n- ", $failures) . "\n");
    exit(1);
}
fwrite(STDOUT, "Phase 24 public license activation contract passed.\n");

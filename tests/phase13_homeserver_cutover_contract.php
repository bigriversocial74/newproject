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

$signer = $read('src/HomeServers/HomeServerLeaseSigner.php');
$catalog = $read('src/Releases/ReleaseCatalogService.php');
$config = $read('config/config-example.php');
$bootstrap = $read('bootstrap.php');
$migration = $read('database/migrations/20260729_phase13_homeserver_cutover_contract.sql');
$installer = $read('database/vp3-single-install.sql');

$assert(str_contains($signer, "'Ed25519'"), 'HomeServer entitlement leases are not Ed25519 signed.');
$assert(str_contains($signer, 'sodium_crypto_sign_detached'), 'HomeServer lease detached signature generation is missing.');
$assert(str_contains($signer, 'sodium_crypto_sign_verify_detached'), 'HomeServer lease public verification is missing.');
$assert(str_contains($config, 'VP3_HOMESERVER_LEASE_PRIVATE_KEY_B64'), 'VP3 lease private-key configuration is missing.');
$assert(str_contains($config, 'VP3_HOMESERVER_LEASE_PUBLIC_KEY_B64'), 'VP3 lease public-key configuration is missing.');
$assert(str_contains($bootstrap, 'lease_signing_private_key_base64'), 'VP3 bootstrap does not use the Ed25519 lease private key.');
$assert(str_contains($bootstrap, 'lease_signing_public_key_base64'), 'VP3 bootstrap does not bind the Ed25519 lease public key.');
$assert(str_contains($migration, 'authenticode_thumbprint VARCHAR(64)'), 'HomeServer Authenticode trust metadata migration is missing.');
$assert(str_contains($migration, 'file_name VARCHAR(190)'), 'HomeServer canonical installer name migration is missing.');
$assert(str_contains($catalog, "fileName !== 'Microgifter-HomeServer-Setup.exe'"), 'Canonical HomeServer installer filename enforcement is missing.');
$assert(str_contains($catalog, "(?:[A-F0-9]{40}|[A-F0-9]{64})"), 'Authenticode thumbprint format enforcement is missing.');
$assert(str_contains($catalog, 'authenticode_thumbprint,size_bytes FROM release_artifacts'), 'Authenticode thumbprint is not included in the signed manifest.');
$assert(str_contains($installer, '20260729_phase13_homeserver_cutover_contract.sql'), 'Cumulative installer omits Phase 13.');
$assert(!str_contains($migration, 'credential') && !str_contains($migration, 'token'), 'Phase 13 trust migration stores a credential or token.');

if ($failures !== []) {
    fwrite(STDERR, implode("\n", $failures) . "\n");
    exit(1);
}

echo "Phase 13 HomeServer cutover contract passed.\n";

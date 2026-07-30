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
$base64UrlDecode = static function (string $value): ?string {
    $padding = strlen($value) % 4;
    if ($padding > 0) {
        $value .= str_repeat('=', 4 - $padding);
    }
    $decoded = base64_decode(strtr($value, '-_', '+/'), true);
    return is_string($decoded) ? $decoded : null;
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
$assert(str_contains($catalog, '(?:[A-F0-9]{40}|[A-F0-9]{64})'), 'Authenticode thumbprint format enforcement is missing.');
$assert(str_contains($catalog, 'authenticode_thumbprint,size_bytes FROM release_artifacts'), 'Authenticode thumbprint is not included in the signed manifest.');
$download = $read('public/api/homeserver/v1/installer-download.php');
$assert(str_contains($catalog, "'published_at_utc'"), 'Signed HomeServer release publication time is missing.');
$assert(str_contains($catalog, "'installer_download_path'"), 'Signed stable HomeServer installer path is missing.');
$assert(str_contains($download, 'HomeServerEndpoint::bearerCredential()'), 'Installer grants cannot be supplied as bearer credentials.');
$assert(str_contains($installer, '20260729_phase13_homeserver_cutover_contract.sql'), 'Cumulative installer omits Phase 13.');
$assert(!str_contains($migration, 'credential') && !str_contains($migration, 'token'), 'Phase 13 trust migration stores a credential or token.');

if (!function_exists('sodium_crypto_sign_seed_keypair')) {
    $failures[] = 'The sodium extension is unavailable for the Phase 13 Ed25519 contract drill.';
} else {
    require_once $root . '/src/HomeServers/HomeServerLeaseSigner.php';

    $seed = hash('sha256', 'vp3-phase13-contract-key', true);
    $keyPair = sodium_crypto_sign_seed_keypair($seed);
    $privateKey = sodium_crypto_sign_secretkey($keyPair);
    $publicKey = sodium_crypto_sign_publickey($keyPair);
    $leaseSigner = new \Vp3\HomeServers\HomeServerLeaseSigner(
        base64_encode($privateKey),
        base64_encode($publicKey),
        'homeserver-lease-ed25519-v1'
    );
    $fingerprint = hash('sha256', 'MicrogifterHomeServer:vp3-device:phase13-contract-installation');
    $signed = $leaseSigner->sign([
        'account_id' => 13001,
        'device_fingerprint' => $fingerprint,
        'exp' => 4102444800,
        'iat' => 1893456000,
        'iss' => 'vp3.me',
        'lease_id' => 'LEASE-CONTRACT-1',
        'software_authority' => 'vp3',
        'sub' => 'HS-CONTRACT-1',
        'update_channel' => 'stable',
    ]);

    $expectedDocument = 'eyJhY2NvdW50X2lkIjoxMzAwMSwiZGV2aWNlX2ZpbmdlcnByaW50IjoiZjMyZmI2OWZjZTQwYzZkNmFkNWIxNmUxYjMxMTQzNWVjOWFkOTY0MDRjOWUwMTRhM2NjMzdmNDU2NGFkYWVhZCIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxODkzNDU2MDAwLCJpc3MiOiJ2cDMubWUiLCJsZWFzZV9pZCI6IkxFQVNFLUNPTlRSQUNULTEiLCJzb2Z0d2FyZV9hdXRob3JpdHkiOiJ2cDMiLCJzdWIiOiJIUy1DT05UUkFDVC0xIiwidXBkYXRlX2NoYW5uZWwiOiJzdGFibGUifQ';
    $expectedSignature = 'ieeMo1Sro9beDs97zLUZINMAbMEvPM30zio9eBDCpsY2rYY2wvCIRfrlgJJTyIDMCNV4zu-rc77qCGtc8pQiBA';
    $document = $base64UrlDecode($signed['document']);
    $claims = is_string($document) ? json_decode($document, true, 512, JSON_THROW_ON_ERROR) : null;

    $assert($leaseSigner->algorithm() === 'Ed25519', 'The runtime lease signer did not enter Ed25519 mode.');
    $assert($signed['document'] === $expectedDocument, 'VP3 produced a different canonical Phase 13 lease document.');
    $assert($signed['signature'] === $expectedSignature, 'VP3 produced a different Phase 13 Ed25519 signature.');
    $assert($leaseSigner->verify($signed['document'], $signed['signature']), 'VP3 could not verify its deterministic Phase 13 lease.');
    $assert(is_array($claims) && ($claims['device_fingerprint'] ?? null) === $fingerprint, 'The signed lease is not bound to the shared HomeServer fingerprint.');
    $assert(is_string($document) && hash('sha256', $document) === 'c08076aea798fb5c1cebd51e6f23ef4ba3735d37ef18ee53ff7bb8f601cd3c02', 'The shared lease document hash changed.');

    $tampered = $signed['document'];
    $tampered[10] = $tampered[10] === 'A' ? 'B' : 'A';
    $assert(!$leaseSigner->verify($tampered, $signed['signature']), 'A tampered Phase 13 lease was accepted.');
}

if ($failures !== []) {
    fwrite(STDERR, implode("\n", $failures) . "\n");
    exit(1);
}

echo "Phase 13 HomeServer cutover contract passed.\n";

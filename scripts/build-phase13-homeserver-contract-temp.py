from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text()


def write(path: str, content: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        raise SystemExit(f"{label} was not found")
    return text.replace(old, new, 1)


write(
    "src/HomeServers/HomeServerLeaseSigner.php",
    r'''<?php

declare(strict_types=1);

namespace Vp3\HomeServers;

use RuntimeException;

final class HomeServerLeaseSigner
{
    public function __construct(
        private readonly string $privateKeyBase64,
        private readonly string $publicKeyBase64,
        private readonly string $keyId = 'release-ed25519-v1'
    ) {
    }

    /** @param array<string,mixed> $claims @return array{document:string,signature:string,key_id:string,algorithm:string,document_hash:string,signature_hash:string} */
    public function sign(array $claims): array
    {
        $this->assertSodium();
        $private = base64_decode($this->privateKeyBase64, true);
        if (!is_string($private) || strlen($private) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new RuntimeException('A valid Ed25519 HomeServer authority private key is required.');
        }
        $document = $this->canonicalJson($claims);
        $signature = sodium_crypto_sign_detached($document, $private);
        return [
            'document' => $this->base64Url($document),
            'signature' => $this->base64Url($signature),
            'key_id' => $this->keyId,
            'algorithm' => 'Ed25519',
            'document_hash' => hash('sha256', $document),
            'signature_hash' => hash('sha256', $signature),
        ];
    }

    public function verify(string $document, string $signature): bool
    {
        $this->assertSodium();
        $public = base64_decode($this->publicKeyBase64, true);
        $documentBytes = $this->base64UrlDecode($document);
        $signatureBytes = $this->base64UrlDecode($signature);
        if (!is_string($public) || strlen($public) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
            || $documentBytes === null || $signatureBytes === null
            || strlen($signatureBytes) !== SODIUM_CRYPTO_SIGN_BYTES) {
            return false;
        }
        return sodium_crypto_sign_verify_detached($signatureBytes, $documentBytes, $public);
    }

    public function keyId(): string
    {
        return $this->keyId;
    }

    private function assertSodium(): void
    {
        if (!function_exists('sodium_crypto_sign_detached')) {
            throw new RuntimeException('The sodium extension is required for signed HomeServer authority leases.');
        }
    }

    private function canonicalJson(mixed $value): string
    {
        $normalize = static function (mixed $item) use (&$normalize): mixed {
            if (!is_array($item)) {
                return $item;
            }
            if (array_is_list($item)) {
                return array_map($normalize, $item);
            }
            ksort($item);
            foreach ($item as $key => $child) {
                $item[$key] = $normalize($child);
            }
            return $item;
        };
        return json_encode($normalize($value), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    private function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $value): ?string
    {
        $padding = strlen($value) % 4;
        if ($padding > 0) {
            $value .= str_repeat('=', 4 - $padding);
        }
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);
        return is_string($decoded) ? $decoded : null;
    }
}
''',
)

bootstrap = read("bootstrap.php")
bootstrap = replace_once(
    bootstrap,
    "$homeServerLeaseSigner = new HomeServerLeaseSigner((string) $config['homeserver']['lease_signing_key'], (string) $config['homeserver']['lease_signing_key_id']);",
    "$homeServerLeaseSigner = new HomeServerLeaseSigner((string) $config['releases']['signing_private_key_base64'], (string) $config['releases']['signing_public_key_base64'], (string) $config['releases']['signing_key_id']);",
    "HomeServer lease-signer wiring",
)
bootstrap = replace_once(
    bootstrap,
    "$releaseCatalog = new ReleaseCatalogService($database, $releaseManifestSigner);",
    "$releaseCatalog = new ReleaseCatalogService($database, $releaseManifestSigner, (string) $config['app']['base_url']);",
    "release-catalog base URL wiring",
)
write("bootstrap.php", bootstrap)

registry = read("src/HomeServers/HomeServerRegistryService.php")
registry = replace_once(
    registry,
    "/** @return array{lease_public_id:string,document:string,signature:string,key_id:string,expires_at:string} */",
    "/** @return array{lease_public_id:string,document:string,signature:string,key_id:string,algorithm:string,expires_at:string} */",
    "lease response annotation",
)
registry = replace_once(
    registry,
    "                'key_id' => $signed['key_id'],\n                'expires_at' => $expires,",
    "                'key_id' => $signed['key_id'],\n                'algorithm' => $signed['algorithm'],\n                'expires_at' => $expires,",
    "lease algorithm response",
)
write("src/HomeServers/HomeServerRegistryService.php", registry)

write(
    "database/migrations/20260729_phase13_homeserver_cryptographic_contract.sql",
    r'''SET NAMES utf8mb4;
SET time_zone = '+00:00';

DROP PROCEDURE IF EXISTS vp3_phase13_homeserver_contract_upgrade;
DELIMITER $$
CREATE PROCEDURE vp3_phase13_homeserver_contract_upgrade()
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=DATABASE() AND table_name='software_releases' AND column_name='release_notes'
    ) THEN
        ALTER TABLE software_releases ADD COLUMN release_notes TEXT NULL AFTER release_notes_hash;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=DATABASE() AND table_name='release_artifacts' AND column_name='authenticode_thumbprint'
    ) THEN
        ALTER TABLE release_artifacts ADD COLUMN authenticode_thumbprint VARCHAR(64) NULL AFTER size_bytes;
    END IF;
END$$
DELIMITER ;
CALL vp3_phase13_homeserver_contract_upgrade();
DROP PROCEDURE IF EXISTS vp3_phase13_homeserver_contract_upgrade;
''',
)

installer = read("database/vp3-single-install.sql")
source_line = "SOURCE migrations/20260729_phase13_homeserver_cryptographic_contract.sql;"
if source_line not in installer:
    installer = installer.rstrip() + "\n" + source_line + "\n"
write("database/vp3-single-install.sql", installer)

catalog = read("src/Releases/ReleaseCatalogService.php")
catalog = replace_once(
    catalog,
    "        private readonly ReleaseManifestSigner $signer\n    )",
    "        private readonly ReleaseManifestSigner $signer,\n        private readonly string $baseUrl = 'https://vp3.me'\n    )",
    "release-catalog constructor",
)
catalog = replace_once(
    catalog,
    "SELECT id FROM software_products WHERE id=:id AND status='active' LIMIT 1 FOR UPDATE",
    "SELECT id,target_type FROM software_products WHERE id=:id AND status='active' LIMIT 1 FOR UPDATE",
    "release-product target lookup",
)
product_pattern = re.compile(
    r"(?P<indent>\s*)\$product->execute\(\['id' => \$productId\]\);\n"
    r"(?P=indent)if \(!\$product->fetchColumn\(\)\) \{\n"
    r"(?P=indent)    throw new RuntimeException\('Active software product was not found\.'\);\n"
    r"(?P=indent)\}\n"
)
product_replacement = (
    "\\g<indent>$product->execute(['id' => $productId]);\n"
    "\\g<indent>$productRow = $product->fetch(PDO::FETCH_ASSOC);\n"
    "\\g<indent>if (!is_array($productRow)) {\n"
    "\\g<indent>    throw new RuntimeException('Active software product was not found.');\n"
    "\\g<indent>}\n"
    "\\g<indent>$targetType = (string) $productRow['target_type'];\n"
)
catalog, count = product_pattern.subn(product_replacement, catalog, count=1)
if count != 1:
    raise SystemExit("release-product result handling was not found")

catalog = replace_once(
    catalog,
    "                 (public_id,product_id,version,channel,status,release_notes_hash,emergency_override,created_at,updated_at)\n                  VALUES (:public,:product,:version,:channel,'draft',:notes,:emergency,UTC_TIMESTAMP(),UTC_TIMESTAMP())",
    "                 (public_id,product_id,version,channel,status,release_notes_hash,release_notes,emergency_override,created_at,updated_at)\n                  VALUES (:public,:product,:version,:channel,'draft',:notes_hash,:release_notes,:emergency,UTC_TIMESTAMP(),UTC_TIMESTAMP())",
    "release-note persistence SQL",
)
catalog = replace_once(
    catalog,
    "                'notes' => hash('sha256', $releaseNotes),",
    "                'notes_hash' => hash('sha256', $releaseNotes),\n                'release_notes' => substr($releaseNotes, 0, 20000),",
    "release-note persistence parameters",
)
catalog = replace_once(
    catalog,
    "                 (release_id,platform,architecture,storage_reference,sha256,size_bytes,created_at)\n                  VALUES (:release,:platform,:architecture,:storage,:sha,:size,UTC_TIMESTAMP())",
    "                 (release_id,platform,architecture,storage_reference,sha256,size_bytes,authenticode_thumbprint,created_at)\n                  VALUES (:release,:platform,:architecture,:storage,:sha,:size,:thumbprint,UTC_TIMESTAMP())",
    "release-artifact persistence SQL",
)
validation_marker = """                if (!preg_match('/^[a-f0-9]{64}$/', $sha)
                    || trim((string) ($artifact['platform'] ?? '')) === ''
                    || trim((string) ($artifact['architecture'] ?? '')) === ''
                    || trim((string) ($artifact['storage_reference'] ?? '')) === ''
                    || (int) ($artifact['size_bytes'] ?? 0) < 1) {
                    throw new RuntimeException('Release artifact metadata is invalid.');
                }
"""
validation_replacement = validation_marker + """                $thumbprint = strtoupper(trim((string) ($artifact['authenticode_thumbprint'] ?? '')));
                if ($targetType === 'homeserver'
                    && (!in_array(strlen($thumbprint), [40, 64], true) || !ctype_xdigit($thumbprint))) {
                    throw new RuntimeException('HomeServer release artifacts require a valid Authenticode signer thumbprint.');
                }
"""
catalog = replace_once(catalog, validation_marker, validation_replacement, "artifact validation")
catalog = replace_once(
    catalog,
    "                    'size' => (int) $artifact['size_bytes'],",
    "                    'size' => (int) $artifact['size_bytes'],\n                    'thumbprint' => $thumbprint === '' ? null : $thumbprint,",
    "artifact thumbprint parameter",
)
manifest_pattern = re.compile(
    r"    /\*\* @param array<string,mixed> \$release @return array<string,mixed> \*/\n"
    r"    private function manifest\(PDO \$pdo, array \$release\): array\n"
    r"    \{.*?\n    \}\n\n"
    r"    /\*\* @return array<string,mixed> \*/\n"
    r"    private function release",
    re.S,
)
manifest_method = r'''    /** @param array<string,mixed> $release @return array<string,mixed> */
    private function manifest(PDO $pdo, array $release): array
    {
        $artifacts = $pdo->prepare('SELECT platform,architecture,storage_reference,sha256,size_bytes,authenticode_thumbprint FROM release_artifacts WHERE release_id=:release ORDER BY platform,architecture');
        $artifacts->execute(['release' => $release['id']]);
        $compatibility = $pdo->prepare('SELECT minimum_current_version,maximum_current_version,minimum_php_version,database_family,minimum_database_version FROM release_compatibility_rules WHERE release_id=:release LIMIT 1');
        $compatibility->execute(['release' => $release['id']]);
        $rollout = $pdo->prepare('SELECT percentage,cohort_seed,starts_at,ends_at FROM release_rollouts WHERE release_id=:release LIMIT 1');
        $rollout->execute(['release' => $release['id']]);
        return [
            'schema' => 'vp3.release-manifest.v1',
            'release_public_id' => $release['public_id'],
            'product_code' => $release['product_code'],
            'target_type' => $release['target_type'],
            'version' => $release['version'],
            'channel' => $release['channel'],
            'emergency_override' => (bool) $release['emergency_override'],
            'published_at_utc' => gmdate('Y-m-d\\TH:i:s\\Z'),
            'release_notes' => (string) ($release['release_notes'] ?? ''),
            'release_notes_hash' => $release['release_notes_hash'],
            'installer_download_url' => rtrim($this->baseUrl, '/') . '/api/homeserver/v1/installer-download.php',
            'artifacts' => $artifacts->fetchAll(PDO::FETCH_ASSOC),
            'compatibility' => $compatibility->fetch(PDO::FETCH_ASSOC) ?: [],
            'initial_rollout' => $rollout->fetch(PDO::FETCH_ASSOC) ?: [],
        ];
    }

    /** @return array<string,mixed> */
    private function release'''
catalog, count = manifest_pattern.subn(manifest_method, catalog, count=1)
if count != 1:
    raise SystemExit("release manifest method was not found")
write("src/Releases/ReleaseCatalogService.php", catalog)

control = read("src/HomeServers/HomeServerControlPlaneService.php")
control = replace_once(
    control,
    "                    a.id artifact_id,a.storage_reference,a.sha256,a.size_bytes,",
    "                    a.id artifact_id,a.storage_reference,a.sha256,a.size_bytes,a.authenticode_thumbprint,",
    "control-plane artifact query",
)
control = replace_once(
    control,
    "                'size_bytes' => (int) $release['size_bytes'],",
    "                'size_bytes' => (int) $release['size_bytes'],\n                'authenticode_thumbprint' => strtoupper((string) $release['authenticode_thumbprint']),\n                'file_name' => 'Microgifter-HomeServer-Setup.exe',",
    "control-plane artifact response",
)
write("src/HomeServers/HomeServerControlPlaneService.php", control)

download = read("public/api/homeserver/v1/installer-download.php")
download = replace_once(
    download,
    "    $grant = (string) ($_GET['grant'] ?? '');",
    "    $grant = trim((string) ($_GET['grant'] ?? ''));\n    if ($grant === '') {\n        $grant = HomeServerEndpoint::bearerCredential();\n    }",
    "installer bearer grant",
)
write("public/api/homeserver/v1/installer-download.php", download)

docs = read("docs/vp3-platform-backend/07-HOMESERVER-CONTROL-PLANE-V1.md")
docs = docs.replace("- `VP3_HOMESERVER_LEASE_SIGNING_KEY`\n- `VP3_HOMESERVER_LEASE_SIGNING_KEY_ID`\n", "")
docs = docs.replace(
    "The route rejects traversal and remote storage URLs, resolves the file beneath the configured release root, and verifies exact size and SHA-256 before streaming.",
    "The route accepts the short-lived installer grant as a bearer credential (with the query parameter retained for compatibility), rejects traversal and remote storage URLs, resolves the file beneath the configured release root, and verifies exact size and SHA-256 before streaming.",
)
write("docs/vp3-platform-backend/07-HOMESERVER-CONTROL-PLANE-V1.md", docs)

write(
    "tests/phase13_homeserver_cryptographic_contract.php",
    r'''<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};
$read = static fn(string $path): string => (string) file_get_contents($root . '/' . $path);

$lease = $read('src/HomeServers/HomeServerLeaseSigner.php');
$registry = $read('src/HomeServers/HomeServerRegistryService.php');
$catalog = $read('src/Releases/ReleaseCatalogService.php');
$control = $read('src/HomeServers/HomeServerControlPlaneService.php');
$download = $read('public/api/homeserver/v1/installer-download.php');
$migration = $read('database/migrations/20260729_phase13_homeserver_cryptographic_contract.sql');
$installer = $read('database/vp3-single-install.sql');
$bootstrap = $read('bootstrap.php');

$assert(str_contains($lease, 'sodium_crypto_sign_detached'), 'Lease signer is not Ed25519.');
$assert(str_contains($lease, "'algorithm' => 'Ed25519'"), 'Lease algorithm evidence is missing.');
$assert(!str_contains($lease, 'hash_hmac'), 'Legacy shared-secret lease signing remains.');
$assert(str_contains($registry, "'algorithm' => $signed['algorithm']"), 'Lease response omits algorithm.');
$assert(str_contains($bootstrap, "$config['releases']['signing_private_key_base64']"), 'Lease signer does not use the release authority keypair.');
$assert(str_contains($catalog, 'authenticode_thumbprint'), 'Signed release manifest omits Authenticode identity.');
$assert(str_contains($catalog, 'installer_download_url'), 'Signed release manifest omits the stable installer URL.');
$assert(str_contains($control, "'authenticode_thumbprint'"), 'Manifest endpoint omits Authenticode identity.');
$assert(str_contains($download, 'HomeServerEndpoint::bearerCredential()'), 'Installer grants cannot use bearer authorization.');
$assert(str_contains($migration, 'release_notes') && str_contains($migration, 'authenticode_thumbprint'), 'Phase 13 schema is incomplete.');
$assert(str_contains($installer, '20260729_phase13_homeserver_cryptographic_contract.sql'), 'Cumulative installer omits Phase 13.');

if ($failures !== []) {
    fwrite(STDERR, implode("\n", $failures) . "\n");
    exit(1);
}
echo "Phase 13 HomeServer cryptographic contract passed.\n";
''',
)

write(
    ".github/workflows/phase13-homeserver-cryptographic-contract.yml",
    r'''name: Phase 13 HomeServer Cryptographic Contract

on:
  push:
    branches:
      - main
      - feature/vp3-homeserver-cryptographic-contract-v1-20260729
  pull_request:

permissions:
  contents: read

jobs:
  php:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        php: ['8.2', '8.3']
    steps:
      - uses: actions/checkout@v4
      - uses: shivammathur/setup-php@v2
        with:
          php-version: ${{ matrix.php }}
          extensions: pdo, pdo_mysql, json, mbstring, sodium, openssl
          coverage: none
      - name: Validate PHP syntax
        run: find src public tests config -name '*.php' -print0 | xargs -0 -n1 php -l
      - name: Run retained Phase 12 contract
        run: php tests/phase12_homeserver_control_plane_contract.php
      - name: Run Phase 13 contract
        run: php tests/phase13_homeserver_cryptographic_contract.php
''',
)

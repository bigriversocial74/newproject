<?php

declare(strict_types=1);

namespace Vp3\Deployment;

use PDO;
use RuntimeException;
use Vp3\Database;

final class ReleaseCandidateRegistryService
{
    public function __construct(
        private readonly Database $database,
        private readonly ReleaseManifestService $canonicalizer,
        private readonly string $allowedRoot,
        private readonly string $publicKeyBase64,
        private readonly string $keyId
    ) {
    }

    /** @return array<string,mixed> */
    public function register(string $manifestPath, string $signaturePath, ?int $actorUserId): array
    {
        $manifestPath = $this->safeFile($manifestPath, 'platform-release-manifest.json');
        $signaturePath = $this->safeFile($signaturePath, 'platform-release-signature.json');
        if (!hash_equals(dirname($manifestPath), dirname($signaturePath))) {
            throw new RuntimeException('Release manifest and signature must come from the same release directory.');
        }

        $manifest = $this->jsonFile($manifestPath);
        $signature = $this->jsonFile($signaturePath);
        $this->verify($manifest, $signature);

        $version = trim((string) ($manifest['version'] ?? ''));
        $commit = strtolower(trim((string) ($manifest['commit_sha'] ?? '')));
        $manifestHash = strtolower(trim((string) ($manifest['manifest_sha256'] ?? '')));
        $installerHash = strtolower(trim((string) ($manifest['installer']['sha256'] ?? '')));
        $schemaLevel = (int) ($manifest['schema_level'] ?? 0);
        $sourceTreeHash = strtolower(trim((string) ($manifest['application_source']['tree_sha256'] ?? '')));
        $sourceFileCount = (int) ($manifest['application_source']['file_count'] ?? 0);
        $migrationCount = (int) ($manifest['migration_count'] ?? 0);
        if (!preg_match('/^[A-Za-z0-9._-]{1,64}$/', $version)
            || !preg_match('/^[a-f0-9]{40,64}$/', $commit)
            || !preg_match('/^[a-f0-9]{64}$/', $manifestHash)
            || !preg_match('/^[a-f0-9]{64}$/', $installerHash)
            || !preg_match('/^[a-f0-9]{64}$/', $sourceTreeHash)
            || $schemaLevel < 1 || $sourceFileCount < 1 || $migrationCount < 1) {
            throw new RuntimeException('The signed release manifest contains an invalid release identity.');
        }

        $artifactRootHash = hash('sha256', dirname($manifestPath));
        $signatureBase64 = (string) $signature['signature_base64'];
        $now = $this->now();

        return $this->database->transaction(function (PDO $pdo) use (
            $version,
            $commit,
            $schemaLevel,
            $manifestHash,
            $installerHash,
            $sourceTreeHash,
            $sourceFileCount,
            $migrationCount,
            $signatureBase64,
            $artifactRootHash,
            $actorUserId,
            $now
        ): array {
            $existing = $pdo->prepare(
                'SELECT id,public_id FROM platform_release_candidates
                 WHERE release_version=:version AND commit_sha=:commit LIMIT 1 FOR UPDATE'
            );
            $existing->execute(['version' => $version, 'commit' => $commit]);
            $row = $existing->fetch(PDO::FETCH_ASSOC);
            if (is_array($row)) {
                $pdo->prepare(
                    "UPDATE platform_release_candidates
                     SET schema_level=:schema_level,manifest_sha256=:manifest_sha,installer_sha256=:installer_sha,
                         source_tree_sha256=:source_tree_sha,source_file_count=:source_file_count,
                         migration_count=:migration_count,signing_key_id=:key_id,signature_base64=:signature,
                         artifact_root_hash=:artifact_root,candidate_status='verified',registered_by_user_id=:actor,
                         verified_at=:verified_at,updated_at=:updated_at WHERE id=:id"
                )->execute([
                    'schema_level' => $schemaLevel,
                    'manifest_sha' => $manifestHash,
                    'installer_sha' => $installerHash,
                    'source_tree_sha' => $sourceTreeHash,
                    'source_file_count' => $sourceFileCount,
                    'migration_count' => $migrationCount,
                    'key_id' => $this->keyId,
                    'signature' => $signatureBase64,
                    'artifact_root' => $artifactRootHash,
                    'actor' => $actorUserId,
                    'verified_at' => $now,
                    'updated_at' => $now,
                    'id' => (int) $row['id'],
                ]);
                return $this->candidateById($pdo, (int) $row['id']);
            }

            $publicId = 'PRC-' . strtoupper(bin2hex(random_bytes(12)));
            $pdo->prepare(
                "INSERT INTO platform_release_candidates
                 (public_id,release_version,commit_sha,schema_level,manifest_sha256,installer_sha256,
                  source_tree_sha256,source_file_count,migration_count,signing_key_id,signature_base64,artifact_root_hash,candidate_status,
                  registered_by_user_id,verified_at,created_at,updated_at)
                 VALUES (:public_id,:version,:commit,:schema_level,:manifest_sha,:installer_sha,
                  :source_tree_sha,:source_file_count,:migration_count,:key_id,:signature,:artifact_root,'verified',:actor,:verified_at,:created_at,:updated_at)"
            )->execute([
                'public_id' => $publicId,
                'version' => $version,
                'commit' => $commit,
                'schema_level' => $schemaLevel,
                'manifest_sha' => $manifestHash,
                'installer_sha' => $installerHash,
                'source_tree_sha' => $sourceTreeHash,
                'source_file_count' => $sourceFileCount,
                'migration_count' => $migrationCount,
                'key_id' => $this->keyId,
                'signature' => $signatureBase64,
                'artifact_root' => $artifactRootHash,
                'actor' => $actorUserId,
                'verified_at' => $now,
                'created_at' => $now,
                'updated_at' => $now,
            ]);
            return $this->candidateById($pdo, (int) $pdo->lastInsertId());
        });
    }

    /** @param array<string,mixed> $manifest @param array<string,mixed> $signature */
    public function verify(array $manifest, array $signature): void
    {
        $configuredKey = base64_decode(trim($this->publicKeyBase64), true);
        if (!is_string($configuredKey) || strlen($configuredKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new RuntimeException('A valid platform release verification key is required.');
        }
        if (!hash_equals($this->keyId, (string) ($signature['key_id'] ?? ''))
            || !hash_equals('Ed25519', (string) ($signature['algorithm'] ?? ''))
            || !hash_equals('vp3-platform-release-signature-v1', (string) ($signature['format'] ?? ''))) {
            throw new RuntimeException('The release signature identity is not trusted.');
        }
        $signaturePublic = base64_decode((string) ($signature['public_key_base64'] ?? ''), true);
        if (!is_string($signaturePublic) || !hash_equals($configuredKey, $signaturePublic)) {
            throw new RuntimeException('The release signature public key is not trusted.');
        }

        $claimedManifestHash = strtolower((string) ($manifest['manifest_sha256'] ?? ''));
        $unsigned = $manifest;
        unset($unsigned['manifest_sha256']);
        $calculatedManifestHash = hash('sha256', $this->canonicalizer->canonicalJson($unsigned));
        if (!preg_match('/^[a-f0-9]{64}$/', $claimedManifestHash)
            || !hash_equals($calculatedManifestHash, $claimedManifestHash)
            || !hash_equals($claimedManifestHash, (string) ($signature['manifest_sha256'] ?? ''))) {
            throw new RuntimeException('The release manifest hash is invalid.');
        }

        $detached = base64_decode((string) ($signature['signature_base64'] ?? ''), true);
        if (!is_string($detached) || strlen($detached) !== SODIUM_CRYPTO_SIGN_BYTES
            || !sodium_crypto_sign_verify_detached(
                $detached,
                $this->canonicalizer->canonicalJson($manifest),
                $configuredKey
            )) {
            throw new RuntimeException('The platform release signature is invalid.');
        }
    }

    /** @return array<string,mixed> */
    private function candidateById(PDO $pdo, int $id): array
    {
        $statement = $pdo->prepare(
            'SELECT public_id,release_version,commit_sha,schema_level,manifest_sha256,installer_sha256,
                    source_tree_sha256,source_file_count,migration_count,signing_key_id,candidate_status,verified_at
             FROM platform_release_candidates WHERE id=:id LIMIT 1'
        );
        $statement->execute(['id' => $id]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('The verified release candidate could not be loaded.');
        }
        return $row;
    }

    private function safeFile(string $path, string $requiredName): string
    {
        $root = realpath($this->allowedRoot);
        $real = realpath(trim($path));
        if (!is_string($root) || !is_dir($root) || !is_string($real) || !is_file($real) || !is_readable($real)) {
            throw new RuntimeException('A readable release artifact file is required.');
        }
        $prefix = rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        if (!str_starts_with($real, $prefix) || basename($real) !== $requiredName) {
            throw new RuntimeException('The release artifact path is outside the configured release root.');
        }
        $bytes = filesize($real);
        if (!is_int($bytes) || $bytes < 2 || $bytes > 1048576) {
            throw new RuntimeException('The release artifact file size is invalid.');
        }
        return $real;
    }

    /** @return array<string,mixed> */
    private function jsonFile(string $path): array
    {
        $decoded = json_decode((string) file_get_contents($path), true, 64, JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new RuntimeException('The release artifact is not a JSON object.');
        }
        return $decoded;
    }

    private function now(): string
    {
        return gmdate('Y-m-d H:i:s') . '.000000';
    }
}

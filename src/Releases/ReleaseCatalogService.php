<?php

declare(strict_types=1);

namespace Vp3\Releases;

use PDO;
use RuntimeException;
use Vp3\Database;

final class ReleaseCatalogService
{
    public function __construct(
        private readonly Database $database,
        private readonly ReleaseManifestSigner $signer
    ) {
    }

    public function ensureProduct(string $code, string $name, string $targetType): int
    {
        $code = strtolower(trim($code));
        $targetType = strtolower(trim($targetType));
        if ($code === '' || trim($name) === '' || !in_array($targetType, ['pod', 'homeserver'], true)) {
            throw new RuntimeException('A valid release product code, name, and target type are required.');
        }
        $pdo = $this->database->pdo();
        $pdo->prepare(
            'INSERT INTO software_products (public_id,code,name,target_type,status,created_at,updated_at)
             VALUES (:public,:code,:name,:target,\'active\',UTC_TIMESTAMP(),UTC_TIMESTAMP())
             ON DUPLICATE KEY UPDATE name=VALUES(name),status=\'active\',updated_at=UTC_TIMESTAMP()'
        )->execute([
            'public' => 'PRODUCT-' . strtoupper(bin2hex(random_bytes(12))),
            'code' => $code,
            'name' => substr(trim($name), 0, 190),
            'target' => $targetType,
        ]);
        $query = $pdo->prepare('SELECT id FROM software_products WHERE code=:code LIMIT 1');
        $query->execute(['code' => $code]);
        return (int) $query->fetchColumn();
    }

    /**
     * @param list<array{platform:string,architecture:string,storage_reference:string,sha256:string,size_bytes:int}> $artifacts
     * @param array<string,mixed> $compatibility
     * @return array{release_id:int,release_public_id:string}
     */
    public function createDraftRelease(
        int $productId,
        string $version,
        string $channel,
        array $artifacts,
        array $compatibility,
        int $rolloutPercentage,
        bool $emergencyOverride,
        string $releaseNotes,
        string $requestId
    ): array {
        $this->assertVersion($version);
        $channel = strtolower(trim($channel));
        if (!in_array($channel, ['stable', 'beta', 'security'], true) || $artifacts === []) {
            throw new RuntimeException('A valid release channel and at least one artifact are required.');
        }
        if ($rolloutPercentage < 0 || $rolloutPercentage > 100) {
            throw new RuntimeException('Rollout percentage must be between 0 and 100.');
        }
        if ($emergencyOverride && $channel !== 'security') {
            throw new RuntimeException('Emergency override is restricted to security releases.');
        }
        return $this->database->transaction(function (PDO $pdo) use (
            $productId, $version, $channel, $artifacts, $compatibility, $rolloutPercentage,
            $emergencyOverride, $releaseNotes, $requestId
        ): array {
            $product = $pdo->prepare("SELECT id FROM software_products WHERE id=:id AND status='active' LIMIT 1 FOR UPDATE");
            $product->execute(['id' => $productId]);
            if (!$product->fetchColumn()) {
                throw new RuntimeException('Active software product was not found.');
            }
            $publicId = 'RELEASE-' . strtoupper(bin2hex(random_bytes(12)));
            $pdo->prepare(
                'INSERT INTO software_releases
                 (public_id,product_id,version,channel,status,release_notes_hash,emergency_override,created_at,updated_at)
                 VALUES (:public,:product,:version,:channel,\'draft\',:notes,:emergency,UTC_TIMESTAMP(),UTC_TIMESTAMP())'
            )->execute([
                'public' => $publicId,
                'product' => $productId,
                'version' => trim($version),
                'channel' => $channel,
                'notes' => hash('sha256', $releaseNotes),
                'emergency' => $emergencyOverride ? 1 : 0,
            ]);
            $releaseId = (int) $pdo->lastInsertId();
            $insertArtifact = $pdo->prepare(
                'INSERT INTO release_artifacts
                 (release_id,platform,architecture,storage_reference,sha256,size_bytes,created_at)
                 VALUES (:release,:platform,:architecture,:storage,:sha,:size,UTC_TIMESTAMP())'
            );
            foreach ($artifacts as $artifact) {
                $sha = strtolower(trim((string) ($artifact['sha256'] ?? '')));
                if (!preg_match('/^[a-f0-9]{64}$/', $sha)
                    || trim((string) ($artifact['platform'] ?? '')) === ''
                    || trim((string) ($artifact['architecture'] ?? '')) === ''
                    || trim((string) ($artifact['storage_reference'] ?? '')) === ''
                    || (int) ($artifact['size_bytes'] ?? 0) < 1) {
                    throw new RuntimeException('Release artifact metadata is invalid.');
                }
                $insertArtifact->execute([
                    'release' => $releaseId,
                    'platform' => substr(trim((string) $artifact['platform']), 0, 80),
                    'architecture' => substr(trim((string) $artifact['architecture']), 0, 80),
                    'storage' => substr(trim((string) $artifact['storage_reference']), 0, 512),
                    'sha' => $sha,
                    'size' => (int) $artifact['size_bytes'],
                ]);
            }
            $family = strtolower((string) ($compatibility['database_family'] ?? 'any'));
            if (!in_array($family, ['any', 'mysql', 'mariadb'], true)) {
                throw new RuntimeException('Invalid database compatibility family.');
            }
            foreach (['minimum_current_version', 'maximum_current_version', 'minimum_php_version', 'minimum_database_version'] as $key) {
                if (isset($compatibility[$key]) && $compatibility[$key] !== null && trim((string) $compatibility[$key]) !== '') {
                    $this->assertVersion((string) $compatibility[$key]);
                }
            }
            $pdo->prepare(
                'INSERT INTO release_compatibility_rules
                 (release_id,minimum_current_version,maximum_current_version,minimum_php_version,database_family,minimum_database_version,created_at)
                 VALUES (:release,:minimum_current,:maximum_current,:minimum_php,:family,:minimum_database,UTC_TIMESTAMP())'
            )->execute([
                'release' => $releaseId,
                'minimum_current' => $this->nullableVersion($compatibility['minimum_current_version'] ?? null),
                'maximum_current' => $this->nullableVersion($compatibility['maximum_current_version'] ?? null),
                'minimum_php' => $this->nullableVersion($compatibility['minimum_php_version'] ?? null),
                'family' => $family,
                'minimum_database' => $this->nullableVersion($compatibility['minimum_database_version'] ?? null),
            ]);
            $pdo->prepare(
                'INSERT INTO release_rollouts
                 (release_id,status,percentage,cohort_seed,starts_at,created_at,updated_at)
                 VALUES (:release,\'planned\',:percentage,:seed,UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP())'
            )->execute(['release' => $releaseId, 'percentage' => $rolloutPercentage, 'seed' => bin2hex(random_bytes(32))]);
            $this->event($pdo, $releaseId, $requestId, 'release_draft_created', 'success', [
                'version' => $version,
                'channel' => $channel,
                'artifact_count' => count($artifacts),
                'rollout_percentage' => $rolloutPercentage,
                'emergency_override' => $emergencyOverride,
            ]);
            return ['release_id' => $releaseId, 'release_public_id' => $publicId];
        });
    }

    /** @return array{manifest:string,signature:string,key_id:string,algorithm:string,manifest_hash:string} */
    public function publishRelease(int $releaseId, string $requestId): array
    {
        return $this->database->transaction(function (PDO $pdo) use ($releaseId, $requestId): array {
            $release = $this->release($pdo, $releaseId, true);
            if ($release['status'] !== 'draft') {
                throw new RuntimeException('Only a draft release can be published.');
            }
            $manifest = $this->manifest($pdo, $release);
            $signed = $this->signer->sign($manifest);
            $pdo->prepare(
                'UPDATE software_releases SET status=\'published\',manifest_hash=:hash,manifest_document=:document,
                 manifest_signature=:signature,signature_algorithm=:algorithm,signing_key_id=:key_id,
                 published_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP() WHERE id=:id'
            )->execute([
                'hash' => $signed['manifest_hash'],
                'document' => $signed['manifest'],
                'signature' => $signed['signature'],
                'algorithm' => $signed['algorithm'],
                'key_id' => $signed['key_id'],
                'id' => $releaseId,
            ]);
            $pdo->prepare("UPDATE release_rollouts SET status='active',updated_at=UTC_TIMESTAMP() WHERE release_id=:release")
                ->execute(['release' => $releaseId]);
            $this->event($pdo, $releaseId, $requestId, 'release_published', 'success', [
                'manifest_hash' => $signed['manifest_hash'],
                'key_id' => $signed['key_id'],
                'algorithm' => $signed['algorithm'],
            ]);
            return $signed;
        });
    }

    public function setRollout(int $releaseId, int $percentage, string $status, string $requestId): void
    {
        if ($percentage < 0 || $percentage > 100 || !in_array($status, ['planned', 'active', 'paused', 'completed', 'canceled'], true)) {
            throw new RuntimeException('Invalid rollout policy.');
        }
        $this->database->transaction(function (PDO $pdo) use ($releaseId, $percentage, $status, $requestId): void {
            $this->release($pdo, $releaseId, true);
            $pdo->prepare('UPDATE release_rollouts SET percentage=:percentage,status=:status,updated_at=UTC_TIMESTAMP() WHERE release_id=:release')
                ->execute(['percentage' => $percentage, 'status' => $status, 'release' => $releaseId]);
            $this->event($pdo, $releaseId, $requestId, 'rollout_updated', 'success', ['percentage' => $percentage, 'status' => $status]);
        });
    }

    public function withdrawRelease(int $releaseId, string $requestId): void
    {
        $this->database->transaction(function (PDO $pdo) use ($releaseId, $requestId): void {
            $release = $this->release($pdo, $releaseId, true);
            if (!in_array($release['status'], ['published', 'paused'], true)) {
                throw new RuntimeException('Release cannot be withdrawn from its current state.');
            }
            $pdo->prepare("UPDATE software_releases SET status='withdrawn',withdrawn_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP() WHERE id=:id")
                ->execute(['id' => $releaseId]);
            $pdo->prepare("UPDATE release_rollouts SET status='canceled',updated_at=UTC_TIMESTAMP() WHERE release_id=:release")
                ->execute(['release' => $releaseId]);
            $this->event($pdo, $releaseId, $requestId, 'release_withdrawn', 'success', null);
        });
    }

    /** @return array{manifest:string,signature:string,key_id:string,algorithm:string,manifest_hash:string} */
    public function signedManifest(int $releaseId): array
    {
        $release = $this->release($this->database->pdo(), $releaseId, false);
        if ($release['status'] !== 'published'
            || !is_string($release['manifest_document']) || $release['manifest_document'] === ''
            || !is_string($release['manifest_signature']) || $release['manifest_signature'] === '') {
            throw new RuntimeException('Published signed release was not found.');
        }
        return [
            'manifest' => $release['manifest_document'],
            'signature' => $release['manifest_signature'],
            'key_id' => (string) $release['signing_key_id'],
            'algorithm' => (string) $release['signature_algorithm'],
            'manifest_hash' => (string) $release['manifest_hash'],
        ];
    }

    /** @param array<string,mixed> $release @return array<string,mixed> */
    private function manifest(PDO $pdo, array $release): array
    {
        $artifacts = $pdo->prepare('SELECT platform,architecture,storage_reference,sha256,size_bytes FROM release_artifacts WHERE release_id=:release ORDER BY platform,architecture');
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
            'release_notes_hash' => $release['release_notes_hash'],
            'artifacts' => $artifacts->fetchAll(PDO::FETCH_ASSOC),
            'compatibility' => $compatibility->fetch(PDO::FETCH_ASSOC) ?: [],
            'initial_rollout' => $rollout->fetch(PDO::FETCH_ASSOC) ?: [],
        ];
    }

    /** @return array<string,mixed> */
    private function release(PDO $pdo, int $releaseId, bool $lock): array
    {
        $query = $pdo->prepare(
            'SELECT r.*,p.code product_code,p.target_type FROM software_releases r
             JOIN software_products p ON p.id=r.product_id WHERE r.id=:id LIMIT 1' . ($lock ? ' FOR UPDATE' : '')
        );
        $query->execute(['id' => $releaseId]);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new RuntimeException('Software release was not found.');
        }
        return $row;
    }

    /** @param array<string,mixed>|null $metadata */
    private function event(PDO $pdo, int $releaseId, string $requestId, string $type, string $result, ?array $metadata): void
    {
        if (trim($requestId) === '') {
            throw new RuntimeException('Release mutation request ID is required.');
        }
        $pdo->prepare('INSERT INTO release_events (release_id,request_id,event_type,result,metadata_json,created_at) VALUES (:release,:request,:type,:result,:metadata,UTC_TIMESTAMP())')
            ->execute([
                'release' => $releaseId,
                'request' => $requestId,
                'type' => $type,
                'result' => $result,
                'metadata' => $metadata === null ? null : $this->canonicalJson($metadata),
            ]);
    }

    private function assertVersion(string $version): void
    {
        if (!preg_match('/^\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?$/', trim($version))) {
            throw new RuntimeException('Software versions must use a semantic version format.');
        }
    }

    private function nullableVersion(mixed $value): ?string
    {
        if (!is_string($value) || trim($value) === '') {
            return null;
        }
        $this->assertVersion($value);
        return trim($value);
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
}

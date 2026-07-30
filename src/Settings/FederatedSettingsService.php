<?php

declare(strict_types=1);
namespace Vp3\Settings;

use PDO;
use RuntimeException;
use Vp3\Database;

final class FederatedSettingsService
{
    private const SCHEMA = 'vp3.federated-settings.v1';

    public function __construct(private readonly Database $database)
    {
    }

    /** @return array<string,mixed> */
    public function snapshotForAccount(int $accountId, ?string $devicePublicId = null): array
    {
        $device = $devicePublicId === null || trim($devicePublicId) === ''
            ? null
            : $this->ownedDevice($accountId, $devicePublicId);
        return $this->buildSnapshot($accountId, $device);
    }

    /** @return array<string,mixed> */
    public function updateFromBrowser(
        int $accountId,
        int $userId,
        string $settingKey,
        mixed $value,
        int $expectedRevision,
        ?string $devicePublicId = null
    ): array {
        $definition = $this->definition($settingKey);
        if ($definition['authority'] === 'homeserver') {
            throw new RuntimeException('This setting is controlled by the HomeServer.');
        }
        $device = $devicePublicId === null || trim($devicePublicId) === ''
            ? null
            : $this->ownedDevice($accountId, $devicePublicId);
        $validated = $this->validateValue($definition, $value);
        $scopeType = $device === null ? 'account' : 'device';
        $scopeKey = $device === null ? 'account' : (string) $device['public_id'];
        $deviceId = $device === null ? null : (int) $device['id'];

        $revision = $this->database->transaction(function (PDO $pdo) use (
            $accountId,
            $userId,
            $settingKey,
            $validated,
            $expectedRevision,
            $scopeType,
            $scopeKey,
            $deviceId
        ): int {
            $current = $pdo->prepare(
                'SELECT id,revision FROM federated_settings WHERE account_id=:account AND scope_type=:scope AND scope_key=:scope_key AND setting_key=:setting LIMIT 1 FOR UPDATE'
            );
            $current->execute([
                'account' => $accountId,
                'scope' => $scopeType,
                'scope_key' => $scopeKey,
                'setting' => $settingKey,
            ]);
            $row = $current->fetch(PDO::FETCH_ASSOC);
            $currentRevision = is_array($row) ? (int) $row['revision'] : 0;
            if ($expectedRevision !== $currentRevision) {
                throw new RuntimeException('The setting changed before this update was saved. Refresh and try again.');
            }
            $next = $currentRevision + 1;
            $json = $this->canonicalJson($validated);
            if (is_array($row)) {
                $pdo->prepare(
                    "UPDATE federated_settings SET value_json=:value,value_hash=:hash,revision=:revision,source_authority='vp3',updated_by_user_id=:user,updated_at=UTC_TIMESTAMP() WHERE id=:id"
                )->execute([
                    'value' => $json,
                    'hash' => hash('sha256', $json),
                    'revision' => $next,
                    'user' => $userId,
                    'id' => $row['id'],
                ]);
            } else {
                $pdo->prepare(
                    "INSERT INTO federated_settings (account_id,device_id,scope_type,scope_key,setting_key,value_json,value_hash,revision,source_authority,updated_by_user_id,created_at,updated_at) VALUES (:account,:device,:scope,:scope_key,:setting,:value,:hash,:revision,'vp3',:user,UTC_TIMESTAMP(),UTC_TIMESTAMP())"
                )->execute([
                    'account' => $accountId,
                    'device' => $deviceId,
                    'scope' => $scopeType,
                    'scope_key' => $scopeKey,
                    'setting' => $settingKey,
                    'value' => $json,
                    'hash' => hash('sha256', $json),
                    'revision' => $next,
                    'user' => $userId,
                ]);
            }
            return $next;
        });

        $snapshot = $this->buildSnapshot($accountId, $device);
        $this->recordReceipt($accountId, $deviceId, 'WEB-' . strtoupper(bin2hex(random_bytes(10))), 'vp3_update', $expectedRevision, $revision, (string) $snapshot['snapshot_hash'], 'applied', 0);
        return $snapshot;
    }

    /** @param array<int,array<string,mixed>> $updates @return array<string,mixed> */
    public function synchronizeDevice(
        string $devicePublicId,
        string $credential,
        string $requestId,
        int $baseRevision,
        array $updates
    ): array {
        $device = $this->authenticateDevice($devicePublicId, $credential);
        $replayed = $this->database->pdo()->prepare(
            'SELECT result,conflict_count FROM federated_settings_sync_receipts WHERE device_id=:device AND request_id=:request LIMIT 1'
        );
        $replayed->execute(['device' => $device['id'], 'request' => $requestId]);
        if ($replayed->fetch(PDO::FETCH_ASSOC)) {
            $snapshot = $this->buildSnapshot((int) $device['account_id'], $device);
            $snapshot['replayed'] = true;
            $snapshot['applied'] = [];
            $snapshot['conflicts'] = [];
            return $snapshot;
        }

        if (count($updates) > 64) {
            throw new RuntimeException('The settings sync contains too many updates.');
        }
        $applied = [];
        $conflicts = [];
        $maxApplied = $baseRevision;

        $this->database->transaction(function (PDO $pdo) use ($device, $updates, &$applied, &$conflicts, &$maxApplied): void {
            foreach ($updates as $index => $update) {
                if (!is_array($update)) {
                    throw new RuntimeException('The settings sync update list is invalid.');
                }
                $key = trim((string) ($update['setting_key'] ?? ''));
                $expected = max(0, (int) ($update['expected_revision'] ?? 0));
                $definition = $this->definition($key, $pdo);
                if ($definition['authority'] === 'vp3') {
                    $conflicts[] = ['setting_key' => $key, 'reason' => 'vp3_authority'];
                    continue;
                }
                $value = $this->validateValue($definition, $update['value'] ?? null);
                $scopeType = $definition['authority'] === 'homeserver' ? 'device' : 'account';
                $scopeKey = $scopeType === 'device' ? (string) $device['public_id'] : 'account';
                $deviceId = $scopeType === 'device' ? (int) $device['id'] : null;
                $current = $pdo->prepare(
                    'SELECT id,revision FROM federated_settings WHERE account_id=:account AND scope_type=:scope AND scope_key=:scope_key AND setting_key=:setting LIMIT 1 FOR UPDATE'
                );
                $current->execute([
                    'account' => $device['account_id'],
                    'scope' => $scopeType,
                    'scope_key' => $scopeKey,
                    'setting' => $key,
                ]);
                $row = $current->fetch(PDO::FETCH_ASSOC);
                $currentRevision = is_array($row) ? (int) $row['revision'] : 0;
                if ($currentRevision !== $expected) {
                    $conflicts[] = ['setting_key' => $key, 'reason' => 'revision', 'current_revision' => $currentRevision];
                    continue;
                }
                $next = $currentRevision + 1;
                $json = $this->canonicalJson($value);
                if (is_array($row)) {
                    $pdo->prepare(
                        "UPDATE federated_settings SET value_json=:value,value_hash=:hash,revision=:revision,source_authority='homeserver',updated_by_user_id=NULL,updated_at=UTC_TIMESTAMP() WHERE id=:id"
                    )->execute([
                        'value' => $json,
                        'hash' => hash('sha256', $json),
                        'revision' => $next,
                        'id' => $row['id'],
                    ]);
                } else {
                    $pdo->prepare(
                        "INSERT INTO federated_settings (account_id,device_id,scope_type,scope_key,setting_key,value_json,value_hash,revision,source_authority,updated_by_user_id,created_at,updated_at) VALUES (:account,:device,:scope,:scope_key,:setting,:value,:hash,:revision,'homeserver',NULL,UTC_TIMESTAMP(),UTC_TIMESTAMP())"
                    )->execute([
                        'account' => $device['account_id'],
                        'device' => $deviceId,
                        'scope' => $scopeType,
                        'scope_key' => $scopeKey,
                        'setting' => $key,
                        'value' => $json,
                        'hash' => hash('sha256', $json),
                        'revision' => $next,
                    ]);
                }
                $maxApplied = max($maxApplied, $next);
                $applied[] = ['setting_key' => $key, 'revision' => $next, 'index' => $index];
            }
        });

        $snapshot = $this->buildSnapshot((int) $device['account_id'], $device);
        $result = $conflicts === [] ? 'applied' : ($applied === [] ? 'conflict' : 'partial');
        $this->recordReceipt(
            (int) $device['account_id'],
            (int) $device['id'],
            $requestId,
            'device_push',
            $baseRevision,
            max((int) $snapshot['max_revision'], $maxApplied),
            (string) $snapshot['snapshot_hash'],
            $result,
            count($conflicts)
        );
        $snapshot['replayed'] = false;
        $snapshot['applied'] = $applied;
        $snapshot['conflicts'] = $conflicts;
        return $snapshot;
    }

    /** @param array<string,mixed>|null $device @return array<string,mixed> */
    private function buildSnapshot(int $accountId, ?array $device): array
    {
        $catalog = $this->database->pdo()->query(
            "SELECT setting_key,label,description,category,authority,value_type,default_value_json,allowed_values_json,visible_in_vp3,visible_in_homeserver,sensitivity FROM federated_setting_catalog ORDER BY category,setting_key"
        )->fetchAll(PDO::FETCH_ASSOC);
        $stored = $this->database->pdo()->prepare(
            "SELECT scope_type,scope_key,setting_key,value_json,revision,source_authority,updated_at FROM federated_settings WHERE account_id=:account AND (scope_type='account' OR (scope_type='device' AND scope_key=:device)) ORDER BY scope_type,revision"
        );
        $stored->execute([
            'account' => $accountId,
            'device' => $device === null ? '' : (string) $device['public_id'],
        ]);
        $values = [];
        foreach ($stored->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $values[(string) $row['setting_key']] = $row;
        }

        $settings = [];
        $maxRevision = 0;
        foreach ($catalog as $definition) {
            if ((string) $definition['sensitivity'] !== 'non_secret') {
                continue;
            }
            $key = (string) $definition['setting_key'];
            $row = $values[$key] ?? null;
            $value = json_decode((string) ($row['value_json'] ?? $definition['default_value_json']), true, 16, JSON_THROW_ON_ERROR);
            $allowed = $definition['allowed_values_json'] === null
                ? null
                : json_decode((string) $definition['allowed_values_json'], true, 16, JSON_THROW_ON_ERROR);
            $revision = is_array($row) ? (int) $row['revision'] : 0;
            $maxRevision = max($maxRevision, $revision);
            $settings[] = [
                'setting_key' => $key,
                'label' => (string) $definition['label'],
                'description' => (string) $definition['description'],
                'category' => (string) $definition['category'],
                'authority' => (string) $definition['authority'],
                'value_type' => (string) $definition['value_type'],
                'allowed_values' => $allowed,
                'value' => $value,
                'revision' => $revision,
                'source_authority' => is_array($row) ? (string) $row['source_authority'] : 'default',
                'scope' => is_array($row) ? (string) $row['scope_type'] : 'default',
                'editable_in_vp3' => (bool) $definition['visible_in_vp3'] && $definition['authority'] !== 'homeserver',
                'editable_in_homeserver' => (bool) $definition['visible_in_homeserver'] && $definition['authority'] !== 'vp3',
            ];
        }
        $identity = [
            'schema' => self::SCHEMA,
            'account_id' => $accountId,
            'device_public_id' => $device['public_id'] ?? null,
            'max_revision' => $maxRevision,
            'settings' => $settings,
        ];
        return $identity + [
            'generated_at' => gmdate(DATE_ATOM),
            'snapshot_hash' => hash('sha256', $this->canonicalJson($identity)),
        ];
    }

    /** @return array<string,mixed> */
    private function definition(string $settingKey, ?PDO $pdo = null): array
    {
        if (!preg_match('/^[a-z][a-z0-9_.-]{2,119}$/', $settingKey)) {
            throw new RuntimeException('The setting key is invalid.');
        }
        $pdo ??= $this->database->pdo();
        $query = $pdo->prepare('SELECT * FROM federated_setting_catalog WHERE setting_key=:setting AND sensitivity=\'non_secret\' LIMIT 1');
        $query->execute(['setting' => $settingKey]);
        $definition = $query->fetch(PDO::FETCH_ASSOC);
        if (!is_array($definition)) {
            throw new RuntimeException('The federated setting was not found.');
        }
        return $definition;
    }

    private function validateValue(array $definition, mixed $value): mixed
    {
        $type = (string) $definition['value_type'];
        if ($type === 'boolean' && !is_bool($value)) {
            throw new RuntimeException('The setting value must be true or false.');
        }
        if ($type === 'integer' && !is_int($value)) {
            throw new RuntimeException('The setting value must be an integer.');
        }
        if (($type === 'string' || $type === 'enum') && (!is_string($value) || mb_strlen($value) > 200)) {
            throw new RuntimeException('The setting value must be a bounded string.');
        }
        if ($type === 'enum') {
            $allowed = json_decode((string) $definition['allowed_values_json'], true, 16, JSON_THROW_ON_ERROR);
            if (!is_array($allowed) || !in_array($value, $allowed, true)) {
                throw new RuntimeException('The setting value is not permitted.');
            }
        }
        return $value;
    }

    /** @return array<string,mixed> */
    private function ownedDevice(int $accountId, string $publicId): array
    {
        $query = $this->database->pdo()->prepare('SELECT id,public_id,account_id FROM homeserver_devices WHERE account_id=:account AND public_id=:public AND status<>\'revoked\' LIMIT 1');
        $query->execute(['account' => $accountId, 'public' => trim($publicId)]);
        $device = $query->fetch(PDO::FETCH_ASSOC);
        if (!is_array($device)) {
            throw new RuntimeException('The HomeServer device was not found for this account.');
        }
        return $device;
    }

    /** @return array<string,mixed> */
    private function authenticateDevice(string $publicId, string $credential): array
    {
        $query = $this->database->pdo()->prepare(
            "SELECT d.*,l.status license_status,s.status subscription_status FROM homeserver_devices d JOIN licenses l ON l.id=d.license_id AND l.account_id=d.account_id JOIN subscriptions s ON s.id=d.subscription_id AND s.account_id=d.account_id WHERE d.public_id=:public LIMIT 1"
        );
        $query->execute(['public' => trim($publicId)]);
        $device = $query->fetch(PDO::FETCH_ASSOC);
        if (!is_array($device) || $credential === '' || !hash_equals((string) ($device['credential_hash'] ?? ''), hash('sha256', $credential))) {
            throw new RuntimeException('HomeServer device credential is invalid.');
        }
        if (in_array($device['status'], ['suspended', 'revoked'], true)
            || !in_array($device['license_status'], ['active', 'grace'], true)
            || !in_array($device['subscription_status'], ['active', 'trialing', 'grace'], true)) {
            throw new RuntimeException('HomeServer license is not eligible.');
        }
        return $device;
    }

    private function recordReceipt(
        int $accountId,
        ?int $deviceId,
        string $requestId,
        string $direction,
        int $baseRevision,
        int $appliedRevision,
        string $snapshotHash,
        string $result,
        int $conflictCount
    ): void {
        $this->database->pdo()->prepare(
            'INSERT INTO federated_settings_sync_receipts (public_id,account_id,device_id,request_id,direction,base_revision,applied_revision,snapshot_hash,result,conflict_count,created_at) VALUES (:public,:account,:device,:request,:direction,:base,:applied,:snapshot,:result,:conflicts,UTC_TIMESTAMP())'
        )->execute([
            'public' => 'FSS-' . strtoupper(bin2hex(random_bytes(12))),
            'account' => $accountId,
            'device' => $deviceId,
            'request' => substr($requestId, 0, 64),
            'direction' => $direction,
            'base' => max(0, $baseRevision),
            'applied' => max(0, $appliedRevision),
            'snapshot' => strtolower($snapshotHash),
            'result' => $result,
            'conflicts' => max(0, $conflictCount),
        ]);
    }

    private function canonicalJson(mixed $value): string
    {
        $normalize = function (mixed $item) use (&$normalize): mixed {
            if (!is_array($item)) {
                return $item;
            }
            if (array_is_list($item)) {
                return array_map($normalize, $item);
            }
            ksort($item, SORT_STRING);
            foreach ($item as $key => $entry) {
                $item[$key] = $normalize($entry);
            }
            return $item;
        };
        return json_encode($normalize($value), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}

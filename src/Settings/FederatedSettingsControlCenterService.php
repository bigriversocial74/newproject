<?php

declare(strict_types=1);

namespace Vp3\Settings;

use JsonException;
use PDO;
use RuntimeException;
use Vp3\Auth\AuthPublicException;
use Vp3\Database;

final class FederatedSettingsControlCenterService
{
    private const ROLES = ['customer_owner', 'customer_admin'];

    public function __construct(
        private readonly Database $database,
        private readonly FederatedSettingsService $settings
    ) {
    }

    /** @return array<string,mixed> */
    public function snapshot(
        int $accountId,
        int $actorId,
        string $role,
        ?string $devicePublicId = null
    ): array {
        return $this->database->transaction(function (PDO $pdo) use ($accountId, $actorId, $role, $devicePublicId): array {
            $account = $this->authorize($pdo, $accountId, $actorId, $role, false);
            $devices = $this->devices($pdo, $accountId);
            $selectedDevice = $this->selectedDevice($pdo, $accountId, $devicePublicId, false);
            return $this->browserSnapshot($accountId, $account, $devices, $selectedDevice);
        });
    }

    /** @return array<string,mixed> */
    public function update(
        int $accountId,
        int $actorId,
        string $role,
        string $settingKey,
        mixed $value,
        int $expectedRevision,
        ?string $devicePublicId,
        string $requestId
    ): array {
        $operationResource = trim($settingKey) !== '' ? trim($settingKey) : 'unknown';
        try {
            return $this->database->transaction(function (PDO $pdo) use (
                $accountId,
                $actorId,
                $role,
                $settingKey,
                $value,
                $expectedRevision,
                $devicePublicId,
                $requestId
            ): array {
                $account = $this->authorize($pdo, $accountId, $actorId, $role, true);
                $definition = $this->definition($pdo, $settingKey);
                $authority = (string) $definition['authority'];
                if ($authority === 'homeserver') {
                    throw new AuthPublicException(
                        'settings_homeserver_authority',
                        'This setting is controlled by the HomeServer.',
                        422
                    );
                }

                $selectedDevice = null;
                $scopeType = 'account';
                $scopeKey = 'account';
                $deviceId = null;
                if ($authority === 'shared') {
                    $selectedDevice = $this->selectedDevice($pdo, $accountId, $devicePublicId, true);
                    $scopeType = 'device';
                    $scopeKey = (string) $selectedDevice['public_id'];
                    $deviceId = (int) $selectedDevice['id'];
                }

                $validated = $this->validateValue($definition, $value);
                $requestHash = hash('sha256', $this->canonicalJson([
                    'setting_key' => (string) $definition['setting_key'],
                    'value' => $validated,
                    'expected_revision' => max(0, $expectedRevision),
                    'device_public_id' => $selectedDevice['public_id'] ?? null,
                ]));

                $replay = $this->existingReceipt($pdo, $accountId, $deviceId, $requestId);
                if (is_array($replay)) {
                    if (!hash_equals((string) $replay['request_hash'], $requestHash)) {
                        throw new AuthPublicException(
                            'settings_request_conflict',
                            'The settings request ID was already used for a different update.',
                            409
                        );
                    }
                    $devices = $this->devices($pdo, $accountId);
                    $snapshot = $this->browserSnapshot($accountId, $account, $devices, $selectedDevice);
                    $snapshot['replayed'] = true;
                    return $snapshot;
                }

                $current = $pdo->prepare(
                    'SELECT id,revision FROM federated_settings
                     WHERE account_id=:account AND scope_type=:scope AND scope_key=:scope_key
                       AND setting_key=:setting LIMIT 1 FOR UPDATE'
                );
                $current->execute([
                    'account' => $accountId,
                    'scope' => $scopeType,
                    'scope_key' => $scopeKey,
                    'setting' => $definition['setting_key'],
                ]);
                $row = $current->fetch(PDO::FETCH_ASSOC);
                $currentRevision = is_array($row) ? (int) $row['revision'] : 0;
                if ($currentRevision !== max(0, $expectedRevision)) {
                    throw new AuthPublicException(
                        'settings_revision_conflict',
                        'The setting changed before this update was saved. Refresh and try again.',
                        409
                    );
                }

                $nextRevision = $currentRevision + 1;
                $json = $this->canonicalJson($validated);
                if (is_array($row)) {
                    $update = $pdo->prepare(
                        "UPDATE federated_settings
                         SET value_json=:value,value_hash=:hash,revision=:revision,
                             source_authority='vp3',updated_by_user_id=:user,updated_at=UTC_TIMESTAMP()
                         WHERE id=:id"
                    );
                    $update->execute([
                        'value' => $json,
                        'hash' => hash('sha256', $json),
                        'revision' => $nextRevision,
                        'user' => $actorId,
                        'id' => $row['id'],
                    ]);
                } else {
                    $insert = $pdo->prepare(
                        "INSERT INTO federated_settings
                         (account_id,device_id,scope_type,scope_key,setting_key,value_json,value_hash,
                          revision,source_authority,updated_by_user_id,created_at,updated_at)
                         VALUES
                         (:account,:device,:scope,:scope_key,:setting,:value,:hash,:revision,
                          'vp3',:user,UTC_TIMESTAMP(),UTC_TIMESTAMP())"
                    );
                    $insert->execute([
                        'account' => $accountId,
                        'device' => $deviceId,
                        'scope' => $scopeType,
                        'scope_key' => $scopeKey,
                        'setting' => $definition['setting_key'],
                        'value' => $json,
                        'hash' => hash('sha256', $json),
                        'revision' => $nextRevision,
                        'user' => $actorId,
                    ]);
                }

                $devices = $this->devices($pdo, $accountId);
                $snapshot = $this->browserSnapshot($accountId, $account, $devices, $selectedDevice);
                $this->receipt(
                    $pdo,
                    $accountId,
                    $deviceId,
                    $requestId,
                    $requestHash,
                    max(0, $expectedRevision),
                    $nextRevision,
                    (string) $snapshot['snapshot_hash']
                );
                $this->audit(
                    $pdo,
                    $accountId,
                    $actorId,
                    'settings.updated',
                    'success',
                    (string) $definition['setting_key'],
                    $requestId
                );
                $snapshot['replayed'] = false;
                return $snapshot;
            });
        } catch (AuthPublicException $exception) {
            if ($exception->publicCode() === 'settings_permission_denied') {
                $this->database->transaction(function (PDO $pdo) use ($accountId, $actorId, $operationResource, $requestId): void {
                    $this->audit(
                        $pdo,
                        $accountId,
                        $actorId,
                        'settings.updated',
                        'denied',
                        $operationResource,
                        $requestId
                    );
                });
            }
            throw $exception;
        }
    }

    /** @return array{public_id:string,display_name:string} */
    private function authorize(PDO $pdo, int $accountId, int $actorId, string $role, bool $lock): array
    {
        $sql = "SELECT a.public_id,a.display_name,au.role
                FROM account_users au
                JOIN accounts a ON a.id=au.account_id
                WHERE au.account_id=:account AND au.user_id=:actor
                  AND au.status='active' AND a.status='active'
                LIMIT 1" . ($lock ? ' FOR UPDATE' : '');
        $statement = $pdo->prepare($sql);
        $statement->execute(['account' => $accountId, 'actor' => $actorId]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        $storedRole = is_array($row) ? (string) $row['role'] : '';
        if (!is_array($row)
            || !hash_equals($storedRole, $role)
            || !in_array($storedRole, self::ROLES, true)) {
            throw new AuthPublicException(
                'settings_permission_denied',
                'An active customer owner or administrator membership is required to manage settings.',
                403
            );
        }
        return [
            'public_id' => (string) $row['public_id'],
            'display_name' => (string) $row['display_name'],
        ];
    }

    /** @return list<array<string,mixed>> */
    private function devices(PDO $pdo, int $accountId): array
    {
        $query = $pdo->prepare(
            "SELECT public_id,status,pairing_status,software_version,last_heartbeat_at
             FROM homeserver_devices
             WHERE account_id=:account AND status<>'revoked'
             ORDER BY COALESCE(last_heartbeat_at,created_at) DESC,id DESC"
        );
        $query->execute(['account' => $accountId]);
        return array_map(static fn (array $row): array => [
            'public_id' => (string) $row['public_id'],
            'status' => (string) $row['status'],
            'pairing_status' => (string) $row['pairing_status'],
            'software_version' => $row['software_version'] === null ? null : (string) $row['software_version'],
            'last_heartbeat_at' => $row['last_heartbeat_at'] === null ? null : (string) $row['last_heartbeat_at'],
        ], $query->fetchAll(PDO::FETCH_ASSOC));
    }

    /** @return array{id:int,public_id:string,status:string}|null */
    private function selectedDevice(PDO $pdo, int $accountId, ?string $publicId, bool $required): ?array
    {
        $publicId = trim((string) $publicId);
        if ($publicId === '') {
            if ($required) {
                throw new AuthPublicException(
                    'settings_device_required',
                    'Select an account-owned HomeServer before changing a shared setting.',
                    422
                );
            }
            return null;
        }
        if (!preg_match('/^[A-Za-z0-9._:-]{3,64}$/', $publicId)) {
            throw new AuthPublicException('settings_device_invalid', 'A valid HomeServer identity is required.', 422);
        }
        $query = $pdo->prepare(
            "SELECT id,public_id,status
             FROM homeserver_devices
             WHERE account_id=:account AND public_id=:public AND status<>'revoked'
             LIMIT 1 FOR UPDATE"
        );
        $query->execute(['account' => $accountId, 'public' => $publicId]);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            throw new AuthPublicException(
                'settings_device_not_found',
                'The account-owned HomeServer was not found.',
                404
            );
        }
        return [
            'id' => (int) $row['id'],
            'public_id' => (string) $row['public_id'],
            'status' => (string) $row['status'],
        ];
    }

    /** @return array<string,mixed> */
    private function definition(PDO $pdo, string $settingKey): array
    {
        $settingKey = trim($settingKey);
        if (!preg_match('/^[a-z][a-z0-9_.-]{2,119}$/', $settingKey)) {
            throw new AuthPublicException('settings_key_invalid', 'A valid setting key is required.', 422);
        }
        $query = $pdo->prepare(
            "SELECT setting_key,label,description,category,authority,value_type,
                    allowed_values_json,visible_in_vp3,sensitivity
             FROM federated_setting_catalog
             WHERE setting_key=:setting AND sensitivity='non_secret' LIMIT 1"
        );
        $query->execute(['setting' => $settingKey]);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row) || !(bool) $row['visible_in_vp3']) {
            throw new AuthPublicException('settings_not_found', 'The federated setting was not found.', 404);
        }
        return $row;
    }

    private function validateValue(array $definition, mixed $value): mixed
    {
        $type = (string) $definition['value_type'];
        if ($type === 'boolean' && !is_bool($value)) {
            throw new AuthPublicException('settings_value_invalid', 'The setting value must be true or false.', 422);
        }
        if ($type === 'integer' && !is_int($value)) {
            throw new AuthPublicException('settings_value_invalid', 'The setting value must be an integer.', 422);
        }
        if (($type === 'string' || $type === 'enum')
            && (!is_string($value) || mb_strlen($value) > 200)) {
            throw new AuthPublicException('settings_value_invalid', 'The setting value must be a bounded string.', 422);
        }
        if ($type === 'enum') {
            try {
                $allowed = json_decode((string) $definition['allowed_values_json'], true, 16, JSON_THROW_ON_ERROR);
            } catch (JsonException) {
                throw new AuthPublicException('settings_catalog_invalid', 'The setting catalog is invalid.', 500);
            }
            if (!is_array($allowed) || !in_array($value, $allowed, true)) {
                throw new AuthPublicException('settings_value_invalid', 'The setting value is not permitted.', 422);
            }
        }
        return $value;
    }

    /** @return array<string,mixed> */
    private function browserSnapshot(int $accountId, array $account, array $devices, ?array $selectedDevice): array
    {
        $internal = $this->settings->snapshotForAccount(
            $accountId,
            $selectedDevice['public_id'] ?? null
        );
        $settings = array_map(static function (array $setting): array {
            $authority = (string) $setting['authority'];
            return [
                'setting_key' => (string) $setting['setting_key'],
                'label' => (string) $setting['label'],
                'description' => (string) $setting['description'],
                'category' => (string) $setting['category'],
                'authority' => $authority,
                'value_type' => (string) $setting['value_type'],
                'allowed_values' => $setting['allowed_values'],
                'value' => $setting['value'],
                'revision' => (int) $setting['revision'],
                'source_authority' => (string) $setting['source_authority'],
                'scope' => (string) $setting['scope'],
                'editable_in_vp3' => (bool) $setting['editable_in_vp3'],
                'requires_device' => $authority === 'shared',
            ];
        }, (array) $internal['settings']);

        $identity = [
            'schema' => 'vp3.control-center-federated-settings.v1',
            'account' => [
                'public_id' => (string) $account['public_id'],
                'display_name' => (string) $account['display_name'],
            ],
            'devices' => $devices,
            'selected_device_public_id' => $selectedDevice['public_id'] ?? null,
            'max_revision' => (int) $internal['max_revision'],
            'settings' => $settings,
        ];
        return $identity + [
            'generated_at' => gmdate(DATE_ATOM),
            'snapshot_hash' => hash('sha256', $this->canonicalJson($identity)),
            'replayed' => false,
        ];
    }

    /** @return array<string,mixed>|null */
    private function existingReceipt(PDO $pdo, int $accountId, ?int $deviceId, string $requestId): ?array
    {
        $sql = 'SELECT request_hash FROM federated_settings_sync_receipts
                WHERE account_id=:account AND request_id=:request AND direction=\'vp3_update\'';
        $parameters = ['account' => $accountId, 'request' => substr($requestId, 0, 64)];
        if ($deviceId === null) {
            $sql .= ' AND device_id IS NULL';
        } else {
            $sql .= ' AND device_id=:device';
            $parameters['device'] = $deviceId;
        }
        $sql .= ' ORDER BY id DESC LIMIT 1 FOR UPDATE';
        $query = $pdo->prepare($sql);
        $query->execute($parameters);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        return is_array($row) ? $row : null;
    }

    private function receipt(
        PDO $pdo,
        int $accountId,
        ?int $deviceId,
        string $requestId,
        string $requestHash,
        int $baseRevision,
        int $appliedRevision,
        string $snapshotHash
    ): void {
        $insert = $pdo->prepare(
            "INSERT INTO federated_settings_sync_receipts
             (public_id,account_id,device_id,request_id,request_hash,direction,base_revision,
              applied_revision,snapshot_hash,result,conflict_count,created_at)
             VALUES
             (:public,:account,:device,:request,:request_hash,'vp3_update',:base,
              :applied,:snapshot,'applied',0,UTC_TIMESTAMP())"
        );
        $insert->execute([
            'public' => 'FSS-' . strtoupper(bin2hex(random_bytes(12))),
            'account' => $accountId,
            'device' => $deviceId,
            'request' => substr($requestId, 0, 64),
            'request_hash' => strtolower($requestHash),
            'base' => max(0, $baseRevision),
            'applied' => max(0, $appliedRevision),
            'snapshot' => strtolower($snapshotHash),
        ]);
    }

    private function audit(
        PDO $pdo,
        int $accountId,
        int $actorId,
        string $eventType,
        string $result,
        string $settingKey,
        string $requestId
    ): void {
        $insert = $pdo->prepare(
            "INSERT INTO audit_events
             (request_id,actor_type,actor_id,account_id,event_type,resource_type,
              resource_public_id,result,created_at)
             VALUES
             (:request,'user',:actor,:account,:event,'federated_setting',:resource,:result,UTC_TIMESTAMP())"
        );
        $insert->execute([
            'request' => substr($requestId, 0, 64),
            'actor' => $actorId,
            'account' => $accountId,
            'event' => substr($eventType, 0, 100),
            'resource' => substr($settingKey, 0, 190),
            'result' => $result,
        ]);
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
            ksort($item, SORT_STRING);
            foreach ($item as $key => $entry) {
                $item[$key] = $normalize($entry);
            }
            return $item;
        };
        return json_encode($normalize($value), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}

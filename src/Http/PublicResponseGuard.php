<?php

declare(strict_types=1);

namespace Vp3\Http;

use LogicException;

final class PublicResponseGuard
{
    private static bool $enabled = false;

    /** @var array<string,true> */
    private const FORBIDDEN_KEYS = [
        'id' => true,
        'account_id' => true,
        'user_id' => true,
        'plan_id' => true,
        'subscription_id' => true,
        'domain_id' => true,
        'domain_registration_id' => true,
        'entitlement_bundle_id' => true,
        'license_id' => true,
        'pod_deployment_id' => true,
        'deployment_id' => true,
        'device_id' => true,
        'release_id' => true,
        'snapshot_id' => true,
        'backup_id' => true,
        'restore_id' => true,
        'policy_id' => true,
        'job_id' => true,
        'provider_connection_id' => true,
        'binding_id' => true,
        'operation_id' => true,
        'incident_id' => true,
        'channel_id' => true,
        'notification_id' => true,
        'membership_id' => true,
        'invitation_id' => true,
        'session_id' => true,
        'actor_user_id' => true,
        'target_user_id' => true,
        'source_id' => true,
    ];

    public static function enable(): void
    {
        self::$enabled = true;
    }

    public static function disable(): void
    {
        self::$enabled = false;
    }

    public static function enabled(): bool
    {
        return self::$enabled;
    }

    /** @param array<string|int,mixed> $payload */
    public static function assertSafe(array $payload): void
    {
        self::walk($payload, '$');
    }

    /** @param array<string|int,mixed> $value */
    private static function walk(array $value, string $path): void
    {
        foreach ($value as $key => $child) {
            $childPath = $path . '[' . (is_int($key) ? (string) $key : "'" . $key . "'") . ']';
            if (is_string($key) && isset(self::FORBIDDEN_KEYS[$key])) {
                throw new LogicException('Internal identifier reached a public response at ' . $childPath . '.');
            }
            if (is_array($child)) {
                self::walk($child, $childPath);
            }
        }
    }
}

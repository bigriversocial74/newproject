<?php

declare(strict_types=1);

namespace Vp3\Settings;

use RuntimeException;
use Vp3\HomeServers\HomeServerLeaseSigner;

final class FederatedSettingsControlCenterSigner
{
    private const MAX_LIFETIME_SECONDS = 300;

    public function __construct(private readonly HomeServerLeaseSigner $signer)
    {
    }

    /** @param array<string,mixed> $snapshot @return array<string,mixed> */
    public function sign(array $snapshot): array
    {
        foreach (['schema', 'account', 'devices', 'selected_device_public_id', 'max_revision', 'settings', 'generated_at', 'snapshot_hash', 'replayed'] as $required) {
            if (!array_key_exists($required, $snapshot)) {
                throw new RuntimeException('The Control Center settings snapshot is incomplete.');
            }
        }
        if ($this->signer->algorithm() !== 'Ed25519') {
            throw new RuntimeException('Control Center settings require the production Ed25519 signing key.');
        }
        $account = $snapshot['account'];
        if (!is_array($account) || trim((string) ($account['public_id'] ?? '')) === '') {
            throw new RuntimeException('The Control Center settings account identity is invalid.');
        }
        if (!is_array($snapshot['devices']) || !is_array($snapshot['settings']) || !is_bool($snapshot['replayed'])) {
            throw new RuntimeException('The Control Center settings snapshot structure is invalid.');
        }

        $issuedAt = time();
        $signed = $this->signer->sign([
            'schema' => (string) $snapshot['schema'],
            'account_public_id' => (string) $account['public_id'],
            'devices' => $snapshot['devices'],
            'selected_device_public_id' => $snapshot['selected_device_public_id'] === null
                ? null
                : (string) $snapshot['selected_device_public_id'],
            'max_revision' => max(0, (int) $snapshot['max_revision']),
            'settings' => $snapshot['settings'],
            'generated_at' => (string) $snapshot['generated_at'],
            'snapshot_hash' => strtolower((string) $snapshot['snapshot_hash']),
            'replayed' => $snapshot['replayed'],
            'iat' => $issuedAt,
            'exp' => $issuedAt + self::MAX_LIFETIME_SECONDS,
        ]);

        return $snapshot + [
            'signed_document' => $signed['document'],
            'signature' => $signed['signature'],
            'signing_key_id' => $signed['key_id'],
            'signature_algorithm' => $signed['algorithm'],
            'signed_document_hash' => $signed['document_hash'],
        ];
    }
}

<?php

declare(strict_types=1);

namespace Vp3\Settings;

use RuntimeException;
use Vp3\HomeServers\HomeServerLeaseSigner;

final class FederatedSettingsSigner
{
    private const MAX_LIFETIME_SECONDS = 900;

    public function __construct(private readonly HomeServerLeaseSigner $signer)
    {
    }

    /** @param array<string,mixed> $snapshot @return array<string,mixed> */
    public function sign(array $snapshot): array
    {
        foreach (['schema', 'account_id', 'device_public_id', 'max_revision', 'settings', 'generated_at', 'snapshot_hash'] as $required) {
            if (!array_key_exists($required, $snapshot)) {
                throw new RuntimeException('The federated settings snapshot is incomplete.');
            }
        }
        if ($this->signer->algorithm() !== 'Ed25519') {
            throw new RuntimeException('Federated settings require the production Ed25519 HomeServer signing key.');
        }
        $normalized = $snapshot + [
            'replayed' => false,
            'applied' => [],
            'conflicts' => [],
        ];
        if (!is_bool($normalized['replayed']) || !is_array($normalized['applied']) || !is_array($normalized['conflicts'])) {
            throw new RuntimeException('The federated settings sync result is invalid.');
        }
        $issuedAt = time();
        $signed = $this->signer->sign([
            'schema' => (string) $normalized['schema'],
            'account_id' => (int) $normalized['account_id'],
            'device_public_id' => $normalized['device_public_id'] === null ? null : (string) $normalized['device_public_id'],
            'max_revision' => max(0, (int) $normalized['max_revision']),
            'snapshot_hash' => strtolower((string) $normalized['snapshot_hash']),
            'generated_at' => (string) $normalized['generated_at'],
            'settings' => $normalized['settings'],
            'replayed' => $normalized['replayed'],
            'applied' => $normalized['applied'],
            'conflicts' => $normalized['conflicts'],
            'iat' => $issuedAt,
            'exp' => $issuedAt + self::MAX_LIFETIME_SECONDS,
        ]);
        return $normalized + [
            'signed_document' => $signed['document'],
            'signature' => $signed['signature'],
            'signing_key_id' => $signed['key_id'],
            'signature_algorithm' => $signed['algorithm'],
            'signed_document_hash' => $signed['document_hash'],
        ];
    }
}

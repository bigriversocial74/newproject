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
        foreach (['schema', 'account_id', 'device_public_id', 'max_revision', 'settings', 'snapshot_hash'] as $required) {
            if (!array_key_exists($required, $snapshot)) {
                throw new RuntimeException('The federated settings snapshot is incomplete.');
            }
        }
        if ($this->signer->algorithm() !== 'Ed25519') {
            throw new RuntimeException('Federated settings require the production Ed25519 HomeServer signing key.');
        }
        $issuedAt = time();
        $signed = $this->signer->sign([
            'schema' => (string) $snapshot['schema'],
            'account_id' => (int) $snapshot['account_id'],
            'device_public_id' => $snapshot['device_public_id'] === null ? null : (string) $snapshot['device_public_id'],
            'max_revision' => max(0, (int) $snapshot['max_revision']),
            'snapshot_hash' => strtolower((string) $snapshot['snapshot_hash']),
            'settings' => $snapshot['settings'],
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

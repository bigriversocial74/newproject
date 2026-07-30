<?php

declare(strict_types=1);

namespace Vp3\Settings;

use DateTimeImmutable;
use Vp3\HomeServers\HomeServerLeaseSigner;

final class FederatedSettingsControlCenterSigner
{
    public function __construct(private readonly HomeServerLeaseSigner $signer)
    {
    }

    /**
     * @param array<string,mixed> $snapshot
     * @return array{document:string,signature:string,key_id:string,algorithm:string,document_hash:string,signature_hash:string}
     */
    public function sign(array $snapshot): array
    {
        $issued = new DateTimeImmutable('now');
        return $this->signer->sign([
            'schema' => 'vp3.control-center-federated-settings.v1',
            'account_public_id' => (string) $snapshot['account']['public_id'],
            'device_public_id' => $snapshot['selected_device_public_id'],
            'max_revision' => (int) $snapshot['max_revision'],
            'snapshot_hash' => (string) $snapshot['snapshot_hash'],
            'settings' => $snapshot['settings'],
            'issued_at' => $issued->format(DATE_ATOM),
            'expires_at' => $issued->modify('+5 minutes')->format(DATE_ATOM),
        ]);
    }
}

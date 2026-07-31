<?php

declare(strict_types=1);

namespace Vp3\Deployment;

use RuntimeException;

final class PlatformReleaseSignatureService
{
    private ?string $privateKey;
    private string $publicKey;

    public function __construct(
        string $privateKeyBase64,
        string $publicKeyBase64,
        private readonly string $keyId
    ) {
        $private = base64_decode(trim($privateKeyBase64), true);
        $public = base64_decode(trim($publicKeyBase64), true);
        if (!is_string($private) || strlen($private) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new RuntimeException('The platform release signing private key must be a 64-byte Ed25519 key.');
        }
        if (!is_string($public) || strlen($public) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new RuntimeException('The platform release signing public key must be a 32-byte Ed25519 key.');
        }
        if (!preg_match('/^[A-Za-z0-9._:-]{3,64}$/', $this->keyId)) {
            throw new RuntimeException('The platform release signing key ID is invalid.');
        }
        $derived = sodium_crypto_sign_publickey_from_secretkey($private);
        if (!hash_equals($derived, $public)) {
            throw new RuntimeException('The platform release signing key pair does not match.');
        }
        $this->privateKey = $private;
        $this->publicKey = $public;
    }

    /** @param array<string,mixed> $manifest @return array<string,string> */
    public function sign(array $manifest, ReleaseManifestService $canonicalizer): array
    {
        $manifestHash = (string) ($manifest['manifest_sha256'] ?? '');
        if (!preg_match('/^[a-f0-9]{64}$/', $manifestHash)) {
            throw new RuntimeException('A verified release manifest hash is required before signing.');
        }
        if (!is_string($this->privateKey)) {
            throw new RuntimeException('The platform release signing private key is unavailable.');
        }
        $payload = $canonicalizer->canonicalJson($manifest);
        $signature = sodium_crypto_sign_detached($payload, $this->privateKey);
        return [
            'format' => 'vp3-platform-release-signature-v1',
            'key_id' => $this->keyId,
            'algorithm' => 'Ed25519',
            'manifest_sha256' => $manifestHash,
            'signature_base64' => base64_encode($signature),
            'public_key_base64' => base64_encode($this->publicKey),
        ];
    }

    /** @param array<string,mixed> $manifest @param array<string,mixed> $signature */
    public function verify(
        array $manifest,
        array $signature,
        ReleaseManifestService $canonicalizer
    ): void {
        if (!hash_equals($this->keyId, (string) ($signature['key_id'] ?? ''))
            || !hash_equals('Ed25519', (string) ($signature['algorithm'] ?? ''))
            || !hash_equals(
                (string) ($manifest['manifest_sha256'] ?? ''),
                (string) ($signature['manifest_sha256'] ?? '')
            )) {
            throw new RuntimeException('The release signature identity does not match the manifest.');
        }
        $decoded = base64_decode((string) ($signature['signature_base64'] ?? ''), true);
        if (!is_string($decoded) || strlen($decoded) !== SODIUM_CRYPTO_SIGN_BYTES) {
            throw new RuntimeException('The release signature is malformed.');
        }
        if (!sodium_crypto_sign_verify_detached(
            $decoded,
            $canonicalizer->canonicalJson($manifest),
            $this->publicKey
        )) {
            throw new RuntimeException('The platform release signature is invalid.');
        }
    }

    public function __destruct()
    {
        if (is_string($this->privateKey)) {
            sodium_memzero($this->privateKey);
        }
    }
}

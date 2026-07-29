<?php

declare(strict_types=1);

namespace Vp3\Backups;

use RuntimeException;

final class BackupMetadataCipher
{
    public function __construct(
        private readonly string $keyBase64,
        private readonly string $keyId = 'backup-aes256gcm-v1'
    ) {
    }

    /** @return array{ciphertext:string,nonce:string,tag:string,key_id:string} */
    public function encrypt(string $plaintext, string $context): array
    {
        $key = $this->key();
        $nonce = random_bytes(12);
        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $context,
            16
        );
        if (!is_string($ciphertext) || strlen($tag) !== 16) {
            throw new RuntimeException('Backup metadata encryption failed.');
        }
        return [
            'ciphertext' => base64_encode($ciphertext),
            'nonce' => base64_encode($nonce),
            'tag' => base64_encode($tag),
            'key_id' => $this->keyId,
        ];
    }

    public function decrypt(string $ciphertext, string $nonce, string $tag, string $context): string
    {
        $decodedCiphertext = base64_decode($ciphertext, true);
        $decodedNonce = base64_decode($nonce, true);
        $decodedTag = base64_decode($tag, true);
        if (!is_string($decodedCiphertext) || !is_string($decodedNonce) || !is_string($decodedTag)) {
            throw new RuntimeException('Backup metadata encoding is invalid.');
        }
        $plaintext = openssl_decrypt(
            $decodedCiphertext,
            'aes-256-gcm',
            $this->key(),
            OPENSSL_RAW_DATA,
            $decodedNonce,
            $decodedTag,
            $context
        );
        if (!is_string($plaintext)) {
            throw new RuntimeException('Backup metadata authentication failed.');
        }
        return $plaintext;
    }

    public function keyId(): string
    {
        return $this->keyId;
    }

    private function key(): string
    {
        $key = base64_decode($this->keyBase64, true);
        if (!is_string($key) || strlen($key) !== 32) {
            throw new RuntimeException('A valid 32-byte backup metadata encryption key is required.');
        }
        return $key;
    }
}

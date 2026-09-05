<?php
namespace Bonemesh;

// BMX key schedule (security.md §5): a Noise-style symmetric state carrying a
// transcript hash h and chaining key ck. Pinned constants match every other
// implementation (shared vector spec/corpus/transcripts/keyschedule.json).
final class KeySchedule
{
    public const PROTOCOL_NAME = 'BoneMesh_BMX_v3_X25519MLKEM768_ChaChaPoly_SHA256';

    public string $h;
    public string $ck;
    private ?string $key = null;
    private int $nonce = 0;

    public function __construct()
    {
        $this->h = Crypto::sha256(self::PROTOCOL_NAME);
        $this->ck = $this->h;
    }

    // h = SHA-256(h || data)
    public function mixHash(string $data): void
    {
        $this->h = Crypto::sha256($this->h . $data);
    }

    // Derive a fresh key and chaining key, resetting the nonce.
    public function mixKey(string $ikm): void
    {
        $okm = Crypto::hkdf($this->ck, $ikm, '', 64);
        $this->ck = substr($okm, 0, 32);
        $this->key = substr($okm, 32, 32);
        $this->nonce = 0;
    }

    // Seal plaintext with h as AAD, then absorb the ciphertext.
    public function encryptAndHash(string $plaintext): string
    {
        $ct = Crypto::aeadSeal($this->key, $this->nonce12(), $this->h, $plaintext);
        $this->nonce++;
        $this->mixHash($ct);
        return $ct;
    }

    // Open a ciphertext (AAD is the current h), then absorb it. Null on failure.
    public function decryptAndHash(string $ciphertext): ?string
    {
        $ad = $this->h;
        $pt = Crypto::aeadOpen($this->key, $this->nonce12(), $ad, $ciphertext);
        if ($pt === null) {
            return null;
        }
        $this->nonce++;
        $this->mixHash($ciphertext);
        return $pt;
    }

    // Derive the two directional transport keys: [i2r, r2i].
    public function split(): array
    {
        $okm = Crypto::hkdf($this->ck, '', '', 64);
        return [substr($okm, 0, 32), substr($okm, 32, 32)];
    }

    private function nonce12(): string
    {
        return "\0\0\0\0" . pack('P', $this->nonce);
    }
}

<?php
namespace Bonemesh;

// BoneMesh v3 cryptographic primitives (security.md §1). SHA-256, HKDF-SHA-256,
// ChaCha20-Poly1305, and X25519 come from PHP's built-in libsodium. ML-KEM-768
// and ML-DSA-65/87 — which PHP has no native binding for — are reached through
// the platform's openssl 3.5 CLI, the same OpenSSL the Node port uses. Public
// keys, ciphertexts, secrets, and signatures are the raw FIPS/RFC encodings,
// matching the Java, Elixir, Rust, Go, and JS implementations.
//
// Only the node identity's ML-DSA private key is ever serialized (as an opaque
// PEM, which never crosses a node boundary). Ephemeral X25519 keys are raw
// scalars; ephemeral ML-KEM keys are PEM strings held for the handshake.
final class Crypto
{
    // Fixed SubjectPublicKeyInfo headers: prepending one to a raw public key
    // yields the DER the openssl CLI imports. Constant because each algorithm's
    // key size is fixed; a round-trip self-test guards these in the suite.
    private const SPKI_HEADER = [
        'ML-DSA-65'  => '308207b2300b0609608648016503040312038207a100',
        'ML-DSA-87'  => '30820a32300b060960864801650304031303820a2100',
        'ML-KEM-768' => '308204b2300b0609608648016503040402038204a100',
    ];
    private const RAW_PUB_LEN = ['ML-DSA-65' => 1952, 'ML-DSA-87' => 2592, 'ML-KEM-768' => 1184];

    public static function sha256(string $data): string
    {
        return hash('sha256', $data, true);
    }

    // Full extract-then-expand HKDF-SHA-256 (RFC 5869), implemented over HMAC so
    // an empty IKM (used by split) is accepted — PHP's hash_hkdf rejects it.
    public static function hkdf(string $salt, string $ikm, string $info, int $length): string
    {
        $prk = hash_hmac('sha256', $ikm, $salt, true);
        $t = '';
        $okm = '';
        $i = 1;
        while (strlen($okm) < $length) {
            $t = hash_hmac('sha256', $t . $info . chr($i), $prk, true);
            $okm .= $t;
            $i++;
        }
        return substr($okm, 0, $length);
    }

    // ChaCha20-Poly1305 (IETF) with the 16-byte tag appended.
    public static function aeadSeal(string $key, string $nonce, ?string $aad, string $plaintext): string
    {
        return sodium_crypto_aead_chacha20poly1305_ietf_encrypt($plaintext, $aad ?? '', $nonce, $key);
    }

    // Returns the plaintext, or null on tag failure.
    public static function aeadOpen(string $key, string $nonce, ?string $aad, string $ct): ?string
    {
        $pt = sodium_crypto_aead_chacha20poly1305_ietf_decrypt($ct, $aad ?? '', $nonce, $key);
        return $pt === false ? null : $pt;
    }

    // Returns ['pub' => raw 32, 'priv' => raw 32 scalar].
    public static function x25519Generate(): array
    {
        $priv = random_bytes(32);
        return ['pub' => sodium_crypto_scalarmult_base($priv), 'priv' => $priv];
    }

    public static function x25519Agree(string $priv, string $peerPub): string
    {
        return sodium_crypto_scalarmult($priv, $peerPub);
    }

    // --- ML-DSA / ML-KEM via the openssl CLI ---------------------------------

    // Returns ['pub' => raw 1952, 'priv' => PEM]. The PEM is this port's opaque
    // private-key form and never crosses a node boundary.
    public static function mldsa65Generate(): array
    {
        return self::pqcGenerate('ML-DSA-65');
    }

    public static function mldsa65Sign(string $privPem, string $message): string
    {
        [$priv, $msg, $sig] = [self::tmp($privPem), self::tmp($message), self::tmp()];
        try {
            [$code] = self::run(['openssl', 'pkeyutl', '-sign', '-inkey', $priv, '-rawin', '-in', $msg, '-out', $sig]);
            if ($code !== 0) {
                throw new \RuntimeException('ML-DSA sign failed');
            }
            return file_get_contents($sig);
        } finally {
            self::cleanup([$priv, $msg, $sig]);
        }
    }

    public static function mldsa65Verify(string $pubRaw, string $message, string $signature): bool
    {
        return self::pqcVerify('ML-DSA-65', $pubRaw, $message, $signature);
    }

    public static function mldsa87Verify(string $pubRaw, string $message, string $signature): bool
    {
        return self::pqcVerify('ML-DSA-87', $pubRaw, $message, $signature);
    }

    // Returns ['ek' => raw 1184, 'dk' => PEM].
    public static function mlkem768Keypair(): array
    {
        $r = self::pqcGenerate('ML-KEM-768');
        return ['ek' => $r['pub'], 'dk' => $r['priv']];
    }

    // Returns ['ss' => 32, 'ct' => 1088].
    public static function mlkem768Encapsulate(string $ekRaw): array
    {
        $key = self::tmp(hex2bin(self::SPKI_HEADER['ML-KEM-768']) . $ekRaw);
        [$ct, $ss] = [self::tmp(), self::tmp()];
        try {
            [$code] = self::run(['openssl', 'pkeyutl', '-encap', '-inkey', $key, '-keyform', 'DER', '-pubin', '-out', $ct, '-secret', $ss]);
            if ($code !== 0) {
                throw new \RuntimeException('ML-KEM encapsulate failed');
            }
            return ['ss' => file_get_contents($ss), 'ct' => file_get_contents($ct)];
        } finally {
            self::cleanup([$key, $ct, $ss]);
        }
    }

    // Returns the shared secret, or null on failure.
    public static function mlkem768Decapsulate(string $dkPem, string $ct): ?string
    {
        [$priv, $ctf, $ss] = [self::tmp($dkPem), self::tmp($ct), self::tmp()];
        try {
            [$code] = self::run(['openssl', 'pkeyutl', '-decap', '-inkey', $priv, '-in', $ctf, '-secret', $ss]);
            return $code === 0 ? file_get_contents($ss) : null;
        } finally {
            self::cleanup([$priv, $ctf, $ss]);
        }
    }

    private static function pqcGenerate(string $alg): array
    {
        [$priv, $der] = [self::tmp(), self::tmp()];
        try {
            [$c1] = self::run(['openssl', 'genpkey', '-algorithm', $alg, '-out', $priv]);
            [$c2] = self::run(['openssl', 'pkey', '-in', $priv, '-pubout', '-outform', 'DER', '-out', $der]);
            if ($c1 !== 0 || $c2 !== 0) {
                throw new \RuntimeException("$alg keygen failed");
            }
            $spki = file_get_contents($der);
            $pub = substr($spki, strlen($spki) - self::RAW_PUB_LEN[$alg]);
            return ['pub' => $pub, 'priv' => file_get_contents($priv)];
        } finally {
            self::cleanup([$priv, $der]);
        }
    }

    private static function pqcVerify(string $alg, string $pubRaw, string $message, string $signature): bool
    {
        $key = self::tmp(hex2bin(self::SPKI_HEADER[$alg]) . $pubRaw);
        [$msg, $sig] = [self::tmp($message), self::tmp($signature)];
        try {
            [$code] = self::run(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', $key, '-keyform', 'DER', '-rawin', '-in', $msg, '-sigfile', $sig]);
            return $code === 0;
        } finally {
            self::cleanup([$key, $msg, $sig]);
        }
    }

    // Runs an argv without a shell; returns [exitCode, stdout, stderr].
    private static function run(array $argv): array
    {
        $desc = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $proc = proc_open($argv, $desc, $pipes);
        if (!is_resource($proc)) {
            throw new \RuntimeException('failed to spawn openssl');
        }
        $out = stream_get_contents($pipes[1]);
        $err = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        return [proc_close($proc), $out, $err];
    }

    private static function tmp(string $content = ''): string
    {
        $f = tempnam(sys_get_temp_dir(), 'bm');
        if ($content !== '') {
            file_put_contents($f, $content);
        }
        return $f;
    }

    private static function cleanup(array $files): void
    {
        foreach ($files as $f) {
            if (is_file($f)) {
                @unlink($f);
            }
        }
    }
}

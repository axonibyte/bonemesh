<?php
namespace Bonemesh;

// BoneMesh v3 membership certificate (security.md §3): a mesh-root-signed
// binding of a label to a node's ML-DSA-65 identity key. Represented as an
// associative array (the JSON form); its signed pre-image is the canon
// canonicalization of every field except "sig". Base64 fields are standard.
final class Cert
{
    // Build an unsigned certificate. $identityKey is the raw ML-DSA-65 pubkey.
    public static function build(string $mesh, string $label, string $identityKey, int $notBefore, int $notAfter): array
    {
        return [
            'v' => 3,
            'mesh' => $mesh,
            'label' => $label,
            'idk' => base64_encode($identityKey),
            'nbf' => $notBefore,
            'exp' => $notAfter,
        ];
    }

    // Verify against the pinned root public key, mesh, and time. Returns null if
    // valid, else a reason string.
    public static function verify(array $cert, string $rootPublic, string $expectedMesh, int $now): ?string
    {
        if (($cert['mesh'] ?? null) !== $expectedMesh) {
            return 'mesh mismatch';
        }
        if (!isset($cert['nbf']) || !is_int($cert['nbf']) || $now < $cert['nbf']) {
            return 'certificate not yet valid';
        }
        if (!isset($cert['exp']) || !is_int($cert['exp']) || $now > $cert['exp']) {
            return 'certificate expired';
        }
        if (!isset($cert['sig']) || !is_string($cert['sig'])) {
            return 'certificate is unsigned';
        }
        $sig = base64_decode($cert['sig'], true);
        if ($sig === false) {
            return 'signature is not base64';
        }
        try {
            $preImage = Canon::canonicalize($cert);
        } catch (\Throwable $e) {
            return 'canon: ' . $e->getMessage();
        }
        if (!Crypto::mldsa87Verify($rootPublic, $preImage, $sig)) {
            return 'root signature does not verify';
        }
        return null;
    }

    // The node's raw ML-DSA-65 public key.
    public static function identityKey(array $cert): string
    {
        return base64_decode($cert['idk'], true);
    }
}

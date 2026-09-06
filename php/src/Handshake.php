<?php
namespace Bonemesh;

// BMX handshake (security.md §4): a three-message, mutually authenticated,
// forward-secret exchange. Hybrid X25519 + ML-KEM-768 forward secrecy through
// the key schedule; authentication by a root-signed certificate plus an ML-DSA
// signature over the live transcript. Field-for-field identical to the Java,
// Elixir, Rust, Go, and JS implementations.
//
// write* methods return an encoded frame string ready for the wire; read*
// methods take the peer's already-decoded frame array.
final class Handshake
{
    private KeySchedule $ks;
    private ?array $session = null;
    private string $ephDHPub;
    private string $ephDHPriv;
    private string $ephKEMek;
    private string $ephKEMdk;

    public function __construct(
        private string $mesh,
        private string $rootPublic,
        private int $now,
        private array $cert,
        private string $idPrivate
    ) {
        $this->ks = new KeySchedule();
        $this->ks->mixHash($mesh);
    }

    public static function initiator(string $mesh, string $rootPublic, int $now, array $cert, string $idPrivate): self
    {
        return new self($mesh, $rootPublic, $now, $cert, $idPrivate);
    }

    public static function responder(string $mesh, string $rootPublic, int $now, array $cert, string $idPrivate): self
    {
        return new self($mesh, $rootPublic, $now, $cert, $idPrivate);
    }

    public function session(): ?array
    {
        return $this->session;
    }

    public function writeMessage1(): string
    {
        $dh = Crypto::x25519Generate();
        $kem = Crypto::mlkem768Keypair();
        $n = random_bytes(32);
        $this->ephDHPub = $dh['pub'];
        $this->ephDHPriv = $dh['priv'];
        $this->ephKEMek = $kem['ek'];
        $this->ephKEMdk = $kem['dk'];
        $this->ks->mixHash($dh['pub']);
        $this->ks->mixHash($kem['ek']);
        $this->ks->mixHash($n);
        return Frame::encode([
            't' => 'bmx1', 'v' => 3, 'mesh' => $this->mesh,
            'e' => base64_encode($dh['pub']), 'k' => base64_encode($kem['ek']), 'n' => base64_encode($n),
        ]);
    }

    public function readMessage1WriteMessage2(array $m): string
    {
        if (($m['t'] ?? null) !== 'bmx1') {
            throw new \RuntimeException('expected bmx1');
        }
        if (($m['v'] ?? null) !== 3) {
            throw new \RuntimeException('unsupported version');
        }
        if (($m['mesh'] ?? null) !== $this->mesh) {
            throw new \RuntimeException('mesh mismatch');
        }
        $eiPub = self::b64Field($m, 'e');
        $kiEk = self::b64Field($m, 'k');
        $this->ks->mixHash($eiPub);
        $this->ks->mixHash($kiEk);
        $this->ks->mixHash(self::b64Field($m, 'n'));

        $er = Crypto::x25519Generate();
        $this->ks->mixHash($er['pub']);
        $this->ks->mixKey(Crypto::x25519Agree($er['priv'], $eiPub));

        $enc = Crypto::mlkem768Encapsulate($kiEk);
        $this->ks->mixHash($enc['ct']);
        $this->ks->mixKey($enc['ss']);

        $auth = $this->sealIdentity();
        return Frame::encode([
            't' => 'bmx2', 'e' => base64_encode($er['pub']),
            'ct' => base64_encode($enc['ct']), 'auth' => base64_encode($auth),
        ]);
    }

    public function readMessage2WriteMessage3(array $m): string
    {
        $erPub = self::b64Field($m, 'e');
        $ct = self::b64Field($m, 'ct');
        $auth = self::b64Field($m, 'auth');

        $this->ks->mixHash($erPub);
        $this->ks->mixKey(Crypto::x25519Agree($this->ephDHPriv, $erPub));
        $this->ks->mixHash($ct);
        $ssKem = Crypto::mlkem768Decapsulate($this->ephKEMdk, $ct);
        if ($ssKem === null) {
            throw new \RuntimeException('decapsulation failed');
        }
        $this->ks->mixKey($ssKem);

        $peerCert = $this->openIdentity($auth);
        $authI = $this->sealIdentity();
        $out = Frame::encode(['t' => 'bmx3', 'auth' => base64_encode($authI)]);
        [$i2r, $r2i] = $this->ks->split();
        $this->session = ['sendKey' => $i2r, 'receiveKey' => $r2i, 'peerCert' => $peerCert, 'h' => $this->ks->h];
        return $out;
    }

    public function readMessage3(array $m): void
    {
        $peerCert = $this->openIdentity(self::b64Field($m, 'auth'));
        [$i2r, $r2i] = $this->ks->split();
        $this->session = ['sendKey' => $r2i, 'receiveKey' => $i2r, 'peerCert' => $peerCert, 'h' => $this->ks->h];
    }

    private function sealIdentity(): string
    {
        $sig = Crypto::mldsa65Sign($this->idPrivate, $this->ks->h);
        $payload = json_encode(['cert' => $this->cert, 'sig' => base64_encode($sig)], JSON_UNESCAPED_SLASHES);
        return $this->ks->encryptAndHash($payload);
    }

    private function openIdentity(string $auth): array
    {
        $hPre = $this->ks->h;
        $pt = $this->ks->decryptAndHash($auth);
        if ($pt === null) {
            throw new \RuntimeException('handshake authentication failed');
        }
        $payload = json_decode($pt, true);
        if (!is_array($payload) || !isset($payload['cert'], $payload['sig'])) {
            throw new \RuntimeException('bad auth payload');
        }
        $peerCert = $payload['cert'];
        $reason = Cert::verify($peerCert, $this->rootPublic, $this->mesh, $this->now);
        if ($reason !== null) {
            throw new \RuntimeException("peer certificate invalid: $reason");
        }
        $idk = Cert::identityKey($peerCert);
        if (!Crypto::mldsa65Verify($idk, $hPre, base64_decode((string) $payload['sig'], true))) {
            throw new \RuntimeException('peer transcript signature does not verify');
        }
        return $peerCert;
    }

    // Decodes a required base64 field, rejecting a missing, non-string, or
    // non-base64 value cleanly — so malformed peer input throws (and the node
    // closes the connection) instead of emitting undefined-key / null-argument
    // warnings. Surfaced by interop tier 7's fuzzing.
    private static function b64Field(array $m, string $key): string
    {
        if (!isset($m[$key]) || !is_string($m[$key])) {
            throw new \RuntimeException("missing or non-string field: $key");
        }
        $v = base64_decode($m[$key], true);
        if ($v === false) {
            throw new \RuntimeException("field is not base64: $key");
        }
        return $v;
    }
}

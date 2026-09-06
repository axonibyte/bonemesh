<?php
namespace Bonemesh;

// Encrypted transport channel over a completed handshake (protocol.md §4): each
// frame is a sequence-numbered AEAD carrier {"seq":n,"ct":...} whose plaintext
// is the inner JSON message. The per-direction sequence is the
// ChaCha20-Poly1305 nonce; reordered or replayed frames are rejected. Matches
// the shared transport-frame vector.
final class Transport
{
    private string $sendKey;
    private string $receiveKey;
    private int $sendSeq = 0;
    private int $receiveSeq = 0;

    public function __construct(array $session)
    {
        $this->sendKey = $session['sendKey'];
        $this->receiveKey = $session['receiveKey'];
    }

    // Seal an inner message into a { seq, ct } carrier array.
    public function seal(array $inner): array
    {
        $seq = $this->sendSeq;
        $pt = json_encode($inner, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $ct = Crypto::aeadSeal($this->sendKey, self::nonce($seq), null, $pt);
        $this->sendSeq++;
        return ['seq' => $seq, 'ct' => base64_encode($ct)];
    }

    // Open a carrier, enforcing in-order delivery. Returns the inner array, or
    // throws on gap/replay or authentication failure.
    public function open(array $carrier): array
    {
        $seq = $carrier['seq'];
        if ($seq !== $this->receiveSeq) {
            throw new \RuntimeException('out-of-order frame');
        }
        $ct = base64_decode($carrier['ct'], true);
        $pt = Crypto::aeadOpen($this->receiveKey, self::nonce($seq), null, $ct);
        if ($pt === null) {
            throw new \RuntimeException('frame authentication failed');
        }
        $this->receiveSeq++;
        return json_decode($pt, true);
    }

    // Per-direction frame counters, so the node can decide when a rekey is due (F5).
    public function sendSeq(): int
    {
        return $this->sendSeq;
    }

    public function receiveSeq(): int
    {
        return $this->receiveSeq;
    }

    // Install a new outbound key and reset the send counter to 0, called at the
    // rekey boundary immediately after sealing the last old-key frame in this
    // direction so the next frame uses the new key at seq 0 (F5).
    public function swapSend(string $key): void
    {
        $this->sendKey = $key;
        $this->sendSeq = 0;
    }

    // Install a new inbound key and reset the receive counter, called right
    // after opening the last old-key frame in this direction.
    public function swapReceive(string $key): void
    {
        $this->receiveKey = $key;
        $this->receiveSeq = 0;
    }

    private static function nonce(int $seq): string
    {
        return "\0\0\0\0" . pack('P', $seq);
    }
}

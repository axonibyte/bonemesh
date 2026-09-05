<?php
// Test-only mesh-root helper: generates a throwaway ML-DSA-87 root and signs a
// certificate pre-image, via the openssl CLI. Kept out of the shipped Crypto
// class, which nodes use and which never signs root certificates.
use Bonemesh\Canon;

function ca_root(): array
{
    $priv = tempnam(sys_get_temp_dir(), 'ca');
    $der = tempnam(sys_get_temp_dir(), 'ca');
    ca_run(['openssl', 'genpkey', '-algorithm', 'ML-DSA-87', '-out', $priv]);
    ca_run(['openssl', 'pkey', '-in', $priv, '-pubout', '-outform', 'DER', '-out', $der]);
    $spki = file_get_contents($der);
    $pubRaw = substr($spki, strlen($spki) - 2592);
    $privPem = file_get_contents($priv);
    @unlink($priv);
    @unlink($der);
    return ['pubRaw' => $pubRaw, 'privPem' => $privPem];
}

function ca_sign_cert(array $root, array $cert): array
{
    $priv = tempnam(sys_get_temp_dir(), 'ca');
    $msg = tempnam(sys_get_temp_dir(), 'ca');
    $sig = tempnam(sys_get_temp_dir(), 'ca');
    file_put_contents($priv, $root['privPem']);
    file_put_contents($msg, Canon::canonicalize($cert));
    ca_run(['openssl', 'pkeyutl', '-sign', '-inkey', $priv, '-rawin', '-in', $msg, '-out', $sig]);
    $cert['sig'] = base64_encode(file_get_contents($sig));
    @unlink($priv);
    @unlink($msg);
    @unlink($sig);
    return $cert;
}

function ca_run(array $argv): void
{
    $p = proc_open($argv, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    stream_get_contents($pipes[1]);
    stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    if (proc_close($p) !== 0) {
        throw new \RuntimeException('openssl (ca) failed: ' . implode(' ', $argv));
    }
}

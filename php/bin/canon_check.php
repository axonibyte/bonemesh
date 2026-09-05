<?php
// Reads the shared corpus (spec/corpus/canon.json) and confirms this PHP
// canonicalizer reproduces each vector's expected bytes. Agreement with the
// other implementations means a certificate signed by any of them verifies
// under this one. Invoked by interop/check-canon-php.sh; exits non-zero on any
// mismatch.
require __DIR__ . '/../src/autoload.php';

use Bonemesh\Canon;

$path = $argv[1] ?? null;
if ($path === null) {
    fwrite(STDERR, "usage: canon_check <canon.json>\n");
    exit(2);
}
$doc = json_decode(file_get_contents($path), true);
$failures = 0;
foreach ($doc['vectors'] as $v) {
    try {
        $got = Canon::canonicalize($v['cert']);
    } catch (\Throwable $e) {
        echo "FAIL {$v['name']}\n  error: {$e->getMessage()}\n";
        $failures++;
        continue;
    }
    if ($got === $v['canonical']) {
        echo "PASS {$v['name']}\n";
    } else {
        echo "FAIL {$v['name']}\n  got:  $got\n  want: {$v['canonical']}\n";
        $failures++;
    }
}
if ($failures > 0) {
    fwrite(STDERR, "$failures vector(s) mismatched\n");
    exit(1);
}
echo 'all ' . count($doc['vectors']) . " canon vectors match\n";

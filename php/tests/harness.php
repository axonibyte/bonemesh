<?php
// Tiny dependency-free test harness. Each test file calls test('name', fn);
// tests/run.php includes the files and reports. Keeps the port free of Composer
// and PHPUnit — nothing to vendor for the reaper tenant.

$GLOBALS['__bm_tests'] = ['pass' => 0, 'fail' => 0];

function test(string $name, callable $fn): void
{
    try {
        $fn();
        $GLOBALS['__bm_tests']['pass']++;
        fwrite(STDOUT, "PASS $name\n");
    } catch (\Throwable $e) {
        $GLOBALS['__bm_tests']['fail']++;
        fwrite(STDOUT, "FAIL $name: " . $e->getMessage() . "\n");
    }
}

function assertTrue($cond, string $msg = ''): void
{
    if (!$cond) {
        throw new \Exception($msg !== '' ? $msg : 'assertTrue failed');
    }
}

function assertEq($expected, $actual, string $msg = ''): void
{
    if ($expected !== $actual) {
        $e = is_string($expected) ? $expected : var_export($expected, true);
        $a = is_string($actual) ? $actual : var_export($actual, true);
        throw new \Exception(($msg !== '' ? $msg : 'not equal') . " (expected=$e actual=$a)");
    }
}

function assertNull($v, string $msg = ''): void
{
    if ($v !== null) {
        throw new \Exception($msg !== '' ? $msg : 'expected null, got ' . var_export($v, true));
    }
}

function assertNotNull($v, string $msg = ''): void
{
    if ($v === null) {
        throw new \Exception($msg !== '' ? $msg : 'expected non-null');
    }
}

function assertThrows(callable $fn, string $msg = ''): void
{
    try {
        $fn();
    } catch (\Throwable $e) {
        return;
    }
    throw new \Exception($msg !== '' ? $msg : 'expected an exception');
}

function test_summary(): int
{
    $t = $GLOBALS['__bm_tests'];
    $total = $t['pass'] + $t['fail'];
    fwrite(STDOUT, "\ntests $total  pass {$t['pass']}  fail {$t['fail']}\n");
    return $t['fail'] > 0 ? 1 : 0;
}

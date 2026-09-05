<?php
// JCS canonicalization tests. Vectors mirror the shared corpus
// (spec/corpus/canon.json) and security.md §11.1; byte-for-byte agreement with
// the other implementations over that corpus is checked by bin/canon_check.php.
// Escape-heavy expected strings are built from chr() so the source cannot
// smuggle a raw control byte in place of an escape sequence.
use Bonemesh\Canon;

test('basic sorted keys', function () {
    $cert = ['v' => 3, 'mesh' => 'acme-prod', 'label' => 'alpha', 'idk' => 'YWJj', 'nbf' => 1788500000, 'exp' => 1790000000];
    assertEq('{"exp":1790000000,"idk":"YWJj","label":"alpha","mesh":"acme-prod","nbf":1788500000,"v":3}', Canon::canonicalize($cert));
});

test('sig field is stripped', function () {
    $cert = ['v' => 3, 'mesh' => 'm', 'label' => 'alpha', 'idk' => 'AA==', 'nbf' => 0, 'exp' => 1, 'sig' => 'IGNORED'];
    assertEq('{"exp":1,"idk":"AA==","label":"alpha","mesh":"m","nbf":0,"v":3}', Canon::canonicalize($cert));
});

test('non-ascii emitted as raw utf-8', function () {
    $cert = ['v' => 3, 'mesh' => 'm', 'label' => 'café', 'idk' => 'AA==', 'nbf' => 0, 'exp' => 1];
    assertEq('{"exp":1,"idk":"AA==","label":"café","mesh":"m","nbf":0,"v":3}', Canon::canonicalize($cert));
});

test('quote and backslash escaping', function () {
    $bs = chr(0x5c);
    $cert = ['v' => 3, 'mesh' => 'm', 'label' => 'a"b' . $bs . 'c', 'idk' => 'AA==', 'nbf' => 0, 'exp' => 1];
    $labelTok = '"a' . $bs . '"b' . $bs . $bs . 'c"';
    assertEq('{"exp":1,"idk":"AA==","label":' . $labelTok . ',"mesh":"m","nbf":0,"v":3}', Canon::canonicalize($cert));
});

test('control characters use short and unicode escapes', function () {
    $bs = chr(0x5c);
    $label = 'a' . chr(0x08) . chr(0x09) . chr(0x0a) . chr(0x0c) . chr(0x0d) . chr(0x01) . 'b';
    $labelTok = '"a' . $bs . 'b' . $bs . 't' . $bs . 'n' . $bs . 'f' . $bs . 'r' . $bs . 'u0001b"';
    assertEq('{"label":' . $labelTok . '}', Canon::canonicalize(['label' => $label]));
});

test('negative integer is rejected', function () {
    assertThrows(fn () => Canon::canonicalize(['nbf' => -1]));
});

test('float is rejected', function () {
    assertThrows(fn () => Canon::canonicalize(['v' => 3.5]));
});

test('boolean is rejected', function () {
    assertThrows(fn () => Canon::canonicalize(['ok' => true]));
});

test('json array value is rejected', function () {
    assertThrows(fn () => Canon::canonicalize(['xs' => [1, 2, 3]]));
});

test('nested objects sorted independently', function () {
    assertEq('{"a":{"b":3,"y":2},"z":1}', Canon::canonicalize(['z' => 1, 'a' => ['y' => 2, 'b' => 3]]));
});

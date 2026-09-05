<?php
// Runs every tests/*.test.php file and reports a summary; exit code is non-zero
// if any test failed. This is the reaper tenant's run command.
require __DIR__ . '/../src/autoload.php';
require __DIR__ . '/harness.php';
require __DIR__ . '/ca.php';

foreach (glob(__DIR__ . '/*.test.php') as $file) {
    require $file;
}

exit(test_summary());

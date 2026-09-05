<?php
// Minimal PSR-4 autoloader for the Bonemesh namespace, so the port needs no
// Composer install (nothing to vendor). Maps Bonemesh\Foo -> src/Foo.php.
spl_autoload_register(static function (string $class): void {
    $prefix = 'Bonemesh\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $rel = substr($class, strlen($prefix));
    $file = __DIR__ . '/' . str_replace('\\', '/', $rel) . '.php';
    if (is_file($file)) {
        require $file;
    }
});

<?php

/**
 * What one require costs, printed as the list of files it pulled in.
 *
 * Run in a FRESH interpreter - `php test/included.php src/Sekreto.php` -
 * because the process running the suite has required everything on
 * purpose, and a require_once is a no-op the second time. This is the only
 * way to see the core's real include graph, and test/plugins.php reads it.
 *
 * Only files under this port are listed; voxgig/plugin and voxgig/omni
 * live elsewhere and are not what is being measured.
 */

declare(strict_types=1);

$root = realpath(__DIR__ . '/..');

require_once $root . '/' . $argv[1];

foreach (get_included_files() as $file) {
    $real = realpath($file);

    if (null === $real || false === $real || __FILE__ === $real) {
        continue;
    }

    if (str_starts_with($real, $root . '/')) {
        echo substr($real, strlen($root) + 1), "\n";
    }
}

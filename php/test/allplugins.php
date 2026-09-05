<?php

/**
 * Building the full set, and nothing else, for `php test/included.php
 * test/allplugins.php` to measure. Naming `allplugins` costs one file;
 * CALLING it costs all ten, and that difference is the point.
 */

declare(strict_types=1);

require_once __DIR__ . '/../plugins/plugins.php';

\Voxgig\Sekreto\Plugins\allplugins();

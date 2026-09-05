<?php

/**
 * Where voxgig/plugin is.
 *
 * sekreto's core is built on [voxgig/plugin](https://github.com/voxgig/plugin):
 * a provider kind is a plugin definition and a configured provider is a
 * plugin instance. Every other port takes that dependency the way its
 * language takes one - npm for typescript, the module proxy for go, pip
 * for python. PHP here has no package manager at all: this port ships no
 * composer manifest and no `vendor/` tree, for the same reason plugin's
 * own php port ships none, so the dependency is a CHECKOUT, found the way
 * this port already finds voxgig/omni.
 *
 * That makes this the one file in the core that touches the filesystem to
 * decide what to load, and it is deliberately the only one: the search
 * happens once, here, and `Sekreto.php` simply requires this. An embedding
 * host that has already required plugin's `src/plugin.php` itself - from a
 * vendored copy, an autoloader, anywhere - is detected and left alone.
 *
 * `make deps` fetches a shallow clone into `../.plugin` when nothing else
 * is on disk, which is what `npm install` and `pip install` do for the
 * ports that have a registry.
 */

declare(strict_types=1);

namespace Voxgig\Sekreto;

/**
 * The root of a voxgig/plugin checkout, or null when there is none.
 *
 * $PLUGIN_HOME first, then the places a sibling checkout lives - including
 * the ../.plugin that `make deps` writes.
 */
function pluginhome(): ?string
{
    $cands = [
        getenv('PLUGIN_HOME') ?: null,
        __DIR__ . '/../../../plugin',
        __DIR__ . '/../../../../plugin',
        __DIR__ . '/../../.plugin',
        '/workspace/plugin',
        '/home/user/plugin',
    ];

    foreach ($cands as $cand) {
        if (null !== $cand && file_exists($cand . '/php/src/plugin.php')) {
            return realpath($cand) ?: $cand;
        }
    }

    return null;
}

/**
 * Make voxgig/plugin's php port available: already loaded, or from a
 * checkout.
 */
function requireplugin(): void
{
    if (function_exists('Voxgig\\Plugin\\make_host')) {
        return;
    }

    $home = pluginhome();

    if (null === $home) {
        throw new SekretoError(
            'sekreto: voxgig/plugin not found - set PLUGIN_HOME, or run make deps'
        );
    }

    require_once $home . '/php/src/plugin.php';
}

<?php

/**
 * THE FULL SET - every plugin kind this library ships, in one call.
 *
 * One plugin is its own file, and requiring it requires nothing else:
 *
 *     require_once __DIR__ . '/plugins/hashicorp.php';
 *
 *     use Voxgig\Sekreto\Sekreto;
 *     use function Voxgig\Sekreto\Plugins\hashicorp;
 *
 *     $secrets = new Sekreto([
 *         'plugins' => [hashicorp()],
 *         'providers' => [['kind' => 'env'], ['kind' => 'hashicorp', ...]],
 *     ]);
 *
 * THIS FILE IS THE ONE THING THAT REQUIRES ALL TEN. It is for the CLI, the
 * conformance suite, and an app whose chain is decided at run time.
 * Reaching it pulls in every network client, AWS request signing and the
 * two child-process kinds - which is the cost the core/plugin split exists
 * to remove, so an app requires the kinds it actually configures, each
 * from its own file.
 *
 * The requires are INSIDE the function on purpose. At file scope they
 * would make requiring this file - to read the list, to name the type -
 * load all ten as a side effect, and a side effect of an import is exactly
 * what the split forbids (docs/design/plugin-providers.md).
 */

declare(strict_types=1);

namespace Voxgig\Sekreto\Plugins;

/**
 * Every plugin kind, built on demand, in the order the design doc lists
 * them.
 *
 * @return array<int, array<string, mixed>>
 */
function allplugins(): array
{
    require_once __DIR__ . '/hashicorp.php';
    require_once __DIR__ . '/boru.php';
    require_once __DIR__ . '/aws.php';
    require_once __DIR__ . '/gcpsecrets.php';
    require_once __DIR__ . '/azuresecrets.php';
    require_once __DIR__ . '/onepassword.php';
    require_once __DIR__ . '/doppler.php';
    require_once __DIR__ . '/infisical.php';
    require_once __DIR__ . '/secretspec.php';

    return [
        hashicorp(), boru(), awssecrets(), awsparams(), gcpsecrets(),
        azuresecrets(), onepassword(), doppler(), infisical(), secretspec(),
    ];
}

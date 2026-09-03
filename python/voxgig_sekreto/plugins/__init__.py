# THE PLUGINS PACKAGE - one module per plugin, and the full set on demand.
#
# One plugin is its own module, and importing it imports nothing else:
#
#     from voxgig_sekreto.plugins.hashicorp import hashicorp
#
# THIS FILE IMPORTS NO PLUGIN. It used to import all ten so that they
# could be re-exported from here, and that made the single-plugin import
# above execute this initializer first and load every network client,
# AWS request signing and the two CLIs behind it - the whole set, for a
# consumer that had named exactly one. So the full set is built only
# when it is asked for, through PEP 562's module `__getattr__`:
#
#     from voxgig_sekreto.plugins import ALL
#     Sekreto({'plugins': ALL, 'providers': [...]})
#
# ALL is for the CLI, the conformance suite, and an app whose chain is
# decided at run time. Reaching it imports every plugin, which is the
# cost the core/plugin split exists to remove; an app imports the kinds
# it actually configures, each from its own module.
#
# ONE TRAP, stated because Python makes it easy: `from
# voxgig_sekreto.plugins import hashicorp` yields the MODULE, not the
# definition inside it - the package has no attribute of that name until
# the submodule is imported, and then the attribute IS the submodule.
# Sekreto refuses a module passed as a plugin and says what to import
# instead. For the same reason this package exports nothing else that
# shares a name with a module in it: `sigv4` comes from `.aws` (or
# `.sigv4`), `fetchjson` from `.httpjson`. See
# docs/design/plugin-providers.md.

_MODULES = [
    'hashicorp', 'boru', 'aws', 'gcpsecrets', 'azuresecrets',
    'onepassword', 'doppler', 'infisical', 'secretspec',
]


def _all():
    from .hashicorp import hashicorp
    from .boru import boru
    from .aws import awssecrets, awsparams
    from .gcpsecrets import gcpsecrets
    from .azuresecrets import azuresecrets
    from .onepassword import onepassword
    from .doppler import doppler
    from .infisical import infisical
    from .secretspec import secretspec

    return [
        hashicorp, boru, awssecrets, awsparams, gcpsecrets, azuresecrets,
        onepassword, doppler, infisical, secretspec,
    ]


def __getattr__(name):
    if 'ALL' == name:
        return _all()
    raise AttributeError('module ' + __name__ + ' has no attribute ' + name)


__all__ = ['ALL'] + _MODULES

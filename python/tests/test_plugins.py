# RUN: python3 -m unittest discover -s tests -k plugins
#
# THE PLUGIN SEAM, from both sides.
#
# Moving the provider kinds that open sockets and spawn processes out of
# the core made a consumer's PLUGIN LIST load-bearing: a kind nobody
# passed in is not in the catalog, and a chain naming it is refused. That
# is the intended behaviour, and it means a consumer can be broken
# without a single conformance test noticing - the conformance suite
# passes every plugin, so it can never see a missing one. So the full set
# is pinned here: it holds every kind, every kind builds, and the CLI
# passes it.

import os
import subprocess
import sys
import unittest

from pluginhome import pluginhome, pluginpath

pluginpath()

from voxgig_sekreto import BUILTINS, KINDS, Sekreto, SekretoError, providerplugin  # noqa: E402
from voxgig_sekreto.plugins import ALL  # noqa: E402
from voxgig_sekreto.plugins.hashicorp import hashicorp  # noqa: E402

PLUGINS = [
    'awsparams', 'awssecrets', 'azuresecrets', 'boru', 'doppler', 'gcpsecrets',
    'hashicorp', 'infisical', 'onepassword', 'secretspec',
]

EVERY = sorted(['dotenv', 'env', 'file', 'memory'] + PLUGINS)

HERE = os.path.dirname(os.path.abspath(__file__))


class TestPlugins(unittest.TestCase):

    def test_the_full_set_holds_every_kind(self):
        self.assertEqual(sorted(d['name'] for d in ALL), PLUGINS)
        for name in PLUGINS:
            module = 'aws' if name.startswith('aws') else name
            self.assertIn(module, dir(sys.modules['voxgig_sekreto.plugins']))
        self.assertEqual([d['name'] for d in BUILTINS], KINDS['builtin'])
        self.assertEqual(sorted(KINDS['plugin']), PLUGINS)

    # Naming a kind is not enough: a kind can be in the catalog and still
    # fail to build. Construction is what the CLI does before any network.
    def test_every_kind_builds_from_a_spec(self):
        chain = [{
            'kind': kind, 'addr': 'http://127.0.0.1:8200', 'token': 't',
            'dir': '/tmp', 'file': '/tmp/.env', 'values': {},
        } for kind in EVERY]

        secrets = Sekreto({'plugins': ALL, 'providers': chain})

        self.assertEqual(secrets.stores(), EVERY)
        self.assertEqual(sorted(secrets.host.list()), EVERY)
        self.assertEqual(set(secrets.host.list().values()), {'live'})

    def test_the_cli_passes_the_full_set(self):
        with open(os.path.join(HERE, '..', 'cli', 'sekreto_cli.py'), encoding='utf8') as handle:
            src = handle.read()
        self.assertIn("from voxgig_sekreto.plugins import ALL", src)
        self.assertIn("'plugins': ALL", src)

    # --- what a consumer sees ---------------------------------------------

    def test_one_plugin_is_enough_for_a_chain_that_names_only_it(self):
        secrets = Sekreto({
            'plugins': [hashicorp],
            'providers': [
                {'kind': 'memory', 'values': {'API_TOKEN': 'tok01'}},
                {'kind': 'hashicorp', 'name': 'prod', 'addr': 'https://vault.example.com', 'token': 't'},
            ],
        })

        self.assertEqual(secrets.stores(), ['memory', 'prod'])
        self.assertEqual(secrets.sources(), ['memory', 'hashicorp:https://vault.example.com/secret'])
        self.assertEqual(secrets.get('api.token'), 'tok01')

        # The plugin host is what the chain is made of, and it reads like
        # the chain: the kind, or kind$store for a named store.
        self.assertEqual(secrets.host.list(), {'memory': 'live', 'hashicorp$prod': 'live'})
        self.assertEqual(secrets.catalog.names(), ['dotenv', 'env', 'file', 'hashicorp', 'memory'])

    def test_a_kind_that_was_not_passed_in_is_refused_naming_the_fix(self):
        with self.assertRaises(SekretoError) as caught:
            Sekreto({'plugins': [hashicorp], 'providers': [{'kind': 'doppler', 'token': 't'}]})
        self.assertEqual(
            str(caught.exception),
            'sekreto: unknown provider kind: doppler (available: dotenv, env, file, hashicorp, memory)'
            ' - doppler is a sekreto plugin, not built in: pass it in the plugins option')

        # A kind nobody ships is a typo, and gets no such hint.
        with self.assertRaises(SekretoError) as caught:
            Sekreto({'providers': [{'kind': 'vualt'}]})
        self.assertEqual(
            str(caught.exception),
            'sekreto: unknown provider kind: vualt (available: dotenv, env, file, memory)')

    # Two providers MAY share a store name - a directed read walks both,
    # and the spec pins it - but an instance ref may not, so the second
    # gets a numbered tag from the host and keeps its store name.
    def test_a_repeated_store_name_keeps_the_store_and_numbers_the_instance(self):
        secrets = Sekreto({'providers': [
            {'kind': 'memory', 'values': {}},
            {'kind': 'memory', 'values': {'API_TOKEN': 'second'}},
            {'kind': 'memory', 'name': 'pair', 'values': {}},
            {'kind': 'memory', 'name': 'pair', 'values': {'API_TOKEN': 'pair2'}},
        ]})

        self.assertEqual(secrets.stores(), ['memory', 'pair'])
        self.assertEqual(list(secrets.host.list()), ['memory', 'memory$1', 'memory$2', 'memory$pair'])
        self.assertEqual(secrets.getfrom('memory', 'api.token'), 'second')
        self.assertEqual(secrets.getfrom('pair', 'api.token'), 'pair2')

    def test_a_store_name_must_be_a_valid_tag(self):
        with self.assertRaises(SekretoError) as caught:
            Sekreto({'providers': [{'kind': 'memory', 'name': 'my store', 'values': {}}]})
        self.assertEqual(str(caught.exception), 'sekreto: invalid store name: my store')

    # A provider that refuses its own configuration raises a SekretoError
    # from inside the plugin's `define`. The spec pins that message byte
    # for byte, so it must come back out of the host as itself - not
    # wrapped as plugin_define_failed, and not as a PluginError.
    def test_a_sekreto_error_raised_in_define_comes_back_out_as_itself(self):
        with self.assertRaises(SekretoError) as caught:
            Sekreto({
                'plugins': [hashicorp],
                'providers': [{'kind': 'hashicorp', 'addr': 'http://127.0.0.1:1', 'token': 't', 'kv': 3}],
            })
        self.assertEqual(str(caught.exception), 'sekreto: hashicorp: unsupported kv version: 3')

    # ...and any other error is not sekreto's to rewrite: it surfaces as
    # the host reports it, naming the instance and the cause.
    def test_any_other_error_raised_in_define_is_the_hosts_report_of_it(self):
        def boom(spec):
            raise TypeError('boom')

        with self.assertRaises(Exception) as caught:
            Sekreto({'plugins': [providerplugin('broken', boom)], 'providers': [{'kind': 'broken'}]})
        self.assertEqual(getattr(caught.exception, 'code', None), 'plugin_define_failed')
        self.assertIn('boom', str(caught.exception))

    def test_a_custom_kind_is_one_providerplugin_call(self):
        class Shouty:
            def __init__(self, values):
                self.values = values

            def lookup(self, name):
                return self.values.get(name.upper())

            def describe(self):
                return 'shouty'

        shouty = providerplugin('shouty', lambda spec: Shouty(spec.get('values') or {}))

        secrets = Sekreto({
            'plugins': [shouty],
            'providers': [{'kind': 'shouty', 'values': {'API.TOKEN': 'loud'}}],
        })

        self.assertEqual(secrets.get('api.token'), 'loud')
        self.assertEqual(secrets.host.list(), {'shouty': 'live'})

    # A plugin that names a built-in kind replaces it: that is how a host
    # substitutes an implementation, and never an accident, because the
    # four names are documented.
    def test_a_plugin_may_replace_a_built_in_kind(self):
        class Replaced:
            def lookup(self, name):
                return 'replaced'

            def describe(self):
                return 'memory'

        secrets = Sekreto({
            'plugins': [providerplugin('memory', lambda spec: Replaced())],
            'providers': [{'kind': 'memory', 'values': {'API_TOKEN': 'original'}}],
        })

        self.assertEqual(secrets.get('api.token'), 'replaced')

    def test_close_tears_the_chain_down_and_keeps_redaction(self):
        secrets = Sekreto({'providers': [{'kind': 'memory', 'values': {'API_TOKEN': 'tok01'}}]})
        self.assertEqual(secrets.get('api.token'), 'tok01')

        secrets.close()

        self.assertEqual(secrets.host.list(), {})
        self.assertEqual(secrets.stores(), [])
        self.assertIsNone(secrets.try_('api.token'))
        self.assertEqual(secrets.redact('token=tok01'), 'token=[redacted]')

    # What an import pulls in, checked in a fresh interpreter because this
    # one has imported everything (above) on purpose.
    def fresh(self, code):
        code = ("import sys; " + code + "; "
                "print(sorted(m for m in sys.modules if m.startswith('voxgig_sekreto')))")
        path = os.pathsep.join([os.path.join(HERE, '..'), os.path.join(pluginhome(), 'python')])
        return subprocess.run(
            [sys.executable, '-c', code], capture_output=True, text=True, check=True,
            env={**os.environ, 'PYTHONPATH': path},
        ).stdout.strip()

    # The core imports no plugin: importing voxgig_sekreto brings in the
    # chain, the built-ins and voxgig_plugin, and not one module under
    # plugins/.
    def test_the_core_imports_no_plugin(self):
        self.assertEqual(
            self.fresh("import voxgig_sekreto"),
            "['voxgig_sekreto', 'voxgig_sekreto.addr', 'voxgig_sekreto.providers', 'voxgig_sekreto.sekreto']")

    # ...and one plugin imports only itself. The package initializer used
    # to import all ten so it could re-export them, which made the
    # single-plugin import execute it first and load every network client
    # behind it - the whole set, for a consumer that named exactly one.
    def test_one_plugin_imports_only_itself(self):
        self.assertEqual(
            self.fresh("from voxgig_sekreto.plugins.hashicorp import hashicorp"),
            "['voxgig_sekreto', 'voxgig_sekreto.addr', 'voxgig_sekreto.plugins', "
            "'voxgig_sekreto.plugins.hashicorp', 'voxgig_sekreto.plugins.httpjson', "
            "'voxgig_sekreto.providers', 'voxgig_sekreto.sekreto']")

    # The full set is built on demand, and reaching it imports everything.
    def test_the_full_set_is_built_on_demand(self):
        before = self.fresh("import voxgig_sekreto.plugins")
        self.assertNotIn('plugins.hashicorp', before)
        after = self.fresh("from voxgig_sekreto.plugins import ALL")
        for name in ['hashicorp', 'boru', 'aws', 'gcpsecrets', 'azuresecrets',
                     'onepassword', 'doppler', 'infisical', 'secretspec', 'sigv4', 'httpjson']:
            self.assertIn("'voxgig_sekreto.plugins." + name + "'", after)

    # `from voxgig_sekreto.plugins import hashicorp` is the MODULE, and a
    # module is refused by name, saying what to import instead.
    def test_a_module_passed_as_a_plugin_is_refused(self):
        from voxgig_sekreto.plugins import hashicorp as module
        self.assertIsInstance(module, type(sys))
        with self.assertRaises(SekretoError) as caught:
            Sekreto({'plugins': [module], 'providers': []})
        self.assertEqual(
            str(caught.exception),
            'sekreto: not a plugin definition: the module voxgig_sekreto.plugins.hashicorp'
            ' - import the definition it holds: from voxgig_sekreto.plugins.hashicorp import hashicorp')


if __name__ == '__main__':
    unittest.main()

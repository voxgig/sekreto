# RUN: python3 -m unittest discover -s tests
# RUN-SOME: python3 -m unittest discover -s tests -k envkey
#
# The sekreto conformance suite. Every port runs these same groups, from
# the same spec/sekreto.json, through its own voxgig/omni runner.

import os
import sys
import unittest

from voxgig_sekreto import Sekreto, envkey, parsedotenv, redact, validname, vaultref


def specfile(name):
    """Find the shared spec directory by walking up from this file."""
    directory = os.path.dirname(os.path.abspath(__file__))
    for _i in range(8):
        cand = os.path.join(directory, 'spec', name)
        if os.path.exists(cand):
            return cand
        directory = os.path.dirname(directory)
    raise FileNotFoundError('sekreto: spec not found: ' + name)


def omnihome():
    """omni is a sibling checkout, not a published package (yet)."""
    here = os.path.dirname(os.path.abspath(__file__))
    cands = [
        os.environ.get('OMNI_HOME'),
        os.path.join(here, '..', '..', '..', 'omni'),
        os.path.join(here, '..', '..', '..', '..', 'omni'),
        '/workspace/omni',
        '/home/user/omni',
    ]

    for cand in cands:
        if cand and os.path.exists(os.path.join(cand, 'spec', 'fib.json')):
            return os.path.abspath(cand)

    raise FileNotFoundError('sekreto: voxgig/omni not found - set OMNI_HOME')


sys.path.insert(0, os.path.join(omnihome(), 'python'))

from voxgig_omni import makeRunner  # noqa: E402


def chainof(spec):
    """Build a Sekreto from the spec's declarative chain description."""
    return Sekreto({'providers': spec['chain'], 'cache': False})


R = makeRunner(specfile('sekreto.json'))('sekreto')

spec = R['spec']
runset = R['runset']
runsetflags = R['runsetflags']


class TestSekreto(unittest.TestCase):

    def test_validname(self):
        runsetflags(spec['validname'], {'null': False}, validname)

    def test_envkey(self):
        runset(spec['envkey'], lambda vin: envkey(vin['name'], vin.get('prefix')))

    def test_vaultref(self):
        runset(spec['vaultref'], vaultref)

    def test_parsedotenv(self):
        runset(spec['parsedotenv'], parsedotenv)

    def test_resolve(self):
        runset(spec['resolve'], lambda vin: chainof(vin).get(vin['name']))

    def test_trysecret(self):
        runset(spec['trysecret'], lambda vin: chainof(vin).try_(vin['name']))

    def test_sources(self):
        runset(spec['sources'], lambda vin: chainof(vin).sources())

    def test_redact(self):
        runset(spec['redact'], lambda vin: redact(vin['text'], vin['values']))


if __name__ == '__main__':
    unittest.main()

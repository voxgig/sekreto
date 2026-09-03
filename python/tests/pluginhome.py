# Where voxgig/plugin is, for a checkout that has not pip-installed it.
#
# voxgig_sekreto depends on voxgig_plugin - the python port of
# voxgig/plugin - and declares it in pyproject.toml, so `pip install`
# brings it. A developer working from checkouts has not run that, and
# neither has CI's conformance job, so the tests and the CLI look for a
# sibling checkout the same way every port looks for omni: $PLUGIN_HOME,
# then the usual places. An installed package wins; this is only the
# fallback.

import os
import sys


def pluginhome():
    here = os.path.dirname(os.path.abspath(__file__))
    cands = [
        os.environ.get('PLUGIN_HOME'),
        os.path.join(here, '..', '..', '..', 'plugin'),
        os.path.join(here, '..', '..', '..', '..', 'plugin'),
        os.path.join(here, '..', '..', '.plugin'),
        '/workspace/plugin',
        '/home/user/plugin',
    ]

    for cand in cands:
        if cand and os.path.exists(os.path.join(cand, 'python', 'voxgig_plugin', '__init__.py')):
            return os.path.abspath(cand)

    raise ImportError('sekreto: voxgig/plugin not found - pip install voxgig-plugin, or set PLUGIN_HOME')


def pluginpath():
    """Make voxgig_plugin importable: already installed, or from a checkout."""
    try:
        import voxgig_plugin  # noqa: F401
    except ImportError:
        sys.path.insert(0, os.path.join(pluginhome(), 'python'))

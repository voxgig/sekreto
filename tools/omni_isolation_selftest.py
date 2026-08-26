#!/usr/bin/env python3
"""Mutation test for tools/omni_isolation.py.

A guard that has never failed is not a guard.  This injects an omni
declaration into every port - once into the library manifest, once into a
shipped source file - and requires the checker to catch each one.  It also
injects into the block that is deliberately EXEMPT (npm `devDependencies`)
and requires the checker to stay quiet, because a check that fires on the
correct tree is as useless as one that never fires.

Not ceremony.  In the struct port of this tool three source globs described
a layout that repo does not have, and all three reported "clean" while
reading zero files; a whole port was missing from the tables while the output
said everything was fine; and the devDependencies exemption inserted a
duplicate JSON key, so the injected entry was discarded before the checker
saw it and the case passed without exercising anything.  Only mutation found
any of that.

Every mutation is applied to a working-tree copy and reverted in a `finally`,
so an interrupted run leaves the tree as it found it.

Exit status: 0 if every mutation produced the expected verdict, 1 otherwise.
"""

import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECK = [sys.executable, 'tools/omni_isolation.py']

_spec = importlib.util.spec_from_file_location(
    'omni_isolation', ROOT / 'tools' / 'omni_isolation.py')
ISO = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ISO)

# NOT a comment: whole-line comments are skipped by the scanner on purpose,
# so a `//`-prefixed marker would be silently ignored and every source
# mutation would pass while testing nothing. Spells omni every way any
# port's pattern looks for, including a standalone `Omni`.
LEAK = 'LEAK voxgig_omni VoxgigOmni Omni voxgig.omni voxgig/omni omni\n'

MANIFEST = [
    ('go', 'go/go.mod', 'go 1.21',
     'go 1.21\n\nrequire github.com/voxgig/omni/go v0.0.0-20260825220049-74ae081d405a'),
    ('rust', 'rust/Cargo.toml', '[lib]',
     '[dev-dependencies]\nvoxgig_omni = { path = "../vendor/omni/rust" }\n\n[lib]'),
    # A renamed crate: the key says `runner`, and code imports the alias too.
    ('rust', 'rust/Cargo.toml', '[lib]',
     '[dependencies]\nrunner = { package = "voxgig_omni", version = "0.1" }\n\n[lib]'),
    ('typescript', 'typescript/package.json', '"main": "dist/src/index.js",',
     '"dependencies": { "@voxgig/omni": "^0.1.1" },\n  "main": "dist/src/index.js",'),
    # An npm alias: same evasion, different spelling.
    ('javascript', 'javascript/package.json', '"main": "src/index.js",',
     '"dependencies": { "runner": "npm:@voxgig/omni@1.0.0" },\n  "main": "src/index.js",'),
    ('python', 'python/pyproject.toml', '[project]',
     '[project]\ndependencies = ["voxgig-omni>=0.1"]'),
    # Dependencies declared dynamic with no resolvable source must FAIL.
    ('python', 'python/pyproject.toml', '[project]',
     '[project]\ndynamic = ["dependencies"]'),
    ('csharp', 'csharp/src/Sekreto.csproj', '</Project>',
     '<ItemGroup><PackageReference Include="Voxgig.Omni" Version="0.1.0" /></ItemGroup></Project>'),

    # THE FIVE EVASIONS Codex found after the first version shipped. Each
    # declares omni in a way that read clean, and each is here so it cannot
    # read clean again.
    # A block-form `replace` redirecting an innocuous module. The old parser
    # recorded the literal `replace (` and ignored everything inside it.
    ('go', 'go/go.mod', 'go 1.21',
     'go 1.21\n\nrequire innocent/pkg v1.0.0\n\nreplace (\n\tinnocent/pkg => github.com/voxgig/omni/go v0.0.0\n)'),
    # Single-quoted XML, which is valid and which a double-quote-only pattern
    # read as no dependency at all.
    ('csharp', 'csharp/src/Sekreto.csproj', '</Project>',
     "<ItemGroup><PackageReference Include='Voxgig.Omni' Version='0.1.0' /></ItemGroup></Project>"),
    # Cargo workspace inheritance: the real crate is named in
    # [workspace.dependencies], and a package-level read never sees it.
    ('rust', 'rust/Cargo.toml', '[lib]',
     '[dependencies]\nrunner = { workspace = true }\n\n[workspace.dependencies]\nrunner = { package = "voxgig_omni", version = "0.1" }\n\n[lib]'),
]

# The module spelling that actually appears in code. `\bomni\b` could not
# match `voxgig_omni` - `_` is a word character, so there is no boundary - and
# that is exactly what Python and Rust import. The old LEAK marker happened to
# carry a standalone `omni`, so every source mutation passed while this
# spelling went unchecked.
SOURCE_SPELLINGS = 'import voxgig_omni\nuse voxgig_omni::Runner;\n'

EXEMPT = [
    ('typescript', 'typescript/package.json', '"devDependencies": {',
     '"devDependencies": {\n    "@voxgig/omni": "^0.1.1",',
     'npm devDependencies are never installed transitively'),
]


def check():
    return subprocess.run(CHECK, cwd=ROOT, capture_output=True, text=True)


def mutate(relpath, anchor, replacement, needle, expect, tag):
    path = ROOT / relpath
    original = path.read_text(encoding='utf-8', errors='surrogateescape')
    if anchor and anchor not in original:
        return ('FAIL', tag, f'anchor vanished from {relpath} - mutation tests nothing')
    try:
        body = (original.replace(anchor, replacement, 1) if anchor
                else replacement + original)
        path.write_text(body, encoding='utf-8', errors='surrogateescape')
        result = check()
        hit = 0 != result.returncode and needle in (result.stderr or '')
    finally:
        path.write_text(original, encoding='utf-8', errors='surrogateescape')
    return ('PASS' if hit == expect else 'FAIL', tag,
            'caught' if hit else 'clean')


def first_source(port):
    spec = ISO.SOURCES[port]
    for glob in spec['globs']:
        for path in sorted(ROOT.glob(glob)):
            rel = path.relative_to(ROOT).as_posix()
            if not any(rel.startswith(s) for s in spec['skip']):
                return rel
    return None


def main():
    results = []

    for n, (port, rel, anchor, repl) in enumerate(MANIFEST):
        results.append(mutate(rel, anchor, repl, f'{port}: ', True,
                              f'{port}:manifest[{n}]'))

    for port, rel, anchor, repl, why in EXEMPT:
        results.append(mutate(rel, anchor, repl, f'{port}: ', False,
                              f'{port}:exempt ({why})'))

    for port in sorted(ISO.SOURCES):
        rel = first_source(port)
        if rel is None:
            results.append(('FAIL', f'{port}:source',
                            'no shipped source file matched - the glob is dead'))
            continue
        results.append(mutate(rel, '', LEAK,
                              f'{port}: shipped source names omni', True,
                              f'{port}:source'))
        # And again with ONLY the ecosystem module spelling, no standalone
        # `omni` anywhere in the marker.
        results.append(mutate(rel, '', SOURCE_SPELLINGS,
                              f'{port}: shipped source names omni', True,
                              f'{port}:source-spelling'))

    for status, tag, note in results:
        print(f'{status}  {tag:56} {note}')

    bad = [r for r in results if 'PASS' != r[0]]
    print(f'\n{len(results) - len(bad)}/{len(results)} mutations produced the '
          'expected verdict')
    if bad:
        print('\nthe 4.13 guard did not catch what it must:', file=sys.stderr)
        for status, tag, note in bad:
            print(f'  {tag}: {note}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

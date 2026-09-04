#!/usr/bin/env python3
"""Omni register 4.13: no port's LIBRARY may declare voxgig/omni.

omni is the conformance runner. It is a TEST dependency of every port here
and a published dependency of none, so nothing a consumer of sekreto
resolves may name it.

WHY THIS IS NOT A BUILD-WITHOUT-OMNI CHECK.  4.13's rule is about
DECLARATION - does the library manifest name omni.  The proof omni's register
originally prescribed is about RESOLUTION - "CI must prove it with the
checkout absent".  Those are the same test only while omni is unfindable by
any other route, and Go left that state without anyone deciding to:
`github.com/voxgig/omni/go` resolves from proxy.golang.org today, because
omni is a public repo.  `go mod tidy` in a module with no omni checkout
anywhere resolves a pseudo-version and writes the require line.

That hole is Go's specifically - rust names omni by a literal PATH, which has
no fallback - but a declaration check earns its place in every port for a
separate reason: it catches an omni reference at the commit that introduces
it, rather than at the `go mod tidy` that publishes it.

Ported from voxgig/struct's tools/omni_isolation.py, where the same rule is
enforced across 23 ports.  Kept deliberately similar so the two can be read
against each other.

Exit status: 0 if every library manifest is clean, 1 otherwise.  Every
failure is reported, not just the first.
"""

import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Every way omni is spelled across ecosystems, including concatenated
# CamelCase (VoxgigOmni).  The separator is optional: requiring it missed
# SwiftPM's spelling entirely in the struct port of this tool.
OMNI = re.compile(r'(^|[^a-z0-9])(@?voxgig[/_.-]?omni|omni)([^a-z0-9]|$)', re.I)


def names_omni(text):
    return bool(OMNI.search(text or ''))


# THE SPELLING THAT ACTUALLY APPEARS IN CODE.
#
# Every port's source pattern used to be hand-written, and most were
# `\bomni\b` - which cannot match `voxgig_omni`, because `_` is a word
# character so there is no boundary before `omni`. That is the exact module
# name Python and Rust import. The guard would have read
# `import voxgig_omni` in a shipped file and called it clean.
#
# The mutation suite did not catch it either, because the injected marker
# happened to contain a standalone `omni` - mutation testing proves what you
# thought to mutate, and this was not thought of.
#
# One matcher now, shared with the manifest side, so the two cannot drift.
SOURCE = OMNI




def read_go_mod(path):
    """go.mod: every module path in a require, replace or exclude.

    ALL THREE HAVE A BLOCK FORM. Handling `require (` alone recorded the
    literal `replace (` and ignored every entry inside it, so an innocuously
    named module redirected to omni - `innocent/pkg => github.com/voxgig/omni/go`
    - read clean.
    """
    deps, block = [], None
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.split('//')[0].strip()
        if not line:
            continue
        if block is not None:
            if line == ')':
                block = None
            else:
                # A replace line is `old => new`; both sides matter.
                deps.append(line)
            continue
        for kw in ('require', 'replace', 'exclude'):
            if line == f'{kw} (' or line.startswith(f'{kw} ('):
                block = kw
                break
        else:
            for kw in ('require ', 'replace ', 'exclude '):
                if line.startswith(kw):
                    deps.append(line[len(kw):])
                    break
    return deps


def read_cargo(path):
    """Cargo.toml: dependencies AND dev-dependencies, keys, `package`, and
    anything inherited from `[workspace.dependencies]`.

    dev-dependencies are not exempt the way npm devDependencies are: Cargo
    resolves them even for a plain `cargo build`, which is why the conformance
    harness is a separate package.

    Three spellings hide the real crate. `runner = { package = "voxgig_omni" }`
    renames it, so the key says `runner` and code imports `runner`.
    `runner = { workspace = true }` moves the real declaration into
    `[workspace.dependencies]`, which a package-level read never sees. And a
    `[target.*]` block repeats both.
    """
    data = tomllib.loads(path.read_text(encoding='utf-8'))
    wsdeps = ((data.get('workspace') or {}).get('dependencies') or {})

    def entries(block):
        for name, spec in (block or {}).items():
            yield name
            if not isinstance(spec, dict):
                continue
            if spec.get('package'):
                yield spec['package']
            if spec.get('workspace'):
                inherited = wsdeps.get(name)
                if isinstance(inherited, dict):
                    yield inherited.get('package') or name
                    if inherited.get('git'):
                        yield str(inherited['git'])
                    if inherited.get('path'):
                        yield str(inherited['path'])
                elif isinstance(inherited, str):
                    yield inherited
            for key in ('path', 'git'):
                if spec.get(key):
                    yield str(spec[key])

    deps = []
    for block in ('dependencies', 'dev-dependencies', 'build-dependencies'):
        deps.extend(entries(data.get(block)))
    deps.extend(entries(wsdeps))
    for tgt in (data.get('target') or {}).values():
        for block in ('dependencies', 'dev-dependencies', 'build-dependencies'):
            deps.extend(entries(tgt.get(block)))
    return deps


def read_package_json(path):
    """package.json: every block EXCEPT devDependencies, keys AND values.

    devDependencies is the isolation device for the Node ports - npm never
    installs one transitively.  Values matter because
    `"runner": "npm:@voxgig/omni@1.0.0"` is an alias whose key says nothing.
    """
    data = json.loads(path.read_text(encoding='utf-8'))
    deps = []
    for block in ('dependencies', 'peerDependencies', 'optionalDependencies'):
        for name, spec in (data.get(block) or {}).items():
            deps.append(name)
            if isinstance(spec, str):
                deps.append(spec)
    return deps


def read_pyproject(path):
    """pyproject.toml, including dynamic dependency declarations."""
    data = tomllib.loads(path.read_text(encoding='utf-8'))
    proj = data.get('project') or {}
    deps = list(proj.get('dependencies') or [])
    for group in (proj.get('optional-dependencies') or {}).values():
        deps.extend(group)
    deps.extend((data.get('build-system') or {}).get('requires') or [])
    if set(proj.get('dynamic') or []) & {'dependencies', 'optional-dependencies'}:
        cfg = ((data.get('tool') or {}).get('setuptools') or {}).get('dynamic') or {}
        targets = []
        for key in ('dependencies', 'optional-dependencies'):
            spec = cfg.get(key)
            if not isinstance(spec, dict):
                continue
            if 'file' in spec:
                targets.extend(_aslist(spec['file']))
            else:
                for group in spec.values():
                    if isinstance(group, dict):
                        targets.extend(_aslist(group.get('file')))
        if not targets:
            deps.append(DYNAMIC_UNRESOLVED)
        for rel in targets:
            ref = path.parent / rel
            deps.extend(ref.read_text(encoding='utf-8').splitlines()
                        if ref.exists() else [DYNAMIC_UNRESOLVED])
    return deps


def read_csproj(path):
    """A .csproj: the Include/Update of every Package/ProjectReference.

    BOTH XML QUOTE STYLES. A double-quote-only pattern returned nothing at all
    for `Include='Voxgig.Omni'`, which is valid XML, and a package reference
    resolves whether or not any source file imports its namespace - so the
    source scan does not close that hole.

    Text-scoped rather than parsed: semgrep blocks `xml.etree` repo-wide as an
    XXE risk, and `defusedxml` would be a new dependency for a threat that
    does not exist on committed repo content.
    """
    text = path.read_text(encoding='utf-8')
    return [m.group(1) or m.group(2) for m in re.finditer(
        r'<(?:Package|Project)Reference\b[^>]*?\b(?:Include|Update)\s*='
        r'\s*(?:"([^"]*)"|\'([^\']*)\')',
        text, re.I)]


def read_deps_edn(path):
    """deps.edn: the CONSUMER-RESOLVED region - everything before `:aliases`.

    tools.deps ignores a dependency's aliases entirely: a consumer taking
    this port resolves its `:paths` and its `:deps`, and nothing else.  An
    alias is therefore clojure's devDependencies - the place a conformance
    runner may legitimately be named - and this reads up to the first one.
    Both `:paths` and `:deps` are in scope, not `:deps` alone: an external
    path lands on a consumer's classpath the same way a coordinate does.

    COMMENTS ARE STRIPPED FIRST, and that is not a nicety.  A comment can
    open the scope by accident: in the struct port of this tool the clojure
    scan started at `:deps\b`, an explanatory comment ABOVE the map
    contained `:deps/root "clojure"`, and the read began inside prose -
    reading the word omni out of an explanation of why omni is NOT declared
    there.  Measured, not hypothetical.  It strips by line, so a `;` inside
    a string would be cut too; no deps.edn here has one, and a parse is the
    real answer if one ever does.

    A textual scan, and saying so plainly matters: it is weaker than a parse
    and it is what is available without an EDN reader, which python has no
    more of in its standard library than these ports are allowed as a
    dependency.
    """
    text = re.sub(r';.*$', '', path.read_text(encoding='utf-8'), flags=re.M)
    head = re.split(r':aliases\b', text, maxsplit=1)[0]
    return [line for line in head.splitlines() if line.strip()]


def read_pubspec(path):
    """pubspec.yaml: the CONSUMER-RESOLVED sections.

    `dependencies:` and `dependency_overrides:` are what a consumer taking
    this package resolves.  `dev_dependencies:` is not - pub resolves those
    only for the package's own development, exactly as npm does with
    devDependencies, which this tool already exempts for the two Node
    ports.  A conformance runner may legitimately be named there.

    COMMENTS ARE STRIPPED FIRST, and this port is the proof rather than the
    theory: dart/pubspec.yaml opens by saying "nothing here names
    voxgig/omni", so a reader that kept comments would read the word omni
    out of the very sentence promising it is absent, and report the port
    for the presence of its own documentation.  That is the same failure
    read_deps_edn records from struct's port of this tool, met a second
    time in a different language.

    A textual scan, said plainly: it is weaker than a YAML parse, and
    python's standard library has no YAML reader - which these tools are no
    more entitled to take as a dependency than a port is.
    """
    text = re.sub(r'#.*$', '', path.read_text(encoding='utf-8'), flags=re.M)
    want, out = False, []
    for line in text.splitlines():
        if not line.strip():
            continue
        if re.match(r'^\S', line):
            # Any top-level key closes the previous section.
            want = bool(re.match(r'^(dependencies|dependency_overrides)\s*:', line))
            if want:
                out.append(line)
            continue
        if want:
            out.append(line)
    return out


DYNAMIC_UNRESOLVED = ('<dynamic dependencies with no resolvable source: '
                      'omni cannot be ruled out here>')


def _aslist(value):
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


# `lib` is what a consumer resolves; `harness` is listed only so the output
# can say it was deliberately skipped rather than missed.
PORTS = {
    'go':         dict(lib=[('go/go.mod', read_go_mod)],
                       harness=['go/testutil/go.mod']),
    'rust':       dict(lib=[('rust/Cargo.toml', read_cargo)],
                       harness=['rust/corpus/Cargo.toml']),
    'csharp':     dict(lib=[('csharp/src/Sekreto.csproj', read_csproj),
                            ('csharp/cli/SekretoCli.csproj', read_csproj)],
                       harness=['csharp/test/SekretoTest.csproj']),
    'clojure':    dict(lib=[('clojure/deps.edn', read_deps_edn)]),
    'dart':       dict(lib=[('dart/pubspec.yaml', read_pubspec)]),
    'typescript': dict(lib=[('typescript/package.json', read_package_json)]),
    'javascript': dict(lib=[('javascript/package.json', read_package_json)]),
    'python':     dict(lib=[('python/pyproject.toml', read_pyproject)]),

    # No manifest a consumer resolves - reported, never silently passed.
    'java':       dict(lib=[], why='no manifest a consumer resolves'),
    # zig: the library is two modules named on the compiler's command line
    # (see zig/Makefile); there is no build.zig.zon, so nothing a consumer
    # resolves. The source scan below is this port's only check.
    'zig':        dict(lib=[], why='no manifest a consumer resolves'),
    # kotlin: kotlinc is handed a file list, exactly as javac is for the
    # java port, so the same applies.
    'kotlin':     dict(lib=[], why='no manifest a consumer resolves'),
    # swift: the Makefile drives swiftc over a file list and there is no
    # Package.swift, so SwiftPM has nothing to resolve. Introducing one
    # would make this entry wrong, and the manifest guard below would say
    # so rather than let it pass.
    'swift':      dict(lib=[], why='no manifest a consumer resolves'),
    # elixir: the escript is assembled by tool/escript.exs from OTP's own
    # :escript.create/2 rather than `mix escript.build`, precisely so there
    # is no mix.exs -- a project manifest whose only content would be the
    # absence of dependencies. Nothing for a consumer to resolve.
    'elixir':     dict(lib=[], why='no manifest a consumer resolves'),
    # cpp: the Makefile drives g++ over a file list. There is no CMakeLists,
    # no vcpkg.json, no conanfile -- nothing a consumer resolves.
    'cpp':        dict(lib=[], why='no manifest a consumer resolves'),
    # c: a Makefile and a compiler, and nothing else. No manifest exists
    # for C at all, so there is nothing here a consumer could resolve.
    'c':          dict(lib=[], why='no manifest a consumer resolves'),
    # lua: no rockspec. luarocks is not in play at all -- the port's only
    # native piece is an in-tree C module the Makefile compiles -- so
    # there is nothing for a consumer to resolve.
    'lua':        dict(lib=[], why='no manifest a consumer resolves'),
    # ocaml: no dune-project and no .opam file -- the Makefile drives
    # ocamlopt directly, C stubs included. Nothing a consumer resolves.
    'ocaml':      dict(lib=[], why='no manifest a consumer resolves'),
    # lean: no lakefile.toml and no lakefile.lean -- only a lean-toolchain,
    # which pins a compiler version and declares no dependency. Lake never
    # resolves anything here, so there is nothing for a consumer to take.
    # Note that lakefile.toml IS on the manifest list below, so if one is
    # ever added this entry stops being true and the guard will say so.
    'lean':       dict(lib=[], why='no manifest a consumer resolves'),
    # haskell: no .cabal and no cabal.project. ghc is driven straight from
    # the Makefile, and the OpenSSL binding is `foreign import ccall`
    # rather than a package, so Hackage is never consulted and there is
    # nothing for a consumer to resolve.
    'haskell':    dict(lib=[], why='no manifest a consumer resolves'),
    # scala: scalac is handed a file list too - the Makefile drives it
    # directly and there is no build.sbt, so the same applies again.
    'scala':      dict(lib=[], why='no manifest a consumer resolves'),
    'perl':       dict(lib=[], why='no manifest a consumer resolves'),
    'php':        dict(lib=[], why='no manifest a consumer resolves'),
    'ruby':       dict(lib=[], why='no manifest a consumer resolves'),
}

# The shipped source of each port, harness trees excluded.  A manifest check
# alone is not enough for a compiled port with a module system, because the
# manifest is DERIVED from the imports: struct/go's founding 4.13 bug was an
# import in a normal package, and the require line only appeared later, at
# someone's `go mod tidy`.
SOURCES = {
    'go':         dict(globs=['go/**/*.go'], skip=['go/testutil/'],
                       pattern=SOURCE),
    'rust':       dict(globs=['rust/src/**/*.rs'], skip=[], pattern=SOURCE),
    'csharp':     dict(globs=['csharp/src/**/*.cs', 'csharp/cli/**/*.cs'],
                       skip=[], pattern=SOURCE),
    'java':       dict(globs=['java/src/**/*.java'], skip=[], pattern=SOURCE),
    'perl':       dict(globs=['perl/lib/**/*.pm'], skip=[], pattern=SOURCE),
    'php':        dict(globs=['php/src/**/*.php'], skip=[], pattern=SOURCE),
    'python':     dict(globs=['python/**/*.py'],
                       skip=['python/test', 'python/tests'], pattern=SOURCE),
    'ruby':       dict(globs=['ruby/lib/**/*.rb'], skip=[], pattern=SOURCE),
    # The harness trees - zig/test, kotlin/test - are where omni legitimately
    # appears, and they are excluded here exactly as go/testutil and
    # rust/corpus are by living outside the globs.
    'zig':        dict(globs=['zig/src/**/*.zig', 'zig/cli/**/*.zig'],
                       skip=[], pattern=SOURCE),
    'kotlin':     dict(globs=['kotlin/src/**/*.kt', 'kotlin/cli/**/*.kt'],
                       skip=[], pattern=SOURCE),
    'scala':      dict(globs=['scala/src/**/*.scala', 'scala/cli/**/*.scala'],
                       skip=[], pattern=SOURCE),
    # clojure/test is where omni legitimately appears, and it is excluded by
    # living outside the globs - as go/testutil and rust/corpus are. Note
    # that a `;;` comment is NOT skipped by the comment rule below, which
    # only knows the markers of the languages that were here first: a
    # clojure source file must not name omni even in prose.
    'clojure':    dict(globs=['clojure/src/**/*.clj', 'clojure/cli/**/*.clj'],
                       skip=[], pattern=SOURCE),
    'dart':       dict(globs=['dart/src/**/*.dart', 'dart/cli/**/*.dart'],
                       skip=[], pattern=SOURCE),
    'swift':      dict(globs=['swift/src/**/*.swift', 'swift/cli/**/*.swift'],
                       skip=[], pattern=SOURCE),
    # elixir/tool is build machinery, not shipped source, and sits outside
    # the globs exactly as go/testutil and rust/corpus do.
    'elixir':     dict(globs=['elixir/src/**/*.ex', 'elixir/cli/**/*.ex'],
                       skip=[], pattern=SOURCE),
    # Headers are shipped source too: a cpp port carries much of itself in
    # .hpp, and scanning only .cpp would leave most of it unread.
    'cpp':        dict(globs=['cpp/src/**/*.cpp', 'cpp/src/**/*.hpp',
                              'cpp/cli/**/*.cpp', 'cpp/cli/**/*.hpp'],
                       skip=[], pattern=SOURCE),
    # Headers again, for the same reason as cpp: .h is shipped source.
    'c':          dict(globs=['c/src/**/*.c', 'c/src/**/*.h',
                              'c/cli/**/*.c', 'c/cli/**/*.h'],
                       skip=[], pattern=SOURCE),
    # lua/native is shipped source too: the OpenSSL binding is a C module
    # the library requires at runtime, so it is as much a part of what a
    # consumer gets as the .lua files are.
    'lua':        dict(globs=['lua/src/**/*.lua', 'lua/cli/**/*.lua',
                              'lua/native/**/*.c', 'lua/native/**/*.h'],
                       skip=[], pattern=SOURCE),
    # The .c stubs are the OpenSSL binding and ship with the library, so
    # they are scanned alongside the .ml -- same reasoning as lua/native.
    # Note for anyone editing this port: the COMMENT rule below does not
    # know OCaml's `(*`, any more than it knows Clojure's `;`, so an .ml
    # file must not name omni even in prose. It caught exactly that here --
    # a comment explaining which reader consumes `Printexc.to_string` --
    # and the comment was reworded rather than the guard widened. Widening
    # a guard so a port passes is the move this whole tool exists to stop.
    'ocaml':      dict(globs=['ocaml/src/**/*.ml', 'ocaml/src/**/*.mli',
                              'ocaml/src/**/*.c', 'ocaml/src/**/*.h',
                              'ocaml/cli/**/*.ml'],
                       skip=[], pattern=SOURCE),
    # lean/ffi is the libcurl binding and ships with the library, so it is
    # scanned like lua/native and ocaml's stubs. A further note for editors
    # of this port: the COMMENT rule knows Lean's `--` but NOT its block
    # form `/-`, so a `/-` comment naming omni would be reported.
    'lean':       dict(globs=['lean/src/**/*.lean', 'lean/cli/**/*.lean',
                              'lean/ffi/**/*.c', 'lean/ffi/**/*.h'],
                       skip=[], pattern=SOURCE),
    # .hsc and .c are included in case the FFI grows either; today the
    # binding is plain `foreign import ccall` in .hs, needing no stub file.
    'haskell':    dict(globs=['haskell/src/**/*.hs', 'haskell/src/**/*.hsc',
                              'haskell/src/**/*.c', 'haskell/src/**/*.h',
                              'haskell/cli/**/*.hs'],
                       skip=[], pattern=SOURCE),
    # No skip in either Node port: omni comes from npm as a devDependency,
    # so the checkout resolver that used to live in typescript/src is gone
    # and nothing under src/ has any business naming omni.
    'typescript': dict(globs=['typescript/src/**/*.ts'], skip=[], pattern=SOURCE),
    'javascript': dict(globs=['javascript/src/**/*.js'], skip=[], pattern=SOURCE),
}


# A WHOLE-LINE comment is skipped; a trailing one is not. These repos discuss
# omni in prose constantly, and a bare mention is not a reference - scanning
# comments is how a guard trains people to ignore it. Deliberately narrow:
# only a line whose FIRST non-space characters are a comment marker.
COMMENT = re.compile(r'^\s*(//|#|--|\*|/\*|"""|\'\'\')')

# `#` OPENS A COMMENT IN SOME LANGUAGES AND A PREPROCESSOR DIRECTIVE IN OTHERS.
# Treating every `#` line as prose made `#include "voxgig/omni.h"` invisible -
# in c and cpp, which have NO manifest, so the source scan is the only check
# they get. A regression introduced by the comment skip itself.
#
# Listed rather than keyed on file type, and erring towards CODE: a prose line
# that happens to start `# if you want to...` is scanned, which is the safe
# direction. Missing a directive is not.
DIRECTIVE = re.compile(
    r'^\s*#\s*(include|import|define|pragma|if|ifdef|ifndef|elif|else|endif|'
    r'undef|error|warning|line)\b', re.I)


def is_comment(line):
    if DIRECTIVE.match(line):
        return False
    return bool(COMMENT.match(line))


def scan_sources(port):
    spec = SOURCES.get(port)
    if not spec:
        return [], 0
    rx = spec['pattern']
    hits, seen = [], 0
    for glob in spec['globs']:
        for path in ROOT.glob(glob):
            rel = path.relative_to(ROOT).as_posix()
            if any(rel.startswith(s) for s in spec['skip']):
                continue
            seen += 1
            try:
                text = path.read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue
            for n, line in enumerate(text.splitlines(), 1):
                if is_comment(line):
                    continue
                if rx.search(line):
                    hits.append(f'{rel}:{n}: {line.strip()[:70]}')
    return hits, seen


def discover_ports():
    """Every port directory, found rather than listed.

    A port here carries its own Makefile.  Discovering them is the point: a
    port absent from both tables is a port nothing checks, and in the struct
    port of this tool exactly that happened - a whole language was missed
    while the output said everything was clean.
    """
    skip = {'tools', 'spec', 'test', 'doc', 'api'}
    found = set()
    for entry in ROOT.iterdir():
        if not entry.is_dir() or entry.name.startswith('.') or entry.name in skip:
            continue
        if any((entry / n).exists() for n in ('Makefile', 'makefile')):
            found.add(entry.name)
    return found


def main():
    fails, uncovered, checked = [], [], []

    # BOTH tables, not their union. A port listed in only one is still
    # "known", so neither check fires while half its scanning is silently
    # skipped - and the error for a wholly new port said only to add "an
    # entry", which invites exactly that. A port with no manifest declares
    # `lib=[]` explicitly; there is no opting out of SOURCES.
    ports = discover_ports()
    for port in sorted(ports - set(PORTS)):
        fails.append(f'{port}: is a port directory with no PORTS entry - its '
                     'manifests are unchecked; add one (lib=[] with a `why` if '
                     'it has no manifest a consumer resolves)')
    for port in sorted(ports - set(SOURCES)):
        fails.append(f'{port}: is a port directory with no SOURCES entry - its '
                     'shipped source is unscanned; add one')
    for port in sorted((set(PORTS) | set(SOURCES)) - ports):
        fails.append(f'{port}: has an entry here but is not a port directory - '
                     'stale, and its checks read nothing')

    # An UNCOVERED port must still BE uncovered. `lib=[]` prints a reason
    # forever, so a port that later gains a real manifest - a pom.xml, a
    # gemspec - would keep printing it while an omni declaration in that new
    # manifest sailed through. Discovery already counts the port as known, so
    # nothing else would notice.
    MANIFEST_NAMES = ('go.mod', 'Cargo.toml', 'pom.xml', 'build.gradle',
                      'build.gradle.kts', 'deps.edn', 'pubspec.yaml', 'mix.exs',
                      'composer.json', 'pyproject.toml', 'setup.py',
                      'Package.swift', 'lakefile.toml', 'Makefile.PL',
                      'package.json')
    for port in sorted(PORTS):
        if PORTS[port]['lib']:
            continue
        found = [n for n in MANIFEST_NAMES if (ROOT / port / n).exists()]
        found += [q.name for q in (ROOT / port).glob('*.csproj')]
        found += [q.name for q in (ROOT / port).glob('*.gemspec')]
        if found:
            fails.append(f'{port}: is declared UNCOVERED ("{PORTS[port].get("why")}") '
                         f'but now has {", ".join(sorted(set(found)))} - give it a '
                         'real PORTS entry')

    for port in sorted(PORTS):
        spec = PORTS[port]
        if not spec['lib']:
            uncovered.append((port, spec.get('why', 'no manifest')))
            continue
        for relpath, reader in spec['lib']:
            path = ROOT / relpath
            if not path.exists():
                fails.append(f'{port}: {relpath} is missing - has the port moved?')
                continue
            try:
                found = reader(path)
            except Exception as err:                     # noqa: BLE001
                fails.append(f'{port}: could not read {relpath}: {err!r}')
                continue
            checked.append(relpath)
            for dep in found:
                if names_omni(dep):
                    fails.append(f'{port}: {relpath} declares omni: '
                                 + ' '.join(str(dep).split())[:80])

    # A glob matching NOTHING is a failure, not a pass.
    scanned = 0
    for port in sorted(SOURCES):
        hits, seen = scan_sources(port)
        scanned += seen
        if 0 == seen:
            fails.append(f'{port}: source globs matched NO files '
                         f'({SOURCES[port]["globs"]}) - the scan is checking '
                         'nothing; fix the glob')
        for hit in hits:
            fails.append(f'{port}: shipped source names omni: {hit}')

    # A SKIP MUST BE JUSTIFIED BY SOMETHING THIS FILE CHECKS, and derived
    # rather than hard-coded, so it stays true per repo.
    #
    # A port keeps its OMNI_HOME resolver out of the package with a `files`
    # negation, and SOURCES skips that path on that basis. Drop the negation
    # and the resolver ships again while the scan still looks away - the skip
    # would assert a fact nothing verified. python had exactly this shape and
    # no exclusion at all, which is how omnihome.py reached PyPI.
    #
    # A skip matching NO file is reported too: it is the same
    # silence-looks-like-success failure as a dead glob, and a skip copied
    # between repos is how one arrives.
    for port in sorted(SOURCES):
        for prefix in SOURCES[port]['skip']:
            matched = sorted(ROOT.glob(prefix + '*'))
            if not matched:
                fails.append(f'{port}: SOURCES skips {prefix!r} and nothing '
                             'matches it - a dead skip; remove it')
                continue
            manifest = ROOT / port / 'package.json'
            if not manifest.exists():
                continue
            files = json.loads(manifest.read_text(encoding='utf-8')).get('files')
            if not files:
                continue
            rel = prefix.split('/', 1)[1] if '/' in prefix else prefix
            if not any(f.startswith('!') and f.lstrip('!').startswith(rel.split('/')[0] + '/')
                       and rel.rsplit('/', 1)[-1] in f
                       for f in files):
                fails.append(f'{port}: package.json `files` no longer excludes '
                             f'{rel!r}, but SOURCES still skips it - the file '
                             'would ship unscanned')

    print(f'omni register 4.13 - library manifests checked: {len(checked)}, '
          f'shipped source files scanned: {scanned}')
    for port, why in uncovered:
        print(f'  UNCOVERED  {port}: {why}')

    if fails:
        print('\nsekreto: omni is named by something a consumer resolves\n',
              file=sys.stderr)
        for f in fails:
            print(f'  {f}', file=sys.stderr)
        return 1

    print('  all clean')
    return 0


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""The core/plugin split, read out of the BUILT ARTIFACT.

A grep of the sources proves what a reader can see. This reads what the
linker actually put in the binary, by exact symbol name, because the
audits of three other ports found cores that could open a socket and
spawn a child without naming one word on a source-level check's list.

Three claims, each with a control that fails if this script read nothing:

  A  build/sekreto-core contains no plugin MODULE.  GHC names a home
     module's symbols `<ZencodedModule>_<name>_<closure|info>`, so the
     first underscore-separated field is that module, exactly.  The
     comparison is set intersection over exact names - never a substring
     - and the same extraction over build/sekreto-cli must find every
     plugin module, which is what proves the extraction works at all.

  B  build/sekreto-core references no socket, no TLS and no exec.  A
     process cannot open a connection without `socket` and `connect`,
     cannot resolve a name without `getaddrinfo`, cannot speak TLS
     without the OpenSSL entry points, and cannot run a child program
     without one of the `exec` family.  The family is named in full -
     the `l` variants spawn a child exactly as the `v` variants do, and
     a list that stops at `execv` is a list a core can walk past.  None
     of these appears in a bare GHC binary's symbol table, and the ones
     a child process needs appear in build/sekreto-cli, which is the
     control below.  (`fork`, `syscall`, `dlopen` and `dlsym` are NOT on
     the list: the GHC runtime references all four on its own, so
     banning them would be a check that fires on the compiler rather
     than on this library.)

  C  build/sekreto-core loads no libssl and no libcrypto.  build/sekreto-cli
     loads both.

  D  build/sekreto-one imports ONE plugin and links one.  The plugin
     modules in it are EXACTLY Hashicorp and the machinery it needs, so
     the other nine kinds are absent and so are the AWS signer and its
     hash functions.  A consumer that configures one vault and still
     links seven vault clients has not been made lean, and nothing in
     the conformance run can see that.

Run it with `make check-core`, which builds all three artifacts first.
Pass `core`, `one` or `platform` to check one claim; the controls run
whichever is asked for.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = os.path.dirname(HERE)

CORE = os.path.join(PORT, 'build', 'sekreto-core')
CLI = os.path.join(PORT, 'build', 'sekreto-cli')
ONE = os.path.join(PORT, 'build', 'sekreto-one')

# The one plugin build/sekreto-one imports, and every plugin module a
# build of it may then carry: the kind, the HTTP-JSON round trip under it,
# and the transport under that. Crypto, Sigv4 and Subproc are NOT on the
# list, which is the half of the claim that would go unnoticed if this
# were an intersection rather than an equality.
ONEKIND = 'hashicorp'
ONEMODULES = ['Hashicorp', 'Http', 'Httpjson', 'Json', 'Tls']

# Every Haskell module the core is ALLOWED to carry, by exact name.
# COREMODULES is this port's own - the five that hold the four built-in
# kinds; PLUGINLIBMODULES is voxgig/plugin's, which the core is built on;
# GHCMODULES is the entry point GHC generates for any program.
#
# Claim A is an EQUALITY against the three together, and not only an
# intersection against plugins/. An intersection answers just "is a
# plugin in here"; a module the core grew somewhere else - a hand-rolled
# SHA-256 in src/ under a name no plugin uses - is named after no plugin,
# and only an equality sees it. That is the lesson claim D already
# learned, where an intersection passed while a one-plugin build linked
# the AWS signer.
COREMODULES = ['Bytes', 'Names', 'Provider', 'Providers', 'Sekreto']
PLUGINLIBMODULES = ['Capability', 'Catalog', 'Config', 'Defs', 'Depend',
                    'Export', 'Host', 'Order', 'Point', 'Ref', 'Types',
                    'Value', 'Version']
GHCMODULES = ['Main', 'ZCMain']

# The ten plugin kinds, and the module each lives in. `aws` carries two
# kinds, and Httpjson, Subproc, Http, Tls, Json, Crypto and Sigv4 are the
# machinery underneath them.
KINDMODULE = {
    'hashicorp': 'Hashicorp',
    'boru': 'Boru',
    'awssecrets': 'Aws',
    'awsparams': 'Aws',
    'gcpsecrets': 'Gcpsecrets',
    'azuresecrets': 'Azuresecrets',
    'onepassword': 'Onepassword',
    'doppler': 'Doppler',
    'infisical': 'Infisical',
    'secretspec': 'Secretspec',
}

# Exact C symbol names. A binary holding none of these can neither reach
# the network nor start a program, whatever its Haskell says.
BANNED = [
    'socket', 'connect', 'bind', 'listen', 'accept', 'accept4',
    'getaddrinfo', 'gethostbyname', 'send', 'sendto', 'recv', 'recvfrom',
    'execv', 'execve', 'execvp', 'execvpe', 'fexecve',
    'execl', 'execlp', 'execle',
    'posix_spawn', 'posix_spawnp', 'system', 'popen', 'pclose',
]

# The OpenSSL families, by prefix, because a binding names dozens of them
# and a list of dozens goes stale. Paired with the exact list above and
# with the positive control on the CLI, so neither half stands alone.
TLSFAMILIES = ('SSL_', 'TLS_', 'X509_', 'EVP_', 'BIO_', 'OPENSSL_', 'HMAC')

# What the CLI must show, so a green run cannot mean "nm printed nothing".
MUSTBEINCLI = ['socket', 'connect', 'getaddrinfo', 'execvp',
               'SSL_connect', 'SSL_read', 'SSL_write']

failures = []


def fail(claim, detail):
    failures.append((claim, claim + ': ' + detail))


def clean(claim):
    """Did this claim survive? A summary line is only printed for one that
    did, so a green line can never sit above a FAIL about the same thing."""
    return not any(claim == at for at, _ in failures)


def zencode(name):
    """GHC's Z-encoding, over the alphabet a module name here may use.

    Only `z` and `Z` escape in a name of letters and digits - `Azuresecrets`
    is `Azzuresecrets` in the symbol table, which is precisely the sort of
    near-miss a substring check gets wrong."""
    out = ''
    for letter in name:
        if 'z' == letter:
            out += 'zz'
        elif 'Z' == letter:
            out += 'ZZ'
        elif letter.isalnum():
            out += letter
        else:
            raise SystemExit('checkcore: cannot encode module name ' + name)
    return out


def symbols(path):
    """Every symbol name in a binary, defined and undefined alike, with the
    glibc version suffix cut off."""
    if not os.path.exists(path):
        raise SystemExit('checkcore: ' + path + ' is not built - run make check-core')

    out = subprocess.run(['nm', path], capture_output=True, text=True)
    if 0 != out.returncode and not out.stdout:
        raise SystemExit('checkcore: nm failed on ' + path + ': ' + out.stderr.strip())

    names = set()
    for line in out.stdout.splitlines():
        fields = line.split()
        if fields:
            names.add(fields[-1].split('@')[0])
    return names


def modules(names):
    """The Haskell modules compiled INTO a binary, by exact name.

    A home module's symbols are `<Module>_<name>_closure` and friends; a
    module from a package carries the PACKAGE ID first -
    `base_GHCziBase_map_closure` - so the leading field there names the
    package and not a module. A Haskell module name begins with a capital
    and a package id never does, which is what tells the two apart - and
    it has to be told, because claim A now asks what the core carries and
    not merely whether a plugin is among it."""
    found = set()
    for name in names:
        for suffix in ('_closure', '_con_info', '_info'):
            if name.endswith(suffix):
                head = name[: -len(suffix)].split('_')[0]
                if head[:1].isupper():
                    found.add(head)
                break
    return found


def main(claim):
    pluginfiles = sorted(
        entry[:-3]
        for entry in os.listdir(os.path.join(PORT, 'plugins'))
        if entry.endswith('.hs')
    )

    # CONTROL: the right-hand side of every intersection below is non-empty
    # and holds a module for each of the ten kinds. An empty set intersects
    # emptily with anything, and that is exactly how this check would pass
    # while proving nothing.
    if not pluginfiles:
        fail('control', 'plugins/ holds no module - nothing was compared')
    for kind, module in sorted(KINDMODULE.items()):
        if module not in pluginfiles:
            fail('control', 'no module for the ' + kind + ' kind: plugins/' + module + '.hs')

    encoded = {zencode(module): module for module in pluginfiles}

    coresyms = symbols(CORE)
    clisyms = symbols(CLI)

    corehome = modules(coresyms)
    clihome = modules(clisyms)

    # CONTROL: the left-hand side is a symbol table that was really read,
    # and the allowed list is a list of modules that are really there - so
    # a rename breaks the list rather than quietly widening what claim A
    # permits.
    for module in COREMODULES + PLUGINLIBMODULES:
        if zencode(module) not in corehome:
            fail('control', 'build/sekreto-core has no symbol from ' + module
                 + ' - nm read nothing usable')

    # CONTROL, the positive one: the same extraction, run over a binary
    # that DOES link every plugin, must find every plugin. A check that
    # cannot see a plugin when one is there is a check that always passes.
    missing = sorted(encoded[found] for found in encoded if found not in clihome)
    if missing:
        fail('control', 'build/sekreto-cli links every plugin, yet this check '
             'found no symbol from ' + ', '.join(missing))

    # A: the core holds no plugin module, AND nothing else either.
    intruders = sorted(encoded[found] for found in encoded if found in corehome)
    strangers = sorted(corehome - set(encoded)
                       - set(COREMODULES) - set(PLUGINLIBMODULES) - set(GHCMODULES))
    if 'core' in claim and intruders:
        fail('A', 'build/sekreto-core carries plugin modules: ' + ', '.join(intruders))
    if 'core' in claim and strangers:
        fail('A', 'build/sekreto-core carries modules that are not the core: '
             + ', '.join(strangers))

    # D: one plugin imports only itself. The kind modules are the ten the
    # catalog names; the machinery under them - Httpjson, Http, Tls, Json
    # - is shared and comes along, which is the point of sharing it.
    onehome = modules(symbols(ONE))
    carried = sorted(encoded[found] for found in encoded if found in onehome)
    if 'one' in claim:
        if KINDMODULE[ONEKIND] not in carried:
            fail('control', 'build/sekreto-one imports ' + KINDMODULE[ONEKIND]
                 + ' and this check found no symbol from it')
        strays = sorted(set(carried) - set(ONEMODULES))
        if strays:
            fail('D', 'build/sekreto-one imports one plugin and links '
                 + ', '.join(strays))

    # B: the core reaches no socket, no TLS and no exec.
    reached = sorted(name for name in BANNED if name in coresyms)
    tls = sorted(name for name in coresyms if name.startswith(TLSFAMILIES))
    if 'platform' in claim and reached:
        fail('B', 'build/sekreto-core names ' + ', '.join(reached))
    if 'platform' in claim and tls:
        fail('B', 'build/sekreto-core names ' + ', '.join(tls[:6]))

    # CONTROL: those names are findable, in the binary that has them.
    absent = sorted(name for name in MUSTBEINCLI if name not in clisyms)
    if absent:
        fail('control', 'build/sekreto-cli reaches the network and a child '
             'process, yet this check found no ' + ', '.join(absent))

    # C: and the loader agrees.
    corelibs = subprocess.run(['ldd', CORE], capture_output=True, text=True).stdout
    clilibs = subprocess.run(['ldd', CLI], capture_output=True, text=True).stdout
    for library in ('libssl', 'libcrypto'):
        if 'platform' in claim and library in corelibs:
            fail('C', 'build/sekreto-core loads ' + library)
        if library not in clilibs:
            fail('control', 'build/sekreto-cli does not load ' + library
                 + ' - ldd was not read')

    print('the core, as built: ' + str(len(corehome)) + ' modules, '
          + str(len(coresyms)) + ' symbols')
    if 'core' in claim and clean('A'):
        print('  A  no plugin module of ' + str(len(encoded)) + ' (all '
              + str(len(encoded)) + ' are in the CLI), and its '
              + str(len(corehome)) + ' modules are exactly the core')
    if 'platform' in claim and clean('B'):
        print('  B  none of ' + str(len(BANNED)) + ' socket, exec and TLS entry points'
              + ' (the CLI has ' + str(len([n for n in BANNED if n in clisyms])) + ')')
    if 'platform' in claim and clean('C'):
        print('  C  no libssl, no libcrypto (the CLI loads both)')
    if 'one' in claim and clean('D'):
        print('  D  build/sekreto-one links exactly ' + ', '.join(carried)
              + ' of the ' + str(len(encoded)) + ' plugin modules')

    for _, line in failures:
        print('FAIL - ' + line, file=sys.stderr)

    return 1 if failures else 0


if __name__ == '__main__':
    asked = sys.argv[1:] or ['core', 'one', 'platform']
    for name in asked:
        if name not in ('core', 'one', 'platform'):
            raise SystemExit('checkcore: no such claim: ' + name)
    sys.exit(main(asked))

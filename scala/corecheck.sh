#!/bin/sh
# THE CORE JAR, GREPPED.
#
# The compiler proves the core does not NAME a plugin (Makefile: the core is
# built with plugins/ nowhere on the classpath). This proves the rest: that
# no class in the core jar mentions a plugin, a socket, a cipher or a child
# process - the three platform facilities the split exists to keep out of a
# chain of built-in kinds.
#
# A class file carries every type it refers to as a UTF8 constant, so
# grepping the class bytes for `com/voxgig/sekreto/plugins` finds a reference
# the compiler resolved and a reader would not. Scala 3 writes a `.tasty`
# beside every `.class` and the whole jar is scanned, so a reference the
# typed tree carries and the bytecode erased is caught too.
#
# `make check-core` runs it, and test/PluginsTest.scala runs the same list
# in-process.

set -e

jar=${1:-build/sekreto.jar}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

unzip -qq -o "$jar" -d "$work"

# What the core may not so much as mention. BOTH SPELLINGS, and the second is
# the one that is easy to miss. A constant pool holds a resolved type with
# slashes -- com/voxgig/sekreto/plugins -- so the slash list catches every
# reference the COMPILER resolved. It does not catch a reference only
# REFLECTION would reach, because Class.forName takes a dotted string
# literal. A guard that overstates what it checks is worse than one that says
# less, so both are listed.
#
# Ljava/lang/Runtime; CARRIES ITS DESCRIPTOR FORM DELIBERATELY. The bare
# java/lang/Runtime is a substring of java/lang/RuntimeException, which five
# clean core classes carry, so the naive spelling fails a green build. The
# slash list is matched with grep -F against the constant pool, where a
# resolved type appears as a descriptor, and the L...; form is exact.
#
# Runtime and java/net/URL are here because an audit smuggled
# Runtime.getRuntime.exec and URI.create(x).toURL.openStream into the core
# and this check passed, printing "none reaching a plugin, a socket, a cipher
# or a subprocess". java/net/URL is a prefix on purpose: it takes
# URLConnection and HttpURLConnection with it, and URLEncoder too, since
# percent-encoding belongs with the transport rather than the core.
banned='com/voxgig/sekreto/plugins
java/net/http
java/net/Socket
javax/crypto
java/security/MessageDigest
java/lang/ProcessBuilder
Ljava/lang/Runtime;
java/net/URL
com.voxgig.sekreto.plugins
java.net.http
java.net.Socket
javax.crypto
java.security.MessageDigest
java.lang.ProcessBuilder
java.lang.Runtime
java.net.URL'

bad=0
for pattern in $banned; do
  # -F: these are literal class names, and the dotted ones would otherwise
  # let `.` match any byte.
  hits=$(grep -rlF "$pattern" "$work" 2>/dev/null || true)
  if [ -n "$hits" ]; then
    echo "core: $jar reaches $pattern:"
    echo "$hits" | sed "s#^$work/#  #"
    bad=1
  fi
done

test 0 -eq $bad || exit 1

classes=$(find "$work" -name '*.class' | wc -l)
echo "core: $classes classes in $jar, none reaching a plugin, a socket, a cipher or a subprocess"

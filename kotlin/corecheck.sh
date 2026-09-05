#!/bin/sh
# THE CORE JAR, GREPPED.
#
# The compiler proves the core does not NAME a plugin (Makefile: the core
# is built with plugins/ nowhere on the classpath). This proves the rest:
# that no class in the core jar mentions a plugin, a socket, a cipher or a
# child process - the three platform facilities the split exists to keep
# out of a chain of built-in kinds.
#
# A class file carries every type it refers to as a UTF8 constant, so
# grepping the class bytes for `com/voxgig/sekreto/plugins` finds a
# reference the compiler resolved and the reader would not - including one
# that only a reflective call would reach. `make check-core` runs it, and
# test/PluginsTest.kt runs the same list in-process.

set -e

jar=${1:-build/sekreto.jar}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

unzip -qq -o "$jar" -d "$work"

# What the core may not so much as mention. The class-file spelling, with
# slashes, is what a constant pool holds.
banned='com/voxgig/sekreto/plugins
java/net/http
java/net/Socket
javax/crypto
java/security/MessageDigest
java/lang/ProcessBuilder'

bad=0
for pattern in $banned; do
  hits=$(grep -rl "$pattern" "$work" 2>/dev/null || true)
  if [ -n "$hits" ]; then
    echo "core: $jar reaches $pattern:"
    echo "$hits" | sed "s#^$work/#  #"
    bad=1
  fi
done

test 0 -eq $bad || exit 1

classes=$(find "$work" -name '*.class' | wc -l)
echo "core: $classes classes in $jar, none reaching a plugin, a socket, a cipher or a subprocess"

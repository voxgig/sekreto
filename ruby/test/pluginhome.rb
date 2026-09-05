# frozen_string_literal: true

# Where voxgig/plugin is, for a checkout that has not installed it.
#
# voxgig_sekreto depends on voxgig_plugin - the ruby port of
# voxgig/plugin - and requires it by name, so an installed gem wins and
# the library itself searches nothing. There is no gem yet, and a
# developer working from checkouts has none installed, so the tests and
# the CLI find a checkout the same way every port finds omni:
# $PLUGIN_HOME, then the usual places - including the ../.plugin that the
# Makefile's `deps` target fetches when nothing else is found.

def pluginhome
  here = File.dirname(File.expand_path(__FILE__))
  cands = [
    ENV.fetch('PLUGIN_HOME', nil),
    File.join(here, '..', '..', '..', 'plugin'),
    File.join(here, '..', '..', '..', '..', 'plugin'),
    File.join(here, '..', '..', '.plugin'),
    '/workspace/plugin',
    '/home/user/plugin'
  ]

  cands.each do |cand|
    next if cand.nil? || cand.empty?
    return File.expand_path(cand) if File.exist?(File.join(cand, 'ruby', 'lib', 'voxgig_plugin.rb'))
  end

  raise 'sekreto: voxgig/plugin not found - set PLUGIN_HOME'
end

# Make `require "voxgig_plugin"` work: already installed, or from a
# checkout.
def pluginpath
  require 'voxgig_plugin'
rescue LoadError
  $LOAD_PATH.unshift(File.join(pluginhome, 'ruby', 'lib'))
end

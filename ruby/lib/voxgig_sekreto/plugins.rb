# frozen_string_literal: true

# THE FULL SET - every plugin this library ships, in one require.
#
# It exists for the callers that genuinely want all ten kinds: the CLI,
# the conformance suite, an app whose chain is decided at run time.
#
#     require 'voxgig_sekreto'
#     require 'voxgig_sekreto/plugins'
#
#     VoxgigSekreto::Sekreto.new('plugins' => VoxgigSekreto::Plugins::ALL,
#                                'providers' => [...])
#
# IT IS ALSO THE THING TO AVOID IF YOU CARE ABOUT WHAT GETS LOADED.
# Reaching one plugin through this file loads every other one - AWS
# request signing and seven HTTP vault clients included - which is the
# cost the core/plugin split exists to remove. A lean consumer requires
# the kinds it actually configures, each its own file:
#
#     require 'voxgig_sekreto/plugins/hashicorp'
#     VoxgigSekreto::Plugins::HASHICORP
#
# Nothing here is loaded by requiring `voxgig_sekreto`, and requiring one
# plugin loads one plugin: ruby has no package initializer to run, so the
# laziness python's plugins package has to arrange with a module
# `__getattr__` is what a directory of files already does.
#
# See docs/design/plugin-providers.md.

require_relative 'plugins/hashicorp'
require_relative 'plugins/boru'
require_relative 'plugins/aws'
require_relative 'plugins/gcpsecrets'
require_relative 'plugins/azuresecrets'
require_relative 'plugins/onepassword'
require_relative 'plugins/doppler'
require_relative 'plugins/infisical'
require_relative 'plugins/secretspec'

module VoxgigSekreto
  module Plugins
    ALL = [
      HASHICORP, BORU, AWSSECRETS, AWSPARAMS, GCPSECRETS, AZURESECRETS,
      ONEPASSWORD, DOPPLER, INFISICAL, SECRETSPEC
    ].freeze
  end
end

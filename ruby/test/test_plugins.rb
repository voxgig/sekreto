# frozen_string_literal: true

# RUN: ruby test/test_plugins.rb
# RUN-SOME: ruby test/test_plugins.rb -n test_the_core_requires_no_plugin
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

require 'English'
require 'minitest/autorun'
require 'rbconfig'

require_relative 'pluginhome'

pluginpath

require_relative '../lib/voxgig_sekreto'
require_relative '../lib/voxgig_sekreto/plugins'
require_relative '../lib/voxgig_sekreto/plugins/hashicorp'

PLUGINS = %w[
  awsparams awssecrets azuresecrets boru doppler gcpsecrets hashicorp
  infisical onepassword secretspec
].freeze

EVERY = (%w[dotenv env file memory] + PLUGINS).sort.freeze

HERE = File.dirname(File.expand_path(__FILE__))

# A provider that shouts: the smallest custom kind there is.
class Shouty
  def initialize(values)
    @values = values
  end

  def lookup(name)
    @values[name.upcase]
  end

  def describe
    'shouty'
  end
end

# A provider that answers everything, for the built-in it replaces.
class Replaced
  def lookup(_name)
    'replaced'
  end

  def describe
    'memory'
  end
end

class TestPlugins < Minitest::Test
  def test_the_full_set_holds_every_kind
    assert_equal PLUGINS, VoxgigSekreto::Plugins::ALL.map { |d| d['name'] }.sort

    PLUGINS.each do |name|
      assert VoxgigSekreto::Plugins.const_defined?(name.upcase), name
    end

    assert_equal VoxgigSekreto::KINDS['builtin'], VoxgigSekreto::BUILTINS.map { |d| d['name'] }
    assert_equal PLUGINS, VoxgigSekreto::KINDS['plugin'].sort
  end

  # Naming a kind is not enough: a kind can be in the catalog and still
  # fail to build. Construction is what the CLI does before any network.
  def test_every_kind_builds_from_a_spec
    chain = EVERY.map do |kind|
      { 'kind' => kind, 'addr' => 'http://127.0.0.1:8200', 'token' => 't',
        'dir' => '/tmp', 'file' => '/tmp/.env', 'values' => {} }
    end

    secrets = VoxgigSekreto::Sekreto.new('plugins' => VoxgigSekreto::Plugins::ALL,
                                         'providers' => chain)

    assert_equal EVERY, secrets.stores
    assert_equal EVERY, secrets.host.list.keys.sort
    assert_equal ['live'], secrets.host.list.values.uniq
  end

  def test_the_cli_passes_the_full_set
    src = File.read(File.join(HERE, '..', 'cli', 'sekreto_cli.rb'))

    assert_includes src, "require_relative '../lib/voxgig_sekreto/plugins'"
    assert_includes src, "'plugins' => VoxgigSekreto::Plugins::ALL"
  end

  # --- what a consumer sees --------------------------------------------

  def test_one_plugin_is_enough_for_a_chain_that_names_only_it
    secrets = VoxgigSekreto::Sekreto.new(
      'plugins' => [VoxgigSekreto::Plugins::HASHICORP],
      'providers' => [
        { 'kind' => 'memory', 'values' => { 'API_TOKEN' => 'tok01' } },
        { 'kind' => 'hashicorp', 'name' => 'prod',
          'addr' => 'https://vault.example.com', 'token' => 't' }
      ]
    )

    assert_equal %w[memory prod], secrets.stores
    assert_equal ['memory', 'hashicorp:https://vault.example.com/secret'], secrets.sources
    assert_equal 'tok01', secrets.get('api.token')

    # The plugin host is what the chain is made of, and it reads like the
    # chain: the kind, or kind$store for a named store.
    assert_equal({ 'memory' => 'live', 'hashicorp$prod' => 'live' }, secrets.host.list)
    assert_equal %w[dotenv env file hashicorp memory], secrets.catalog.names
  end

  def test_a_kind_that_was_not_passed_in_is_refused_naming_the_fix
    err = assert_raises(VoxgigSekreto::SekretoError) do
      VoxgigSekreto::Sekreto.new('plugins' => [VoxgigSekreto::Plugins::HASHICORP],
                                 'providers' => [{ 'kind' => 'doppler', 'token' => 't' }])
    end

    assert_equal 'sekreto: unknown provider kind: doppler ' \
                 '(available: dotenv, env, file, hashicorp, memory)' \
                 ' - doppler is a sekreto plugin, not built in: pass it in the plugins option',
                 err.message

    # A kind nobody ships is a typo, and gets no such hint.
    err = assert_raises(VoxgigSekreto::SekretoError) do
      VoxgigSekreto::Sekreto.new('providers' => [{ 'kind' => 'vualt' }])
    end

    assert_equal 'sekreto: unknown provider kind: vualt (available: dotenv, env, file, memory)',
                 err.message
  end

  # Two providers MAY share a store name - a directed read walks both, and
  # the spec pins it - but an instance ref may not, so the second gets a
  # numbered tag from the host and keeps its store name.
  def test_a_repeated_store_name_keeps_the_store_and_numbers_the_instance
    secrets = VoxgigSekreto::Sekreto.new('providers' => [
                                           { 'kind' => 'memory', 'values' => {} },
                                           { 'kind' => 'memory',
                                             'values' => { 'API_TOKEN' => 'second' } },
                                           { 'kind' => 'memory', 'name' => 'pair',
                                             'values' => {} },
                                           { 'kind' => 'memory', 'name' => 'pair',
                                             'values' => { 'API_TOKEN' => 'pair2' } }
                                         ])

    assert_equal %w[memory pair], secrets.stores
    assert_equal %w[memory memory$1 memory$2 memory$pair], secrets.host.list.keys
    assert_equal 'second', secrets.getfrom('memory', 'api.token')
    assert_equal 'pair2', secrets.getfrom('pair', 'api.token')
  end

  def test_a_store_name_must_be_a_valid_tag
    err = assert_raises(VoxgigSekreto::SekretoError) do
      VoxgigSekreto::Sekreto.new('providers' => [{ 'kind' => 'memory', 'name' => 'my store',
                                                   'values' => {} }])
    end

    assert_equal 'sekreto: invalid store name: my store', err.message
  end

  # A provider that refuses its own configuration raises a SekretoError
  # from inside the plugin's `define`. The spec pins that message byte for
  # byte, so it must come back out of the host as itself - not wrapped as
  # plugin_define_failed, and not as a PluginError.
  def test_a_sekreto_error_raised_in_define_comes_back_out_as_itself
    err = assert_raises(VoxgigSekreto::SekretoError) do
      VoxgigSekreto::Sekreto.new(
        'plugins' => [VoxgigSekreto::Plugins::HASHICORP],
        'providers' => [{ 'kind' => 'hashicorp', 'addr' => 'http://127.0.0.1:1',
                          'token' => 't', 'kv' => 3 }]
      )
    end

    assert_equal 'sekreto: hashicorp: unsupported kv version: 3', err.message
  end

  # ...and any other error is not sekreto's to rewrite: it surfaces as the
  # host reports it, naming the instance and the cause.
  def test_any_other_error_raised_in_define_is_the_hosts_report_of_it
    broken = VoxgigSekreto.providerplugin('broken', ->(_spec) { raise TypeError, 'boom' })

    err = assert_raises(VoxgigPlugin::PluginError) do
      VoxgigSekreto::Sekreto.new('plugins' => [broken],
                                 'providers' => [{ 'kind' => 'broken' }])
    end

    assert_equal 'plugin_define_failed', err.code
    assert_includes err.message, 'boom'
  end

  def test_a_custom_kind_is_one_providerplugin_call
    shouty = VoxgigSekreto.providerplugin('shouty',
                                          ->(spec) { Shouty.new(spec['values'] || {}) })

    secrets = VoxgigSekreto::Sekreto.new(
      'plugins' => [shouty],
      'providers' => [{ 'kind' => 'shouty', 'values' => { 'API.TOKEN' => 'loud' } }]
    )

    assert_equal 'loud', secrets.get('api.token')
    assert_equal({ 'shouty' => 'live' }, secrets.host.list)
  end

  # A plugin that names a built-in kind replaces it: that is how a host
  # substitutes an implementation, and never an accident, because the four
  # names are documented.
  def test_a_plugin_may_replace_a_built_in_kind
    secrets = VoxgigSekreto::Sekreto.new(
      'plugins' => [VoxgigSekreto.providerplugin('memory', ->(_spec) { Replaced.new })],
      'providers' => [{ 'kind' => 'memory', 'values' => { 'API_TOKEN' => 'original' } }]
    )

    assert_equal 'replaced', secrets.get('api.token')
  end

  def test_close_tears_the_chain_down_and_keeps_redaction
    secrets = VoxgigSekreto::Sekreto.new(
      'providers' => [{ 'kind' => 'memory', 'values' => { 'API_TOKEN' => 'tok01' } }]
    )

    assert_equal 'tok01', secrets.get('api.token')

    secrets.close

    assert_empty secrets.host.list
    assert_empty secrets.stores
    assert_nil secrets.try('api.token')
    assert_equal 'token=[redacted]', secrets.redact('token=tok01')
  end

  # --- the boundary itself ---------------------------------------------

  # What a require pulls in, measured in a FRESH interpreter because this
  # one has required everything (above) on purpose.
  #
  # Ruby has no compile-time boundary, so the proof is an import-graph
  # one: $LOADED_FEATURES after the require, which is the whole truth
  # about what the process has read.
  def fresh(code, pick)
    lib = File.realpath(File.join(HERE, '..', 'lib'))
    probe = 'puts $LOADED_FEATURES.grep(' + pick + ')' \
            ".map { |f| f.sub(#{lib.inspect} + '/', '') }.sort.join(' ')"

    out = IO.popen([RbConfig.ruby, '-I', lib, '-I', File.join(pluginhome, 'ruby', 'lib'),
                    '-e', code + "\n" + probe], &:read)

    raise 'sekreto: probe failed: ' + code unless $CHILD_STATUS.success?

    out.strip
  end

  SEKRETO = '%r{/voxgig_sekreto}'

  # A plugin needs a socket, a signature or a child process, and those are
  # the modules to look for: no port's core may reach one.
  PLATFORM = '%r{/(net/http|net/protocol|openssl|open3)\\.rb\\z}'

  # The core requires no plugin: requiring voxgig_sekreto brings in the
  # chain, the built-ins and voxgig_plugin, and not one file under
  # plugins/.
  def test_the_core_requires_no_plugin
    assert_equal 'voxgig_sekreto.rb voxgig_sekreto/addr.rb voxgig_sekreto/providers.rb' \
                 ' voxgig_sekreto/sekreto.rb',
                 fresh("require 'voxgig_sekreto'", SEKRETO)

    # ...and therefore reaches no socket, no crypto and no child process.
    assert_equal '', fresh("require 'voxgig_sekreto'", PLATFORM)
  end

  # ...and one plugin requires only itself. Python's plugins package had
  # to arrange this deliberately - its initializer once imported all ten
  # so it could re-export them, which made a single-plugin import load
  # every network client behind it. Ruby has no package initializer, so a
  # directory of files gets it for free; this pins that it stays true.
  def test_one_plugin_requires_only_itself
    assert_equal 'voxgig_sekreto.rb voxgig_sekreto/addr.rb' \
                 ' voxgig_sekreto/plugins/hashicorp.rb voxgig_sekreto/plugins/httpjson.rb' \
                 ' voxgig_sekreto/providers.rb voxgig_sekreto/sekreto.rb',
                 fresh("require 'voxgig_sekreto/plugins/hashicorp'", SEKRETO)
  end

  # The full set is loaded on demand, and reaching it loads everything.
  def test_the_full_set_is_loaded_on_demand
    before = fresh("require 'voxgig_sekreto/plugins/hashicorp'", SEKRETO)

    refute_includes before, 'plugins/doppler'
    refute_includes before, 'plugins/sigv4'

    after = fresh("require 'voxgig_sekreto/plugins'", SEKRETO)

    %w[hashicorp boru aws gcpsecrets azuresecrets onepassword doppler infisical
       secretspec sigv4 httpjson].each do |name|
      assert_includes after, 'voxgig_sekreto/plugins/' + name + '.rb'
    end
  end

  # `require` hands back true, a plugin file defines a MODULE, and the
  # definition is one constant further on. All three are refused by name,
  # saying what to pass instead.
  def test_a_module_passed_as_a_plugin_is_refused
    err = assert_raises(VoxgigSekreto::SekretoError) do
      VoxgigSekreto::Sekreto.new('plugins' => [VoxgigSekreto::Plugins], 'providers' => [])
    end

    assert_equal 'sekreto: not a plugin definition: the module VoxgigSekreto::Plugins' \
                 ' - a plugin is a definition, such as VoxgigSekreto::Plugins::HASHICORP,' \
                 ' or VoxgigSekreto::Plugins::ALL for every one',
                 err.message

    err = assert_raises(VoxgigSekreto::SekretoError) do
      VoxgigSekreto::Sekreto.new('plugins' => [true], 'providers' => [])
    end

    assert_includes err.message, 'sekreto: not a plugin definition: true'
  end
end

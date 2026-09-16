# frozen_string_literal: true

# RUN: ruby test/test_minivault.rb
#
# The mini vault, from both sides: the store a chain reads, and the
# programmatic API a plugin definition can publish beside it.
#
# The vault is not in spec/sekreto.json and cannot be until every port
# ships the kind. The spec runs against all twenty-three of them, so an
# entry naming `minivault` would fail the ports that have no such
# provider. What the shared corpus would have carried is here instead,
# plus the one thing it could not carry either way: a file written by
# this port and read by another, pinned by test/fixture/*.skmv.

require 'fileutils'
require 'minitest/autorun'
require 'tmpdir'

require_relative 'pluginhome'

pluginpath

require_relative '../lib/voxgig_sekreto'
require_relative '../lib/voxgig_sekreto/plugins/minivault'

MASTER = 'master-passphrase'

# The rounds every test here uses. The library default is 210000, which
# is the point of PBKDF2 and the wrong thing to pay per assertion.
ROUNDS = 1000

FIXTUREDIR = File.expand_path(File.join(File.dirname(File.expand_path(__FILE__)),
                                        '..', '..', 'test', 'fixture'))

# The mini vault: the file, the keys, the API and the chain.
class TestMiniVault < Minitest::Test
  def setup
    @work = Dir.mktmpdir('sekreto-minivault')
    @count = 0
  end

  def teardown
    FileUtils.remove_entry(@work)
  end

  def vaultpath
    @count += 1
    File.join(@work, 'vault' + @count.to_s + '.skmv')
  end

  def fresh
    VoxgigSekreto.createvault('file' => vaultpath, 'passphrase' => MASTER,
                              'iterations' => ROUNDS)
  end

  # A committed vault, copied so that a test which writes cannot edit the
  # bytes the format contract is made of.
  def fixture(name)
    mine = vaultpath
    FileUtils.copy_file(File.join(FIXTUREDIR, name), mine)
    mine
  end

  # EVERY committed vault, read off disk rather than listed here. A
  # hard-coded list is one more place to edit when a port lands, and the
  # edit that gets forgotten is the one that makes this suite stop
  # checking the port that just arrived.
  def self.fixtures
    Dir[File.join(FIXTUREDIR, '*.skmv')].map { |f| File.basename(f) }.sort
  end

  # --- the file --------------------------------------------------------

  def test_a_new_vault_holds_nothing_and_answers_as_its_master_key
    vault = fresh

    assert_empty vault.list
    assert_equal 'master', vault.key
    assert_equal({ 'key' => 'master', 'master' => true, 'write' => true, 'grants' => [] },
                 vault.open)
  end

  def test_a_written_secret_comes_back_and_a_new_handle_reads_it
    vault = fresh
    vault.set('api.token', 'tok01')
    vault.set('db.pass', 'hunter2')

    assert_equal 'tok01', vault.get('api.token')
    assert_equal %w[api.token db.pass], vault.list
    assert vault.has?('api.token')
    refute vault.has?('nope')
    assert_nil vault.get('nope')

    again = VoxgigSekreto.openvault('file' => vault.file, 'passphrase' => MASTER)

    assert_equal 'tok01', again.get('api.token')
  end

  def test_the_file_is_binary_and_names_nothing_in_plaintext
    vault = fresh
    vault.set('api.token', 'tok01')

    raw = File.binread(vault.file)

    assert_equal 'SKMV', raw[0, 4]
    # The key ids are plaintext and documented as such; a secret name is
    # not, and neither is a value.
    assert_includes raw, 'master'
    refute_includes raw, 'api.token'
    refute_includes raw, 'tok01'
  end

  def test_rewriting_a_name_replaces_it_rather_than_adding_one
    vault = fresh
    vault.set('api.token', 'one')
    vault.set('api.token', 'two')

    assert_equal 'two', vault.get('api.token')
    assert_equal ['api.token'], vault.list
  end

  def test_remove_drops_a_name_and_refuses_one_that_is_not_there
    vault = fresh
    vault.set('api.token', 'tok01')
    vault.remove('api.token')

    assert_empty vault.list
    assert_nil vault.get('api.token')

    err = assert_raises(VoxgigSekreto::SekretoError) { vault.remove('api.token') }
    assert_includes err.message, 'no such secret'
  end

  def test_a_name_the_library_refuses_is_refused_here_too
    vault = fresh

    assert_raises(VoxgigSekreto::SekretoError) { vault.get('') }
    assert_raises(VoxgigSekreto::SekretoError) { vault.set('bad name', 'x') }
  end

  # --- the keys --------------------------------------------------------

  def test_a_restricted_key_reads_its_grants_and_misses_on_the_rest
    vault = fresh
    vault.set('api.token', 'tok01')
    vault.set('db.pass', 'hunter2')
    vault.grant('key' => 'ci', 'passphrase' => 'ci-phrase', 'names' => ['api.token'],
                'iterations' => ROUNDS)

    ci = VoxgigSekreto.openvault('file' => vault.file, 'key' => 'ci',
                                 'passphrase' => 'ci-phrase')

    assert_equal ['api.token'], ci.list
    assert_equal 'tok01', ci.get('api.token')
    # Not an error: the vault answers as the key that opened it, so a
    # name outside the grant is a miss.
    assert_nil ci.get('db.pass')
    assert_equal({ 'key' => 'ci', 'master' => false, 'write' => false,
                   'grants' => ['api.token'] }, ci.open)
  end

  def test_a_read_only_key_refuses_to_write_and_a_write_key_updates
    vault = fresh
    vault.set('db.pass', 'hunter2')
    vault.grant('key' => 'ro', 'passphrase' => 'ro-phrase', 'names' => ['db.pass'],
                'iterations' => ROUNDS)
    vault.grant('key' => 'rw', 'passphrase' => 'rw-phrase', 'names' => ['db.pass'],
                'write' => true, 'iterations' => ROUNDS)

    ro = VoxgigSekreto.openvault('file' => vault.file, 'key' => 'ro',
                                 'passphrase' => 'ro-phrase')
    err = assert_raises(VoxgigSekreto::SekretoError) { ro.set('db.pass', 'nope') }
    assert_includes err.message, 'read-only'

    rw = VoxgigSekreto.openvault('file' => vault.file, 'key' => 'rw',
                                 'passphrase' => 'rw-phrase')
    rw.set('db.pass', 'changed')

    assert_equal 'changed', vault.get('db.pass')
  end

  def test_a_restricted_key_cannot_write_a_name_it_was_not_granted
    vault = fresh
    vault.set('db.pass', 'hunter2')
    vault.grant('key' => 'rw', 'passphrase' => 'rw-phrase', 'names' => ['db.pass'],
                'write' => true, 'iterations' => ROUNDS)

    rw = VoxgigSekreto.openvault('file' => vault.file, 'key' => 'rw',
                                 'passphrase' => 'rw-phrase')
    err = assert_raises(VoxgigSekreto::SekretoError) { rw.set('other.name', 'x') }

    assert_includes err.message, 'was not granted'
  end

  def test_a_granted_name_that_does_not_exist_yet_reads_once_a_master_writes_it
    vault = fresh
    vault.grant('key' => 'ci', 'passphrase' => 'ci-phrase', 'names' => ['later.name'],
                'iterations' => ROUNDS)

    ci = VoxgigSekreto.openvault('file' => vault.file, 'key' => 'ci',
                                 'passphrase' => 'ci-phrase')

    assert_empty ci.list
    assert_nil ci.get('later.name')

    vault.set('later.name', 'here now')

    assert_equal 'here now', ci.get('later.name')
    assert_equal ['later.name'], ci.list
  end

  def test_the_master_lists_every_key_and_what_it_may_do
    vault = fresh
    vault.grant('key' => 'ro', 'passphrase' => 'p1', 'names' => ['a.one'],
                'iterations' => ROUNDS)
    vault.grant('key' => 'rw', 'passphrase' => 'p2', 'names' => %w[a.one b.two],
                'write' => true, 'iterations' => ROUNDS)

    assert_equal([
                   { 'key' => 'master', 'master' => true, 'write' => true, 'grants' => [] },
                   { 'key' => 'ro', 'master' => false, 'write' => false, 'grants' => ['a.one'] },
                   { 'key' => 'rw', 'master' => false, 'write' => true,
                     'grants' => %w[a.one b.two] }
                 ], vault.keys)
  end

  def test_the_master_only_methods_refuse_a_restricted_key
    vault = fresh
    vault.set('a.one', 'x')
    vault.grant('key' => 'ci', 'passphrase' => 'ci-phrase', 'names' => ['a.one'],
                'write' => true, 'iterations' => ROUNDS)

    ci = VoxgigSekreto.openvault('file' => vault.file, 'key' => 'ci',
                                 'passphrase' => 'ci-phrase')

    [-> { ci.keys }, -> { ci.remove('a.one') }, -> { ci.rotate },
     -> { ci.revoke('master') },
     -> { ci.grant('key' => 'x', 'passphrase' => 'y', 'names' => []) }].each do |call|
      err = assert_raises(VoxgigSekreto::SekretoError) { call.call }

      assert_includes err.message, 'master key'
    end
  end

  def test_a_repeated_key_id_is_refused_rather_than_overwriting_one
    vault = fresh
    vault.grant('key' => 'ci', 'passphrase' => 'one', 'names' => [], 'iterations' => ROUNDS)
    err = assert_raises(VoxgigSekreto::SekretoError) do
      vault.grant('key' => 'ci', 'passphrase' => 'two', 'names' => [], 'iterations' => ROUNDS)
    end

    assert_includes err.message, 'key already exists'
  end

  def test_revoke_drops_a_key_and_a_key_cannot_revoke_itself
    vault = fresh
    vault.set('a.one', 'x')
    vault.grant('key' => 'ci', 'passphrase' => 'ci-phrase', 'names' => ['a.one'],
                'iterations' => ROUNDS)

    ci = VoxgigSekreto.openvault('file' => vault.file, 'key' => 'ci',
                                 'passphrase' => 'ci-phrase')

    assert_equal 'x', ci.get('a.one')

    vault.revoke('ci')

    err = assert_raises(VoxgigSekreto::SekretoError) { ci.get('a.one') }

    assert_includes err.message, 'no such key'

    err = assert_raises(VoxgigSekreto::SekretoError) { vault.revoke('master') }

    assert_includes err.message, 'cannot revoke itself'
  end

  def test_rotate_keeps_the_secrets_and_drops_every_other_key
    vault = fresh
    vault.set('api.token', 'tok01')
    vault.set('db.pass', 'hunter2')
    vault.grant('key' => 'ci', 'passphrase' => 'ci-phrase', 'names' => ['api.token'],
                'iterations' => ROUNDS)

    vault.rotate

    assert_equal %w[api.token db.pass], vault.list
    assert_equal 'tok01', vault.get('api.token')
    assert_equal 'hunter2', vault.get('db.pass')
    assert_equal ['master'], vault.keys.map { |k| k['key'] }

    ci = VoxgigSekreto.openvault('file' => vault.file, 'key' => 'ci',
                                 'passphrase' => 'ci-phrase')

    assert_raises(VoxgigSekreto::SekretoError) { ci.get('api.token') }
  end

  # --- refusals --------------------------------------------------------

  def test_a_wrong_passphrase_an_unknown_key_and_a_missing_file_all_refuse
    vault = fresh
    vault.set('a.one', 'x')

    bad = VoxgigSekreto.openvault('file' => vault.file, 'passphrase' => 'wrong')
    err = assert_raises(VoxgigSekreto::SekretoError) { bad.get('a.one') }

    assert_includes err.message, 'wrong passphrase'

    nokey = VoxgigSekreto.openvault('file' => vault.file, 'key' => 'nope',
                                    'passphrase' => MASTER)
    assert_raises(VoxgigSekreto::SekretoError) { nokey.get('a.one') }

    missing = VoxgigSekreto.openvault('file' => File.join(@work, 'nothing.skmv'),
                                      'passphrase' => MASTER)
    err = assert_raises(VoxgigSekreto::SekretoError) { missing.get('a.one') }

    assert_includes err.message, 'no vault file'
  end

  def test_a_damaged_file_is_refused_rather_than_read_as_a_short_one
    vault = fresh
    vault.set('a.one', 'x')
    raw = File.binread(vault.file)

    short = vaultpath
    File.binwrite(short, raw[0, raw.bytesize - 10])
    err = assert_raises(VoxgigSekreto::SekretoError) do
      VoxgigSekreto.openvault('file' => short, 'passphrase' => MASTER).get('a.one')
    end

    assert_includes err.message, 'truncated'

    trailing = vaultpath
    File.binwrite(trailing, raw + 'junk')
    err = assert_raises(VoxgigSekreto::SekretoError) do
      VoxgigSekreto.openvault('file' => trailing, 'passphrase' => MASTER).get('a.one')
    end

    assert_includes err.message, 'trailing bytes'

    notvault = vaultpath
    File.binwrite(notvault, 'NOPE' + raw[4..])
    err = assert_raises(VoxgigSekreto::SekretoError) do
      VoxgigSekreto.openvault('file' => notvault, 'passphrase' => MASTER).get('a.one')
    end

    assert_includes err.message, 'not a vault file'
  end

  def test_creating_over_an_existing_vault_is_refused
    vault = fresh
    err = assert_raises(VoxgigSekreto::SekretoError) do
      VoxgigSekreto.createvault('file' => vault.file, 'passphrase' => MASTER,
                                'iterations' => ROUNDS)
    end

    assert_includes err.message, 'already exists'
  end

  def test_a_vault_needs_a_file_and_a_passphrase
    assert_raises(VoxgigSekreto::SekretoError) do
      VoxgigSekreto.openvault('file' => '', 'passphrase' => MASTER)
    end
    assert_raises(VoxgigSekreto::SekretoError) do
      VoxgigSekreto.openvault('file' => vaultpath, 'passphrase' => '')
    end
  end

  def test_create_makes_the_file_and_only_when_asked
    path = vaultpath

    refuses = VoxgigSekreto.openvault('file' => path, 'passphrase' => MASTER,
                                      'iterations' => ROUNDS)
    assert_raises(VoxgigSekreto::SekretoError) { refuses.list }
    refute_path_exists path

    makes = VoxgigSekreto.openvault('file' => path, 'passphrase' => MASTER,
                                    'iterations' => ROUNDS, 'create' => true)

    assert_empty makes.list
    assert_path_exists path
  end

  def test_a_key_id_longer_than_the_format_allows_is_refused
    vault = fresh
    long = 'k' * 256

    err = assert_raises(VoxgigSekreto::SekretoError) do
      vault.grant('key' => long, 'passphrase' => 'p', 'names' => [], 'iterations' => ROUNDS)
    end

    assert_includes err.message, 'longer than 255'
    assert_equal ['master'], vault.keys.map { |k| k['key'] }
  end

  # --- the handle ------------------------------------------------------

  def test_the_key_information_a_caller_gets_cannot_change_what_the_key_may_do
    vault = fresh
    vault.set('a.one', 'x')
    vault.grant('key' => 'ro', 'passphrase' => 'ro-phrase', 'names' => ['a.one'],
                'iterations' => ROUNDS)

    ro = VoxgigSekreto.openvault('file' => vault.file, 'key' => 'ro',
                                 'passphrase' => 'ro-phrase')
    info = ro.open
    info['write'] = true
    info['grants'].push('b.two')

    err = assert_raises(VoxgigSekreto::SekretoError) { ro.set('a.one', 'nope') }

    assert_includes err.message, 'read-only'
    assert_equal ['a.one'], ro.open['grants']
  end

  def test_a_revoked_key_stops_reading_even_from_a_handle_that_already_read
    vault = fresh
    vault.set('a.one', 'x')
    vault.grant('key' => 'ci', 'passphrase' => 'ci-phrase', 'names' => ['a.one'],
                'iterations' => ROUNDS)

    ci = VoxgigSekreto.openvault('file' => vault.file, 'key' => 'ci',
                                 'passphrase' => 'ci-phrase')

    assert_equal 'x', ci.get('a.one')

    vault.revoke('ci')

    assert_raises(VoxgigSekreto::SekretoError) { ci.get('a.one') }
  end

  def test_a_re_granted_key_id_does_not_keep_the_old_passphrase_working
    vault = fresh
    vault.set('a.one', 'x')
    vault.grant('key' => 'ci', 'passphrase' => 'first', 'names' => ['a.one'],
                'iterations' => ROUNDS)

    ci = VoxgigSekreto.openvault('file' => vault.file, 'key' => 'ci', 'passphrase' => 'first')

    assert_equal 'x', ci.get('a.one')

    vault.revoke('ci')
    vault.grant('key' => 'ci', 'passphrase' => 'second', 'names' => ['a.one'],
                'iterations' => ROUNDS)

    err = assert_raises(VoxgigSekreto::SekretoError) { ci.get('a.one') }

    assert_includes err.message, 'wrong passphrase'

    fresh_ci = VoxgigSekreto.openvault('file' => vault.file, 'key' => 'ci',
                                       'passphrase' => 'second')

    assert_equal 'x', fresh_ci.get('a.one')
  end

  def test_close_forgets_the_derived_keys_and_the_next_call_opens_again
    vault = fresh
    vault.set('a.one', 'x')

    assert_equal 'x', vault.get('a.one')

    vault.close

    assert_equal 'x', vault.get('a.one')
  end

  # --- the format, across ports ----------------------------------------

  # EVERY COMMITTED VAULT, not only this port's. A suite that reads only
  # the vault its own port wrote proves the reader agrees with the writer
  # beside it - which a port whose serializer and parser share a mistake
  # satisfies perfectly.
  fixtures.each do |name|
    define_method('test_the_committed_fixture_reads_key_by_key_' +
                  name.tr('-.', '__')) do
      file = fixture(name)

      master = VoxgigSekreto.openvault('file' => file, 'passphrase' => 'fixture-master')

      assert_equal %w[api.token db.pass deep.nested.name], master.list
      assert_equal 'fixture-token', master.get('api.token')
      assert_equal 'fixture-pass', master.get('db.pass')
      assert_equal 'fixture-deep', master.get('deep.nested.name')

      assert_equal([
                     { 'key' => 'master', 'master' => true, 'write' => true, 'grants' => [] },
                     { 'key' => 'reader', 'master' => false, 'write' => false,
                       'grants' => ['api.token'] },
                     { 'key' => 'writer', 'master' => false, 'write' => true,
                       'grants' => ['db.pass'] }
                   ], master.keys)

      reader = VoxgigSekreto.openvault('file' => file, 'key' => 'reader',
                                       'passphrase' => 'fixture-reader')

      assert_equal ['api.token'], reader.list
      assert_equal 'fixture-token', reader.get('api.token')
      assert_nil reader.get('db.pass')

      writer = VoxgigSekreto.openvault('file' => file, 'key' => 'writer',
                                       'passphrase' => 'fixture-writer')
      writer.set('db.pass', 'written by this port')

      assert_equal 'written by this port', master.get('db.pass')
    end
  end

  # --- the chain -------------------------------------------------------

  def test_a_vault_is_one_store_in_a_chain
    vault = fresh
    vault.set('api.token', 'from the vault')

    secrets = VoxgigSekreto::Sekreto.new(
      'plugins' => [VoxgigSekreto::Plugins::MINIVAULT],
      'providers' => [
        { 'kind' => 'memory', 'values' => { 'DB_PASS' => 'from memory' } },
        { 'kind' => 'minivault', 'file' => vault.file, 'passphrase' => MASTER }
      ]
    )

    assert_equal 'from the vault', secrets.get('api.token')
    assert_equal 'from memory', secrets.get('db.pass')
  end

  def test_a_restricted_key_in_a_chain_falls_through_on_what_it_cannot_read
    vault = fresh
    vault.set('api.token', 'from the vault')
    vault.set('db.pass', 'in the vault, not granted')
    vault.grant('key' => 'ci', 'passphrase' => 'ci-phrase', 'names' => ['api.token'],
                'iterations' => ROUNDS)

    secrets = VoxgigSekreto::Sekreto.new(
      'plugins' => [VoxgigSekreto::Plugins::MINIVAULT],
      'providers' => [
        { 'kind' => 'minivault', 'file' => vault.file, 'vaultkey' => 'ci',
          'passphrase' => 'ci-phrase' },
        { 'kind' => 'memory', 'values' => { 'DB_PASS' => 'from memory' } }
      ]
    )

    assert_equal 'from the vault', secrets.get('api.token')
    assert_equal 'from memory', secrets.get('db.pass')
  end

  def test_the_vault_behind_a_store_is_reachable_as_an_api
    vault = fresh
    vault.set('api.token', 'tok01')

    secrets = VoxgigSekreto::Sekreto.new(
      'plugins' => [VoxgigSekreto::Plugins::MINIVAULT],
      'providers' => [{ 'kind' => 'minivault', 'file' => vault.file,
                        'passphrase' => MASTER }]
    )

    api = VoxgigSekreto.vaultof(secrets)

    assert_equal ['api.token'], api.list
    api.set('db.pass', 'written through the api')

    assert_equal 'written through the api', secrets.get('db.pass')
  end

  def test_a_named_store_is_reached_by_name_and_the_alias_by_itself
    vault = fresh
    vault.set('api.token', 'tok01')

    secrets = VoxgigSekreto::Sekreto.new(
      'plugins' => [VoxgigSekreto::Plugins::MINIVAULT],
      'providers' => [{ 'kind' => 'minivault', 'name' => 'app', 'file' => vault.file,
                        'passphrase' => MASTER }]
    )

    assert_equal ['api.token'], VoxgigSekreto.vaultof(secrets, 'app').list
    assert_equal ['api.token'], VoxgigSekreto.vaultof(secrets).list
  end

  def test_an_explicit_store_name_must_exist_rather_than_falling_back
    vault = fresh

    secrets = VoxgigSekreto::Sekreto.new(
      'plugins' => [VoxgigSekreto::Plugins::MINIVAULT],
      'providers' => [{ 'kind' => 'minivault', 'name' => 'app', 'file' => vault.file,
                        'passphrase' => MASTER }]
    )

    err = assert_raises(VoxgigSekreto::SekretoError) do
      VoxgigSekreto.vaultof(secrets, 'minivault')
    end

    assert_includes err.message, 'no minivault store named'
  end

  def test_a_chain_that_has_no_vault_says_so
    secrets = VoxgigSekreto::Sekreto.new(
      'plugins' => [VoxgigSekreto::Plugins::MINIVAULT],
      'providers' => [{ 'kind' => 'memory', 'values' => {} }]
    )

    err = assert_raises(VoxgigSekreto::SekretoError) { VoxgigSekreto.vaultof(secrets) }

    assert_includes err.message, 'no minivault store'
  end

  def test_a_chain_missing_the_file_or_the_passphrase_is_refused_at_construction
    err = assert_raises(VoxgigSekreto::SekretoError) do
      VoxgigSekreto::Sekreto.new(
        'plugins' => [VoxgigSekreto::Plugins::MINIVAULT],
        'providers' => [{ 'kind' => 'minivault', 'passphrase' => MASTER }]
      )
    end

    assert_includes err.message, 'a vault needs a file'

    err = assert_raises(VoxgigSekreto::SekretoError) do
      VoxgigSekreto::Sekreto.new(
        'plugins' => [VoxgigSekreto::Plugins::MINIVAULT],
        'providers' => [{ 'kind' => 'minivault', 'file' => vaultpath }]
      )
    end

    assert_includes err.message, 'a vault needs a passphrase'
  end

  def test_the_file_is_reached_at_the_first_lookup_never_at_construction
    path = vaultpath

    # No file, and construction still succeeds: the handle is lazy.
    secrets = VoxgigSekreto::Sekreto.new(
      'plugins' => [VoxgigSekreto::Plugins::MINIVAULT],
      'providers' => [{ 'kind' => 'minivault', 'file' => path, 'passphrase' => MASTER }]
    )

    err = assert_raises(VoxgigSekreto::SekretoError) { secrets.get('api.token') }

    assert_includes err.message, 'no vault file'
  end
end

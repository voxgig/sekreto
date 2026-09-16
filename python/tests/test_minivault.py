# RUN: python3 -m unittest discover -s tests -k minivault
#
# THE MINI VAULT: a store this library owns outright, and the port's
# worked example of a plugin publishing an API beside its provider.
#
# Three things are pinned here. THE BEHAVIOUR: what a master key may do,
# what a restricted key may do, and what each is refused. THE FORMAT: the
# vaults committed under test/fixture are read byte for byte, so a change
# to the writer that this port's own reader would forgive is caught by the
# files every other port wrote. THE SEAM: a vault is one store in a chain,
# and `vaultof` reaches the API behind it.

import json
import os
import shutil
import sys
import tempfile
import threading
import unittest

from pluginhome import pluginpath

pluginpath()

from voxgig_sekreto import Sekreto, SekretoError  # noqa: E402
from voxgig_sekreto.plugins.minivault import (  # noqa: E402
    MASTERKEY, createvault, minivault, openvault, vaultof,
)

MASTER = 'master-pass'
READER = 'reader-pass'
WRITER = 'writer-pass'

# The fixtures are written with 1000 rounds and so is everything here: the
# library default of 210000 is the right cost for a real vault and the
# wrong one for a suite that opens a hundred of them.
ROUNDS = 1000

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, '..', '..', 'test', 'fixture')

FIXTUREMASTER = 'fixture-master'
FIXTUREREADER = 'fixture-reader'
FIXTUREWRITER = 'fixture-writer'


class MiniVaultCase(unittest.TestCase):

    def setUp(self):
        self.work = tempfile.mkdtemp(prefix='sekreto-minivault-py-')
        self.count = 0

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def vaultpath(self):
        self.count += 1
        return os.path.join(self.work, 'vault%d.skmv' % self.count)

    def opts(self, file, key=None, passphrase=MASTER, **more):
        out = {'file': file, 'key': key, 'passphrase': passphrase,
               'iterations': ROUNDS}
        out.update(more)
        return out

    def fresh(self):
        return createvault(self.opts(self.vaultpath()))

    def openas(self, file, key, passphrase):
        return openvault(self.opts(file, key, passphrase))

    def refusal(self, call, *args):
        with self.assertRaises(SekretoError) as caught:
            call(*args)
        return str(caught.exception)

    # A copy, because the committed bytes are the contract: a test that
    # writes to one proves nothing about what the other ports wrote.
    def copyof(self, name):
        to = os.path.join(self.work, name)
        shutil.copyfile(os.path.join(FIXTURES, name), to)
        return to


class TestMiniVault(MiniVaultCase):

    def test_a_new_vault_holds_nothing_and_answers_as_its_master_key(self):
        vault = self.fresh()

        self.assertEqual([], vault.list())
        self.assertEqual({'key': MASTERKEY, 'master': True, 'write': True,
                          'grants': []}, vault.open())
        self.assertEqual(MASTERKEY, vault.key)
        self.assertIsNone(vault.get('api.token'))
        self.assertFalse(vault.has('api.token'))

        # 0600 AT CREATION. A vault readable by everyone on the box for
        # even a moment is a vault that leaked.
        if hasattr(os, 'getuid'):
            self.assertEqual(0o600, os.stat(vault.file).st_mode & 0o777)

    def test_a_written_secret_comes_back_and_a_new_handle_reads_it(self):
        vault = self.fresh()
        vault.set('api.token', 'tok01')
        vault.set('deep.nested.name', 'deep01')

        self.assertEqual('tok01', vault.get('api.token'))
        self.assertTrue(vault.has('api.token'))
        self.assertEqual(['api.token', 'deep.nested.name'], vault.list())

        # A SECOND HANDLE, from the file alone: nothing here is cached
        # into the answer.
        again = self.openas(vault.file, None, MASTER)
        self.assertEqual('tok01', again.get('api.token'))
        self.assertEqual('deep01', again.get('deep.nested.name'))

    def test_the_file_is_binary_and_names_nothing_in_plaintext(self):
        vault = self.fresh()
        vault.set('api.token', 'tok01')

        with open(vault.file, 'rb') as handle:
            raw = handle.read()

        self.assertEqual(b'SKMV', raw[:4])
        self.assertNotIn(b'api.token', raw)
        self.assertNotIn(b'tok01', raw)
        self.assertNotIn(MASTER.encode('utf-8'), raw)

        # The key id IS in the file: a reader has to find its own record
        # before it can try a passphrase against it.
        self.assertIn(MASTERKEY.encode('utf-8'), raw)

    def test_rewriting_a_name_replaces_it_rather_than_adding_one(self):
        vault = self.fresh()
        vault.set('api.token', 'tok01')
        vault.set('api.token', 'tok02')

        self.assertEqual('tok02', vault.get('api.token'))
        self.assertEqual(['api.token'], vault.list())

    def test_remove_drops_a_name_and_refuses_one_that_is_not_there(self):
        vault = self.fresh()
        vault.set('api.token', 'tok01')
        vault.set('db.pass', 'pw01')
        vault.remove('api.token')

        self.assertEqual(['db.pass'], vault.list())
        self.assertIsNone(vault.get('api.token'))
        self.assertEqual('sekreto: minivault: no such secret: api.token',
                         self.refusal(vault.remove, 'api.token'))

    def test_a_name_the_library_refuses_is_refused_here_too(self):
        vault = self.fresh()

        for bad in ['', 'API.TOKEN', 'api..token', '.api', 'api token']:
            self.assertEqual('sekreto: invalid name: ' + bad,
                             self.refusal(vault.get, bad))
            self.assertEqual('sekreto: invalid name: ' + bad,
                             self.refusal(vault.set, bad, 'v'))

        self.assertEqual('sekreto: minivault: a secret value must be text: api.token',
                         self.refusal(vault.set, 'api.token', 1))

    # --- restricted keys ------------------------------------------------

    def test_a_restricted_key_reads_its_grants_and_misses_on_the_rest(self):
        vault = self.fresh()
        vault.set('api.token', 'tok01')
        vault.set('db.pass', 'pw01')
        vault.grant({'key': 'ci', 'passphrase': READER, 'names': ['api.token']})

        ci = self.openas(vault.file, 'ci', READER)

        self.assertEqual({'key': 'ci', 'master': False, 'write': False,
                          'grants': ['api.token']}, ci.open())
        self.assertEqual(['api.token'], ci.list())
        self.assertEqual('tok01', ci.get('api.token'))

        # NOT AN ERROR, A MISS: the vault answers as the key that opened
        # it, so a name this key cannot read is a name this store does not
        # hold for this caller.
        self.assertIsNone(ci.get('db.pass'))
        self.assertFalse(ci.has('db.pass'))

    def test_a_read_only_key_refuses_to_write_and_a_write_key_updates(self):
        vault = self.fresh()
        vault.set('db.pass', 'pw01')
        vault.grant({'key': 'ro', 'passphrase': READER, 'names': ['db.pass']})
        vault.grant({'key': 'rw', 'passphrase': WRITER, 'names': ['db.pass'],
                     'write': True})

        ro = self.openas(vault.file, 'ro', READER)
        self.assertEqual('sekreto: minivault: key ro is read-only',
                         self.refusal(ro.set, 'db.pass', 'pw02'))

        rw = self.openas(vault.file, 'rw', WRITER)
        rw.set('db.pass', 'pw02')

        self.assertEqual('pw02', rw.get('db.pass'))
        self.assertEqual('pw02', vault.get('db.pass'))
        self.assertTrue(rw.open()['write'])

    def test_a_restricted_key_cannot_write_a_name_it_was_not_granted(self):
        vault = self.fresh()
        vault.set('api.token', 'tok01')
        vault.set('db.pass', 'pw01')
        vault.grant({'key': 'rw', 'passphrase': WRITER, 'names': ['db.pass'],
                     'write': True})

        rw = self.openas(vault.file, 'rw', WRITER)

        self.assertEqual('sekreto: minivault: key rw was not granted api.token',
                         self.refusal(rw.set, 'api.token', 'tok02'))
        # ...and it cannot grow the vault either: a new name needs the
        # name key, which only a master holds.
        self.assertEqual('sekreto: minivault: key rw was not granted new.name',
                         self.refusal(rw.set, 'new.name', 'v'))
        self.assertEqual('tok01', vault.get('api.token'))

    def test_a_granted_name_that_does_not_exist_yet_reads_once_a_master_writes_it(self):
        vault = self.fresh()
        vault.grant({'key': 'ci', 'passphrase': READER, 'names': ['api.token']})

        ci = self.openas(vault.file, 'ci', READER)
        self.assertIsNone(ci.get('api.token'))
        # Granted but not yet written, so `list` does not offer it.
        self.assertEqual([], ci.list())
        self.assertEqual(['api.token'], ci.open()['grants'])

        vault.set('api.token', 'tok01')

        self.assertEqual('tok01', ci.get('api.token'))
        self.assertEqual(['api.token'], ci.list())

    def test_the_master_lists_every_key_and_what_it_may_do(self):
        vault = self.fresh()
        vault.set('api.token', 'tok01')
        vault.set('db.pass', 'pw01')
        vault.grant({'key': 'ci', 'passphrase': READER, 'names': ['api.token']})
        vault.grant({'key': 'rw', 'passphrase': WRITER,
                     'names': ['db.pass', 'api.token'], 'write': True})

        self.assertEqual([
            {'key': MASTERKEY, 'master': True, 'write': True, 'grants': []},
            {'key': 'ci', 'master': False, 'write': False, 'grants': ['api.token']},
            {'key': 'rw', 'master': False, 'write': True,
             'grants': ['api.token', 'db.pass']},
        ], vault.keys())

    def test_the_master_only_methods_refuse_a_restricted_key(self):
        vault = self.fresh()
        vault.set('api.token', 'tok01')
        vault.grant({'key': 'ci', 'passphrase': READER,
                     'names': ['api.token', 'new.name'], 'write': True})

        ci = self.openas(vault.file, 'ci', READER)
        restricted = ' needs a master key, and ci is restricted'

        self.assertEqual('sekreto: minivault: removing a secret' + restricted,
                         self.refusal(ci.remove, 'api.token'))
        self.assertEqual('sekreto: minivault: listing the keys' + restricted,
                         self.refusal(ci.keys))
        self.assertEqual('sekreto: minivault: granting a key' + restricted,
                         self.refusal(ci.grant, {'key': 'x', 'passphrase': 'p'}))
        self.assertEqual('sekreto: minivault: revoking a key' + restricted,
                         self.refusal(ci.revoke, 'x'))
        self.assertEqual('sekreto: minivault: rotating the vault' + restricted,
                         self.refusal(ci.rotate))
        # A NEW NAME NEEDS THE NAME KEY, which only a master holds - so
        # a write key granted a name the vault does not hold yet updates
        # nothing and cannot grow the vault either.
        self.assertEqual(
            'sekreto: minivault: creating the secret new.name' + restricted,
            self.refusal(ci.set, 'new.name', 'v'))

    def test_a_repeated_key_id_is_refused_rather_than_overwriting_one(self):
        vault = self.fresh()
        vault.grant({'key': 'ci', 'passphrase': READER, 'names': []})

        self.assertEqual('sekreto: minivault: key already exists: ci',
                         self.refusal(vault.grant,
                                      {'key': 'ci', 'passphrase': WRITER}))
        self.assertEqual('sekreto: minivault: key already exists: ' + MASTERKEY,
                         self.refusal(vault.grant,
                                      {'key': MASTERKEY, 'passphrase': WRITER}))

        self.assertEqual('sekreto: minivault: a grant needs a key id',
                         self.refusal(vault.grant, {'passphrase': WRITER}))
        self.assertEqual('sekreto: minivault: a grant needs a passphrase',
                         self.refusal(vault.grant, {'key': 'x'}))

    # A ring with no `grants` is a MASTER's ring in every port's reader,
    # so a key granted nothing has to write the empty map rather than
    # leave the field out - otherwise the smaller file is a key that reads
    # the whole vault. The size is the evidence: the field is inside the
    # sealed ring, where nothing else can see it.
    def test_a_key_granted_nothing_still_writes_a_grants_map(self):
        vault = self.fresh()
        vault.grant({'key': 'ci', 'passphrase': READER, 'names': []})

        none = self.openas(vault.file, 'ci', READER)

        self.assertEqual({'key': 'ci', 'master': False, 'write': False,
                          'grants': []}, none.open())
        self.assertEqual([], none.list())
        self.assertEqual(401, os.path.getsize(vault.file))

    def test_revoke_drops_a_key_and_a_key_cannot_revoke_itself(self):
        vault = self.fresh()
        vault.set('api.token', 'tok01')
        vault.grant({'key': 'ci', 'passphrase': READER, 'names': ['api.token']})
        vault.revoke('ci')

        self.assertEqual([MASTERKEY], [one['key'] for one in vault.keys()])
        self.assertEqual('sekreto: minivault: no such key: ci',
                         self.refusal(self.openas(vault.file, 'ci', READER).list))
        self.assertEqual('sekreto: minivault: no such key: gone',
                         self.refusal(vault.revoke, 'gone'))
        self.assertEqual(
            'sekreto: minivault: a key cannot revoke itself: ' + MASTERKEY,
            self.refusal(vault.revoke, MASTERKEY))

    def test_rotate_keeps_the_secrets_and_drops_every_other_key(self):
        vault = self.fresh()
        vault.set('api.token', 'tok01')
        vault.set('db.pass', 'pw01')
        vault.grant({'key': 'ci', 'passphrase': READER, 'names': ['api.token']})

        vault.rotate()

        self.assertEqual(['api.token', 'db.pass'], vault.list())
        self.assertEqual('tok01', vault.get('api.token'))
        self.assertEqual([MASTERKEY], [one['key'] for one in vault.keys()])

        # The same passphrase still opens it, from a fresh handle.
        again = self.openas(vault.file, None, MASTER)
        self.assertEqual('pw01', again.get('db.pass'))

        # ...and the revoked key's derived keys are gone with the root.
        self.assertEqual('sekreto: minivault: no such key: ci',
                         self.refusal(self.openas(vault.file, 'ci', READER).list))

    # --- refusals -------------------------------------------------------

    def test_a_wrong_passphrase_an_unknown_key_and_a_missing_file_all_refuse(self):
        vault = self.fresh()
        vault.set('api.token', 'tok01')

        self.assertEqual(
            'sekreto: minivault: wrong passphrase for key ' + MASTERKEY +
            ', or a damaged vault',
            self.refusal(self.openas(vault.file, None, 'wrong').list))

        self.assertEqual('sekreto: minivault: no such key: nobody',
                         self.refusal(self.openas(vault.file, 'nobody', MASTER).list))

        gone = os.path.join(self.work, 'gone.skmv')
        self.assertEqual('sekreto: minivault: no vault file: ' + gone,
                         self.refusal(self.openas(gone, None, MASTER).list))

    def test_a_damaged_file_is_refused_rather_than_read_as_a_short_one(self):
        vault = self.fresh()
        vault.set('api.token', 'tok01')

        with open(vault.file, 'rb') as handle:
            raw = handle.read()

        def written(bytes):
            path = self.vaultpath()
            with open(path, 'wb') as handle:
                handle.write(bytes)
            return self.openas(path, None, MASTER)

        self.assertEqual('sekreto: minivault: not a vault file',
                         self.refusal(written(b'nope' + raw[4:]).list))
        self.assertEqual('sekreto: minivault: unsupported format version: 9',
                         self.refusal(written(raw[:4] + b'\x09' + raw[5:]).list))
        self.assertEqual('sekreto: minivault: unsupported kdf or cipher: 9/1',
                         self.refusal(written(raw[:5] + b'\x09' + raw[6:]).list))
        self.assertEqual('sekreto: minivault: the vault file is truncated',
                         self.refusal(written(raw[:len(raw) - 1]).list))
        self.assertEqual('sekreto: minivault: the vault file has trailing bytes',
                         self.refusal(written(raw + b'\x00').list))

        # A FLIPPED BYTE IN A SEALED BLOB is what the tag is for: the
        # ciphertext still parses and the vault still refuses it.
        damaged = bytearray(raw)
        damaged[len(damaged) - 1] ^= 0xff
        self.assertEqual('sekreto: minivault: the value of api.token is damaged',
                         self.refusal(written(bytes(damaged)).get, 'api.token'))

    def test_creating_over_an_existing_vault_is_refused(self):
        vault = self.fresh()
        vault.set('api.token', 'tok01')

        self.assertEqual(
            'sekreto: minivault: vault file already exists: ' + vault.file,
            self.refusal(createvault, self.opts(vault.file)))

        # ...and the vault it refused to replace is untouched.
        self.assertEqual('tok01', self.openas(vault.file, None, MASTER).get('api.token'))

    def test_a_vault_needs_a_file_and_a_passphrase(self):
        self.assertEqual('sekreto: minivault: a vault needs a file',
                         self.refusal(openvault, {'passphrase': MASTER}))
        self.assertEqual('sekreto: minivault: a vault needs a file',
                         self.refusal(openvault, {'file': '', 'passphrase': MASTER}))
        self.assertEqual('sekreto: minivault: a vault needs a passphrase',
                         self.refusal(openvault, {'file': 'x.skmv'}))
        self.assertEqual('sekreto: minivault: a vault needs a passphrase',
                         self.refusal(openvault, {'file': 'x.skmv', 'passphrase': ''}))
        self.assertEqual('sekreto: minivault: a vault needs a file',
                         self.refusal(createvault, {'passphrase': MASTER}))
        self.assertEqual('sekreto: minivault: a vault needs a passphrase',
                         self.refusal(createvault, {'file': 'x.skmv'}))

    # AN EMPTY KEY IS NO KEY, so it means `master`. A CLI reaches here
    # with SEKRETO_VAULT_KEY set and empty, which is what an unset shell
    # variable expands to.
    def test_an_empty_key_means_the_master_key(self):
        vault = createvault({'file': self.vaultpath(), 'key': '',
                             'passphrase': MASTER, 'iterations': ROUNDS})
        vault.set('api.token', 'tok01')

        self.assertEqual(MASTERKEY, vault.key)
        self.assertEqual('tok01', self.openas(vault.file, '', MASTER).get('api.token'))
        self.assertEqual('tok01', self.openas(vault.file, None, MASTER).get('api.token'))

    def test_create_makes_the_file_and_only_when_asked(self):
        path = self.vaultpath()

        # Without `create`, a missing vault is a broken deployment rather
        # than an empty store: answering a miss would send the chain on to
        # a weaker source.
        self.assertEqual('sekreto: minivault: no vault file: ' + path,
                         self.refusal(self.openas(path, None, MASTER).list))
        self.assertFalse(os.path.exists(path))

        made = openvault(self.opts(path, create=True))
        made.set('api.token', 'tok01')

        self.assertTrue(os.path.exists(path))
        self.assertEqual('tok01', self.openas(path, None, MASTER).get('api.token'))

    # A length is written in ONE byte, so a longer id would wrap it and
    # every field after it would shift. Checked where an id is ACCEPTED,
    # so the refusal names the id rather than the file.
    def test_a_key_id_longer_than_the_format_allows_is_refused(self):
        vault = self.fresh()
        long = 'k' * 256

        self.assertEqual(
            'sekreto: minivault: key id is longer than 255 bytes: ' + long[:32] + '...',
            self.refusal(vault.grant, {'key': long, 'passphrase': READER}))
        self.assertEqual(
            'sekreto: minivault: key id is longer than 255 bytes: ' + long[:32] + '...',
            self.refusal(openvault, self.opts(self.vaultpath(), long)))

        # 255 bytes is the largest the format can record, and it works.
        fits = 'k' * 255
        vault.grant({'key': fits, 'passphrase': READER, 'names': []})
        self.assertEqual([MASTERKEY, fits], [one['key'] for one in vault.keys()])

    def test_the_key_information_a_caller_gets_cannot_change_what_the_key_may_do(self):
        vault = self.fresh()
        vault.set('api.token', 'tok01')
        vault.grant({'key': 'ci', 'passphrase': READER, 'names': ['api.token']})

        ci = self.openas(vault.file, 'ci', READER)
        info = ci.open()
        info['write'] = True
        info['grants'].append('db.pass')

        self.assertEqual({'key': 'ci', 'master': False, 'write': False,
                          'grants': ['api.token']}, ci.open())
        self.assertEqual('sekreto: minivault: key ci is read-only',
                         self.refusal(ci.set, 'api.token', 'tok02'))

    def test_a_revoked_key_stops_reading_even_from_a_handle_that_already_read(self):
        vault = self.fresh()
        vault.set('api.token', 'tok01')
        vault.grant({'key': 'ci', 'passphrase': READER, 'names': ['api.token']})

        ci = self.openas(vault.file, 'ci', READER)
        self.assertEqual('tok01', ci.get('api.token'))

        vault.revoke('ci')

        # THE FILE IS THE AUTHORITY, checked on every call: a handle that
        # answered from what it derived would keep reading a key the
        # master has taken away.
        self.assertEqual('sekreto: minivault: no such key: ci',
                         self.refusal(ci.get, 'api.token'))

    def test_a_re_granted_key_id_does_not_keep_the_old_passphrase_working(self):
        vault = self.fresh()
        vault.set('api.token', 'tok01')
        vault.set('db.pass', 'pw01')
        vault.grant({'key': 'ci', 'passphrase': READER, 'names': ['api.token']})

        ci = self.openas(vault.file, 'ci', READER)
        self.assertEqual('tok01', ci.get('api.token'))

        vault.revoke('ci')
        vault.grant({'key': 'ci', 'passphrase': WRITER, 'names': ['db.pass']})

        # The id is the same and the RING IS NOT, which is what the handle
        # notices: a key re-granted under another passphrase is a
        # different key wearing the id.
        self.assertEqual(
            'sekreto: minivault: wrong passphrase for key ci, or a damaged vault',
            self.refusal(ci.get, 'api.token'))

        fresh = self.openas(vault.file, 'ci', WRITER)
        self.assertEqual(['db.pass'], fresh.list())
        self.assertIsNone(fresh.get('api.token'))

    def test_close_forgets_the_derived_keys_and_the_next_call_opens_again(self):
        vault = self.fresh()
        vault.set('api.token', 'tok01')

        vault.close()

        self.assertEqual('tok01', vault.get('api.token'))

    # Two handles on one path, writing at once. Without the per-path lock
    # both finish reading before either saves, and the second rename
    # discards the first one's change while reporting success.
    #
    # THE GIL DOES NOT MAKE THIS SAFE: it is released around every file
    # read and write, which is exactly where the two handles interleave.
    def test_two_handles_writing_at_once_lose_nothing(self):
        vault = self.fresh()
        rounds = 40

        one = self.openas(vault.file, None, MASTER)
        two = self.openas(vault.file, None, MASTER)
        failed = []

        def writing(handle, tag):
            try:
                for at in range(rounds):
                    handle.set('%s.n%d' % (tag, at), 'v%d' % at)
            except BaseException as err:  # pragma: no cover - a failure is the report
                failed.append(err)

        threads = [threading.Thread(target=writing, args=(one, 'one')),
                   threading.Thread(target=writing, args=(two, 'two'))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual([], failed)

        want = sorted(['one.n%d' % at for at in range(rounds)] +
                      ['two.n%d' % at for at in range(rounds)])
        self.assertEqual(want, self.openas(vault.file, None, MASTER).list())

    # --- the committed format -------------------------------------------

    # EVERY FIXTURE IN THE DIRECTORY, not a list: a port joins by adding
    # its file, and this suite reads the new one without being edited.
    def test_every_committed_fixture_reads(self):
        names = sorted(one for one in os.listdir(FIXTURES) if one.endswith('.skmv'))
        self.assertLess(1, len(names))

        for name in names:
            file = self.copyof(name)
            why = 'fixture ' + name

            master = self.openas(file, None, FIXTUREMASTER)
            self.assertEqual(['api.token', 'db.pass', 'deep.nested.name'],
                             master.list(), why)
            self.assertEqual('fixture-token', master.get('api.token'), why)
            self.assertEqual('fixture-pass', master.get('db.pass'), why)
            self.assertEqual('fixture-deep', master.get('deep.nested.name'), why)

            self.assertEqual([
                {'key': MASTERKEY, 'master': True, 'write': True, 'grants': []},
                {'key': 'reader', 'master': False, 'write': False,
                 'grants': ['api.token']},
                {'key': 'writer', 'master': False, 'write': True,
                 'grants': ['db.pass']},
            ], master.keys(), why)

            reader = self.openas(file, 'reader', FIXTUREREADER)
            self.assertEqual(['api.token'], reader.list(), why)
            self.assertEqual('fixture-token', reader.get('api.token'), why)
            self.assertIsNone(reader.get('db.pass'), why)
            self.assertEqual('sekreto: minivault: key reader is read-only',
                             self.refusal(reader.set, 'api.token', 'x'), why)

            writer = self.openas(file, 'writer', FIXTUREWRITER)
            self.assertEqual(['db.pass'], writer.list(), why)
            writer.set('db.pass', 'changed')
            self.assertEqual('changed', master.get('db.pass'), why)


# --- the seam ------------------------------------------------------------


class TestMiniVaultChain(MiniVaultCase):

    def vaultspec(self, file, key=None, passphrase=MASTER, **more):
        out = {'kind': 'minivault', 'file': file, 'vaultkey': key,
               'passphrase': passphrase, 'iterations': ROUNDS}
        out.update(more)
        return out

    def chain(self, providers):
        return Sekreto({'plugins': [minivault], 'providers': providers})

    def test_a_vault_is_one_store_in_a_chain(self):
        vault = self.fresh()
        vault.set('api.token', 'tok01')

        secrets = self.chain([self.vaultspec(vault.file)])

        self.assertEqual(['minivault'], secrets.stores())
        self.assertEqual(['minivault:' + vault.file], secrets.sources())
        self.assertEqual('tok01', secrets.get('api.token'))
        self.assertTrue(secrets.has('api.token'))

    def test_a_restricted_key_in_a_chain_falls_through_on_what_it_cannot_read(self):
        vault = self.fresh()
        vault.set('api.token', 'tok01')
        vault.set('db.pass', 'pw01')
        vault.grant({'key': 'ci', 'passphrase': READER, 'names': ['api.token']})

        secrets = self.chain([
            self.vaultspec(vault.file, 'ci', READER),
            {'kind': 'memory', 'values': {'DB_PASS': 'fallback'}},
        ])

        self.assertEqual('tok01', secrets.get('api.token'))
        # The vault holds `db.pass` and this key cannot read it, so the
        # chain carries on rather than failing.
        self.assertEqual('fallback', secrets.get('db.pass'))

    def test_the_vault_behind_a_store_is_reachable_as_an_api(self):
        vault = self.fresh()
        secrets = self.chain([self.vaultspec(vault.file)])

        api = vaultof(secrets)
        api.set('api.token', 'written-through-the-api')

        self.assertEqual('written-through-the-api', secrets.get('api.token'))
        self.assertEqual(['api.token'], api.list())
        self.assertEqual(vault.file, api.file)

    def test_a_named_store_is_reached_by_name_and_the_alias_by_itself(self):
        one = self.fresh()
        one.set('api.token', 'one')
        two = self.fresh()
        two.set('api.token', 'two')

        secrets = self.chain([
            self.vaultspec(one.file, name='first'),
            self.vaultspec(two.file, name='second'),
        ])

        self.assertEqual('one', vaultof(secrets, 'first').get('api.token'))
        self.assertEqual('two', vaultof(secrets, 'second').get('api.token'))

        # A NAMED STORE MUST EXIST, and the alias must not stand in for
        # it: `exports` falls back to the alias when the exact ref misses.
        self.assertEqual(
            'sekreto: minivault: no minivault store named third in this chain',
            self.refusal(vaultof, secrets, 'third'))

    def test_a_chain_that_has_no_vault_says_so(self):
        secrets = self.chain([{'kind': 'memory', 'values': {}}])

        self.assertEqual('sekreto: minivault: no minivault store in this chain',
                         self.refusal(vaultof, secrets))

    def test_a_chain_missing_the_file_or_the_passphrase_is_refused_at_construction(self):
        self.assertEqual(
            'sekreto: minivault: a vault needs a file',
            self.refusal(self.chain, [self.vaultspec('')]))
        self.assertEqual(
            'sekreto: minivault: a vault needs a passphrase',
            self.refusal(self.chain, [self.vaultspec('x.skmv', passphrase='')]))

    # The handle is LAZY: a chain is built without touching the disk, so
    # a vault that is not there yet is a failed lookup rather than a
    # failed startup.
    def test_the_file_is_reached_at_the_first_lookup_never_at_construction(self):
        path = self.vaultpath()
        secrets = self.chain([self.vaultspec(path)])

        self.assertEqual(['minivault:' + path], secrets.sources())
        self.assertEqual('sekreto: minivault: no vault file: ' + path,
                         self.refusal(secrets.get, 'api.token'))


if __name__ == '__main__':  # pragma: no cover
    unittest.main()

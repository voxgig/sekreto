# Fixture vaults

Mini vaults written by one port and read by every other, so the on-disk
format is pinned by bytes rather than by agreement between
implementations.

| file | written by |
|---|---|
| `minivault.skmv` | typescript, the canonical port |
| `minivault-go.skmv` | go |
| `minivault-js.skmv` | javascript |
| `minivault-rb.skmv` | ruby |
| `minivault-php.skmv` | php |
| `minivault-java.skmv` | java |
| `minivault-cs.skmv` | csharp |

**One file per writing port, and every port reads all of them.** A suite
that reads only what its own port wrote proves the reader agrees with the
writer beside it, which a port whose serializer and parser share a
mistake satisfies perfectly. A port joins this directory by adding its
own file; the suites read the directory rather than a list, so nothing
else has to be edited for a new one to be checked everywhere.

A format two implementations merely agree about is a format that drifts,
and nothing else in either suite would notice: each port can write and
read its own vault perfectly while disagreeing with every other port
about where a length prefix goes.

## What is in it

Both files hold the same keys and the same secrets, so a suite asserts
the same values whichever it reads.

Written with 1000 PBKDF2 rounds rather than the library default of
210000, so that reading them costs a test nothing. **These passphrases
are published, and the files hold no real secret.** Regenerate them only
when the format version changes, each with the port named above.

| key | passphrase | reads |
|---|---|---|
| `master` | `fixture-master` | everything, and writes |
| `reader` | `fixture-reader` | `api.token`, read-only |
| `writer` | `fixture-writer` | `db.pass`, and may overwrite it |

| secret | value |
|---|---|
| `api.token` | `fixture-token` |
| `db.pass` | `fixture-pass` |
| `deep.nested.name` | `fixture-deep` |

A test that writes copies the file to a temporary directory first: the
committed bytes are the contract and a suite that edits them proves
nothing.

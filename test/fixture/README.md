# Fixture vault

`minivault.skmv` is a mini vault written by the canonical typescript
port. Every port that ships the `minivault` kind reads it in its own
suite, so the on-disk format is pinned by bytes rather than by agreement
between implementations.

A format two implementations merely agree about is a format that drifts,
and nothing else in either suite would notice: each port can write and
read its own vault perfectly while disagreeing with every other port
about where a length prefix goes.

## What is in it

Written with 1000 PBKDF2 rounds rather than the library default of
210000, so that reading it costs a test nothing. **These passphrases are
published, and the file holds no real secret.** Regenerate it only when
the format version changes, and with the canonical port.

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

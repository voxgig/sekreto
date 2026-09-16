// Write the mini vault the integration suite reads.
//
// Built by the CANONICAL port, and read by every port that ships the
// `minivault` kind, so the run proves the on-disk format across ports
// through the thing an app actually uses: the CLI. The per-port suites
// check the same file from inside the library; this checks it from
// outside, with the vault on disk and no library call in sight.
//
// Usage: node test/minivaultinit.js <file> <token>
//
// Two keys, because the point of the vault is that they differ:
//
//   master  - reads everything
//   reader  - granted `api.token` and nothing else
//
// The passphrases are fixed and published here. The vault holds one
// integration token and no real secret.

const { createvault } = require('../typescript/dist/plugins/minivault')
const { existsSync, unlinkSync } = require('node:fs')

const file = process.argv[2]
const token = process.argv[3]

if (!file || !token) {
  console.error('usage: minivaultinit.js <file> <token>')
  process.exit(2)
}

if (existsSync(file)) {
  unlinkSync(file)
}

// 1000 rounds rather than the library default of 210000: this vault is
// opened once per port per check, its passphrases are in this file, and
// stretching them buys the suite nothing but seconds.
const vault = createvault({ file, passphrase: 'integration-master', iterations: 1000 })

vault.set('api.token', token)
vault.set('db.pass', 'not-the-api-token')

vault.grant({
  key: 'reader',
  passphrase: 'integration-reader',
  names: ['api.token'],
  iterations: 1000,
})

console.log('minivault: ' + file + ' [' + vault.list().join(' ') + ']')

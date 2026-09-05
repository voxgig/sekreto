/* Copyright (c) 2025 Voxgig Ltd, MIT License */

const { SekretoError, envkey, nodemod } = require('./support')

/** A directory of one-secret-per-file entries, keyed like the
 * environment: `api.token` reads `<dir>/API_TOKEN`.
 *
 * This is the shape of a mounted Kubernetes Secret, a Docker or Swarm
 * secret, and a systemd credentials directory, so those all work with no
 * further configuration. One trailing newline is stripped - tools that
 * write these files disagree about it, and a newline is never part of a
 * secret on purpose. */
function fileprovider(dir, prefix) {
  return {
    lookup: (name) => {
      const { join } = nodemod('node:path')
      const file = join(dir, envkey(name, prefix))

      let text
      try {
        const { readFileSync } = nodemod('node:fs')
        text = readFileSync(file, 'utf8')
      } catch (err) {
        // An absent file - or an absent directory - means "no secrets
        // here", exactly like a missing .env. Anything else (permission
        // denied, an unreadable mount) is a store that could not answer.
        if ('ENOENT' === err.code || 'ENOTDIR' === err.code) {
          return undefined
        }
        throw new SekretoError('sekreto: file provider cannot read ' + file + ': ' + err.message)
      }

      return text.replace(/\r?\n$/, '')
    },
    describe: () => 'file:' + dir,
  }
}

module.exports = { fileprovider }

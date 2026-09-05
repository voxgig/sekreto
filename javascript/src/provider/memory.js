/* Copyright (c) 2025 Voxgig Ltd, MIT License */

const { envkey } = require('./support')

/** Literal values, keyed like environment variables. The spec uses this
 * to test chain behaviour without touching the outside world, and an app
 * uses it for defaults. */
function memoryprovider(values, prefix) {
  return {
    lookup: (name) => values[envkey(name, prefix)],
    describe: () => 'memory' + (prefix ? ':' + prefix : ''),
  }
}

module.exports = { memoryprovider }

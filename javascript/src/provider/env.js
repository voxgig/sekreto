/* Copyright (c) 2025 Voxgig Ltd, MIT License */

const { envkey } = require('./support')

/** Environment variables: `api.token` from `API_TOKEN`. */
function envprovider(prefix, source) {
  const env = source || process.env

  return {
    lookup: (name) => {
      const value = env[envkey(name, prefix)]
      return undefined === value || null === value ? undefined : String(value)
    },
    describe: () => 'env' + (prefix ? ':' + prefix : ''),
  }
}

module.exports = { envprovider }

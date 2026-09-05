/* Copyright (c) 2025 Voxgig Ltd, MIT License */

// THE FULL SET - every plugin this library ships, in one require.
//
// It exists for the callers that genuinely want all ten kinds: the CLI,
// the conformance suite, an app whose chain is decided at run time.
//
//     const { allplugins } = require('@voxgig/sekreto-js/plugins')
//     new Sekreto({ plugins: allplugins, providers: [...] })
//
// IT IS ALSO THE THING TO AVOID IF YOU CARE ABOUT SIZE. Reaching one
// plugin through this file makes every other reachable too - AWS request
// signing and seven HTTP vault clients included - which is the cost the
// core/plugin split exists to remove. A lean consumer requires the kinds
// it actually configures, each from its own module:
//
//     const { hashicorp } = require('@voxgig/sekreto-js/plugins/hashicorp')
//
// See docs/design/plugin-providers.md.

const { hashicorp, hashicorpprovider } = require('./hashicorp')
const { boru, boruprovider } = require('./boru')
const {
  awsparams, awsparamsprovider, awssecrets, awssecretsprovider, sigv4,
} = require('./aws')
const { gcpsecrets, gcpsecretsprovider } = require('./gcpsecrets')
const { azuresecrets, azuresecretsprovider } = require('./azuresecrets')
const { onepassword, onepasswordprovider } = require('./onepassword')
const { doppler, dopplerprovider } = require('./doppler')
const { infisical, infisicalprovider } = require('./infisical')
const { secretspec, secretspecprovider } = require('./secretspec')
const { fetchjson } = require('./httpjson')

const allplugins = [
  hashicorp, boru, awssecrets, awsparams, gcpsecrets, azuresecrets,
  onepassword, doppler, infisical, secretspec,
]

module.exports = {
  allplugins,

  hashicorp, boru, awssecrets, awsparams, gcpsecrets, azuresecrets,
  onepassword, doppler, infisical, secretspec,

  awsparamsprovider,
  awssecretsprovider,
  azuresecretsprovider,
  boruprovider,
  dopplerprovider,
  fetchjson,
  gcpsecretsprovider,
  hashicorpprovider,
  infisicalprovider,
  onepasswordprovider,
  secretspecprovider,
  sigv4,
}

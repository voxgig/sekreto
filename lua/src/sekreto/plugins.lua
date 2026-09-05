-- THE FULL SET - every plugin this library ships, in one require.
--
-- It exists for the callers that genuinely want all ten kinds: the CLI,
-- the conformance suite, an app whose chain is decided at run time.
--
--     local sekreto = require('sekreto')
--     local allplugins = require('sekreto.plugins').allplugins
--
--     sekreto.sekreto({ plugins = allplugins, providers = { ... } })
--
-- IT IS ALSO THE THING TO AVOID IF YOU CARE ABOUT WHAT GETS LOADED.
-- Reaching one plugin through this file loads every other one - AWS
-- request signing, SHA-256, seven HTTP vault clients and the transport
-- binding behind them - which is the cost the core/plugin split exists to
-- remove. A lean consumer requires the kinds it actually configures, each
-- from its own module:
--
--     local hashicorp = require('sekreto.plugins.hashicorp').hashicorp
--
-- Nothing here is loaded by `require('sekreto')`, and requiring one
-- plugin requires one plugin: lua runs no package initializer for
-- `sekreto.plugins.hashicorp`, so the laziness python's plugins package
-- has to arrange with a module `__getattr__` is what a directory of
-- files already does here. `require('sekreto.plugins')` finds THIS file,
-- and it is the only file that names all ten.
--
-- See docs/design/plugin-providers.md.

local hashicorp = require('sekreto.plugins.hashicorp')
local boru = require('sekreto.plugins.boru')
local aws = require('sekreto.plugins.aws')
local gcpsecrets = require('sekreto.plugins.gcpsecrets')
local azuresecrets = require('sekreto.plugins.azuresecrets')
local onepassword = require('sekreto.plugins.onepassword')
local doppler = require('sekreto.plugins.doppler')
local infisical = require('sekreto.plugins.infisical')
local secretspec = require('sekreto.plugins.secretspec')

local M = {}

--- The ten kinds that are not built in, in the order they are
--- documented.
M.allplugins = {
  hashicorp.hashicorp,
  boru.boru,
  aws.awssecrets,
  aws.awsparams,
  gcpsecrets.gcpsecrets,
  azuresecrets.azuresecrets,
  onepassword.onepassword,
  doppler.doppler,
  infisical.infisical,
  secretspec.secretspec,
}

return M

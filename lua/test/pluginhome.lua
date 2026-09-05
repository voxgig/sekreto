-- Where voxgig/plugin is, for a checkout that has not installed it.
--
-- sekreto depends on voxgig/plugin - the lua port - and requires it by
-- the plain module name `plugin`, so whatever is already on the caller's
-- `package.path` wins and the LIBRARY ITSELF SEARCHES NOTHING. Lua has no
-- luarocks in play in this repository, so a developer working from
-- checkouts has nothing installed: the tests and the CLI find a checkout
-- the same way every port finds omni - $PLUGIN_HOME, then the usual
-- places, including the ../.plugin that the Makefile's `deps` target
-- fetches when nothing else is found.
--
-- Paths are resolved from THIS FILE's own location, never from the
-- working directory: test/checks.sh runs the CLI from an empty directory
-- with the environment wiped, so neither the cwd nor $PLUGIN_HOME can be
-- relied on there.

local M = {}

--- The directory holding this file.
local function here()
  local source = debug.getinfo(1, 'S').source

  if '@' == source:sub(1, 1) then
    return source:sub(2):match('^(.*)/[^/]+$') or '.'
  end

  return '.'
end

local function exists(path)
  local handle = io.open(path, 'r')
  if nil == handle then
    return false
  end
  handle:close()
  return true
end

--- The root of a voxgig/plugin checkout.
---
--- $PLUGIN_HOME is APPENDED rather than written into a literal list, and
--- that is not a style choice: `os.getenv` answers nil when the variable
--- is unset, a nil leaves a hole in a table constructor, and `ipairs`
--- stops dead at the first hole. Written the other way, the whole search
--- was skipped exactly when the environment was wiped - which is how
--- test/checks.sh runs the CLI, and the only place it mattered.
function M.pluginhome()
  local root = here() .. '/..'

  local candidates = {}

  local given = os.getenv('PLUGIN_HOME')
  if nil ~= given and '' ~= given then
    candidates[#candidates + 1] = given
  end

  candidates[#candidates + 1] = root .. '/../../plugin'
  candidates[#candidates + 1] = root .. '/../../../plugin'
  candidates[#candidates + 1] = root .. '/../.plugin'
  candidates[#candidates + 1] = '/workspace/plugin'
  candidates[#candidates + 1] = '/home/user/plugin'

  for _, dir in ipairs(candidates) do
    if exists(dir .. '/lua/src/plugin.lua') then
      return dir
    end
  end

  error('sekreto: voxgig/plugin not found - set PLUGIN_HOME', 0)
end

--- Make `require('plugin')` work: already reachable, or from a checkout.
function M.pluginpath()
  if pcall(require, 'plugin') then
    return
  end

  package.path = M.pluginhome() .. '/lua/src/?.lua;' .. package.path
end

return M

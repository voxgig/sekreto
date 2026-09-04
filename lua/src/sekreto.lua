-- sekreto: one interface for secrets, wherever they live.
--
-- A Sekreto is an ordered chain of providers. `get` asks each in turn and
-- returns the first hit, so an app can be configured from environment
-- variables in development and a vault in production without changing a
-- line of its own code.
--
-- This module is the whole public surface: the facade, the pure name
-- functions (re-exported from sekreto.name, which the providers need
-- too), the error type, and the declarative factory.
--
-- A port of typescript/src/Sekreto.ts, which is canonical.

local err = require('sekreto.err')
local name = require('sekreto.name')
local addr = require('sekreto.addr')
local providers = require('sekreto.providers')
local sigv4 = require('sekreto.sigv4')
local json = require('sekreto.json')

local M = {}

-- ---------------------------------------------------------- re-exports

M.SekretoError = err.SekretoError
M.issekretoerror = err.issekretoerror
M.errmessage = err.message

M.validname = name.validname
M.checkname = name.checkname
M.envkey = name.envkey
M.vaultref = name.vaultref
M.flatname = name.flatname
M.awsparam = name.awsparam
M.parsedotenv = name.parsedotenv
M.redact = name.redact
M.storename = name.storename

M.checkaddr = addr.checkaddr
M.safeaddr = addr.safeaddr

M.sigv4 = sigv4.sigv4
M.uriescape = sigv4.uriescape

M.spec = providers.spec
M.authspec = providers.authspec
M.makeprovider = providers.makeprovider
M.KINDS = providers.KINDS

M.json = json

-- ------------------------------------------------------------- the type

local Sekreto = {}
Sekreto.__index = Sekreto

--- The stores this Sekreto can be asked by name, without repeats.
--- Defined before the print hooks, which are the only reason it needs to
--- come first.
function Sekreto:stores()
  local out = {}
  local seen = {}

  for _, entry in ipairs(self.entries) do
    if nil == seen[entry.store] then
      seen[entry.store] = true
      out[#out + 1] = entry.store
    end
  end

  return out
end

-- Print hooks, and they are not optional. `cache` and `seen` are
-- ordinary fields, so anything that walks or prints a Sekreto - a
-- debugger, a logging helper, an error formatter - would otherwise emit
-- every secret ever resolved. Neither hook reaches a value.
Sekreto.__tostring = function(self)
  return 'Sekreto { stores: [ ' .. table.concat(self:stores(), ', ') .. ' ] }'
end
Sekreto.__name = 'Sekreto'

--- The JSON-shaped form: the store names, and nothing else.
function Sekreto:tojson()
  return { stores = self:stores() }
end

--- Make a Sekreto from live providers.
---
--- `names` gives the store names positionally; an entry left nil or empty
--- falls back to the provider's own kind. Construction contacts nothing:
--- the first network call is the first lookup.
function M.Sekreto(useproviders, names, docache)
  local self = setmetatable({}, Sekreto)

  self.entries = {}

  for index, provider in ipairs(useproviders or {}) do
    local given = (names or {})[index]
    self.entries[index] = {
      store = (nil == given or '' == given) and name.storename(provider) or given,
      provider = provider,
    }
  end

  -- A list, not a map: the store a value came from stays attached, and
  -- redaction order does not vary between runs.
  self.cache = {}

  -- Every value ever resolved, for redact(). Kept independently of the
  -- read cache so that redaction still works when caching is off -
  -- otherwise an uncached Sekreto would silently disable redact() and
  -- leak secrets to logs. Append-only for the object's life: neither
  -- refresh() nor close() clears it.
  self.seen = {}

  -- A strict identity test, as canonical: only an exact `false` turns
  -- caching off, so nil leaves it on.
  self.docache = (false ~= docache)

  return self
end

--- The one resolution path both readers share.
function Sekreto:resolve(store, secret, useentries)
  -- The name is validated FIRST: before the cache, before the first
  -- provider.
  name.checkname(secret)

  if self.docache then
    for _, hit in ipairs(self.cache) do
      if store == hit.store and secret == hit.name then
        return hit.value
      end
    end
  end

  for _, entry in ipairs(useentries) do
    local found = entry.provider.lookup(secret)

    -- The empty string is a HIT. Only nil is a miss, and a provider that
    -- raises is not caught here: the error propagates out of get/try.
    if nil ~= found then
      if self.docache then
        self.cache[#self.cache + 1] = { store = store, name = secret, value = found }
      end
      self.seen[#self.seen + 1] = found
      return found
    end
  end

  -- Misses are never cached.
  return nil
end

--- The secret, or nil if no provider has it.
---
--- Named `tryget` because `try` is not usable as a Lua field name without
--- quoting at every call site; `sekreto['try']` is kept as an alias for
--- callers translating from canonical.
function Sekreto:tryget(secret)
  return self:resolve('', secret, self.entries)
end

Sekreto.try = Sekreto.tryget

--- The secret, or a SekretoError if no provider has it.
function Sekreto:get(secret)
  local found = self:tryget(secret)

  if nil == found then
    err.fail('sekreto: unknown secret: ' .. tostring(secret))
  end

  return found
end

--- The secret from one named store, or nil if that store does not have
--- it.
---
--- Naming a store that is not in the chain is an error, not a miss:
--- `tryget` already means "this store may not have it", so it cannot also
--- mean "this store may not exist" without hiding a typo. It is raised
--- BEFORE the name is validated.
function Sekreto:tryfrom(store, secret)
  local matching = {}

  for _, entry in ipairs(self.entries) do
    if store == entry.store then
      matching[#matching + 1] = entry
    end
  end

  if 0 == #matching then
    err.fail('sekreto: unknown store: ' .. tostring(store))
  end

  return self:resolve(store, secret, matching)
end

--- The secret from one named store, or a SekretoError.
function Sekreto:getfrom(store, secret)
  local found = self:tryfrom(store, secret)

  if nil == found then
    err.fail('sekreto: unknown secret: ' .. tostring(store) .. ':' .. tostring(secret))
  end

  return found
end

--- Does any provider have this secret?
function Sekreto:has(secret)
  return nil ~= self:tryget(secret)
end

--- Does this named store have this secret?
function Sekreto:hasin(store, secret)
  return nil ~= self:tryfrom(store, secret)
end

--- Every named secret at once. Missing ones are an error.
function Sekreto:all(secrets)
  local out = {}
  local order = {}

  for _, secret in ipairs(secrets) do
    out[secret] = self:get(secret)
    order[#order + 1] = secret
  end

  return out, order
end

--- A description of each provider, in resolution order, repeats kept.
function Sekreto:sources()
  local out = {}

  for index, entry in ipairs(self.entries) do
    out[index] = entry.provider.describe()
  end

  return out
end

--- Replace every value this Sekreto has resolved with `[redacted]`.
--- Works whether or not caching is enabled.
function Sekreto:redact(text)
  return name.redact(text, self.seen)
end

--- Drop cached values, so the next `get` asks the providers again. The
--- redaction history is NOT cleared.
function Sekreto:refresh()
  self.cache = {}
end

--- Tear the chain down. Afterwards `stores()` and `sources()` are empty,
--- `tryget` misses and `get` raises - and `redact` still knows every
--- value ever resolved.
function Sekreto:close()
  self.entries = {}
  self.cache = {}
end

M.SekretoClass = Sekreto

-- ---------------------------------------------------------- the factory

--- Make a Sekreto from declarative provider specs - the same shape the
--- shared spec and an app's config file use.
---
--- An element that already has a callable `lookup` is taken as a live
--- provider (duck-typed, never by class identity) and keeps its own
--- describe()-derived store name.
function M.sekreto(specs, cache)
  local built = {}
  local names = {}

  for index, spec in ipairs(specs or {}) do
    if 'function' == type(spec.lookup) then
      built[index] = spec
      names[index] = nil
    else
      built[index] = providers.makeprovider(spec)
      names[index] = spec.name
    end
  end

  return M.Sekreto(built, names, cache)
end

return M

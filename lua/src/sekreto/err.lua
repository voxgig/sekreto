-- Anything sekreto refuses to do: a bad name, a missing secret, a
-- provider that could not be reached.
--
-- Lua has no exception type, so an error is a table carrying a message
-- and nothing else - no code, no fields, no cause. The message IS the
-- contract: spec/sekreto.json pins every one of them byte for byte.
--
-- Raised with `error(value, 0)` so that Lua does not prepend a source
-- position: `sekreto: invalid name: a b` must arrive exactly as written.

local M = {}

local ERRMT = {
  __tostring = function(err) return err.message end,
  __name = 'SekretoError',
}

--- A SekretoError value.
function M.SekretoError(message)
  return setmetatable(
    { sekreto = true, name = 'SekretoError', message = message },
    ERRMT
  )
end

--- Is this a SekretoError?
function M.issekretoerror(err)
  return 'table' == type(err) and true == err.sekreto
end

--- Raise a SekretoError.
function M.fail(message)
  error(M.SekretoError(message), 0)
end

--- The message of anything raised, SekretoError or not.
function M.message(err)
  if 'table' == type(err) and nil ~= err.message then
    return tostring(err.message)
  end
  return tostring(err)
end

return M

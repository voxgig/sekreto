-- One TLS handshake, and whether it was accepted.
--
-- Driven by test/tlscheck.sh. Prints `OK` when the handshake completed
-- and the peer was verified, or `REFUSED <reason>` when it was not.
--
-- Usage: lua5.4 test/tlsprobe.lua <host> <port>

package.path = 'src/?.lua;' .. package.path

local net = require('sekreto.net')

local host = arg[1]
local port = tonumber(arg[2])

local request = 'GET / HTTP/1.1\r\nHost: ' .. host ..
  '\r\nAccept: */*\r\nConnection: close\r\n\r\n'

local got, why = net.fetch(host, port, true, request, 10000, 8 * 1024 * 1024)

if nil == got then
  print('REFUSED ' .. why)
  os.exit(0)
end

print('OK')

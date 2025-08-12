#!/usr/bin/lua

-- This is a prototype.

local ubus = require "ubus"
local uloop = require "uloop"
local nixio = require "nixio"
local fs = require "nixio.fs"
local dbg = require "luci.tools.debug"
local json = require "luci.json"
local ltn12 = require "luci.ltn12"
local subprocess = require "luci.model.subprocess"

local UBUS_STATUS_INVALID_ARGUMENT = 2
local SCRIPTS_DIR = "/lib/sync-server/scripts/"
local RUNTIME_DIR = "/tmp/sync-server/"
local pid = nixio.getpid()

-- TODO: 10min +- (random reasonable seconds) to avoid collision
local probe_timer = nil
local PROBE_STABLE_TIMEOUT = 10 * 60 * 1000

local STORE_MAX = 16
local store_id = 0
local store = {}

local devlist = {}
local myid = nil

local conn = nil

local function probe_done(r, outfile)
    assert(r == 0, "Probe failed with rc " .. tostring(r))
    local decoder = json.Decoder()
    local rc, err = ltn12.pump.all(ltn12.source.file(io.open(outfile, "rb")),
                                   decoder:sink())
    assert(rc, err)
    local result = decoder:get()
    assert(result.success >= 0, result.errmsg)
    fs.unlink(outfile)
    devlist = result.data

    local ip_list = {}
    for devid, dev in pairs(devlist) do
        if devid == myid then
            dev.myself = true
        end

        if dev.config_to_update then
            ip_list[#ip_list+1] = dev.ip
            dev.config_to_update = nil
        end
    end
    if #ip_list > 0 then
        local prog = SCRIPTS_DIR .. "sync-config"
        local args = ip_list
        uloop.process(prog, args, {}, function(r)
                          if r ~= 0 then
                              dbg("sync-config failed with rc " .. tostring(r))
                          end
        end)
    end
end

local function probe()
    local time = os.time()
    local outfile = RUNTIME_DIR .. ("probe-output-%d-%d"):format(time, pid)

    local prog = SCRIPTS_DIR .. "probe"
    local args = {"/dev/null", outfile}
    uloop.process(prog, args, {}, function(r)
                      local rc, msg = pcall(probe_done, r, outfile)
                      if not rc then
                          dbg(msg)
                      end
    end)
end

-- TODO: exception
local function cleanup(infile, outfile)
    fs.unlink(infile)
    fs.unlink(outfile)
end

local function finalize(req, rc, infile, outfile)
    local result = nil
    if rc == 0 then
        local decoder = json.Decoder()
        local rc, err = ltn12.pump.all(ltn12.source.file(io.open(outfile, "rb")),
                                       decoder:sink())
        assert(rc, err)
        result = decoder:get()
    else
        result = {
            success = -1,
            errmsg = "process exited with code " .. tostring(rc)
        }
    end

    cleanup(infile, outfile)

    conn:reply(req, result)
    return 0
end

local function handle_pcall(req, msg, handler, ...)
    local rc, data = pcall(handler, req, msg, ...)
    if not rc then
        conn:reply(req, {
                       success = -1,
                       errmsg = "Lua exception: " .. tostring(data)
        })
    else
        return data
    end
end

local function check_dev(dev, msg)
    if msg.target_type ~= "ALL" and dev.role ~= msg.target_type then
        return false
    end

    if dev.myself and not msg.include_myself then
        return false
    end

    local mydev = devlist[myid]
    assert(mydev, "Probe failed to find myself")

    if type(msg.my_role) == "string"
        and msg.my_role ~= mydev.role
    then
        return false
    end

    return true
end

local function handle_request(req, msg, async)
    if msg.data == nil then
        msg.data = {}
    end

    if type(msg.opcode) ~= "number" or type(msg.data) ~= "table" then
        return UBUS_STATUS_INVALID_ARGUMENT
    end

    local ip_list = {}
    if type(msg.target_id) == "string" then
        local dev = devlist[msg.target_id]
        if dev and check_dev(dev, msg) then
            ip_list[#ip_list+1] = dev.ip
        end
    elseif type(msg.target_type) == "string" then
        for _, dev in pairs(devlist) do
            if check_dev(dev, msg) then
                ip_list[#ip_list+1] = dev.ip
            end
        end
    end

    if #ip_list == 0 then
        conn:reply(req, {
                       success = 0,
                       total = 0
        })
        return 0
    end

    local time = os.time()
    local infile = RUNTIME_DIR .. ("request-input-%s-%d"):format(time, pid)
    local outfile = RUNTIME_DIR .. ("request-output-%s-%d"):format(time, pid)

    local encoder = json.Encoder(msg.data)
    local rc, err = ltn12.pump.all(encoder:source(),
                                   ltn12.sink.file(io.open(infile, "wb")))
    assert(rc, err)

    local prog = SCRIPTS_DIR .. "request"
    local args = {infile, outfile, tostring(msg.opcode), unpack(ip_list)}

    if async then
        if msg.store then
            -- TODO: memory
            store_id = (store_id + 1) % 65536
            store[store_id] = {
                infile = infile, outfile = outfile, done = false
            }
            uloop.process(prog, args, {}, function(r)
                              if store[store_id] then
                                  store[store_id].done = true
                                  store[store_id].rc = r
                              end
            end)
            conn:reply(req, {
                           success = 0,
                           id = store_id
            })
        else
            uloop.process(prog, args, {}, function(f)
                              cleanup(infile, outfile)
            end)
            conn:reply(req, {success = 0})
        end
    else
        rc = subprocess.call({prog, unpack(args)})
        return finalize(req, rc, infile, outfile)
    end
end

local function handle_fetch(req, msg)
    if type(msg.id) ~= "number" then
        return UBUS_STATUS_INVALID_ARGUMENT
    end

    local entry = store[msg.id]
    if entry then
        if entry.done then
            finalize(req, entry.rc, entry.infile, entry.outfile)
            store[msg.id] = nil
        else
            conn:reply(req, {
                           success = -1,
                           errmsg = "running"
            })
        end
    else
        conn:reply(req, {
                       success = -1,
                       errmsg = "ID not found"
        })
    end
end

local function handle_probe(req, msg)
    -- TODO: one probe and sync-config at a time
    probe()

    -- TODO: use more frequent timeout
    probe_timer:set(PROBE_STABLE_TIMEOUT)

    conn:reply(req, {
                   success = 0
    })
end

local methods = {
    sync = {
        send = {
            function(req, msg)
                return handle_pcall(req, msg, handle_request, true)
            end, {opcode = ubus.INT32, data = ubus.TABLE, target_type = ubus.STRING,
                  target_id = ubus.STRING, include_myself = ubus.BOOLEAN,
                  my_role = ubus.STRING,
                  store = ubus.BOOLEAN}
        },
        request = {
            function(req, msg)
                return handle_pcall(req, msg, handle_request, false)
            end, {opcode = ubus.INT32, data = ubus.TABLE, target_type = ubus.STRING,
                  target_id = ubus.STRING, include_myself = ubus.BOOLEAN,
                  my_role = ubus.STRING}
        },
        fetch = {
            function(req, msg)
                return handle_pcall(req, msg, handle_fetch)
            end, {id = ubus.INT32}
        },
        list = {
            function(req, msg)
                conn:reply(req, devlist)
            end, {}
        },
        probe = {
            function(req, msg)
                return handle_pcall(req, msg, handle_probe)
            end, {}
        },
    }
}

local events = {
    role_changed = function(msg)
        -- TODO: probe
        dbg("Role changed!!")
    end
}

local function get_device_id()
    local sync = require "luci.model.sync"
    myid = sync.get_device_id()
    dbg("Device ID:", myid)
end

local function main()
    fs.mkdirr(RUNTIME_DIR)
    get_device_id()

    probe()

    uloop.init()

    conn = ubus.connect()
    if not conn then
        error("Failed to connect to ubus")
    end

    conn:add(methods)
    conn:listen(events)

    -- TODO: use more frequent timeout
    probe_timer = uloop.timer(
        function()
            probe()
            probe_timer:set(PROBE_STABLE_TIMEOUT)
        end, PROBE_STABLE_TIMEOUT
    )

    uloop.run()
end

main()

#! /usr/bin/env lua
--
-- mix_network_check.lua
-- Copyright (C) 2018 tpuser <liushuaiwei@liushuaiwei@tp-link.com.cn>
-- check bind device list, if any different kinds of Deco in our system, 
-- which will trigger mix_network action, such as opcode forward
--

local uci   = require "luci.model.uci"
local nixio = require "nixio"
local json   = require "luci.json"
local uci_r = uci.cursor()

local MIX_NETWORK_STATUS_FILE = "/tmp/mix_network_status"
local MIX_NETWORK_STATUS_LOCK = "/var/run/mix_network.lock"
local MESH_DEVICE_LIST = "/tmp/sync-server/mesh_dev_list"

local mixed = false
local device_model_cache = nil

local fp = io.open(MESH_DEVICE_LIST, "r")

if fp ~= nil then
    local dev_str = fp:read("*all")
    fp:close()

    if dev_str then
        local mesh_dev_list = json.decode(dev_str)
        if mesh_dev_list then
            for i, v in pairs(mesh_dev_list) do
                if not device_model_cache then
                    device_model_cache = tostring(v.hwid)
                elseif device_model_cache ~= tostring(v.hwid) then
                    mixed = true
                    break
                end
            end
        end
    end
else
    print("File /tmp/sync-server/mesh_dev_list doesn't exist")
end


-- add lock
local RWLocker = require("luci.model.locker").RWLocker
local locker = RWLocker(MIX_NETWORK_STATUS_LOCK)
locker:wlock()

if not nixio.fs.access(MIX_NETWORK_STATUS_FILE) and mixed then
    local file = io.open(MIX_NETWORK_STATUS_FILE,"w")
    file:close()
elseif nixio.fs.access(MIX_NETWORK_STATUS_FILE) and not mixed then
    os.remove(MIX_NETWORK_STATUS_FILE)
end
locker:ulock()


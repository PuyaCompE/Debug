module("deco_on_off_iface", package.seeall)

local ubus  = require "ubus"
local dbg = require "luci.tools.debug"
local json = require "luci.json"

local is_dbg_on = true
local ONLINE_INFORM_TABLE
local OFFLINE_INFORM_TABLE

--[[
    Public functions
]]
function module_dbg(str)
    if is_dbg_on == true then
        dbg(str)
    end
end

function inform_online_event_to_all(dev_list)
    for __, table_data in pairs(ONLINE_INFORM_TABLE) do
        if table_data["enabled"] == true then
            table_data.cb(dev_list, true)
        end
    end
end

function inform_offline_event_to_all(dev_list)
    for __, table_data in pairs(OFFLINE_INFORM_TABLE) do
        if table_data["enabled"] == true then
            table_data.cb(dev_list, false)
        end
    end
end

--[[
    Callback functions of online/offline events. 
    Params:
    dev_list    Online/Offline deco list.
    is_online   List is online or offline list.
    Handle online/offline events in one function or seperately.
--]]

--[[
    dev_list example:
    {"80197867CB29EA43F549BBD628EE12BC18CBE731", 
     "80195552A246C48C7E6BBCDC60A1722818918946"}
--]]
function link_pri_cb(dev_list, is_online)
    local ubus_msg = {}

    if is_online == true then
        ubus_msg["new_online_devId"] = dev_list
        ubus_msg["new_offline_devId"] = {}
    else
        ubus_msg["new_online_devId"] = {}
        ubus_msg["new_offline_devId"] = dev_list
    end

    local _ubus_c = ubus.connect()
    _ubus_c:send("online_devId_list", ubus_msg)
    module_dbg("send msg to nrd"..json.encode(ubus_msg))
    _ubus_c:close()
end

function topology_cb(dev_list, is_online)
    local uci = require "luci.model.uci"
    local uci_s = uci.cursor_state()
    local mode = uci_s:get("repacd", "repacd", "DeviceType")
    if mode ~= "RE" then
        return
    end

    local sync = require "luci.model.sync"
    local self_device_id = sync.get_device_id()
    if #dev_list == 1 and dev_list[1] == self_device_id then
        return
    end

    local uci_r = uci.cursor()
    local is_bind = false
    for _, dev_id in pairs(dev_list) do
        if uci_r:get("bind_device_list", dev_id, "mac") ~= nil then
            is_bind = true
            break
        end
    end

    if is_bind ~= true then
        return
    end

    local _ubus_c = ubus.connect()
    local awn_msg = {}

    if is_online == true then
        awn_msg["new_online_devId"] = dev_list
        awn_msg["new_offline_devId"] = {}
    else
        awn_msg["new_online_devId"] = {}
        awn_msg["new_offline_devId"] = dev_list
    end

    _ubus_c:send("topology_change", awn_msg)
    module_dbg("send msg to awn, online/offline dev id = "..json.encode(awn_msg))
    _ubus_c:close()
end

function tss_on_off_cb(dev_list, is_online)
    local ubus_msg = {}

    if is_online == true then
        ubus_msg["new_online_devId"] = dev_list
        ubus_msg["new_offline_devId"] = {}
    else
        ubus_msg["new_online_devId"] = {}
        ubus_msg["new_offline_devId"] = dev_list
    end

    local _ubus_c = ubus.connect()
    _ubus_c:send("online_devId_list", ubus_msg)
    module_dbg("send msg to tss"..json.encode(ubus_msg))
    _ubus_c:close()
end

function apsd_reconfigure_cb(dev_list, is_online)
    module_dbg("Informing apsd of topology change to trigger reconfiguration...")
    
    local _ubus_c = ubus.connect()
    if not _ubus_c then
        module_dbg("Error: Failed to connect to ubus for apsd reconfigure")
        return
    end

    _ubus_c:send("apsd.configure", {})
    _ubus_c:close()
    
    module_dbg("Sent 'apsd.configure' event.")
end

--[[
    Table of events that should be done when Deco 
    online/offline is triggered.
    ["enabled"] == true means informing is enabled.
]]
ONLINE_INFORM_TABLE = {
    {
        ["event_name"] = "link_priority_on",
        ["enabled"] = true,
        cb = link_pri_cb
    },
    {
        ["event_name"] = "topology_on",
        ["enabled"] = true,
        cb = topology_cb
    },
    {
        ["event_name"] = "tss_device_on",
        ["enabled"] = true,
        cb = tss_on_off_cb
    },
    {
        ["event_name"] = "apsd_reconfigure_on",
        ["enabled"] = true,
        cb = apsd_reconfigure_cb
    }
}

OFFLINE_INFORM_TABLE = {
    {
        ["event_name"] = "link_priority_off",
        ["enabled"] = true,
        cb = link_pri_cb
    },
    {
        ["event_name"] = "topology_off",
        ["enabled"] = true,
        cb = topology_cb
    },
    {
        ["event_name"] = "apsd_reconfigure_off",
        ["enabled"] = true,
        cb = apsd_reconfigure_cb
    }
}
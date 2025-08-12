module("comp_whole_leave", package.seeall)

local config = require "luci.sys.config"
local sync = require "luci.model.sync"
local Locker = require("luci.model.locker").Locker
local uci  = require "luci.model.uci"
local uci_r = uci.new_cursor()
local dbg = require "luci.tools.debug"
local update = require "update-info"

local COMPONENT_CHECK_TABLE

--[[
    Public functions
]]
function config_changed()
    local locker = Locker(sync.CONFIG_LOCK)
    locker:lock()
    config.saveconfig("user-config")
    locker:close()
    local subprocess = require "luci.model.subprocess"
    subprocess.exec({"/sbin/reload_config"})    
end

function config_version_changed()
    config.save_config_version("0")
    sync.sync_boost()
end

function check_if_comp_whole_leave(record_data_whole, record_dev_id)
    local changed = 0

    dbg("()()()()()check if a component-whole leaves")
    if record_data_whole ~= nil then
        local version_locker = Locker(sync.CONFIG_LOCK)
        version_locker:lock();            
        for coms, vers in pairs(record_data_whole) do
            if vers ~= nil then
                for table_index, table_data in pairs(COMPONENT_CHECK_TABLE) do
                    if table_data["enabled"] == true and coms == table_data["comp_name"] then
                        changed = changed + table_data.cb(vers, record_dev_id)
                    end
                end 
            end        
        end

        if changed ~= 0 then
            config_changed()
        end
        version_locker:close()

        if changed ~= 0 then
            config_version_changed()
        end

    end
end

--[[
    Callback functions of components.
    change == 1 means this component needs to reload user config
    and sync this change to REs. 
--]]

function wireless_wpa3_cb(vers, record_dev_id)
    local change = 0
    for ver, devs in pairs(vers) do
        local wifi = require("luci.model.app_wifi").Wifi()
        local wpa3_enabled = wifi:wpa3_enabled()
        if wpa3_enabled then
            --if #devs ~= #record_dev_id then
            if not update.whole_comp_valid(devs) then
                -- Disable WPA3 when new device(s) without wireless_wpa3 component
                -- added into network
                dbg("No wireless_wpa3, disable wpa3 for compatibility")
                uci_r:delete("wifi", "ap", "wpa3")
                uci_r:delete("wifi", "guest", "wpa3")
                uci_r:set("wifi", "ap", "enc_type", "wpa2")
                uci_r:set("wifi", "guest", "enc_type", "wpa2")
                uci_r:rawcommit("wifi")
                change = 1
            end
        end
    end
    return change
end

function iptv_port_cb(vers, record_dev_id)
    local change = 0
    for ver, devs in pairs(vers) do
        --if #devs ~= #record_dev_id then
        if not update.whole_comp_valid(devs) then
            local iptv= require("luci.model.iptv").IPTV(); 
            if iptv:component_whole_leave() then
                change = 1
            end
        end
    end
    return change
end

function link_priority_cb(vers, record_dev_id)
    local change = 0
    
    for ver, devs in pairs(vers) do
        --if #devs ~= #record_dev_id then
        if not update.whole_comp_valid(devs) then
            change = 1
        end
    end
    
    if change == 1 then
        uci_r:foreach("client_mgmt", "client",
            function(section)
                uci_r:delete("client_mgmt", section[".name"], "link_pri_device_id")
                uci_r:delete("client_mgmt", section[".name"], "link_pri_band")
            end
        )
        uci_r:rawcommit("client_mgmt")
    end
    
    return change
end

function client_isolation_cb(vers, record_dev_id)
    local change = 0
    for ver, devs in pairs(vers) do
        --if #devs ~= #record_dev_id then
        if not update.whole_comp_valid(devs) then
            local wifi = require("luci.model.app_wifi").Wifi()
            local client_isolation_enabled = wifi:client_isolation_enabled()
            if client_isolation_enabled then
                -- Disable client isolation when new device(s) without client_isolation componen
                uci_r:set("iot_wifi", "iot", "client_isolation", 0)
                uci_r:rawcommit("iot_wifi")

                -- delete client_mgmt config
                uci_r:foreach("client_mgmt", "client",
                    function(section)
                        if section.enable_isolation and section.enable_isolation == '1' then
                            uci_r:set("client_mgmt", section[".name"], "enable_isolation", '0')
                        end
                    end
                )
                uci_r:rawcommit("client_mgmt")
                change = 1
            end
        end
    end
    return change
end

function eco_mode_cb(vers, record_dev_id)
    local change = 0
    for ver, devs in pairs(vers) do
        if not update.whole_comp_valid(devs) then
            local eco_mode = require("luci.controller.admin.mobile_app.eco_mode");
            if eco_mode.eco_mode_component_whole_leave() then
                dbg("New Deco device does not support eco_mode, disable it.")
                change = 1
            end
        end
    end

    return change
end

function wifi_schedule_cb(vers, record_dev_id)
    local change = 0
    for ver, devs in pairs(vers) do
        if not update.whole_comp_valid(devs) then
            local wireless = require("luci.controller.admin.mobile_app.wireless");
            if wireless.wifi_schedule_component_whole_leave() then
                dbg("New Deco device does not support wifi_schedule, disable it.")
                change = 1
            end
        end
    end

    return change
end

function wifi_control_cb(vers, record_dev_id)
    local change = 0
    local msg	= require "luci.model.message_center"
    local msg_s = msg.Msgcenter()

    for ver, devs in pairs(vers) do
        if not update.whole_comp_valid(devs) then
            local cur_mode = uci_r:get("wifi_access_control", "info", "curr_mode") or 0
            if cur_mode == "white" then
                uci_r:set("wifi_access_control", "info", "curr_mode", "black")
                uci_r:set("wifi_white_list", "info", "enable", "0")
                uci_r:set("blacklist", "blacklist", "enable", "1")
                uci_r:rawcommit("wifi_access_control")
                uci_r:rawcommit("wifi_white_list")
                uci_r:rawcommit("blacklist")
                change = 1
                msg_s:black_list_alert()
            end
        end
    end
    
    return change
end

--[[
    Table of component that should be checked.
    ["enabled"] == true means enable check.
]]
COMPONENT_CHECK_TABLE = {
    {
        ["comp_name"] = "wireless_wpa3",
        ["enabled"] = true,
        cb = wireless_wpa3_cb
    },

    {
        ["comp_name"] = "iptv_port",
        ["enabled"] = true,
        cb = iptv_port_cb
    },

    {
        ["comp_name"] = "client_link",
        ["enabled"] = true,
        cb = link_priority_cb
    },

    {
        ["comp_name"] = "iot_client_link",
        ["enabled"] = true,
        cb = link_priority_cb
    },
    
    {
        ["comp_name"] = "client_isolation",
        ["enabled"] = true,
        cb = client_isolation_cb
    },

    {
        ["comp_name"] = "eco_mode",
        ["enabled"] = true,
        cb = eco_mode_cb
    },

    {
        ["comp_name"] = "wifi_schedule",
        ["enabled"] = true,
        cb = wifi_schedule_cb
    },

    {
        ["comp_name"] = "wifi_access_control",
        ["enabled"] = true,
        cb = wifi_control_cb
    },
    {
        ["comp_name"] = "eco_mode_advanced",
        ["enabled"] = true,
        cb = eco_mode_cb
    },
}

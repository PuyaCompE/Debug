#!/usr/bin/lua

local sys = require "luci.sys"
local json = require "luci.json"
local dbg = require "luci.tools.debug"
local uci = require "luci.model.uci"
local sync = require "luci.model.sync"
local cfg = require "luci.sys.config"
local Locker = require("luci.model.locker").Locker
local FAP_INFO_FILE = "/tmp/fap-info"

local uci_r = uci.cursor_state()

local function check_version()
    local sync_version = sync.get_sync_version()
    local group = sync.read_group_info()
    if not group or not group.gid  then
        return
    end

    if sync.compare_sync_version(sync_version, '2') < 0 or not group.role then
        local role = uci_r:get("cloud_feature", "feature_info", "role")

        if role and role == "master" then
            -- update role in group info       
            group.role = "AP"
            sync.write_group_info(group) 

            -- update bind_device_list
            local device_id = sync.get_device_id()
            local device = {}
            device.mac = sync.getfirm_cached("MAC")
            device.device_model = sync.getfirm_cached("MODEL")
            device.role = "AP"    
            device.nickname = uci_r:get("cloud_feature", "feature_info", "location")
            local device_list = {}
            device_list[device_id] = device
            sync.add_local_device_list(device_list)

            sys.fork_exec("sleep 2; /etc/init.d/awn restart")
            sys.fork_exec("sleep 2; /etc/init.d/tipc-server restart&")
            sys.fork_exec("sleep 2; /etc/init.d/cloud_brd restart&")
            sys.fork_exec("sleep 2; /etc/init.d/repacd start fix_default_config&")

            sync_version = '2'
        else
            if not role then
                dbg("Warning: role in feature info is null")
            end            
            sync_version = '1'
        end 

        local locker = Locker(sync.CONFIG_LOCK)
        locker:lock()

        uci_r:set("sync", "config", "sync_version", sync_version)
        uci_r:rawcommit("sync")
        cfg.saveconfig("user-config")

        locker:close()               
    end
end

local function get_fap_info()
    local f = io.open(FAP_INFO_FILE, "r")
    if not f then
        return false, "open file failed"
    end

    local data = json.decode(f:read("*a"))
    f:close()

    if not data then
        return false, "falied to get fap mac"
    end


    if data.mac then
        data.mac = (data.mac):gsub(":", "-"):upper()
    end

    return data.mac
end

local function write_fap_info(mac)
    local f = io.open(FAP_INFO_FILE, "w")
    if not f then
        return false
    end

    local info = {}
    info.mac = mac

    local data = json.encode(info)
    f:write(data)

    f:close()
    return true
end

local function check_role()
    local group = sync.read_group_info()
    if not group or not group.role then
        dbg("Warning:invaild group or group.role")
        return
    end 

    local device_id = sync.get_device_id()
    local device_info = uci_r:get_all("bind_device_list", device_id)
    local fap_mac
    uci_r:foreach("bind_device_list", "device",
        function(section)
            if section["role"] == "AP" then
                fap_mac = (section["mac"]):gsub(":", "-"):upper()
            end
        end
    )
       
    if not device_info then
        if group.role == "AP" then
            dbg("Warning:AP can't find itself in bind_device_list, try to reset")
            local dev = {device_id = device_id}
            local device_list = {}
            device_list[#device_list+1] = dev
            local params = {}
            params.device_list = device_list

            -- ubus call sync send '{"opcode":XXX, "target_id":YYY,"data":ZZZ}'
            local _ubus = require("ubus").connect() 
            local args = {}
            args.opcode = tonumber(0x4022)
            args.target_id = device_id
            args.include_myself = true
            local data = {}
            data.params = params             
            args.data = data

            _ubus:call("sync", "send", args)
            _ubus:close()                        
        end
    elseif device_info.role ~= group.role then
        group.role = device_info.role
        sync.write_group_info(group)       
        dbg("Warning: DECO bind role changed, ask awn/iptv/guest_eth to update")
        sys.fork_exec("/etc/init.d/awn restart")
        sys.fork_exec("/etc/init.d/iptv reload; /etc/init.d/guest_eth reload bind")
    elseif device_info.role == "RE" and fap_mac then 
        local old_fap_mac, msg = get_fap_info()
        if old_fap_mac ~= false and old_fap_mac ~= fap_mac then
            local _ubus = require("ubus").connect() 
            local args = {}
            dbg("Warning:FAP is changed, ask awn to update")
            _ubus:call("awn", "update", args)
            _ubus:close() 
        end
    end

    if fap_mac then
        write_fap_info(fap_mac)
    end        

end

local param = arg[1]
if param == "version" then
    check_version()
elseif param == "role" then
    check_role()
end 





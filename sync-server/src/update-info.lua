module("update-info", package.seeall)

local tmpv2 = require "tmpv2"
local json = require "luci.json"
local sync = require "luci.model.sync"
local dbg = require "luci.tools.debug"
local util = require "luci.util"
local Locker = require("luci.model.locker").Locker
local script = require "sync-script"
local uci  = require "luci.model.uci"
local config = require "luci.sys.config"
local sys = require "luci.sys"
local uci_r = uci.new_cursor()
local nixio = require "nixio"
local getfirm = require "luci.model.getfirm"

local RECORD_CFG = "/var/run/record_cfg"
local RECORD_OP = "/var/run/record_op"
local RECORD_COMPONENT_ROUTER_OWNER = "/var/run/record_component_router_owner"
local RECORD_COMPONENT_ROUTER_USER = "/var/run/record_component_router_user"
local RECORD_COMPONENT_AP_OWNER = "/var/run/record_component_ap_owner"
local RECORD_COMPONENT_AP_USER = "/var/run/record_component_ap_user"
local RECORD_OPCODE_CFG = "/var/run/record_opcode_cfg"
local RECORD_DEVID = "/var/run/record_devid"
local RECORD_COMPONENT_WHOLE = "/var/run/record_component_whole"
local MAX_RECORD = "/var/run/max_record"
local RECORD_OPCODE_RE_FIRST = "/var/run/record_opcode_re_first"
local RECORD_COMPONENT_AP_RE_SUPPORT = "/var/run/record_component_ap_re_support"
local RECORD_COMPONENT_WHOLE_IGNORE_AP = "/var/run/record_component_whole_ignore_ap"
local RECORD_COMPONENT_WHOLE_RE = "/var/run/record_component_whole_re"
local MAX_RECORD = "/var/run/max_record"
local RECORD_OPCODE_RE_FIRST = "/var/run/record_opcode_re_first"

local LOOKUP_OP = "/var/run/lookup_op"
local LOOKUP_OP_RE_ONLY = "/var/run/lookup_op_re_only"
local LOOKUP_CFG = "/var/run/lookup_cfg"
local LOOKUP_COMPONENT_ROUTER_OWNER = "/var/run/lookup_component_router_owner"
local LOOKUP_COMPONENT_ROUTER_USER = "/var/run/lookup_component_router_user"
local LOOKUP_COMPONENT_AP_OWNER = "/var/run/lookup_component_ap_owner"
local LOOKUP_COMPONENT_AP_USER = "/var/run/lookup_component_ap_user"

local TMP_CHECK_DEV = "/tmp/check_dev"
local TMP_UPDATE_INFO_IP = "/tmp/update_info_ip"
local TMP_MERGE_CFGS = "/tmp/merge_cfgs"

local RECORD_CFG_LOCK = "/var/run/record_cfg.lock"
local RECORD_OP_LOCK = "/var/run/record_op.lock"
local RECORD_COMPONENT_LOCK = "/var/run/record_component.lock"
local RECORD_DEVID_LOCK = "/var/run/record_devid.lock"
local RECORD_OPCODE_CFG_LOCK = "/var/run/record_opcode_cfg.lock"
local RECORD_OPCODE_RE_FIRST_LOCK = "/var/run/record_opcode_re_first.lock"
local LOOKUP_LOCK = "/var/run/lookup.lock"
local MAX_RECORD_LOCK = "/var/run/max_record.lock"

local TMP_CHECK_DEV_LOCK = "/tmp/check_dev.lock"
local TMP_UPDATE_INFO_IP_LOCK = "/tmp/update_info_ip.lock"
local TMP_MERGE_CFGS_LOCK = "/tmp/merge_cfgs.lock"

local TYPE_OP = "op"
local TYPE_OPCODE_RE_FIRST = "opcode_re_first"
local TYPE_CFG = "cfg"
local TYPE_COMPONENT_ROUTER_OWNER = "component_router_owner"
local TYPE_COMPONENT_ROUTER_USER = "component_router_user"
local TYPE_COMPONENT_AP_OWNER = "component_ap_owner"
local TYPE_COMPONENT_AP_USER = "component_ap_user"
local TYPE_OPCODE_CFG = "opcode_cfg"
local TYPE_DEVID = "devid"
local TYPE_CHECK_DEV = "check_dev"
local TYPE_COMPONENT_WHOLE = "component_whole"
local TYPE_COMPONENT_AP_RE_SUPPORT = "component_ap_re_support"
local TYPE_COMPONENT_WHOLE_IGNORE_AP = "component_whole_ignore_ap"
local TYPE_COMPONENT_WHOLE_RE = "component_whole_re"

local MESH_DEV_LIST = "/tmp/sync-server/mesh_dev_list"
local TMP_RECORD_DEV_LIST = "/tmp/record_dev_list"

local CLOUD_FEATURE_UPLOAD = "/tmp/cloud_feature_upload"

local MAJOR_RE_LIST = "/var/run/major_re"

local TYPE_WHOLE_IGNORE_AP = 1
local TYPE_WHOLE_RE = 2

local group = sync.read_group_info()
local my_devid = sync.get_device_id()
major_re_list = nil
online_devid = nil
online_dev_num = 0
whole_valid_component = nil

local function update_config_version()

    config.save_config_version("0")

    sync.sync_boost()
end

--[[
local function update_mixed_network_role(component, dev_model, dev_id)

    local UCI_CONFIG = "mixed_network_role"
    local UCI_SECTION_TYPE = "component"

    local res
    local option = {}
    local find = false
    local change = 0

    -- dbg.print("update_mixed_network_role")
    if dev_id == nil or component == nil or dev_model == nil then
        return 0
    end
    
    uci_r:foreach(UCI_CONFIG, UCI_SECTION_TYPE,
        function(section)
            
            -- dbg.print("find component: " .. section[".name"])
            if section[".name"] == component then
                find = true
                if section[dev_model] ~= nil then
                    -- dbg.print("find model : " .. dev_model)
                    if section[dev_model] == dev_id then
                        -- dbg.print("devid is same")
                    else
                        -- dbg.print("devid is diff")
                        
                        change = change + 1
                    end
                else
                    -- dbg.print("can't find model : " .. dev_model)

                    change = change + 1
                end
            end
        end
    )

    if change >= 1 then
        uci_r:set(UCI_CONFIG, component, dev_model, dev_id)
        uci_r:rawcommit(UCI_CONFIG)
    elseif find == false then
        option[dev_model] = dev_id
        -- dbg.print(("add section: %s %s %s %s"):format(UCI_CONFIG, UCI_SECTION_TYPE, component, json.encode(option)))
        
        res = uci_r:section(UCI_CONFIG, UCI_SECTION_TYPE, component, option)
        -- dbg.print("res = " .. res)
        if not res then
            dbg.print(("failed to add %s %s"):format(UCI_CONFIG, component))
            return 0
        end
        res = uci_r:rawcommit(UCI_CONFIG)
        if not res then
            dbg.print(("failed to save %s %s"):format(UCI_CONFIG, component))
            return 0
        end
        change = change + 1
    else
        -- 
    end

    return change
end



-- TODO
function clean_role_info()
    local UCI_CONFIG_PATH = "/etc/config/mixed_network_role"
    local UCI_CONFIG = "mixed_network_role"
    local UCI_SECTION_TYPE = "component"
    local find = false

    -- dbg.print("clean_role_info")
    
    uci_r:foreach(UCI_CONFIG, UCI_SECTION_TYPE,
        function(section)
            find = true
            
        end
    )

    if find == false then
        -- dbg.print("don't need clean_role_info")
        return false
    end

    dbg.print("clean_role_info all")

    uci_r:delete_all(UCI_CONFIG, UCI_SECTION_TYPE)
    uci_r:rawcommit(UCI_CONFIG)

    update_config_version()

    return true
end

function clean_role_info_nosave()
    local UCI_CONFIG_PATH = "/etc/config/mixed_network_role"
    local UCI_CONFIG = "mixed_network_role"
    local UCI_SECTION_TYPE = "component"
    local find = false

    -- dbg.print("clean_role_info")
    
    uci_r:foreach(UCI_CONFIG, UCI_SECTION_TYPE,
        function(section)
            find = true
            
        end
    )

    if find == false then
        -- dbg.print("don't need clean_role_info")
        return false
    end

    dbg.print("clean_role_info_nosave all")

    uci_r:delete_all(UCI_CONFIG, UCI_SECTION_TYPE)
    uci_r:rawcommit(UCI_CONFIG)

    -- update_config_version()

    return true
end

local function update_iot_config(devid)
    local ZIGBEE_NETWORK_SYNC_PATH = "/etc/config/zigbee_network_sync"
    local BLE_NETWORK_PATH = "/etc/config/ble_network"
    local fp
    local str
    local co_devid
    local ble_key

    fp = io.open(ZIGBEE_NETWORK_SYNC_PATH, "r")
    if fp then
        fp:close()
        co_devid = uci_r:get("zigbee_network_sync", "zigbee_network_sync", "co_device_id")
        
    else
        co_devid = "0"
    end

    fp = io.open(BLE_NETWORK_PATH, "r")
    if fp then
        fp:close()
        ble_key = uci_r:get("ble_network", "settings", "key")
        
    else
        ble_key = "0"
    end


    if co_devid == "0" and (ble_key == "0" or ble_key == "" or ble_key == nil)then
        dbg.print("update_iot_config ble and zigbee ready")
        local data = {}
        data.params = {}  
        data.params.bluetooth = {}
        data.params.bluetooth.enable = false     
        
        local args = {}
        args.opcode = 0x800f --
        args.target_id = devid
        args.data = data

        -- dbg.print("update_iot_config args: " .. json.encode(args))

        cmd = ("ubus -t 5 call sync request '%s' >/dev/null 2>&1 &"):format(json.encode(args))
        sys.fork_call(cmd)
    elseif co_devid == "0" then
        dbg.print("update_iot_config zigbee ready")

        local data = {}
        data.params = {}   
        
        local args = {}
        args.opcode = 0x4100 --
        args.target_id = devid
        args.data = data

        -- dbg.print("update_iot_config args: " .. json.encode(args))

        cmd = ("ubus -t 5 call sync request '%s' >/dev/null 2>&1 &"):format(json.encode(args))
        sys.fork_call(cmd)
    else
        dbg.print("iot config was used")

    end

end
--]]

local function config_is_empty(config, type)
    local empty = true
    
    uci_r:foreach(config, type,
        function(section)
            empty = false
            
        end
    )

    return empty
end

local function read_from_file(file)
    local fp = io.open(file, "r")
    local data = nil
    if fp == nil then
        dbg("error open file failed:" .. file)
    else
        local lines = fp:read("*all")
        fp:close()
        data = json.decode(lines)
    end
	return data
end

local function is_in_comp_list(comp, comp_list)
    if not comp_list then
        return false
    end

    for ig_comp,_ in pairs(comp_list) do
        if comp == ig_comp then
            return true
        end
    end
    return false
end

local function config_in_network(iot_cfg, record_cfg)

	dbg("config_in_network")
	local exist = false
	if iot_cfg == nil or record_cfg == nil then
		dbg("nil params %s %s" % {json.encode(iot_cfg), json.encode(record_cfg)})
		return exist
	end

	local cfg_str = tostring(iot_cfg)
    for k, _ in pairs(record_cfg) do
		if cfg_str ~= nil and string.find(k, cfg_str) then
			exist = true
			break
		end
	end

	if exist then
		dbg("iot_cfg(%s) exist in %s" % {json.encode(iot_cfg), RECORD_CFG})
	else
		dbg("iot_cfg(%s) dose not exist in %s" % {json.encode(iot_cfg), RECORD_CFG})
	end

	return exist

end

function clear_all_iot_config()
    local COMPITABLE_LIST_FILE_PATH = "/tmp/sync-server/dev_compitable_list"
    local uci_r = uci.new_cursor()
    local fs = nixio.fs
    local fp
    local buf
    local find = false
    local write = false
    local comp_list = {}
    local model_list = {}
    local local_model = sync.getfirm_cached("MODEL")
    
    fp = io.open(COMPITABLE_LIST_FILE_PATH, "r")
    if not fp then
        return false
    end
    
    buf = fp:read("*all")
    fp:close()
    comp_list = json.decode(buf)

    for k, v in pairs(comp_list) do
        if model_list[v.model] == nil and v.model ~= local_model then
            model_list[v.model] = v.iot_list
        end
    end

    -- dbg.print("model_list = " .. json.encode(model_list))

    uci_r:foreach("bind_device_list", "device",
        function(section)
            dbg.print("section.device_model :" .. section.device_model)
            if model_list[section.device_model] ~= nil then
                find = true
            end
            
        end
    )

    if find == true then
        dbg.print("!!!!Needn't clean all IOT Config!!!!")
        return true
    end

    local del_list = {}
	local record_cfg = read_from_file(RECORD_CFG)
    -- dbg.print("clear all iot config")
    for model, config_list in pairs(model_list) do
        -- dbg.print("model : " .. model)
        for key, value in pairs(config_list) do
            local sec_list = {}
            for _, ele in ipairs(value) do
                if ((config_is_empty(key, ele) == false) and (config_in_network(key, record_cfg) == false)) then
                    -- dbg.print("key : " .. key)
                    -- dbg.print("clean section type: " .. ele)
                    sec_list[#sec_list + 1] = ele
                    
                end
            end
            del_list[key] = sec_list
        end
    end

    for cfg, sec_list in pairs(del_list) do
        -- dbg.print("del cfg : " .. cfg)
        for _, sec in ipairs(sec_list) do
            -- dbg.print("del section : " .. sec)
            uci_r:delete_all(cfg, sec)
            write = true
        end
        uci_r:rawcommit(cfg)
        
    end


    if write == true then
        dbg.print("!!!!Clean all IOT Config!!!!")
        update_config_version()
    end

    local cmd = ("rm -rf %s &"):format(COMPITABLE_LIST_FILE_PATH)
    sys.fork_call(cmd)

    return true

end

function update_re_role_info()
    local OP_FILE_PATH = "/var/run/lookup_op"
    local str
    local role = sync.get_role()
    local id_list = ""

    if role ~= "AP" then
        return false
    end

    fp = io.open(OP_FILE_PATH, "r")
    if not fp then
        dbg.print("update_role_info failed to open: " .. OP_FILE_PATH)
        return false
    end

    str = fp:read("*all")
    fp:close()

    local info = json.decode(str)
    devid_list = info["0x4042"]
    if devid_list == nil then
        return false
    end
    
    local local_devid = (getfirm.getfirm_cached("DEV_ID")):trim()
    for _, devid in ipairs(devid_list) do
        if local_devid ~= devid then
            if id_list == "" then
                id_list = devid
            else
                id_list = id_list .. "," .. devid   
            end
        end
    end

    if id_list == "" then
        return false
    end

    -- PUSH to RE
    local data = {}
    data.params = {}  
    data.params.file = OP_FILE_PATH
    data.params.content = str

    local args = {}
    args.opcode = 0xc456 -- push file
    args.target_id = id_list
    args.data = data

    local ubus   = require "ubus"
    local _ubus = ubus.connect()        
    local result = _ubus:call("sync", "send", args) 
    _ubus:close()

    -- dbg.print("update_role_info result: " .. json.encode(args))
    --local cmd = ("ubus -t 5 call sync request '%s' >/dev/null 2>&1 &"):format(json.encode(args))
    --sys.fork_call(cmd)
end

local function remove_usb_status(devid_list)
    if not devid_list then
        return
    end

    local usbsync = require "luci.model.usb_sync"
    for _, devid in ipairs(devid_list) do
        usbsync.remove_usb_status(devid)
    end
end

function update_role_info()
    
    update_re_role_info()
    clear_all_iot_config()

    return true

end

function update_compitable_list(data)
    local COMPITABLE_LIST_FILE_PATH = "/tmp/sync-server/dev_compitable_list"
    local fp
    local str = nil
    local info = {}

    if nil == data or data.compatible == nil then
        return 1
    end
    
    local role = sync.get_role()
    if role ~= "AP" then
        return 1
    end

    -- dbg.print("update_compitable_list : " .. json.encode(data.compatible))
    if data.compatible.iot_list == nil then
        dbg.print("update_compitable_list can't support IOT")
        return 1
    end

    if data.devid == getfirm.getfirm_cached("DEV_ID"):trim() then
        dbg.print("update_compitable_list devid and local devid is same")
        return 1
    end

    if data.compatible.model == getfirm.getfirm_cached("MODEL"):trim() then
        dbg.print("update_compitable_list model is same")
        return 1
    end

    fp = io.open(COMPITABLE_LIST_FILE_PATH, "r")
    if fp then
        str = fp:read("*all")
        fp:close()
    end

    if str == nil then
        info[data.devid] = data.compatible
    else
        local old = json.decode(str)
        old[data.devid] = data.compatible
        info = old
    end
    -- dbg.print("update_compitable_list write: " .. json.encode(info))
    fp = io.open(COMPITABLE_LIST_FILE_PATH, "w")
    if fp then
        fp:write(json.encode(info))
        fp:close()
    end

    return 0

end

function is_nil_table(data)
    if data == nil then
        return true
    end
    for _, v in pairs(data) do
        return false
    end
    return true
end

local function write_to_file(file, data)
    local fp = io.open(file, "w")
    if fp == nil then
        dbg("error open file failed:" .. file)
        return false
    end
    fp:write(json.encode(data))
    fp:close()
    return true
end

local function get_lock_record_file(data_type)
	local lock_file, record_file
	if data_type == TYPE_OP then
		lock_file = RECORD_OP_LOCK
		record_file = RECORD_OP
	elseif data_type == TYPE_CFG then
		lock_file = RECORD_CFG_LOCK
		record_file = RECORD_CFG
	elseif data_type == TYPE_COMPONENT_ROUTER_OWNER then
		lock_file = RECORD_COMPONENT_LOCK
		record_file = RECORD_COMPONENT_ROUTER_OWNER
	elseif data_type == TYPE_COMPONENT_ROUTER_USER then
		lock_file = RECORD_COMPONENT_LOCK
		record_file = RECORD_COMPONENT_ROUTER_USER
	elseif data_type == TYPE_COMPONENT_AP_OWNER then
		lock_file = RECORD_COMPONENT_LOCK
		record_file = RECORD_COMPONENT_AP_OWNER
	elseif data_type == TYPE_COMPONENT_AP_USER then
		lock_file = RECORD_COMPONENT_LOCK
		record_file = RECORD_COMPONENT_AP_USER
	elseif data_type == TYPE_OPCODE_CFG then
		lock_file = RECORD_OPCODE_CFG_LOCK
		record_file = RECORD_OPCODE_CFG
	elseif data_type == TYPE_DEVID then
		lock_file = RECORD_DEVID_LOCK
		record_file = RECORD_DEVID
	elseif data_type == TYPE_CHECK_DEV then
		lock_file = TMP_CHECK_DEV_LOCK
		record_file = TMP_CHECK_DEV
    elseif data_type == TYPE_COMPONENT_WHOLE then
        lock_file = RECORD_COMPONENT_LOCK
        record_file = RECORD_COMPONENT_WHOLE
    elseif data_type == TYPE_OPCODE_RE_FIRST then
        lock_file = RECORD_OPCODE_RE_FIRST_LOCK
        record_file = RECORD_OPCODE_RE_FIRST
    elseif data_type == TYPE_COMPONENT_AP_RE_SUPPORT then
        lock_file = RECORD_COMPONENT_LOCK
        record_file = RECORD_COMPONENT_AP_RE_SUPPORT
    elseif data_type == TYPE_COMPONENT_WHOLE_IGNORE_AP then
        lock_file = RECORD_COMPONENT_LOCK
        record_file = RECORD_COMPONENT_WHOLE_IGNORE_AP
    elseif data_type == TYPE_COMPONENT_WHOLE_RE then
        lock_file = RECORD_COMPONENT_LOCK
        record_file = RECORD_COMPONENT_WHOLE_RE
    elseif data_type == TYPE_OPCODE_RE_FIRST then
        lock_file = RECORD_OPCODE_RE_FIRST_LOCK
        record_file = RECORD_OPCODE_RE_FIRST
	end
	return lock_file, record_file
end

local function add_to_record(data, devid, data_type)
	local res = false
	local lock_file, record_file = get_lock_record_file(data_type)
	local locker = Locker(lock_file)
    locker:lock()
	
	local record_data = read_from_file(record_file)
    if record_data==nil then
        record_data={}
    end
	
	for k, v in pairs(data) do
		if data_type == TYPE_OP or data_type == TYPE_CFG or data_type == TYPE_OPCODE_RE_FIRST then
            if data_type == TYPE_OP then
                v = string.lower(v)
            end
			local dev_list = {}
			if record_data[v] ~= nil then
				dev_list = record_data[v]
			end
			table.insert(dev_list, devid)
			record_data[v] = dev_list
		elseif data_type == TYPE_OPCODE_CFG then
            k = string.lower(k)
			if record_data[k] == nil then
				record_data[k] = v
			else
				if json.encode(record_data[k]) ~= json.encode(v) then
					dbg("Warning! detect different opcode_cfg " .. k .. " to_add: " .. json.encode(v) .. " record: " .. json.encode(record_data[k]))
				end
			end
		elseif data_type == TYPE_DEVID then
			local find = false
			for i=1,#record_data do
				if record_data[i] == v then
					find = true
					dbg("Warning! record_devid contains this devid " .. v)
				end
			end
			if find == false then
				table.insert(record_data, v)
			end
		elseif data_type==TYPE_COMPONENT_ROUTER_OWNER or data_type==TYPE_COMPONENT_ROUTER_USER or data_type==TYPE_COMPONENT_AP_OWNER or data_type==TYPE_COMPONENT_AP_USER or data_type==TYPE_COMPONENT_WHOLE then
			local dev_list = {devid}
			local com_item = {}
			if record_data[k] ~= nil then
				com_item = record_data[k]
				if com_item[v] ~= nil then
					local ver_item = com_item[v]
					table.insert(ver_item, devid)
				else
					com_item[v] = dev_list
				end
			else
				com_item[v] = dev_list
				record_data[k] = com_item
			end
		elseif data_type == TYPE_CHECK_DEV then
			record_data[v] = devid
        elseif data_type == TYPE_COMPONENT_AP_RE_SUPPORT or data_type == TYPE_COMPONENT_WHOLE_IGNORE_AP or data_type == TYPE_COMPONENT_WHOLE_RE then
            local dev_list = {devid}
            local com_item = {}
            if record_data[k] ~= nil then
                com_item = record_data[k]
                if com_item[v] ~= nil then
                    local ver_item = com_item[v]
                    table.insert(ver_item, devid)
                else
                    com_item[v] = dev_list
                end
            else
                com_item[v] = dev_list
                record_data[k] = com_item
            end
		end
	end
	res = write_to_file(record_file, record_data)
	locker:close()
	return res
end

local function delete_from_record(dev_list, data_type)
	local res = false
	local lock_file, record_file = get_lock_record_file(data_type)
    local locker = Locker(lock_file)
	locker:lock()
	local record_data = read_from_file(record_file)
	if record_data ~= nil then
		for index=1, #dev_list do
			local devid = dev_list[index]
			if data_type == TYPE_OP or data_type == TYPE_CFG or data_type == TYPE_OPCODE_RE_FIRST then
				for k, v in pairs(record_data) do
					for i=#v, 1, -1 do
						if v[i] == devid then
							table.remove(v, i)
						end
					end
					if #v == 0 then
						record_data[k] = nil
					end
				end
			elseif data_type==TYPE_COMPONENT_ROUTER_OWNER or data_type==TYPE_COMPONENT_ROUTER_USER or data_type==TYPE_COMPONENT_AP_OWNER or data_type==TYPE_COMPONENT_AP_USER or data_type==TYPE_COMPONENT_WHOLE then
				for k, v in pairs(record_data) do
					local record_op = record_data[k]
					for ver, devs in pairs(record_op) do
						for i=#devs, 1, -1 do
							if devs[i] == devid then
								table.remove(devs, i)
							end
						end
						if #devs == 0 then
							record_op[ver] = nil
						end
					end
					if is_nil_table(record_op) then
						record_data[k] = nil
					end
				end
			elseif data_type == TYPE_DEVID then
				for i=#record_data, 1, -1 do
					if record_data[i] == devid then
						table.remove(record_data, i)
					end
				end
            elseif data_type == TYPE_COMPONENT_AP_RE_SUPPORT or data_type == TYPE_COMPONENT_WHOLE_IGNORE_AP or data_type == TYPE_COMPONENT_WHOLE_RE then
                for k, v in pairs(record_data) do
                    local record_op = record_data[k]
                    for ver, devs in pairs(record_op) do
                        for i=#devs, 1, -1 do
                            if devs[i] == devid then
                                table.remove(devs, i)
                            end
                        end
                        if #devs == 0 then
                            record_op[ver] = nil
                        end
                    end
                    if is_nil_table(record_op) then
                        record_data[k] = nil
                    end
                end
			end
		end
		res = write_to_file(record_file, record_data)
	elseif data_type == TYPE_COMPONENT_AP_RE_SUPPORT or data_type == TYPE_COMPONENT_WHOLE_IGNORE_AP or data_type == TYPE_COMPONENT_WHOLE_RE then
        locker:close()
        return true
    end
	locker:close()
	return res
end

local function check_config_iot(lookup_cfg)

	local iot_fap_cfg = "iot_tpra"
	local iot_master_cfg = "zigbee_network_sync"
	local iot_fap_exist = false
	local iot_master_exist = false
	local iot_fap_devid
	local iot_master_devid

	if lookup_cfg == nil then
		dbg("nil lookup_cfg")
		return
	end

	for cfg, devid in pairs(lookup_cfg) do
		local cfg_str = tostring(cfg)
		if string.find(cfg_str, iot_fap_cfg) ~= nil then
			iot_fap_exist = true
			iot_fap_devid = devid
		elseif string.find(cfg_str, iot_master_cfg) ~= nil then
			iot_master_exist = true
			iot_master_devid = devid
		end

		if iot_fap_exist and iot_master_exist then
			break
		end
	end

	if iot_fap_exist == false or iot_fap_devid == nil then
		dbg("there is no iot fap")
		return
	end

	if iot_master_exist == false or iot_master_devid == nil then
		dbg("there is no iot master for zigbee")
		return
	end

	if iot_fap_devid == iot_master_devid then
		dbg("iot fap is iot master")
		return
	end

	dbg("iot mix network! replace config-devid in lookup_cfg")
    uci_r:set_confdir("/etc/profile.d")
    local iot_cfg_tbl = uci_r:get("cfg-wifi-iot", "cfg", "cfg")
    uci_r:set_confdir("/etc/config")
	if iot_cfg_tbl == nil then
		dbg("there is no such file /etc/profile.d/cfg-wifi-iot")
		return
	end

	local replace_num = 0
	local len = #iot_cfg_tbl
	for cfg, devid in pairs(lookup_cfg) do
		for i = 1, len do
			local wifi_iot_cfg = iot_cfg_tbl[i]
			if wifi_iot_cfg and string.find(cfg, wifi_iot_cfg) then
				lookup_cfg[cfg] = iot_master_devid
				replace_num = replace_num + 1
			end
		end

		if replace_num == len then
			dbg("all replacement done")
			break
		end
	end

	dbg("cfg-list now replace iot-fap(%s) with iot-master(%s)" % {iot_fap_devid, iot_master_devid})

end

local function add_to_major(devid_list)
    if not devid_list then
        return false
    end

    if not major_re_list then
        major_re_list =  {}
    end
    if type(devid_list) == "table" then
        for k,v in pairs(devid_list) do
            if  not major_re_list[v] then
                dbg("add "..v.." to major re")
            end
            major_re_list[v] = 1
        end
    elseif type(devid_list) == "string" then
        if  not major_re_list[devid_list] then
            dbg("add "..devid_list.." to major re")
        end
        major_re_list[devid_list] = 1
    end
    return true
end


local function save_to_major( )
    dbg("major_re", json.encode(major_re_list))
    if major_re_list then
        dbg("save major re")
        return write_to_file(MAJOR_RE_LIST, major_re_list)
    end
end

local function is_online(devid)
    if devid == my_devid then
        return true
    end
    if not online_devid then
        local online_devid_data = read_from_file(RECORD_DEVID) or {}
        online_devid = {}
        for i=1, #online_devid_data do
            online_devid[online_devid_data[i]] = 1
        end
        online_dev_num = #online_devid_data
    end

    if online_devid[devid] then
        return true
    end
    return false
end 

local function cfg_to_lookup_table()
	local res = false
    local locker = Locker(RECORD_CFG_LOCK)
    locker:lock()
	local record_cfg = read_from_file(RECORD_CFG)
    if record_cfg ~= nil then
		local lookup_cfg_old = read_from_file(LOOKUP_CFG)
        local lookup_cfg = {}
        local sel_dev
        for k, v in pairs(record_cfg) do
            sel_dev = is_online(v[1]) and v[1] or nil
            for i=1, #v do
                if v[i] == my_devid then
                    sel_dev = my_devid
                    break
                end
                if lookup_cfg_old ~= nil and lookup_cfg_old[k] ~= nil and lookup_cfg_old[k] == v[i] and is_online(v[i]) then
                    sel_dev = lookup_cfg_old[k]
                    break
                end
                if (not sel_dev or sel_dev < v[i]) and is_online(v[i]) then
                    sel_dev = v[i]
                end
            end
            lookup_cfg[k] = sel_dev
        end
        local tmp_table={}
        for k, v in pairs(lookup_cfg) do
            local tmp_cfg, tmp_ver = string.match(k, "(.+)_(%d)")
            if nil == tmp_table[tmp_cfg] then
                tmp_table[tmp_cfg] = {tmp_ver}
            else
                local tmp_item = tmp_table[tmp_cfg]
                tmp_item[#tmp_item+1] = tmp_ver
            end
        end
        for k, v in pairs(tmp_table) do
            if #v > 1 then
                local max = v[1]
                for i=1, #v do
                    if v[i] > max then
                        local cfg = k .. "_" .. max
                        lookup_cfg[cfg] = nil
                        max = v[i]
                    elseif v[i] < max then
                        local cfg = k .. "_" .. v[i]
                        lookup_cfg[cfg] = nil
                    end
                end
                --max_ver cfg's RE is major RE
                local cfg = k .. "_" .. max
                dbg(cfg, lookup_cfg[cfg])
                add_to_major(lookup_cfg[cfg])
            end
        end
		check_config_iot(lookup_cfg)
		res = write_to_file(LOOKUP_CFG, lookup_cfg)
    end
    locker:close()
    return res
end

local function check_opcode_iot(lookup_op)
	dbg("check_opcode_iot")
	local iot_fap_opcode = "0x4045"
	local iot_master_opcode = "0x4096"
	if lookup_op == nil then
		return
	end

	if lookup_op[iot_fap_opcode] == nil or lookup_op[iot_fap_opcode][1] == nil then
		dbg("fap has no iot")
		return
	end

	local iot_fap_devid = lookup_op[iot_fap_opcode][1]
	if lookup_op[iot_master_opcode] == nil or lookup_op[iot_master_opcode][1] == nil then
		dbg("there is no iot-master")
		sys.fork_exec("/usr/lib/lua/notify-iot-role " .. iot_fap_devid)
		return
	end

	local iot_master_devid = lookup_op[iot_master_opcode][1]
	if iot_fap_devid == iot_master_devid then
		dbg("iot fap and iot master is the same(%s)" % iot_fap_devid)
		sys.fork_exec("/usr/lib/lua/notify-iot-role " .. iot_fap_devid)
		return
	end

	dbg("iot mix network!!!")
    uci_r:set_confdir("/etc/profile.d")
    local iot_op_tbl = uci_r:get("opcode-iot", "opcode", "op")
    uci_r:set_confdir("/etc/config")
	if iot_op_tbl == nil then
		dbg("there is no such file:/etc/profile.d/opcode-iot")
		return
	end

	local id_list = {}
	table.insert(id_list, iot_master_devid)
	local len = #iot_op_tbl
	for i = 1, len do
		local iot_op = iot_op_tbl[i]
		if lookup_op[iot_op] ~= nil then
			lookup_op[iot_op] = nil
			lookup_op[iot_op] = id_list
		end
	end

	sys.fork_exec("/usr/lib/lua/notify-iot-role " .. iot_master_devid)

	dbg("now replace iot-fap(%s) with iot-master(%s)" % {iot_fap_devid, iot_master_devid})
end

local function op_to_lookup_table()
	local res = false
    local locker = Locker(RECORD_OP_LOCK)
    locker:lock()
	local record_op = read_from_file(RECORD_OP)
	local record_op_cfg = read_from_file(RECORD_OPCODE_CFG)
	local lookup_cfg = read_from_file(LOOKUP_CFG)
    if record_op ~= nil then
		local lookup_op_old = read_from_file(LOOKUP_OP)
        local lookup_op = {}
        local fp = io.open(LOOKUP_OP_RE_ONLY, "w+")
        for op, v in pairs(record_op) do
            local op_support = false
            for i=1, #v do
                if is_online(v[i]) then
                    op_support = true
                    break
                end
            end
            if op_support then
                sel_opcode = record_op_cfg[op]
                local id_list = {}
                if sel_opcode ~= nil then
                    local id_list_tmp = {}
                    for i=1, #sel_opcode do--for all cfg the opcode may use,find major devid
                        for cfg, id in pairs(lookup_cfg) do
                            local tmp = string.match(cfg, "(.+)_%d")
                            if tmp == sel_opcode[i] then
                                table.insert(id_list_tmp, id)
                                break
                            end
                        end
                    end
                    if #id_list_tmp > 1 then
                        local tmp = {}
                        local devid
                        for i=1, #id_list_tmp do
                            devid = id_list_tmp[i]
                            if tmp[devid] == nil then
                                tmp[devid] = devid
                            end
                        end
                        for k, v in pairs(tmp) do
                            table.insert(id_list, k)
                        end
                    else--<=1
                        local is_in_record_op = false
                        for i=1, #v do
                            if v[i] == id_list_tmp[1] then
                                is_in_record_op = true
                                break
                            end
                        end
                        if is_in_record_op == false then
                            local sel_dev = is_online(v[1]) and v[1] or nil
                            for i=1, #v do
                                if v[i] == my_devid then
                                    sel_dev = my_devid
                                    break
                                end
                                if lookup_op_old ~= nil and lookup_op_old[op] ~= nil and lookup_op_old[op][1] == v[i] and is_online(v[i]) then
                                    sel_dev = lookup_op_old[op][1]
                                    break
                                end
                                if (not sel_dev or sel_dev < v[i]) and is_online(v[i]) then
                                    sel_dev = v[i]
                                end
                            end
                            if op and id_list_tmp[1] and sel_dev then
                                dbg("Warning! op[" .. op .. "]" .. json.encode(sel_opcode) .. " is not supported by dev[" .. id_list_tmp[1] ..  "] so select dev[" .. sel_dev .. "]")
                            end
                            if sel_dev then
                                table.insert(id_list, sel_dev)
                            end
                        else
                            id_list = id_list_tmp
                        end
                    end
                else
                    -- opcode has nothing to do with user-config
                    local sel_dev = is_online(v[1]) and v[1] or nil
                    for i=1, #v do
                        if v[i] == my_devid then
                            sel_dev = my_devid
                            break
                        end
                        if lookup_op_old ~= nil and lookup_op_old[op] ~= nil and lookup_op_old[op][1] == v[i] and is_online(v[i]) then
                            sel_dev = lookup_op_old[op][1]
                            break
                        end
                        if (not sel_dev or sel_dev < v[i]) and is_online(v[i]) then
                            sel_dev = v[i]
                        end
                    end
                    if sel_dev then
                        table.insert(id_list, sel_dev)
                    end
                end
                lookup_op[op] = (#id_list > 0) and id_list or nil
                --dbg(op, json.encode(id_list))
                add_to_major(id_list)
                if #id_list > 0 and not string.find(json.encode(id_list), my_devid) and fp then
                    fp:write(op .. "\n")
                end
            else
                --dbg(op, "now no online dev support")
            end
        end
		check_opcode_iot(lookup_op)
		res = write_to_file(LOOKUP_OP, lookup_op)

        if fp then
            fp:close()
        end
    end
    locker:close()
    return res
end

function whole_comp_valid( devs, online_devid , whole_comp_type)
    local comp_record_online_num = 0
    if not whole_comp_type then
        whole_comp_type = 0
    end

    if not devs then
        return false
    end
    if not online_devid then
        local online_devid_data = read_from_file(RECORD_DEVID) or {}
        online_devid = {}
        for i=1, #online_devid_data do
            online_devid[online_devid_data[i]] = 1
        end
        online_dev_num = #online_devid_data
    end

    for k,v in pairs(devs) do
        if online_devid[v] then
            comp_record_online_num = comp_record_online_num + 1
        end
    end
    
    if whole_comp_type == TYPE_WHOLE_IGNORE_AP then--在线设备数减去FAP自己
        online_dev_num = online_dev_num - 1
    elseif whole_comp_type == TYPE_WHOLE_RE then
        if online_dev_num < 2 then --只要在线设备>=2，必有RE支持
            return false
        end
    end
    if comp_record_online_num == online_dev_num then
        return true
    else
        return false
    end

end

local function select_component_ver_lookup_dev(devs, base_re)
    if not devs then
        return nil
    end
    local sel_dev
    local ap_support = false
    for i=1, #devs do
        if devs[i] == my_devid then
            if not base_re then
                sel_dev = my_devid
                break
            else
                ap_support = true
            end
        elseif (not sel_dev or sel_dev < devs[i]) and is_online(devs[i]) then
            sel_dev = devs[i]
        end
    end
    return sel_dev, ap_support
end

local function component_to_lookup_table(data_type)
    if data_type == TYPE_COMPONENT_ROUTER_OWNER then
        record_file = RECORD_COMPONENT_ROUTER_OWNER
        lookup_file = LOOKUP_COMPONENT_ROUTER_OWNER
    elseif data_type == TYPE_COMPONENT_ROUTER_USER then
        record_file = RECORD_COMPONENT_ROUTER_USER
        lookup_file = LOOKUP_COMPONENT_ROUTER_USER
    elseif data_type == TYPE_COMPONENT_AP_OWNER then
        record_file = RECORD_COMPONENT_AP_OWNER
        lookup_file = LOOKUP_COMPONENT_AP_OWNER
    elseif data_type == TYPE_COMPONENT_AP_USER then
        record_file = RECORD_COMPONENT_AP_USER
        lookup_file = LOOKUP_COMPONENT_AP_USER
    end
	local res = false
    local locker = Locker(RECORD_COMPONENT_LOCK)
    locker:lock()
	local record_component = read_from_file(record_file)
    local record_whole = read_from_file(RECORD_COMPONENT_WHOLE)
    local record_devid = read_from_file(RECORD_DEVID)
    local uci_p = uci.new_cursor()
    uci_p:set_confdir("/etc/profile.d") 
    local record_ap_ignore = uci_p:get_all("component-ap-ignore", "list")
    local record_ap_re_support = read_from_file(RECORD_COMPONENT_AP_RE_SUPPORT)
    local record_whole_ignore_ap = read_from_file(RECORD_COMPONENT_WHOLE_IGNORE_AP)
    local record_whole_re = read_from_file(RECORD_COMPONENT_WHOLE_RE)

    if record_component ~= nil then
        local lookup_component = {}
        for com, vers in pairs(record_component) do
            if vers ~= nil then
                local max_ver = "0"
                local major_dev
                local is_ap_ignore_comp = is_in_comp_list(com, record_ap_ignore)
                local is_ap_re_support_comp = is_in_comp_list(com, record_ap_re_support)
                local ap_support = false
                local base_re = false
                if is_ap_ignore_comp or is_ap_re_support_comp then
                    base_re = true
                end
                for ver, devs in pairs(vers) do
                    if tonumber(ver) > tonumber(max_ver) then
                        local ver_ap_support
                        major_dev, ver_ap_support = select_component_ver_lookup_dev(devs, base_re)
                        ap_support = ap_support or ver_ap_support
                        if major_dev then
                            max_ver = ver
                        end
                    end
                end

                if is_ap_re_support_comp and not ap_support then
                    max_ver = "0"
                end

                if 0 ~= tonumber(max_ver) then
                    local item = {["id"]=com, ["ver_code"]=max_ver}
                    table.insert(lookup_component, item)
                    add_to_major(major_dev)
                else
                    dbg(com, " component now has no online dev support !")
                end
            end
        end

        if is_nil_table(record_whole) == false then
            if not whole_valid_component then
                whole_valid_component = {}
                for com, vers in pairs(record_whole) do
                    if vers ~= nil then
                        for ver, devs in pairs(vers) do
                            if whole_comp_valid(devs, online_devid) then
                                local item = {["id"]=com, ["ver_code"]=ver}
                                table.insert(lookup_component, item)
                                table.insert(whole_valid_component, item)
                                dbg(com, "select")
                            end
                        end
                    end
                end
            else
                for k,item in pairs(whole_valid_component) do
                    table.insert(lookup_component, item)
                end
            end
        end
        if is_nil_table(record_whole_ignore_ap) == false then
            for com, vers in pairs(record_whole_ignore_ap) do
                if vers ~= nil then
                    for ver, devs in pairs(vers) do
                        if whole_comp_valid(devs, online_devid, TYPE_WHOLE_IGNORE_AP) then
                            local item = {["id"]=com, ["ver_code"]=ver}
                            table.insert(lookup_component, item)
                            add_to_major(devs[1])
                        end
                    end
                end
            end
        end
        if is_nil_table(record_whole_re) == false then
            for com, vers in pairs(record_whole_re) do
                if vers ~= nil then
                    for ver, devs in pairs(vers) do
                        if whole_comp_valid(devs, online_devid, TYPE_WHOLE_RE) then -- makesure not only fap support
                            local item = {["id"]=com, ["ver_code"]=ver}
                            table.insert(lookup_component, item)
                        end
                    end
                end
            end
        end

		res = write_to_file(lookup_file, lookup_component)
    end
    locker:close()
    return res
end

local function is_in_record(devid)
    local record_devid = read_from_file(RECORD_DEVID)
    if record_devid==nil then
        return false
    end
    for i=1,#record_devid do
        if record_devid[i] == devid then
            return true
        end
    end
    return false
end


function delete_max_record(data)
    if nil==data or type(data)~="table" then
        return false
    end
    local lock_file = MAX_RECORD_LOCK
    local record_file = MAX_RECORD
    local locker = Locker(lock_file)
    locker:lock()
    
    local record_data = read_from_file(record_file)
    if record_data==nil then
        return false
    end

    for i=1,#data do
        if record_data[data[i]] then
            record_data[data[i]] = nil
            dbg("delete max record:", data[i])
        end
    end
    res = write_to_file(record_file, record_data)
    locker:close()
    return res
end



function add_to_max_record(data)
    if nil==data or nil==data.devid or nil==data.ip then
        return false
    end
    local lock_file = MAX_RECORD_LOCK
    local record_file = MAX_RECORD
    local locker = Locker(lock_file)
    locker:lock()
    
    local record_data = read_from_file(record_file)
    if record_data==nil then
        record_data={}
    end

    --check old?
    local fw_version = "0"
    local ubus   = require "ubus"
    local _ubus = ubus.connect(nil, 20)
    local args = {}
    local result = _ubus:call("sync", "list", args) 
    _ubus:close()

    if result and result[data.devid] then
        fw_version = result[data.devid].fw_version
        -- 旧固件，不记录在max_record，离线后删除完整信息
        if result[data.devid].comp_ver == nil or result[data.devid].comp_ver < 1 then
            dbg("old fw, don't add to max_record")
            return true
        end
    end
    local dev_info = {}
    dev_info.fw_version = fw_version
    record_data[data.devid] = dev_info

    res = write_to_file(record_file, record_data)
    locker:close()
    return res
end

function check_comp_whole_leave()
    local lock_file, record_file = get_lock_record_file(TYPE_COMPONENT_WHOLE)
    local locker = Locker(lock_file)
    locker:lock()
    local record_data_whole = read_from_file(record_file)
    locker:close()
    local record_dev_id = read_from_file(RECORD_DEVID)
    local comp_whole_leave_module = require("comp_whole_leave")
    comp_whole_leave_module.check_if_comp_whole_leave(record_data_whole, record_dev_id)
end

function add_to_table_record(data)
    if nil==data or nil==data.devid or nil==data.ip or nil==data.op or nil==data.cfg or nil==data.opcode_cfg or nil==data.component_router_owner or nil==data.component_router_user or nil==data.component_ap_owner or nil==data.component_ap_user then
        return false
    end
    if is_in_record(data.devid) then
        dbg("Error! Already in record_devid, do nothing " .. data.devid)
        return false
    end
    local id_list = {data.devid}
	local res1 = add_to_record(data.op, data.devid, TYPE_OP)
    local res2 = add_to_record(data.cfg, data.devid, TYPE_CFG)
    local res3 = add_to_record(data.component_router_owner, data.devid, TYPE_COMPONENT_ROUTER_OWNER)
    local res4 = add_to_record(data.component_router_user, data.devid, TYPE_COMPONENT_ROUTER_USER)
    local res5 = add_to_record(data.component_ap_owner, data.devid, TYPE_COMPONENT_AP_OWNER)
	local res6 = add_to_record(data.component_ap_user, data.devid, TYPE_COMPONENT_AP_USER)
	local res7 = add_to_record(data.opcode_cfg, data.devid, TYPE_OPCODE_CFG)
	local res8 = add_to_record(id_list, data.devid, TYPE_DEVID)
    local res9 = add_to_record({data.ip}, data.devid, TYPE_CHECK_DEV)
    local res10 = true
    if nil~=data.opcode_re_first then
        res10 = add_to_record(data.opcode_re_first, data.devid, TYPE_OPCODE_RE_FIRST)
    end
    local res11 = true
    if data.component_ap_re_support ~= nil then
        res11 = add_to_record(data.component_ap_re_support, data.devid, TYPE_COMPONENT_AP_RE_SUPPORT)
    end
    if data.component_whole_ignore_ap ~= nil then
        res11 = res11 and add_to_record(data.component_whole_ignore_ap, data.devid, TYPE_COMPONENT_WHOLE_IGNORE_AP)
    end
    if data.component_whole_re ~= nil then
        res11 = res11 and add_to_record(data.component_whole_re, data.devid, TYPE_COMPONENT_WHOLE_RE)
    end

    if nil~=data.opcode_re_first then
        res10 = add_to_record(data.opcode_re_first, data.devid, TYPE_OPCODE_RE_FIRST)
    end
    if data.component_whole_ap ~= nil and data.component_whole_router ~= nil then
        local sysmode = uci_r:get("sysmode", "sysmode", "mode")
        if sysmode and sysmode:upper() == "AP" then
            dbg("find 2 type component_whole, use component_whole_ap")
            data.component_whole = data.component_whole_ap
        else
            dbg("find 2 type component_whole, use component_whole_router")
            data.component_whole = data.component_whole_router
        end
    end

    if data.component_whole_ap ~= nil and data.component_whole_router ~= nil then
        local sysmode = uci_r:get("sysmode", "sysmode", "mode")
        if sysmode and sysmode:upper() == "AP" then
            dbg("find 2 type component_whole, use component_whole_ap")
            data.component_whole = data.component_whole_ap
        else
            dbg("find 2 type component_whole, use component_whole_router")
            data.component_whole = data.component_whole_router
        end
    end

    if data.component_whole_ap ~= nil and data.component_whole_router ~= nil then
        local sysmode = uci_r:get("sysmode", "sysmode", "mode")
        if sysmode and sysmode:upper() == "AP" then
            dbg("find 2 type component_whole, use component_whole_ap")
            data.component_whole = data.component_whole_ap
        else
            dbg("find 2 type component_whole, use component_whole_router")
            data.component_whole = data.component_whole_router
        end
    end

    if data.component_whole ~= nil then
        local res = add_to_record(data.component_whole, data.devid, TYPE_COMPONENT_WHOLE)
        if res == false then
            if delete_table_record(id_list) == false then
                dbg("Error! delete_table_record " .. json.encode(id_list))
            end
            return false
        end
        -- check if a component-whole component is invalid
        check_comp_whole_leave()
    end
    if res1==false or res2==false or res3==false or res4==false or res5==false or res6==false or res7==false or res8==false or res9==false or res10==false or res11==false then
        if delete_table_record(id_list) == false then
            dbg("Error! delete_table_record " .. json.encode(id_list))
        end
        return false
    end
    return true
end

function delete_table_record(dev_list)
    if nil == dev_list then
        return false
    end
    local res1 = delete_from_record(dev_list, TYPE_OP)
    local res2 = delete_from_record(dev_list, TYPE_CFG)
    local res3 = delete_from_record(dev_list, TYPE_COMPONENT_ROUTER_OWNER)
	local res4 = delete_from_record(dev_list, TYPE_COMPONENT_ROUTER_USER)
	local res5 = delete_from_record(dev_list, TYPE_COMPONENT_AP_OWNER)
	local res6 = delete_from_record(dev_list, TYPE_COMPONENT_AP_USER)
    local res7 = delete_from_record(dev_list, TYPE_DEVID)
    local res8 = delete_from_record(dev_list, TYPE_COMPONENT_WHOLE)
    local res9 = true
    if nixio.fs.access(RECORD_OPCODE_RE_FIRST) then
        res9 = delete_from_record(dev_list, TYPE_OPCODE_RE_FIRST)
    end
    local res10 = delete_from_record(dev_list, TYPE_COMPONENT_AP_RE_SUPPORT)
    local res11 = delete_from_record(dev_list, TYPE_COMPONENT_WHOLE_IGNORE_AP)
    local res12 = delete_from_record(dev_list, TYPE_COMPONENT_WHOLE_RE)
    local mode = require "luci.model.mode"
    if mode.is_usb_control_support() then
        remove_usb_status(dev_list)
    end

    if res1 == false or res2 == false or res3 == false or res4 == false or res5 == false or res6 == false or res7 == false or res8 == false or res9 == false or res10 == false or res11 == false or res12 == false then
        return false
    end
    return true
end

function record_to_lookup_table()
    local locker = Locker(LOOKUP_LOCK)
    locker:lock()
    local res1 = cfg_to_lookup_table()
    local res2 = op_to_lookup_table()
    local res3 = component_to_lookup_table(TYPE_COMPONENT_ROUTER_OWNER)
	local res4 = component_to_lookup_table(TYPE_COMPONENT_ROUTER_USER)
	local res5 = component_to_lookup_table(TYPE_COMPONENT_AP_OWNER)
	local res6 = component_to_lookup_table(TYPE_COMPONENT_AP_USER)
    if res1==false or res2==false or res3==false or res4==false or res5==false or res6==false then
        locker:close()
        return false
    end
    --new
    save_to_major()
    os.remove(CLOUD_FEATURE_UPLOAD)
    os.execute("cloud_status_check & >/dev/null 2>&1")
    locker:close()
	os.execute("mix_network_check")
    return true
end

function get_update_ip_item()
    local update_cfg = {}
    local update_ip = {}
    local locker = Locker(TMP_CHECK_DEV_LOCK)
    locker:lock()
	local check_dev = read_from_file(TMP_CHECK_DEV)
	os.remove(TMP_CHECK_DEV)
	locker:close()
    if check_dev ~= nil then
		local lookup_cfg = read_from_file(LOOKUP_CFG)
        for ip, id in pairs(check_dev) do
            for cfg, l_id in pairs(lookup_cfg) do
                if id == l_id then
                    update_cfg[cfg] = ip
                end
            end
        end
        for cfg, ip in pairs(update_cfg) do
            local ip_item = update_ip[ip]        
            if ip_item == nil then
                ip_item = {cfg}
                update_ip[ip] = ip_item
            else
                ip_item[#ip_item + 1] = cfg
            end
        end
    end
	if is_nil_table(update_ip) then
		return nil
	end
    local locker = Locker(TMP_UPDATE_INFO_IP_LOCK)
    locker:lock()
	write_to_file(TMP_UPDATE_INFO_IP, update_ip)
    locker:close()

    local ip_devid = {}
    for ip, cfgs in pairs(update_ip) do
		for dev_ip, dev_id in pairs(check_dev) do
			if ip == dev_ip and dev_id ~= my_devid then
				ip_devid[ip] = dev_id
				break
			end
		end
    end
    return ip_devid
end

local function get_subcfg(cfg_name)
    local data = {}
    local files = config.get_allcfgname()
    local uci_r = uci.new_cursor()
    for _, file in pairs(files) do
        if string.match(file, "(.+)_%d") == string.match(cfg_name, "(.+)_%d") then
            local etc_cfg_name = config.set_subcfg(file)
            data = uci_r:get_all(etc_cfg_name)
            return data, file
        end
    end
    return nil, nil
end

-- note:
-- files = config.get_allcfgname()
local function get_subcfg_whit_cfgfiles(cfg_name, files)
    local data = {}
    local uci_r = uci.new_cursor()
    for _, file in pairs(files) do
        if string.match(file, "(.+)_%d") == string.match(cfg_name, "(.+)_%d") then
            local etc_cfg_name = config.set_subcfg(file)
            data = uci_r:get_all(etc_cfg_name)
            return data, file
        end
    end
    return nil, nil
end

function get_cfgs(ip)
	local cfgs_item = {}
	local data = {}
    local locker = Locker(TMP_UPDATE_INFO_IP_LOCK)
    locker:lock()
	local update_ip = read_from_file(TMP_UPDATE_INFO_IP)
	locker:close()
    for ip_item, cfgs in pairs(update_ip) do
        if ip_item == ip then
            cfgs_item = cfgs
        end
    end
    if is_nil_table(cfgs_item) then
        return data
    end
    locker = Locker(sync.CONFIG_LOCK)
    locker:lock()

    local files = config.get_allcfgname()

    for i=1, #cfgs_item do
        local sub_cfg = cfgs_item[i]
        -- Function get_subcfg calls config.get_allcfgname() everytime, waste a lot of time,
        -- So read files before for loop, and call get_subcfg_whit_cfgfiles to handle.
        -- before modify: It takes up a lot of CPU for 21s+.
        -- after modify: It takes up a lot of CPU for < 5s.
        -- local info, cfg = get_subcfg(sub_cfg)
        local info, cfg = get_subcfg_whit_cfgfiles(sub_cfg, files)
        if info then
            if is_nil_table(info) then
                local flag = {empty_cfg = 1}
                data[cfg] = flag
            else
                data[cfg] = info
            end
        else
            data[sub_cfg] = {}
        end
    end
    locker:close()
    return data
end

function add_to_merge_cfgs(data)
    local add_cfgs = data.cfg
	local res = false
    if nil == add_cfgs then
        return res
    end
    local locker = Locker(TMP_MERGE_CFGS_LOCK)
    locker:lock()
	local merge_cfgs = read_from_file(TMP_MERGE_CFGS)
    if is_nil_table(merge_cfgs) then
        merge_cfgs = {}
    end
    for k, v in pairs(add_cfgs) do
        merge_cfgs[k] = v
    end
	res = write_to_file(TMP_MERGE_CFGS, merge_cfgs)
    locker:close()
    return res
end

function get_update_user_config()
    local locker = Locker(TMP_MERGE_CFGS_LOCK)
    locker:lock()
	local merge_cfgs = read_from_file(TMP_MERGE_CFGS)
    os.remove(TMP_MERGE_CFGS)
    locker:close()
    return merge_cfgs
end

local function update_list(tmpcli)
    local record_dev_list = read_from_file(TMP_RECORD_DEV_LIST)
    data, msg = tmpcli:request("SYNC_UPDATE_DEV_LIST", json.encode{
                                   params = {
                                       group_id = group.gid,
                                       master_devid = my_devid,
                                       data = record_dev_list
                                   }
    })
    data, msg = script.check_tmp_data(data, msg)
    if not data then
        return nil, msg
    end
    return true
end

function update_dev_list()
    local record_devid = read_from_file(RECORD_DEVID)
    local mesh_dev_list = read_from_file(MESH_DEV_LIST)
    if is_nil_table(record_devid) or is_nil_table(mesh_dev_list) then
        dbg("[update_dev_list]error: record_devid or mesh_dev_list is nil, do nothing")
        return
    end
    local record_dev_list = {}
    local arg = {}
    for i=1, #record_devid do
        local devid = record_devid[i]
        if mesh_dev_list[devid] ~= nil then
            record_dev_list[devid] = mesh_dev_list[devid]
            table.insert(arg, mesh_dev_list[devid]["ip"])
            table.insert(arg, "1")
        else
            dbg("no find " .. record_devid[i])
        end
    end
    local res = write_to_file(TMP_RECORD_DEV_LIST, record_dev_list)
    if res == true then
        local num = tonumber(#arg/2)
        dbg(" Total %d devices need to update dev list" % num)
        local data = script.iterate_request(update_list, "SYNC_UPDATE_DEV_LIST", nil, nil, arg, 1, #arg)
        if data.errmsg then
          dbg("Warning: collected errors:", data.errmsg)
        end
        dbg("Total %d devices were update dev list successfully" % data.success)
    end
    os.remove(TMP_RECORD_DEV_LIST)
end

function update_re_offline_dev_list()
    local record_devid = read_from_file(RECORD_DEVID)

    if is_nil_table(record_devid) then
        dbg("[update_re_offline_dev_list]error: record_devid is nil, do nothing")
        return
    end

    local offline_id_list = {}
    uci_r:foreach("bind_device_list", "device",
    function(section)
        local idx = 0
        for i,rdevid in ipairs(record_devid) do
            if rdevid == section['.name'] then
                idx = i
                break
            end
        end

        if idx == 0 then
            table.insert(offline_id_list, section['.name'])
        end
    end
    )

    if #offline_id_list > 0 then
        local args = {}
        local data = {}

        data.params = {}
        data.params.data = {}
        data.params.data.offline_id_list = offline_id_list

        args.opcode = tonumber(0xc710)
        args.target_type = "RE"
        args.data = data

        local _ubus_c = ubus.connect()
        _ubus_c:call("sync", "request", args)
        _ubus_c:close()
    end
end

function update_usb_status(data)
    local mode = require "luci.model.mode"
    if data.usb then
        if mode.is_usb_control_support() then
            local usb_sync = require "luci.model.usb_sync"
            local usb_status = {}
            usb_status.ip = data.ip
            usb_status.svrname = data.usb.svrname
            usb_sync.update_usb_status(data.devid, usb_status)
        end
    end
end

#!/usr/bin/lua

local dbg = require "luci.tools.debug"
local nixio = require "nixio"
local fs = require "nixio.fs"
local json = require "luci.json"
local sync = require "luci.model.sync"
local update = require "update-info"
local status = require "luci.tools.status"
local Locker = require("luci.model.locker").Locker

local TO_DELETE_INFO = "/tmp/sync-server/to_delete_info"
local RECORD_DEVID = "/var/run/record_devid"

local TO_DELETE_INFO_LOCK = "/tmp/sync-server/to_delete_info.lock"

local safe_mem = 25 * 1024

local function cpu_is_busy()
	local mpstat_fd = io.popen("mpstat -P ALL | awk '/all/{print $12}'")
	local cpu_idle 
	local cpu_threshold = 50
	local fs = require "nixio.fs"
	if mpstat_fd then
		cpu_idle = mpstat_fd:read("*n")
		mpstat_fd:close()
		-- dbg("cpu idle :"..cpu_idle)
		if cpu_idle < cpu_threshold then
			return true
		end
	end
	return false
end

local function mem_is_less()
	local memfree = status.get_memfree()
	-- dbg("mem_free:", memfree)
	if tonumber(memfree) < safe_mem then
		return true
	else
		return false
	end
end

local function read_from_file(file)
	local fp = io.open(file, "r")
	local data = nil
	if fp == nil then
		-- dbg("error open file failed:" .. file)
	else
		local lines = fp:read("*all")
		fp:close()
		data = json.decode(lines)
	end
	return data
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

local function remove_repeat_dev( to_delete_info )
	local tmp = {}
	local res = {}
	for _,id in pairs(to_delete_info) do
		tmp[id] = 1
	end
	for id,_ in pairs(tmp) do
		table.insert(res, id)
	end
	return res
end

local function rm_online_dev( to_delete_info , online_dev)
	local res = {}
	for _,id in pairs(to_delete_info) do
		local is_online = false
		for _,online_id in pairs(online_dev) do
			if id == online_id then
				dbg("to_delete_info dev %s find in record_devid again, dont delete", id)
				is_online = true
				break
			end
		end
		if not is_online then
			table.insert(res, id)
		end
	end
	return res
end

local function main()
	if sync.get_role() ~= "AP" or cpu_is_busy() or mem_is_less() then
		return 0
	end

	local locker = Locker(TO_DELETE_INFO_LOCK)
	locker:lock()
	local to_delete_info = read_from_file(TO_DELETE_INFO)
	if not to_delete_info then
		print("no to delete info dev")
		return 0
	end

	to_delete_info = remove_repeat_dev(to_delete_info)
	dbg(json.encode(to_delete_info))
	local online_devid = read_from_file(RECORD_DEVID)
	local need_delete_info = rm_online_dev(to_delete_info, online_devid)

	dbg("cpu idle! delete record:", json.encode(need_delete_info))
	if need_delete_info and update.delete_table_record(need_delete_info) == false then
		dbg("Error! delete_table_record " .. json.encode(need_delete_info))
		if #need_delete_info ~= #to_delete_info then
			write_to_file(TO_DELETE_INFO, need_delete_info)
		end
	else
		dbg("delete_table_record success or don't need to delete")
		os.execute("rm "..TO_DELETE_INFO)
		update.delete_max_record(need_delete_info)
	end
	locker:ulock()
end

main()
module("sync-script", package.seeall)

local util = require "luci.util"
local json = require "luci.json"
local ltn12 = require "luci.ltn12"
local nixio = require "nixio"
local dbg = require "luci.tools.debug"
local f_debug = nil

infile = "/dev/null"
outfile = "/dev/null"
tmpcli_short = false

function sync_debug(err_msg)
    if not err_msg then
        return 0
    end

    if f_debug then
        dbg.print("[sync_debug-"..nixio.getpid().."]:"..err_msg)
    end
    return 0
end

function read_infile(file)
    file = file or infile
    local decoder = json.Decoder()
    local rc, err = ltn12.pump.all(ltn12.source.file(io.open(file, "rb")),
                                   decoder:sink())
    assert(rc, err)

    return decoder:get()
end

function check_tmp_data(data, msg)
    if not data then
        return nil, msg
    end

    data = json.decode(data)
    if data.error_code ~= 0 then
        return nil, data.msg
    end

    return data
end

function finalize(data)
    local encoder = json.Encoder(data)
    local rc, err = ltn12.pump.all(encoder:source(),
                                   ltn12.sink.file(io.open(outfile, "wb")))
    if not rc then
        dbg("ltn12 error:", err)
        os.exit(1)
    end

    os.exit(0)
end

function die(lastwords)
    local data = {
        success = -1,
        errmsg = lastwords
    }
    return finalize(data)
end

function run(main)
    local tb = nil
    local rc, msg = xpcall(main, function(e)
                               tb = debug.traceback()
                               return e
    end)
    if not rc then
        dbg("Error: Lua exception: " .. msg)
        dbg(tb)
        os.exit(1)
    end
end

function reduce(cb, args, b, e)
    b = b or 1
    e = e or #args

    local success = 0
    local result = {}
    local err = {}

    for i = b, e do
        local arg = args[i]
        local rc, data = cb(arg)
        if rc then
            success = success + 1
            result[#result+1] = data
        else
            err[#err+1] = data
        end
    end

    local total = e - b + 1
    local errmsg = nil
    if #err > 0 then
        errmsg = table.concat(err, ";")
    end

    if #result == 0 then
        result = nil
    elseif #result == 1 then
        result = result[1]
    end

    return {success = success, total = total, errmsg = errmsg, data = result}
end

function reduce_sequence(cb, opcode, args, b, e)
    local tmpv2 = require "tmpv2"
    return reduce(
        function(ip)
            local tmpcli = tmpv2.tmp_client(opcode, ip, nil, true, false, nil, nil)
            local rc, data = tmpcli:connect()
            if not rc then
                tmpcli:close()
                return nil, data
            end

            local rc, data = cb(tmpcli, ip)

            tmpcli:disconnect()
            tmpcli:close()
            return rc, data
        end,
        args, b, e)
end


function workers_run(cb, opcode, ip, isbind, usr, pwd, input, output)
    local tmpv2 = require "tmpv2"
    local user_auth = false;
    if isbind == "0" then 
        if not usr or not pwd then
            output:write(json.encode{rc = false, data = "invaild username or password"})
            input:close()
            output:close()
            os.exit(0)
        end
        user_auth = true; 
    end   


    local tmpcli
    if tmpcli_short then
        tmpcli = tmpv2.tmp_clishort(opcode, ip, nil, true, user_auth, usr, pwd)
    else
        tmpcli = tmpv2.tmp_client(opcode, ip, nil, true, user_auth, usr, pwd)
    end


    local rc, data = tmpcli:connect()
    if not rc then
        sync_debug("no rc, ip["..ip.."]write output pipe")
        output:write(json.encode{rc = false, data = data})

        sync_debug("no rc, ip["..ip.."]tmp close")
        tmpcli:close()
        sync_debug("no rc, ip["..ip.."]close input pipe")
        input:close()
        sync_debug("no rc, ip["..ip.."]close output pipe")
        output:close()
        sync_debug("no rc, ip["..ip.."]exit")
        os.exit(0)
    end

    sync_debug("ip["..ip.."]run tmp callback")
    local rc, data = cb(tmpcli, ip, input, output)
    sync_debug("ip["..ip.."]write output pipe")
    output:write(json.encode{rc = rc, data = data})

    sync_debug("ip["..ip.."]tmp disconnect")
    tmpcli:disconnect()
    sync_debug("ip["..ip.."]tmp close")
    tmpcli:close()
    sync_debug("ip["..ip.."]close input pipe")
    input:close()
    sync_debug("ip["..ip.."]close output pipe")
    output:close()
    sync_debug("ip["..ip.."]exit")
    os.exit(0)
end

function workers_create(cb, opcode, usr, pwd, args, b, e)
    local workers = {}
    
    for i = b, e, 2 do
        local worker = {ip = args[i], isbind = args[i+1]}
        workers[#workers+1] = worker

        local rfdi, rfdo = nixio.pipe()
        local wfdi, wfdo = nixio.pipe()

        local pid = nixio.fork()
        if pid == 0 then
            sync_debug("ip["..worker.ip.."]close rfdi pipe")
            rfdi:close()
            sync_debug("ip["..worker.ip.."]close wfdo pipe")
            wfdo:close()
            workers_run(cb, opcode, worker.ip, worker.isbind, usr, pwd, wfdi, rfdo)
            os.exit(1)
        elseif pid > 0 then
            rfdo:close()
            wfdi:close()

            worker.pid = pid
            worker.input = rfdi
            worker.output = wfdo
            worker.decoder = json.ActiveDecoder(function()
                    local chunk = worker.input:read(2048)
                    if chunk and #chunk > 0 then
                        return chunk
                    end
            end)
        else
            worker.error = "failed to fork"
        end
    end

    return workers
end

function workers_join(workers)
    for _, worker in ipairs(workers) do
        if not worker.error then
            local rc, result = pcall(worker.decoder.get, worker.decoder)
            if rc then
                if result.rc then
                    worker.data = result.data
                else
                    worker.error = result.data or "unknown error"
                end
            else
                worker.error = result or "unknown error"
            end
        end
    end
end

function workers_cleanup(workers)
    for _, worker in ipairs(workers) do
        if worker.input then
            worker.input:close()
        end
        if worker.output then
            worker.output:close()
        end
        worker.decoder = nil

        if not worker.error then
            local pid, stat, code = nixio.waitpid(worker.pid)
            if pid ~= worker.pid or stat ~= "exited" or code ~= 0 then
                worker.error = "process failure"
            end
        end
    end
end

function workers_reduce(workers)
    return reduce(
        function(worker)
            if worker.error then
                dbg("worker error:", worker.ip, worker.error)
                return nil, worker.error
            else
                return true, worker.data
            end
        end, workers)
end

function reduce_concurrent(cb, opcode, usr, pwd, args, b, e)
    f_debug = io.open("/tmp/request_debug", "r")
    local workers = workers_create(cb, opcode, usr, pwd, args, b, e)
    workers_join(workers)
    workers_cleanup(workers)
    if f_debug then
        f_debug:close()
        f_debug = nil
    end
    return workers_reduce(workers)
end

function iterate_request(cb, opcode, usr, pwd, args, b, e)
    local tmpv2 = require "tmpv2"
    local workers = {}
    for i = b, e, 2 do
        local ip = args[i]
        local isbind = args[i+1]
        local user_auth = false;
        if isbind == "0" then
            user_auth = true;
        end
        local tmpcli = tmpv2.tmp_client(opcode, ip, nil, true, user_auth, usr, pwd)
        local rc, data = tmpcli:connect()
        local worker = {}
        if not rc then
            worker.error = data or "unknown error"
        else
            rc, data = cb(tmpcli, ip, input, output)
            if not rc then
                worker.error = data or "unknown error"
            else
                worker.data = data
            end
            tmpcli:disconnect()
        end
        tmpcli:close()
        workers[#workers+1] = worker
    end
    return workers_reduce(workers)
end

--[[

    tests/unit/i2p_network_boundary_test.lua

    Locks the two paths that would otherwise let a Lua plugin bypass the
    local SAM forwarder: the legacy HTTP(S) helper and raw LuaSocket /
    LuaSec constructors. The test uses the real policy and scripts module,
    but deliberately plants unsafe globals behind the plugin sandbox.

    Run: lua5.4 tests/unit/i2p_network_boundary_test.lua

]]--

local failures, checks = 0, 0
local function check( label, condition )
    checks = checks + 1
    if condition then
        io.write( "ok   " .. label .. "\n" )
    else
        failures = failures + 1
        io.write( "FAIL " .. label .. "\n" )
    end
end

local policy = assert( loadfile( "core/i2p_policy.lua" ) )( )
local allowed, denied_reason = policy.outbound_http_allowed( )
check( "I2P policy denies outbound HTTP", allowed == false )
check( "I2P policy has a useful reason",
       denied_reason == "I2P-only hub: outbound HTTP(S) is disabled" )

local socket_calls = 0
local timer_calls = 0
local http_modules = {
    type = type, tostring = tostring, tonumber = tonumber,
    pcall = pcall, pairs = pairs, ipairs = ipairs,
    string = string, table = table, io = io, os = os,
    coroutine = coroutine, i2p_policy = policy,
    socket = {
        gettime = function( ) return 0 end,
        tcp = function( )
            socket_calls = socket_calls + 1
            error( "socket must not be created when I2P policy denies HTTP" )
        end,
    },
    ssl = { },
    out = { put = function( ) end, error = function( ) end },
    server = {
        addtimer = function( )
            timer_calls = timer_calls + 1
            error( "timer must not be scheduled when I2P policy denies HTTP" )
        end,
    },
}

_G.use = function( name )
    return http_modules[ name ]
end
local http_client = assert( loadfile( "core/http_client.lua" ) )( )
local queued, request_err = http_client.request {
    url = "https://example.invalid/",
}
check( "HTTP request denied before queueing", queued == false )
check( "HTTP request returns policy reason", request_err == denied_reason )
check( "HTTP denial creates no socket", socket_calls == 0 )
check( "HTTP denial schedules no timer", timer_calls == 0 )

local cfg_values = {
    scripts = { "i2p_sandbox_probe.lua" },
    script_path = "tests/unit/fixtures/",
    no_global_scripting = true,
}

local sandbox_modules = {
    type = type, error = error, pairs = pairs, pcall = pcall,
    ipairs = ipairs, loadfile = loadfile, tostring = tostring,
    setmetatable = setmetatable, io = io, os = os, table = table,
    _G = {
        assert = assert, error = error, ipairs = ipairs, next = next,
        pairs = pairs, pcall = pcall, print = print, select = select,
        tonumber = tonumber, tostring = tostring, type = type,
        xpcall = xpcall, setmetatable = setmetatable,
        getmetatable = getmetatable, collectgarbage = collectgarbage,
        table = table, math = math, coroutine = coroutine,
        socket = {
            gettime = function( ) return 1 end,
            tcp = function( ) error( "unsafe raw socket reached" ) end,
        },
        ssl = {
            wrap = function( ) error( "unsafe TLS wrapper reached" ) end,
            x509 = { load = function( ) return { } end },
        },
        http_client = {
            request = function( ) error( "unsafe raw HTTP helper reached" ) end,
        },
    },
    adclib = { },
    unicode = { utf8 = { sub = string.sub } },
    socket = {
        gettime = function( ) return 1 end,
        tcp = function( ) error( "unsafe raw socket reached" ) end,
    },
    ssl = {
        wrap = function( ) error( "unsafe TLS wrapper reached" ) end,
        x509 = { load = function( ) return { } end },
    },
    adc = { },
    cfg = {
        get = function( key ) return cfg_values[ key ] end,
    },
    out = {
        error = function( ) end,
        setlistener = function( ) end,
    },
    mem = { free = function( ) end },
    util = {
        checkfile = function( path )
            local f = io.open( path, "rb" )
            if not f then return nil, "cannot read fixture" end
            local source = f:read( "*a" )
            f:close( )
            return source
        end,
        safe_path = function( ) return true end,
    },
    i2p_policy = policy,
}

_G.use = function( name )
    return sandbox_modules[ name ]
end
local scripts = assert( loadfile( "core/scripts.lua" ) )( )
scripts.init( )
scripts.start( { } )
local probe = scripts.import( "i2p_sandbox_probe" )

check( "sandbox probe loaded", type( probe ) == "table" )
check( "plugin cannot see raw socket constructor", probe and probe.raw_socket_exposed == false )
check( "plugin retains socket.gettime", probe and probe.socket_gettime_exposed == true )
check( "plugin cannot mutate socket shim", probe and probe.socket_writable == false )
check( "plugin cannot see LuaSec wrap", probe and probe.raw_ssl_exposed == false )
check( "plugin retains certificate parser", probe and probe.x509_load_exposed == true )
check( "plugin HTTP shim denies request", probe and probe.http_queued == false )
check( "plugin HTTP shim returns policy reason", probe and probe.http_error == denied_reason )

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )

local cid = string.rep("A", 39)
local policy = { bot_nick = "AudioGuard", enforce = true }
local targets, listeners = {}, {}
local kills, audits = 0, 0
PROCESSED = true
util = { loadtable = function() return policy end }
local function user(nick, level, registered, id)
    return {
        isregged = function() return registered end,
        regnick = function() return nick end,
        level = function() return level end,
        cid = function() return id or cid end,
        state = function() return "normal" end,
        isbot = function() return false end,
        reply = function(self, text) self.last_reply = text end,
        kill = function(_, message, reconnect)
            assert(message:find("Audio%-only"))
            assert(reconnect == "TL300")
            kills = kills + 1
        end,
    }
end
hub = {
    getbot = function() return {} end,
    issidonline = function(sid) return targets[sid] end,
    escapeto = function(text) return text end,
    setlistener = function(name, _, callback) listeners[name] = callback end,
    import = function() return { add = function(cmd, _, level, opts)
        assert(cmd == "audiokick" and level == 20 and opts.secret)
        return true
    end } end,
}
audit = { build = function(...) return {...} end, fire = function() audits = audits + 1 end }
local handler = assert(loadfile("scripts/etc_audio_guard.lua"))()._oncommand
listeners.onStart()
local bot = user("AudioGuard", 20, true)
targets.ABCD = user("Member", 20, true)
for _, actor in ipairs({ user("Other", 20, true), user("AudioGuard", 20, false), user("AudioGuard", 100, true) }) do
    handler(actor, nil, "ABCD " .. cid)
    assert(kills == 0)
end
for _, input in ipairs({ "ABCD " .. cid .. " extra", "AAA " .. cid, "ABCD ../bad", "ABCD " .. string.rep("B", 39) }) do
    handler(bot, nil, input)
    assert(kills == 0)
end
handler(bot, nil, "BCDE " .. cid)
assert(kills == 0)
targets.ABCD = bot
handler(bot, nil, "ABCD " .. cid)
assert(kills == 0)
targets.ABCD = user("Operator", 60, true)
handler(bot, nil, "ABCD " .. cid)
assert(kills == 0)
targets.ABCD = user("Bot", 20, true)
targets.ABCD.isbot = function() return true end
handler(bot, nil, "ABCD " .. cid)
assert(kills == 0)
targets.ABCD = user("Member", 20, true)
policy.enforce = false
handler(bot, nil, "ABCD " .. cid)
assert(kills == 0)
policy.enforce = true
util.loadtable = function() return nil end
handler(bot, nil, "ABCD " .. cid)
assert(kills == 0)
util.loadtable = function() return {bot_nick="Replacement", enforce=true} end
handler(bot, nil, "ABCD " .. cid)
assert(kills == 0)
util.loadtable = function() return policy end
for _ = 1, 8 do handler(bot, nil, "ABCD " .. cid) end
assert(kills == 6 and audits == 6)
assert(bot.last_reply:find("rate limited"))
print("PASS: authorization, identity/session binding, protected targets, audit mode, rate limit and kick reason")

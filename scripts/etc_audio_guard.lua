-- SPDX-License-Identifier: GPL-3.0-or-later
-- Optional, narrowly scoped companion for tools/audio-guard/guard.py.
-- The bot checks advertised names, not file contents or legality.
local policy = util.loadtable("cfg/audio_guard.tbl")
if not policy or type(policy.bot_nick) ~= "string" then return end

local reason = "Audio-only hub: remove unsupported files from your share before reconnecting. " ..
    "Text notes, playlists and audio metadata are allowed; images, videos, archives and executables are not. See +rules."
local minute, count = 0, 0

local function reply(user, text)
    user:reply("AudioGuard: " .. text, hub.getbot())
end

local function oncommand(user, _, parameters)
    if not user:isregged() or user:regnick() ~= policy.bot_nick or user:level() ~= 20 then
        reply(user, "denied")
        return PROCESSED
    end
    local sid, cid = tostring(parameters):match("^([A-Z2-7]+) ([A-Z2-7]+)$")
    if not sid or #sid ~= 4 or #cid ~= 39 then
        reply(user, "invalid target")
        return PROCESSED
    end
    local target = hub.issidonline(sid)
    if not target or target:cid() ~= cid or target:state() ~= "normal" then
        reply(user, "stale target")
        return PROCESSED
    end
    if target == user or target:isbot() or target:level() >= 50 then
        reply(user, "protected target")
        return PROCESSED
    end
    local live_policy = util.loadtable("cfg/audio_guard.tbl")
    if not live_policy or live_policy.bot_nick ~= policy.bot_nick or live_policy.enforce ~= true then
        reply(user, "audit mode; no disconnect")
        return PROCESSED
    end
    local now = math.floor(os.time() / 60)
    if now ~= minute then minute, count = now, 0 end
    if count >= 6 then
        reply(user, "rate limited")
        return PROCESSED
    end
    count = count + 1
    target:kill("ISTA 230 " .. hub.escapeto(reason) .. "\n", "TL300")
    audit.fire(audit.build("user.kick", user, target, "audio-only filename policy", nil))
    reply(user, "disconnected " .. sid .. " " .. cid)
    return PROCESSED
end

hub.setlistener("onStart", {}, function()
    local commands = assert(hub.import("etc_hubcommands"))
    assert(commands.add("audiokick", oncommand, 20, { secret = true }))
end)

return { _oncommand = oncommand }

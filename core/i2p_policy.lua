--[[

    i2p_policy.lua - non-configurable network policy for the I2P fork.

    The hub's public listener is reached through the local SAM forwarder.
    Plugins and core helpers must not create a second, clearnet egress path.
    Keep this policy deliberately small and non-configurable: changing a
    cfg.tbl value must never make outbound HTTP(S) available again.

]]--

local OUTBOUND_HTTP_DENIED = "I2P-only hub: outbound HTTP(S) is disabled"

local function outbound_http_allowed( )
    return false, OUTBOUND_HTTP_DENIED
end

return {
    outbound_http_allowed = outbound_http_allowed,
    outbound_http_denied  = OUTBOUND_HTTP_DENIED,
}

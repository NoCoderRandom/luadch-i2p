# Luadch-I2P Network Audit

## Status

This is a pre-implementation record. luadch-ng currently supports ordinary
network listeners and external HTTP functionality. It must not be presented as
an I2P-only hub until the controls below are implemented and tested.

## Final Allow List

| Operation | Final policy |
| --- | --- |
| SAM control and forwarding sockets | Allow only a configured loopback numeric endpoint, default `127.0.0.1:7656`. |
| ADC listener behind the forwarder | Allow only `127.0.0.1`; no wildcard or IPv6 listener. |
| I2P hub traffic | Allow through the live SAM session only. |
| Ordinary ADC listener exposure | Block. |
| UDP, NAT traversal and IP discovery | Block. |
| External HTTP, GeoIP, blocklist feeds, webhooks and reporting | Disable by default until a deliberate I2P-compatible design exists. |

## Inherited Call Sites Requiring Control

| Location | Capability | Required action |
| --- | --- | --- |
| `core/server.lua` | `luasocket.tcp4`, `luasocket.tcp6`, bind, listen and accept | Force loopback IPv4 in I2P mode and reject user configuration that widens the bind address. |
| `luasocket/src/*` | TCP, UDP and DNS primitives | Do not expose ordinary network operations to I2P transport or bundled I2P-mode scripts. |
| `core/adc.lua` | INF address fields and CTM/RCM/NAT/RNT parsing | Strip or reject `I4`, `I6`, `U4`, `U6` and IP-oriented transfer commands until their I2P replacements are enabled. |
| `core/hub_dispatch.lua` | Client-to-client ADC routing | Only relay negotiated I2P extension commands and reject incompatible peers. |
| `core/http_client.lua` | IPv4/IPv6 outbound HTTP sockets | Disable in I2P mode. |
| `core/geoip_update.lua`, blocklist, webhook and reporting scripts | Remote data and callbacks | Disable in I2P mode until each action has an approved I2P path. |

## Required Negative Tests

* Starting I2P mode with no SAM bridge must leave no public listener.
* A configured `0.0.0.0`, `::`, LAN address or public address must be rejected.
* Ordinary ADC CTM, RCM, NAT and RNT commands must be refused.
* HTTP update, webhook, GeoIP and blocklist operations must not cause a
  clearnet request in I2P mode.
* Closing the SAM session must make the hub unavailable through I2P rather than
  falling back to a direct listener.

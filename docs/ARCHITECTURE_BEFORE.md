# Luadch-I2P Architecture Before Transport Changes

This document records the inherited luadch-ng layout before I2P behavior is
introduced. The current fork is not yet I2P-only.

## Baseline

| Item | Value |
| --- | --- |
| Upstream | `https://github.com/luadch-ng/luadch-ng` |
| Upstream branch | `master` |
| Recorded commit | `a620d39d82c63ba184cc2e6714be6a7635c20ad2` |
| Fork branch | `i2p-main` |
| License | Unchanged upstream licensing and attribution |

The local clone keeps the original project under the `upstream` remote and
uses `origin` for `https://github.com/NoCoderRandom/luadch-i2p`.

## Build Baseline

Ubuntu 24.04 with GCC 13.3, CMake 3.28, OpenSSL 3.0 and zlib 1.3 was used.

* `cmake -B build-baseline -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo` succeeds.
* The hub executable builds successfully.
* The CMake install layout is self-contained and the installed `luadch --help`
  command works.
* The uninstalled binary requires its sibling `liblua.so`, so it is not a
  standalone runtime path. This is expected from the install layout, not an
  I2P issue.
* The default CMake build registers no CTest tests.

## Existing Network Layers

| Area | Key paths | Inherited behavior | I2P disposition |
| --- | --- | --- | --- |
| Native launcher | `hub/hub.c` | Loads the bundled Lua runtime and core. | Add a controlled I2P startup mode. |
| Hub listener | `core/server.lua` | Builds IPv4 or IPv6 LuaSocket listeners and binds configured addresses. | In I2P mode bind only `127.0.0.1`; never bind `0.0.0.0` or `::`. |
| Socket implementation | `luasocket/src/*` | Exposes TCP, UDP, DNS and Unix socket capabilities to Lua. | Keep only the loopback listener required by the SAM forwarder. Disable UDP and ordinary outbound socket use for hub transport. |
| ADC parsing | `core/adc.lua` | Accepts INF, CTM, RCM, NAT and RNT structures, including IP and UDP fields. | Add I2P-only validation and reject legacy peer-connection negotiation. |
| Hub routing | `core/hub.lua`, `core/hub_dispatch.lua` | Dispatches ADC commands between clients. | Allow only the documented I2P transfer capability once implemented. |
| External services | `core/http_client.lua`, `core/geoip_update.lua`, blocklist and webhook scripts | Can make HTTP/HTTPS requests and use IP-oriented information. | Disable by default in I2P mode unless a specific operation is reimplemented over I2P. |

## First Hub Milestone

The first practical hub milestone will use SAM `STREAM FORWARD` as a tightly
controlled local server tunnel:

```text
I2P network -> SAM bridge -> 127.0.0.1 hub listener -> luadch
```

The forwarder and its SAM session stay alive with the hub. A failure of SAM
stops the hub's I2P availability; it never exposes an alternate public ADC
listener. Native in-process SAM support can replace the forwarder after the
first secure Linux milestone.

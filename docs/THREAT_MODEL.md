# Luadch-I2P Threat Model

## Scope

Luadch-I2P will provide an ADC hub reachable through a local I2P router's SAM
interface. It must never expose an ordinary public ADC listener as a fallback.

## Protected Goals

The release target protects against accidental public listener exposure,
ordinary ADC IPv4 and IPv6 transport, UDP/NAT traversal, IP-bearing ADC
identity fields, clearnet CTM/RCM negotiation, and accidental external HTTP
requests from I2P-mode services.

## Trust Boundaries

The hub trusts the local SAM bridge only through a numeric loopback endpoint.
The bridge provides I2P reachability; its failure makes the hub unavailable.
The hub dispatches control messages but must not relay file contents. Private
SAM destination material is owner-only configuration and must not enter logs.

## Not Automatically Protected

I2P cannot prevent operator mistakes, disclosure in hub rules, nicknames or
chat, malicious content, a compromised host or router, or vulnerabilities in
the hub and its dependencies. The project must not claim absolute anonymity.

# Luadch-I2P

Experimental I2P-only Direct Connect hub for AirDC++-I2P. Based on luadch-ng /
Luadch; original authors and licenses are preserved.

## Debian Server Package

First target: **Debian 13, x86-64, systemd**. Includes a private i2pd router.
No separate I2P installation, SAM/tunnel configuration, port forwarding or
firewall exceptions are required.

Download the `.deb` and `SHA256SUMS.txt` from this fork's
[PoC release](https://github.com/NoCoderRandom/luadch-i2p/releases/tag/v0.1.0-poc.1), then:

```sh
sha256sum --ignore-missing -c SHA256SUMS.txt
sudo apt install ./luadch-i2p_0.1.0-poc1_amd64.deb
sudo luadch-i2p info
```

The last command shows the hub address and generated administrator credentials.
I2P can need several minutes to establish usable tunnels. Connect with
**AirDC++-I2P**, not an ordinary DC++ client. Registered members can use chat,
search and peer transfers; see the [operator guide](docs/DEBIAN_POC_PACKAGE.md).

This is a public experimental PoC, not a production anonymity product or an
independently audited security release. Earlier native Windows pair tests
covered chat, search, file lists and full-file transfers; the release notes
state the exact checkpoints and remaining verification limits.

Use the [AirDC++-I2P client](https://github.com/NoCoderRandom/airdcpp-i2p).
Ordinary DC++ clients cannot join. The packaged server defaults to registered
members; this is separate from an operator choosing to open a public test hub.
Review the [I2P-specific operator settings](docs/DEBIAN_POC_PACKAGE.md#i2p-specific-operator-settings)
before inviting users. The optional audio filename moderation bot is in the
current source tree, not bundled into this older server package.

## Architecture

`I2P peers -> private i2pd -> SAM forwarder -> loopback-only Luadch`

All three processes are managed together. Keys persist with restrictive
permissions. A managed-process failure takes the service offline. The SAM
listener must belong to the router we started. Other installed I2P instances
and host firewall rules are not changed. Local SAM registration is not proof
of remote I2P reachability.

ADC admission requires the private SAM 3.1 forwarder's source-destination
preamble. Connection and failed-login limits are keyed to that source, not the
shared loopback socket address. Advertised peer identity must match the source.
Incomplete preambles have a 16 KiB size limit, a 10-second deadline and a global
64-socket pending cap. Keep the local forwarder/listener inside the trusted
service boundary; the preamble is not authenticated against other local processes.

[Package guide](docs/DEBIAN_POC_PACKAGE.md) |
[Threat model](docs/THREAT_MODEL.md) | [License](LICENSE)

`docs/UPSTREAM_README.md` preserves historical upstream documentation for
reference. Its upstream downloads, Docker images and clearnet instructions
are **not** this I2P PoC package.

# Luadch-I2P

Experimental I2P-only Direct Connect hub for AirDC++-I2P. Based on luadch-ng /
Luadch; original authors and licenses are preserved.

## Debian Server Package

First target: **Debian 13, x86-64, systemd**. Includes a private i2pd router.
No separate I2P installation, SAM/tunnel configuration, port forwarding or
firewall exceptions are required.

Download the `.deb` and `SHA256SUMS` from this fork's
[releases](https://github.com/NoCoderRandom/luadch-i2p/releases), then:

```sh
sha256sum --ignore-missing -c SHA256SUMS
sudo apt install ./luadch-i2p_0.1.0-poc1_amd64.deb
sudo luadch-i2p info
```

The last command shows the hub address and generated administrator credentials.
I2P can need several minutes to establish usable tunnels. Connect with
**AirDC++-I2P**, not an ordinary DC++ client. Registered members can use chat,
search and peer transfers; see the [operator guide](docs/DEBIAN_POC_PACKAGE.md).

This is a PoC, not a production anonymity product. A draft/prerelease does not
mean final two-client acceptance is complete. The repositories remain private
until the owner approves publication.

## Architecture

`I2P peers -> private i2pd -> SAM forwarder -> loopback-only Luadch`

All three processes are managed together. Keys persist with restrictive
permissions. A managed-process failure takes the service offline. The SAM
listener must belong to the router we started. Other installed I2P instances
and host firewall rules are not changed. Local SAM registration is not proof
of remote I2P reachability.

[Package guide](docs/DEBIAN_POC_PACKAGE.md) |
[Threat model](docs/THREAT_MODEL.md) | [License](LICENSE)

`docs/UPSTREAM_README.md` preserves historical upstream documentation for
reference. Its upstream downloads, Docker images and clearnet instructions
are **not** this I2P PoC package.

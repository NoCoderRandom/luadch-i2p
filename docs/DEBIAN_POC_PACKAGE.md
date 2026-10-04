# Debian PoC Server

## Install

Supported target: Debian 13 x86-64 with systemd. Download the `.deb` and
SHA256SUMS from this private fork's release; verify the checksum, then:

```sh
sudo apt install ./luadch-i2p_0.1.0-poc1_amd64.deb
sudo luadch-i2p info
```

APT installs system-library dependencies. i2pd itself is bundled privately,
not installed as the system I2P service. No router changes or inbound firewall
exceptions are needed. Outbound Internet access is needed by i2pd, including
signed reseeding. Installation enables automatic startup after reboot.
This candidate uses the signed-SU3 reseed at `https://reseed.diva.exchange/`
with the corresponding Debian-shipped signer certificate; verification stays on.

I2P can need several minutes. `SAM active` means the local forwarder is
registered, not that another router has retrieved its LeaseSet. A remote
client's successful connection is the actual reachability check.

## Connect And Invite

1. Run `sudo luadch-i2p info` on the server.
2. Add the displayed `adc://...b32.i2p:1511` address in AirDC++-I2P.
3. Log in as `admin` with the generated initial password.
4. Register each member using `+reg nick MEMBER_NAME 20` in hub chat. It returns
   a generated password. Share that and the address privately with the member.
   Use a different nickname for each client.

The default hub requires registration. The package has no `dummy/test` account.
The traffic manager stays enabled; registered level-20 members can search and
transfer. No lab bypass is used. The HTTP administration API is off. Change
the initial admin password using the existing account commands before wider
use; `info` retains the initial setup credential, not later password changes.

## Operate

```sh
sudo luadch-i2p status
sudo luadch-i2p stop
sudo luadch-i2p start
sudo luadch-i2p restart
sudo journalctl -u luadch-i2p --since today
```

Never upload journals or private configuration. Router/hub/forwarder failure
stops all managed children; systemd restarts the whole service. An explicit
stop stays stopped. Failure never starts a public ADC listener. Normal ADC
listens only on `127.0.0.1:17650`.

## State And Removal

- Programs: `/usr/lib/luadch-i2p`, root-owned/read-only to the service.
- Private state: `/var/lib/luadch-i2p`, mode 0700, dedicated non-login user.
- Hub identity: `cfg/i2p-hub.private`; router identity: `router/`.
- SAM ports: dynamically selected, numeric loopback only, owned-child checked.
  Existing Java I2P/i2pd installations are untouched.
- Initial credential: `setup.txt`, root-only. The users database/master key use
  inherited encrypted-at-rest storage. Protect backups as secrets.
- Private logs: `log/` and journal; transient status: `/run/luadch-i2p`.
- No key, password, runtime user database or log is shipped in the package.

`sudo apt remove luadch-i2p` stops the service and removes its programs.
Remove and purge deliberately **retain private data and identities** to avoid
losing the hub address. Reinstall reuses them. Back up offline; delete only by
explicit administrator decision. Upgrade stops the old service and does not
overwrite existing configuration.

## Build

Build on Debian 13 amd64 with CMake, C/C++, OpenSSL/zlib development headers,
dpkg-dev, binutils and Python 3. Get i2pd through authenticated Debian APT:
`apt-get download i2pd=2.56.0-1`. The packager extracts its binary, signing
certificates and license notice, not its system configuration/sample tunnels.
ELF files determine library dependencies. `ROUTER.txt` records the input
checksum and Debian source location. Upstream source:
https://github.com/PurpleI2P/i2pd; corresponding Debian source/patches:
https://deb.debian.org/debian/pool/main/i/i2pd/.

```sh
cmake -S . -B build-package -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS="-ffile-prefix-map=$PWD=/usr/src/luadch-i2p" \
  -DCMAKE_CXX_FLAGS="-ffile-prefix-map=$PWD=/usr/src/luadch-i2p"
cmake --build build-package -j2
sh packaging/debian/build.sh build-package i2pd_2.56.0-1_amd64.deb dist
python3 -m unittest discover -s tests/packaging -v
```

Targeted tests cover initialization, ownership/lifecycle helpers and installed
service behavior. Final clean-GitHub-download two-Windows-client acceptance
is a separate gate. Do not claim it passed based on installation alone.

## Candidate Verification

The initial package delta was exercised in an isolated Debian 13 VM:

- Five helper tests: own-vs-foreign SAM listener, private atomic status writes,
  destination syntax, first setup/reinstall/interrupted setup, symlink refusal.
- Installation and automatic startup; only numeric-loopback DC sockets.
- Stop with no child processes left; restart with the same identity/address.
- Managed-router termination: old hub/forwarder stopped, automatic recovery
  retained the identity and local-only DC sockets.
- Package privacy/permissions scan and systemd unit validation.

The first install exposed a Linux i2pd argument difference; its launch was
corrected. An unavailable old default reseed host required an explicit signed
reseed URL. Payload permissions were normalized independently of build umask.
No ADC protocol or core transport code was changed for this package.

To run the installed lifecycle delta in a disposable VM only:
`sudo python3 tests/packaging/installed_service.py --disposable-vm`.
It stops the service on completion. It is not included in the installed payload.

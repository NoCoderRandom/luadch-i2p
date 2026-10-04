#!/bin/sh
# Build on Debian 13 amd64. The router .deb must come from authenticated APT.
set -eu
umask 022
if [ "$#" != 3 ]; then
    echo "Usage: $0 BUILD_DIRECTORY I2PD_DEB OUTPUT_DIRECTORY" >&2
    exit 2
fi
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
build_dir=$(realpath "$1")
router_deb=$(realpath "$2")
mkdir -p "$3"
output_dir=$(realpath "$3")
[ "$(dpkg --print-architecture)" = amd64 ]
[ "$(dpkg-deb -f "$router_deb" Package)" = i2pd ]
[ "$(dpkg-deb -f "$router_deb" Architecture)" = amd64 ]
version=0.1.0~poc1
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM
root="$stage/package/usr/lib/luadch-i2p"
mkdir -p "$root" "$stage/package/DEBIAN" "$stage/package/usr/bin" \
    "$stage/package/usr/lib/systemd/system" "$stage/package/usr/share/doc/luadch-i2p"
cmake --install "$build_dir" --prefix "$root/hub"
dpkg-deb -x "$router_deb" "$stage/router"
mkdir -p "$root/router" "$root/defaults" "$root/tunnels.d"
cp "$stage/router/usr/bin/i2pd" "$root/router/"
cp -a "$stage/router/usr/share/i2pd/certificates" "$root/router/"
cp "$stage/router/usr/share/doc/i2pd/copyright" "$stage/package/usr/share/doc/luadch-i2p/i2pd-copyright"
cp "$source_dir/LICENSE" "$stage/package/usr/share/doc/luadch-i2p/copyright"
mkdir -p "$stage/package/usr/share/doc/luadch-i2p/licenses"
(cd "$source_dir" && cp --parents adclib/LICENSE basexx/LICENSE lua/LICENSE lua/COPYRIGHT \
    luasec/LICENSE luasec/src/luasocket/LICENSE luasocket/LICENSE slaxml/LICENSE \
    "$stage/package/usr/share/doc/luadch-i2p/licenses/")
cp "$source_dir/docs/DEBIAN_POC_PACKAGE.md" "$stage/package/usr/share/doc/luadch-i2p/README.md"
cp "$source_dir/examples/cfg/webhooks.tbl" "$root/defaults/"
# The production loader uses an empty Lua environment: retain the literal table.
sed 's/^return {/local config = {/' "$source_dir/examples/cfg/cfg.tbl" > "$root/defaults/cfg.tbl"
cat "$source_dir/packaging/debian/cfg.tbl" >> "$root/defaults/cfg.tbl"
# Only immutable program content belongs in the package. Runtime files are new,
# private state created by postinst, never copied from a running hub.
rm -rf -- "$root/hub/cfg" "$root/hub/log" "$root/hub/certs" "$root/hub/scripts/data" "$root/hub/docs"
ln -s /var/lib/luadch-i2p/cfg "$root/hub/cfg"
ln -s /var/lib/luadch-i2p/log "$root/hub/log"
ln -s /var/lib/luadch-i2p/certs "$root/hub/certs"
ln -s /var/lib/luadch-i2p/script-data "$root/hub/scripts/data"
ln -s /var/lib/luadch-i2p/luadch.lock "$root/hub/luadch.lock"
cp "$source_dir/packaging/debian/"*.py "$source_dir/packaging/debian/i2pd.conf" "$root/"
touch "$root/tunnels.conf"
chmod 755 "$root/"*.py
ln -s /usr/lib/luadch-i2p/manage.py "$stage/package/usr/bin/luadch-i2p"
cp "$source_dir/packaging/debian/luadch-i2p.service" "$stage/package/usr/lib/systemd/system/"
for script in postinst prerm postrm; do
    install -m 755 "$source_dir/packaging/debian/$script" "$stage/package/DEBIAN/$script"
done
# Resolve actual ELF dependencies including the bundled router, not guessed names.
mkdir -p "$stage/debian"
printf 'Source: luadch-i2p\nSection: net\nPriority: optional\nMaintainer: NoCoderRandom <149964871+NoCoderRandom@users.noreply.github.com>\nStandards-Version: 4.7.0\n\nPackage: luadch-i2p\nArchitecture: amd64\nDescription: I2P-only Direct Connect hub\n' > "$stage/debian/control"
depends=$(cd "$stage" && dpkg-shlibdeps -O --ignore-missing-info \
    -l"$root/hub" -e"$root/hub/luadch" -e"$root/hub/luadch-i2p-forward" \
    -e"$root/router/i2pd" -e"$root/hub/lib/adclib/adclib.so" \
    -e"$root/hub/lib/luasec/ssl/ssl.so" -e"$root/hub/lib/zlib_stream/zlib_stream.so" \
    -e"$root/hub/lib/luasocket/socket/socket.so" -e"$root/hub/lib/luasocket/mime/mime.so" \
    | sed -n 's/^shlibs:Depends=//p')
[ -n "$depends" ]
cat > "$stage/package/DEBIAN/control" <<EOF
Package: luadch-i2p
Version: $version
Architecture: amd64
Maintainer: NoCoderRandom <149964871+NoCoderRandom@users.noreply.github.com>
Section: net
Priority: optional
Depends: python3, adduser, systemd, ca-certificates, $depends
Description: I2P-only Direct Connect hub with private bundled router
 Experimental PoC. Includes Luadch, its SAM forwarder and i2pd.
 Does not expose a normal Direct Connect listener to the network.
EOF
printf 'Bundled i2pd: %s\nDebian package SHA256: %s\nSource: https://deb.debian.org/debian/pool/main/i/i2pd/\n' \
    "$(dpkg-deb -f "$router_deb" Version)" "$(sha256sum "$router_deb" | cut -d' ' -f1)" \
    > "$stage/package/usr/share/doc/luadch-i2p/ROUTER.txt"
# Do not inherit a developer's group-writable umask or source-file modes.
find "$stage/package" -type d -exec chmod 755 {} +
find "$stage/package" -type f -exec chmod go-w {} +
dpkg-deb --root-owner-group --build "$stage/package" "$output_dir/luadch-i2p_${version}_amd64.deb"

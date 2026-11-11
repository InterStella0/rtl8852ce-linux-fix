#!/bin/bash
# Install bcn-guard (DKMS module + loader service + helper tools).
#
# What this does NOT do: it does not install, replace, blacklist or
# reconfigure any Wi-Fi or Bluetooth driver or firmware. It adds one small
# extra kernel module and a service that loads it. Remove everything again
# with ./uninstall.sh.
#
#   sudo ./install.sh
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0"; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)
ver=$(sed -n 's/^PACKAGE_VERSION="\(.*\)"/\1/p' "$here/module/dkms.conf")
name=bcn-guard
src=/usr/src/$name-$ver
kver=$(uname -r)
state=/var/lib/bcn-guard

say() { echo ">> $*"; }
command -v dkms > /dev/null || { echo "dkms is not installed (pacman -S dkms)"; exit 1; }
[ -d "/usr/lib/modules/$kver/build" ] || {
	echo "kernel headers for $kver are not installed (needed to build the module)"; exit 1; }

say "installing module source to $src"
if dkms status "$name/$ver" 2> /dev/null | grep -q .; then
	dkms remove "$name/$ver" --all > /dev/null 2>&1 || true
fi
rm -rf "$src"
install -d "$src"
install -m 0644 "$here"/module/{bcn_guard.c,bcn_core.h,Kbuild,Makefile,dkms.conf} "$src/"
dkms add "$name/$ver" > /dev/null

# running kernel first (must work), then any other kernel that has headers
say "building for $kver"
dkms install "$name/$ver" -k "$kver"
for b in /usr/lib/modules/*/build; do
	k=$(basename "$(dirname "$b")")
	[ "$k" = "$kver" ] && continue
	say "building for $k"
	dkms install "$name/$ver" -k "$k" > /dev/null 2>&1 ||
		echo "   (skipped: build failed for $k; that kernel simply runs without the guard)"
done

say "installing loader, service and tools"
install -D -m 0755 "$here/scripts/bcn-guard-load" /usr/local/lib/bcn-guard/bcn-guard-load
install -D -m 0755 "$here/scripts/wifi-bt-status" /usr/local/bin/wifi-bt-status
install -D -m 0755 "$here/scripts/wifi-pin-5ghz" /usr/local/bin/wifi-pin-5ghz
install -D -m 0644 "$here/systemd/bcn-guard.service" /etc/systemd/system/bcn-guard.service
install -D -m 0644 "$here/README.md" /usr/local/share/doc/bcn-guard/README.md
install -d "$state"
rm -f "$state/tripped" "$state/loading"
[ -e "$state/installed-at" ] || date '+%Y-%m-%d %H:%M:%S' > "$state/installed-at"

systemctl daemon-reload
systemctl enable bcn-guard.service > /dev/null 2>&1
say "loading the module"
systemctl restart bcn-guard.service

if [ -r /sys/module/bcn_guard/parameters/stats ]; then
	sleep 2
	say "bcn_guard is active:"
	sed 's/^/   /' /sys/module/bcn_guard/parameters/stats
else
	echo "!! module did not load; Wi-Fi is unaffected. See: journalctl -u bcn-guard -b"
	exit 1
fi

cat << EOF

Done. Next:
  wifi-pin-5ghz apply     keep this network on 5 GHz (recommended, no root needed)
  wifi-bt-status          see whether disconnects / Bluetooth failures stopped
Remove everything with: sudo $here/uninstall.sh
EOF

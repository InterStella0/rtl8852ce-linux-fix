#!/bin/bash
# Remove bcn-guard completely. Wi-Fi/Bluetooth drivers are not touched (they
# never were). The 5 GHz pin is a NetworkManager profile setting; remove it
# with `wifi-pin-5ghz undo` *before* running this if you want it gone too.
#
#   sudo ./uninstall.sh
set -uo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0"; exit 1; }
name=bcn-guard

systemctl disable --now bcn-guard.service 2> /dev/null
modprobe -r bcn_guard 2> /dev/null
for v in $(dkms status "$name" 2> /dev/null | sed -n "s|^$name/\([^,:]*\).*|\1|p" | sort -u); do
	dkms remove "$name/$v" --all
	rm -rf "/usr/src/$name-$v"
done
rm -f /etc/systemd/system/bcn-guard.service
rm -rf /usr/local/lib/bcn-guard /usr/local/share/doc/bcn-guard /var/lib/bcn-guard
rm -f /usr/local/bin/wifi-bt-status /usr/local/bin/wifi-pin-5ghz
systemctl daemon-reload
echo "bcn-guard removed."

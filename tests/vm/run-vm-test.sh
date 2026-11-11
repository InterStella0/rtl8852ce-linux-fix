#!/bin/bash
# End-to-end test of bcn_guard in a throwaway QEMU VM.
#
# Boots the *installed* kernel image with simulated Wi-Fi radios
# (mac80211_hwsim), reproduces the "AP appears to change mode ... disconnect"
# bug and checks that the module prevents it. Nothing on the host is touched:
# no root, no host modules loaded, host Wi-Fi is not involved.
#
#   tests/vm/run-vm-test.sh [kernel-release]
#
# Needs: qemu-system-x86_64, kernel headers for that release, iw, cpio, zstd.
# hostapd is used from the host if installed, otherwise the Arch package is
# downloaded and unpacked into the work directory (not installed).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
kver=${1:-$(uname -r)}
moddir=/usr/lib/modules/$kver
work=${BG_VM_WORK:-$(mktemp -d)}
root=$work/root
mkdir -p "$work"
rm -rf "$root" "$work/build"
mkdir -p "$root"/{bin,lib,lib64,mods,etc,proc,sys,dev,run,tmp,var/run,usr/lib/firmware} "$work/build"

[ -r "$moddir/vmlinuz" ] || { echo "no kernel image at $moddir/vmlinuz"; exit 1; }

echo ">> building bcn_guard for $kver"
cp "$repo"/module/* "$work/build/"
make -s -C "$work/build" KVER="$kver" > "$work/build.log" 2>&1 || { cat "$work/build.log"; exit 1; }
cp "$work/build/bcn_guard.ko" "$root/"

echo ">> collecting hostapd"
if command -v hostapd > /dev/null && command -v hostapd_cli > /dev/null; then
	hostapd_bin=$(command -v hostapd); hostapd_cli_bin=$(command -v hostapd_cli)
else
	pkgdir=$work/hostapd-pkg
	if [ ! -x "$pkgdir/usr/bin/hostapd" ]; then
		url=$(pacman -Sp hostapd | tail -1)
		mkdir -p "$pkgdir"
		curl -fsSL -o "$work/hostapd.pkg.tar.zst" "$url"
		bsdtar -xf "$work/hostapd.pkg.tar.zst" -C "$pkgdir" usr/bin/hostapd usr/bin/hostapd_cli
	fi
	hostapd_bin=$pkgdir/usr/bin/hostapd; hostapd_cli_bin=$pkgdir/usr/bin/hostapd_cli
fi

echo ">> building initramfs"
add_bin() {
	local src=$1 name=${2:-$(basename "$1")}
	cp -L "$src" "$root/bin/$name"
	ldd "$src" 2> /dev/null | awk '$3 ~ /^\// {print $3} $1 ~ /^\// {print $1}' | while read -r lib; do
		[ -e "$root/lib/$(basename "$lib")" ] || cp -L "$lib" "$root/lib/"
	done
}
for b in bash kmod iw ip sleep cat grep sed seq dmesg mount mkdir tail head uname; do
	add_bin "$(command -v $b)"
done
add_bin "$hostapd_bin" hostapd
add_bin "$hostapd_cli_bin" hostapd_cli
for l in insmod rmmod; do ln -sf kmod "$root/bin/$l"; done
# dynamic loader where the binaries expect it
cp -L /lib64/ld-linux-x86-64.so.2 "$root/lib64/"
ln -sf ../lib "$root/usr/lib64" 2> /dev/null || true
for l in "$root"/lib/*; do ln -sf "../../lib/$(basename "$l")" "$root/usr/lib/$(basename "$l")"; done

# the exact modules of the kernel under test, in dependency order
i=0
modprobe -S "$kver" --show-depends mac80211_hwsim | awk '$1 == "insmod" {print $2}' | while read -r ko; do
	i=$((i + 1))
	out=$root/mods/$(printf '%02d' $i)-$(basename "${ko%.zst}")
	case $ko in
	*.zst) zstd -dqc "$ko" > "$out" ;;
	*) cp "$ko" "$out" ;;
	esac
done
# regulatory database so the AP may use 5 GHz
cp /usr/lib/firmware/regulatory.db* "$root/usr/lib/firmware/" 2> /dev/null || true
ln -sf ../usr/lib/firmware "$root/lib/firmware"

cat > "$root/etc/hostapd.conf" << 'EOF'
interface=wlan0
driver=nl80211
ctrl_interface=/var/run/hostapd
ssid=bgtest
country_code=US
hw_mode=a
channel=36
ieee80211n=1
ht_capab=[HT40+]
ieee80211ac=1
vht_oper_chwidth=1
vht_oper_centr_freq_seg0_idx=42
wmm_enabled=1
EOF
cp "$here/init.sh" "$root/init"
chmod +x "$root/init"
(cd "$root" && find . | cpio -o -H newc --quiet) | zstd -q -3 > "$work/initrd.zst"

echo ">> booting $kver in QEMU"
accel=(-accel tcg -cpu max)
[ -w /dev/kvm ] && accel=(-enable-kvm -cpu host)
timeout 300 qemu-system-x86_64 "${accel[@]}" -m 1024 -smp 2 -nographic -no-reboot \
	-kernel "$moddir/vmlinuz" -initrd "$work/initrd.zst" \
	-append "console=ttyS0 rdinit=/init panic=-1 loglevel=3" \
	< /dev/null 2>&1 | tr -d '\r' | tee "$work/vm.log" | grep -E '^(###|  (PASS|FAIL)|    )' || true

grep -q 'VM-TEST-OK' "$work/vm.log" && { echo ">> VM test passed (full log: $work/vm.log)"; exit 0; }
echo ">> VM test FAILED (full log: $work/vm.log)"
exit 1

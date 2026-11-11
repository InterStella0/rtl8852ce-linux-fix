#!/bin/bash
# /init inside the test VM. Reproduces the mac80211 "AP appears to change
# mode ... disconnect" bug on simulated radios (mac80211_hwsim), then shows
# that bcn_guard prevents it. Runs entirely inside QEMU.
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
mkdir -p /run /var/run /tmp
mount -t tmpfs tmpfs /run

pass=0; fail=0
ok()   { echo "  PASS: $*"; pass=$((pass + 1)); }
bad()  { echo "  FAIL: $*"; fail=$((fail + 1)); }
check() { local d="$1"; shift; if "$@"; then ok "$d"; else bad "$d"; fi; }

for m in /mods/*.ko; do
	args=""
	[[ $m == *mac80211_hwsim* ]] && args="radios=2"
	insmod "$m" $args || echo "insmod $m failed"
done

hcli()      { hostapd_cli -p /var/run/hostapd -i wlan0 "$@" > /dev/null; }
connected() { iw dev wlan1 link | grep -q 'Connected to'; }
wait_conn() { for _ in $(seq 60); do connected && return 0; sleep 0.25; done; return 1; }
connect()   { iw dev wlan1 connect bgtest 5180 2> /dev/null; wait_conn; }
nmode()     { dmesg | grep -c 'appears to change mode'; }
stat()      { sed -n "s/^$1: //p" /sys/module/bcn_guard/parameters/stats; }
# make the AP's beacons lose their VHT (or HT+VHT) elements, like the bad
# beacons seen on the real network
degrade() {
	hcli set ieee80211ac 0
	[ "$1" = legacy ] && hcli set ieee80211n 0
	hcli update_beacon
}
restore() { hcli set ieee80211n 1; hcli set ieee80211ac 1; hcli update_beacon; }

echo "### kernel: $(uname -r)"
hostapd -B /etc/hostapd.conf > /tmp/hostapd.log 2>&1
for _ in $(seq 80); do
	hostapd_cli -p /var/run/hostapd -i wlan0 status 2> /dev/null | grep -q 'state=ENABLED' && break
	sleep 0.25
done
ip link set wlan1 up
check "station associates to the VHT test AP" connect
iw dev wlan1 link | grep -E 'Connected|bitrate' | sed 's/^/    /'

echo "### A. stock kernel, no guard: one degraded beacon"
n0=$(nmode)
degrade vht; sleep 1.5; restore
check "bug reproduced: mac80211 disconnected (\"appears to change mode\")" [ "$(nmode)" -gt "$n0" ]
check "station really lost the link" bash -c '! iw dev wlan1 link | grep -q "Connected to"'
dmesg | grep 'appears to change mode' | tail -1 | sed 's/^/    /'

echo "### B. guard loaded: same degraded beacons (missing VHT)"
sleep 1
check "station re-associates" connect
check "bcn_guard loads" insmod /bcn_guard.ko max_hold_ms=4000
sleep 1.5
check "guard sees beacons" [ "$(stat beacons_seen)" -gt 0 ]
n0=$(nmode)
degrade vht; sleep 1.5; restore; sleep 1
check "no disconnect message" [ "$(nmode)" -eq "$n0" ]
check "station still connected" connected
check "guard dropped the bad beacons" [ "$(stat dropped)" -gt 0 ]
d1=$(stat dropped)

echo "### C. guard loaded: beacons missing HT+VHT (\"found legacy\")"
degrade legacy; sleep 1.5; restore; sleep 1
check "no disconnect message" [ "$(nmode)" -eq "$n0" ]
check "station still connected" connected
check "guard dropped more beacons" [ "$(stat dropped)" -gt "$d1" ]

echo "### D. fail-open: AP changes for real (longer than max_hold_ms)"
degrade vht; sleep 6
check "change was let through after the hold time" [ "$(stat let_through_after_hold)" -gt 0 ]
check "mac80211 then reacted as on a stock kernel" [ "$(nmode)" -gt "$n0" ]
restore; sleep 1

echo "### E. kill switch: enabled=0 restores stock behaviour"
check "station re-associates" connect
sleep 1.5
echo 0 > /sys/module/bcn_guard/parameters/enabled
n0=$(nmode)
degrade vht; sleep 1.5; restore
check "stock behaviour (disconnect) with enabled=0" [ "$(nmode)" -gt "$n0" ]
check "counted as would_drop" [ "$(stat would_drop)" -gt 0 ]

echo "### F. unload and kernel health"
check "bcn_guard unloads" rmmod bcn_guard
check "station re-associates after unload" connect
check "no oops/BUG/warning in the kernel log" bash -c '! dmesg | grep -qE "BUG:|Oops|WARNING:|RIP:|Call Trace|general protection"'

echo "### guard log lines"
dmesg | grep bcn_guard | grep -v ': 0000' | head -12 | sed 's/^/    /'
echo "### RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ] && echo "### VM-TEST-OK" || { echo "### VM-TEST-FAILED"; cat /tmp/hostapd.log | tail -20; dmesg | tail -40; }
echo o > /proc/sysrq-trigger
sleep 5

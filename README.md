# rtl8852ce-linux-fix

Stops the random Wi-Fi drop-outs and the Bluetooth audio breakdowns on the
Realtek **RTL8852CE** Wi-Fi/Bluetooth combo card under Linux, **without
replacing, patching or reconfiguring any driver or firmware**.

> [!WARNING]
> **Disclaimer: this is entirely vibecoded, idk how this works.** Every line
> here, including the kernel module, the tests and this README, was written by
> an AI (Claude). It has only been run on my own machine and my own router.
> It loads a kernel module, so read it before you trust it, and use it at
> your own risk.

It is two small things:

| Piece | What it is | What it stops |
|---|---|---|
| `bcn_guard` | a tiny add-on kernel module (DKMS) | the kernel disconnecting Wi-Fi because of one bad beacon |
| `wifi-pin-5ghz` | one NetworkManager profile setting | the router bouncing the PC between its 2.4 GHz and 5 GHz radios |

Plus `wifi-bt-status`, which counts the relevant events so you can see whether
it worked instead of guessing.

## The problem

Symptoms: Wi-Fi freezes for 5–10 s at random; Bluetooth audio starts
stuttering, dies, and will not reconnect until `systemctl restart bluetooth`.
Neither happens on Windows with the same hardware and router.

What the logs show is one chain of events, not two unrelated bugs:

1. **The kernel disconnects on purpose.** A beacon from the access point
   occasionally arrives without its HT/VHT elements (corrupt or truncated).
   mac80211 treats a *single* such beacon as "the AP changed mode" and tears
   the link down:

   ```
   wlan0: AP xx:xx:xx:xx:xx:xx appears to change mode (expected VHT, found legacy) in beacon, disconnect
   ```

   That is `ieee80211_config_bw()` in `net/mac80211/mlme.c`. It does not check
   whether the beacon parsed cleanly first, and there is no setting to turn it
   off. Windows ignores such beacons.

2. **The reconnect lands on 2.4 GHz, and the router pushes back.** The router
   uses one name for both radios and band-steers clients
   (`WNM: Disassociation Imminent`). So every disconnect becomes
   5 GHz → 2.4 GHz → 5 GHz, each hop restarting DHCP and any VPN tunnel. That
   is the 5–10 s freeze.

3. **Every hop hurts Bluetooth.** Wi-Fi and Bluetooth are one chip sharing an
   antenna path. Each reconnect rescans and recalibrates on it
   (`[RX_DCK] S1 RXDCK timeout`), and 2.4 GHz Wi-Fi sits in Bluetooth's own
   band. PipeWire then reports
   `Missing completion reports for packet: Bluetooth adapter firmware bug?`,
   audio dies, and the controller stays wedged until it is reset.

Measured on the affected machine over three days: **28** bad-beacon
disconnects, **57** band-steering requests, **48** landings on 2.4 GHz, and
every Bluetooth failure followed one of them.

## The fix

### `bcn_guard`

A kprobe on `ieee80211_rx_napi()` — the one exported function every driver
uses to hand received frames to mac80211. For beacons only, it compares each
one with what the same access point normally sends. A beacon is hidden from
mac80211 (flagged `RX_FLAG_ONLY_MONITOR`, the standard "do not process"
flag) when:

- its FCS does not match its contents, or
- its element list no longer parses, or
- it is missing an HT/VHT/HE/EHT element that access point always sends.

Everything else passes through untouched. Non-beacon frames leave the hook
after three comparisons.

### `wifi-pin-5ghz`

Sets `802-11-wireless.band = a` on one NetworkManager profile, so
wpa_supplicant refuses 2.4 GHz steering targets and reconnects straight to
the 5 GHz radio. Only use it where 5 GHz reception is good (it checks that a
5 GHz radio is visible first).

## Why this cannot break your Wi-Fi

This was the design constraint, because earlier "fixes" on this machine
replaced the driver and left it without Wi-Fi.

- **No driver is touched.** Nothing is replaced, blacklisted or re-parameterised.
  `rtw89`, `mac80211`, `btusb` and their firmware stay exactly as shipped.
- **Add-on, not dependency.** Wi-Fi does not need the module. If it is
  missing, fails to build for a new kernel, or fails to load, Wi-Fi runs
  exactly as on a stock kernel.
- **Fail-open.** An access point is only protected once a normal beacon has
  been seen from it; one normal beacon ends a suspicious run; and if an access
  point sends *only* changed beacons for `max_hold_ms` (3 s) they are let
  through. A router that really was reconfigured is delayed by 3 s, nothing more.
- **Crash-loop breaker.** The loader notes when it loads the module and clears
  the note 60 s later or on clean shutdown. If the machine goes down hard in
  between, the next boot does not load the module (`wifi-bt-status` says
  `TRIPPED`). Booting with `bcn_guard=off` on the kernel command line also
  skips it.
- **Kill switches at runtime:**
  `echo 0 | sudo tee /sys/module/bcn_guard/parameters/enabled` (count only),
  `sudo systemctl stop bcn-guard` (unload).

## Install

Needs `dkms` and the headers of your kernel (e.g. `linux-cachyos-headers`).

```sh
sudo ./install.sh          # builds + loads the module, installs the tools
wifi-pin-5ghz apply        # optional but recommended; Wi-Fi blips once
```

DKMS rebuilds the module automatically on kernel updates. A kernel without
headers installed simply runs without the guard.

## Did it work?

```sh
wifi-bt-status             # since install
wifi-bt-status 24h
```

The lines marked `(want 0)` should stay at zero. "bad beacons hidden by the
guard" going up while "kernel disconnected because of a bad beacon" stays at 0
is the fix doing its job. The first few hidden beacons are hex-dumped to the
kernel log (`journalctl -k -g bcn_guard`), which shows exactly what was wrong
with them.

## Remove

```sh
wifi-pin-5ghz undo
sudo ./uninstall.sh
```

## Tests

```sh
make -C tests check        # unit tests + 3M fuzzed frames under ASan/UBSan
tests/vm/run-vm-test.sh    # end-to-end in QEMU; needs no root
```

The VM test boots the **installed kernel image** with simulated radios
(`mac80211_hwsim` + hostapd), reproduces the disconnect on a stock kernel,
then checks that with `bcn_guard` loaded the same beacons no longer disconnect,
that a persistent change still gets through, that the kill switch restores
stock behaviour, and that the module unloads without kernel warnings. Passing
on `7.2.9-1-cachyos` (clang/ThinLTO) and `6.18.55-1-cachyos-lts` (gcc).

## Module parameters

`/sys/module/bcn_guard/parameters/`

| Name | Default | Meaning |
|---|---|---|
| `enabled` | 1 | 0 = only count suspicious beacons |
| `max_hold_ms` | 3000 | longest unbroken run of suspicious beacons to hide; 0 = never hide |
| `verify_fcs` | 1 | check beacon FCS when the driver includes it (only trusted after 32 good ones) |
| `log_frames` | 8 | how many more hidden beacons to hex-dump |
| `stats` | – | counters (read-only) |

## Limits

- The guard removes the trigger; it does not repair the RTL8852CE's
  Wi-Fi/Bluetooth coexistence firmware. Realtek has said driver support for
  the current firmware (0.27.129.4) is still in progress. A Wi-Fi scan can
  still cause a brief Bluetooth hiccup.
- If the router's band steering reacts to a refused request by kicking the
  client (`wifi-bt-status` → "kicked by the router"), turn band steering off on
  the router or give the two bands different names.
- x86-64 and arm64 only (uses `regs_get_kernel_argument()`).

## Background

- [linux-wireless: RTL8852CE RX_DCK timeout + Bluetooth A2DP coexistence failures](https://ratatoskr.run/linux-wireless/2026/07/17227566/t)
- [Red Hat Bugzilla 2349675](https://bugzilla.redhat.com/show_bug.cgi?id=2349675)
- [Arch forums: "expected VHT, found HT in beacon, disconnect"](https://bbs.archlinux.org/viewtopic.php?pid=2296915)
- [mac80211-modecheck-skip](https://github.com/rrtt217/mac80211-modecheck-skip) — same symptom solved by rebuilding a patched `mac80211`; this project avoids replacing the module
- [rtl8852ce-bt-coex](https://github.com/hamza-gouda1/rtl8852ce-bt-coex) — analysis of the coexistence firmware on 2.4 GHz

License: GPL-2.0

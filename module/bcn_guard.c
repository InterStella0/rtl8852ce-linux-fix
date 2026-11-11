// SPDX-License-Identifier: GPL-2.0
/*
 * bcn_guard - drop corrupt / downgraded beacons before mac80211 sees them.
 *
 * Problem: when a beacon from the associated AP arrives without the HT/VHT/HE
 * elements the connection was set up with, mac80211 logs
 *
 *   wlan0: AP xx appears to change mode (expected VHT, found legacy) in
 *          beacon, disconnect
 *
 * and tears the link down (net/mac80211/mlme.c, ieee80211_config_bw()). It
 * does this for a single beacon and without checking whether the beacon even
 * parsed cleanly. On RTL8852CE (rtw89) such beacons show up regularly; every
 * one costs a multi-second reconnect and, on this combo chip, a rescan and
 * recalibration on the antenna shared with Bluetooth.
 *
 * This module does NOT replace or patch any driver. It puts a kprobe on the
 * exported driver->mac80211 entry point ieee80211_rx_napi() and, for beacons
 * that look wrong compared to what the same BSSID normally sends, sets
 * RX_FLAG_ONLY_MONITOR so mac80211 discards them like any other bad frame.
 * If this module is absent, fails to build or fails to load, Wi-Fi behaves
 * exactly as it does on a stock kernel.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/crc32.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/ptrace.h>
#include <linux/ratelimit.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/unaligned.h>
#include <net/mac80211.h>

#include "bcn_core.h"

#define BG_VERSION		"1.0.0"
#define BG_FCS_TRUST_MIN	32	/* good FCS beacons before we trust the check */
#define BG_DUMP_MAX		512

static bool enabled = true;
module_param(enabled, bool, 0644);
MODULE_PARM_DESC(enabled, "Drop suspicious beacons (0 = only count them)");

static unsigned int max_hold_ms = 3000;
module_param(max_hold_ms, uint, 0644);
MODULE_PARM_DESC(max_hold_ms,
		 "Longest unbroken run of suspicious beacons to hide from mac80211");

static bool verify_fcs = true;
module_param(verify_fcs, bool, 0644);
MODULE_PARM_DESC(verify_fcs, "Verify the FCS of beacons when the driver includes it");

static unsigned int log_frames = 8;
module_param(log_frames, uint, 0644);
MODULE_PARM_DESC(log_frames, "How many more suspicious beacons to hex-dump to the kernel log");

static DEFINE_RAW_SPINLOCK(bg_lock);
static struct bg_table bg_tbl;

static struct {
	u64 beacons;
	u64 dropped;
	u64 would_drop;		/* suspicious while enabled=0 */
	u64 r_fcs;
	u64 r_malformed;
	u64 r_downgrade;
	u64 expired;
	u64 fcs_good;
	u64 fcs_bad;
	u64 last_drop_ms;
	u8 last_bssid[6];
} bg_stats;

static u64 bg_now_ms(void)
{
	return div_u64(ktime_get_mono_fast_ns(), NSEC_PER_MSEC);
}

static int bg_pre_handler(struct kprobe *kp, struct pt_regs *regs)
{
	struct ieee80211_hw *hw = (void *)regs_get_kernel_argument(regs, 0);
	struct sk_buff *skb = (void *)regs_get_kernel_argument(regs, 2);
	struct ieee80211_rx_status *st;
	struct bg_result res;
	const u8 *bssid, *ies;
	size_t len, fcs_len, ies_len;
	unsigned long flags;
	bool fcs_bad = false, dump = false, act;
	u8 addr[6];
	u16 sig;

	if (unlikely(!hw || !skb))
		return 0;

	/* fast path: everything that is not a linear beacon leaves here */
	len = skb->len;
	if (len < BG_MIN_LEN || skb_is_nonlinear(skb) || skb->data[0] != 0x80)
		return 0;

	st = IEEE80211_SKB_RXCB(skb);
	/* already rejected, or not an 802.11 frame at skb->data */
	if (st->flag & (RX_FLAG_FAILED_FCS_CRC | RX_FLAG_FAILED_PLCP_CRC |
			RX_FLAG_ONLY_MONITOR | RX_FLAG_NO_PSDU | RX_FLAG_8023))
		return 0;
	/* beacons are legacy-rate frames; anything else may carry a prefix */
	if (st->encoding != RX_ENC_LEGACY)
		return 0;

	fcs_len = ieee80211_hw_check(hw, RX_INCLUDES_FCS) ? BG_FCS_LEN : 0;
	if (!bg_frame_is_ap_beacon(skb->data, len, fcs_len, &bssid, &ies, &ies_len))
		return 0;

	if (fcs_len && READ_ONCE(verify_fcs)) {
		u32 calc = ~crc32_le(~0U, skb->data, len - BG_FCS_LEN);
		u32 got = get_unaligned_le32(skb->data + len - BG_FCS_LEN);

		fcs_bad = calc != got;
	}

	sig = bg_signature(ies, ies_len);
	act = READ_ONCE(enabled);

	raw_spin_lock_irqsave(&bg_lock, flags);
	bg_stats.beacons++;
	if (fcs_len && READ_ONCE(verify_fcs)) {
		if (fcs_bad)
			bg_stats.fcs_bad++;
		else
			bg_stats.fcs_good++;
		/*
		 * Only believe a mismatch once the driver has shown that it
		 * really delivers the on-air FCS.
		 */
		if (bg_stats.fcs_good < BG_FCS_TRUST_MIN)
			fcs_bad = false;
	}

	bg_decide(&bg_tbl, bssid, sig, fcs_bad, bg_now_ms(),
		  READ_ONCE(max_hold_ms), &res);

	if (res.drop) {
		if (res.reason & BG_R_FCS)
			bg_stats.r_fcs++;
		if (res.reason & BG_R_MALFORMED)
			bg_stats.r_malformed++;
		if (res.reason & BG_R_DOWNGRADE)
			bg_stats.r_downgrade++;
		if (act)
			bg_stats.dropped++;
		else
			bg_stats.would_drop++;
		bg_stats.last_drop_ms = bg_now_ms();
		memcpy(bg_stats.last_bssid, bssid, 6);
		if (log_frames) {
			log_frames--;
			dump = true;
		}
	} else if (res.reason & BG_R_EXPIRED) {
		bg_stats.expired++;
	}
	raw_spin_unlock_irqrestore(&bg_lock, flags);

	if (!res.drop && !(res.reason & BG_R_EXPIRED))
		return 0;

	memcpy(addr, bssid, 6);

	if (res.reason & BG_R_EXPIRED) {
		pr_warn_ratelimited("%pM: beacons stayed changed for %u ms, letting them through (sig %04x, was %04x, reason %02x)\n",
				    addr, READ_ONCE(max_hold_ms), res.sig,
				    res.base, res.reason);
		return 0;
	}

	if (act)
		st->flag |= RX_FLAG_ONLY_MONITOR;

	pr_info_ratelimited("%pM: %s beacon (len %zu, sig %04x, expected %04x, reason %02x:%s%s%s)\n",
			    addr, act ? "dropped" : "would drop", len, res.sig,
			    res.base, res.reason,
			    res.reason & BG_R_FCS ? " bad-fcs" : "",
			    res.reason & BG_R_MALFORMED ? " malformed" : "",
			    res.reason & BG_R_DOWNGRADE ? " missing-elements" : "");
	if (dump)
		print_hex_dump(KERN_INFO, KBUILD_MODNAME ": ", DUMP_PREFIX_OFFSET,
			       32, 1, skb->data, min_t(size_t, len, BG_DUMP_MAX),
			       false);
	return 0;
}

static struct kprobe bg_kp = {
	.pre_handler = bg_pre_handler,
};

static int bg_stats_get(char *buf, const struct kernel_param *kp)
{
	unsigned long flags;
	typeof(bg_stats) s;
	u64 now = bg_now_ms();
	int n, known = 0, i;

	raw_spin_lock_irqsave(&bg_lock, flags);
	s = bg_stats;
	for (i = 0; i < BG_TABLE_SIZE; i++)
		known += bg_tbl.e[i].used;
	raw_spin_unlock_irqrestore(&bg_lock, flags);

	n = scnprintf(buf, PAGE_SIZE,
		      "version: " BG_VERSION "\n"
		      "enabled: %d\n"
		      "beacons_seen: %llu\n"
		      "dropped: %llu\n"
		      "would_drop: %llu\n"
		      "reason_bad_fcs: %llu\n"
		      "reason_malformed: %llu\n"
		      "reason_missing_elements: %llu\n"
		      "let_through_after_hold: %llu\n"
		      "fcs_good: %llu\n"
		      "fcs_bad: %llu\n"
		      "fcs_trusted: %d\n"
		      "known_bssids: %d\n"
		      "kprobe_missed: %lu\n",
		      enabled, s.beacons, s.dropped, s.would_drop, s.r_fcs,
		      s.r_malformed, s.r_downgrade, s.expired, s.fcs_good,
		      s.fcs_bad, s.fcs_good >= BG_FCS_TRUST_MIN, known,
		      bg_kp.nmissed);
	if (s.last_drop_ms)
		n += scnprintf(buf + n, PAGE_SIZE - n,
			       "last_drop: %llu s ago from %pM\n",
			       div_u64(now - s.last_drop_ms, MSEC_PER_SEC),
			       s.last_bssid);
	else
		n += scnprintf(buf + n, PAGE_SIZE - n, "last_drop: never\n");
	return n;
}

static const struct kernel_param_ops bg_stats_ops = {
	.get = bg_stats_get,
};
module_param_cb(stats, &bg_stats_ops, NULL, 0444);
MODULE_PARM_DESC(stats, "Counters (read-only)");

static int __init bg_init(void)
{
	int ret;

	/*
	 * Taking the address of the exported symbol (instead of looking it up
	 * by name) makes this module depend on mac80211: it is loaded first
	 * and cannot go away underneath the probe.
	 */
	bg_kp.addr = (kprobe_opcode_t *)ieee80211_rx_napi;

	ret = register_kprobe(&bg_kp);
	if (ret) {
		pr_err("cannot probe ieee80211_rx_napi (%d); Wi-Fi is unaffected\n", ret);
		return ret;
	}
	pr_info("v" BG_VERSION " active (enabled=%d max_hold_ms=%u verify_fcs=%d)\n",
		enabled, max_hold_ms, verify_fcs);
	return 0;
}

static void __exit bg_exit(void)
{
	unregister_kprobe(&bg_kp);
	pr_info("unloaded (dropped %llu of %llu beacons)\n",
		bg_stats.dropped, bg_stats.beacons);
}

module_init(bg_init);
module_exit(bg_exit);

MODULE_LICENSE("GPL");
MODULE_VERSION(BG_VERSION);
MODULE_DESCRIPTION("Hide corrupt/downgraded Wi-Fi beacons from mac80211 so it does not disconnect");

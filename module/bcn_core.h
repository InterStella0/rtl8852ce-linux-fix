/* SPDX-License-Identifier: GPL-2.0 */
/*
 * bcn_core.h - beacon sanity logic for bcn_guard.
 *
 * Pure logic, no kernel APIs, so the exact same code is unit-tested and
 * fuzzed in userspace (tests/test_core.c) before it ever runs in softirq
 * context. Every read is bounded by the length the caller passes in.
 */
#ifndef BCN_CORE_H
#define BCN_CORE_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h>
#else
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#endif

#define BG_HDR_LEN	24	/* 802.11 management header */
#define BG_FIXED_LEN	12	/* timestamp(8) + beacon interval(2) + capability(2) */
#define BG_FCS_LEN	4
#define BG_MIN_LEN	(BG_HDR_LEN + BG_FIXED_LEN)

/*
 * Signature of a beacon: which of the elements that decide mac80211's
 * connection mode (legacy/HT/VHT/HE/EHT) are present and large enough to be
 * used. Sizes mirror the checks in net/mac80211/parse.c.
 */
#define BG_E_HT_CAP	0x0001
#define BG_E_HT_OPER	0x0002
#define BG_E_VHT_CAP	0x0004
#define BG_E_VHT_OPER	0x0008
#define BG_E_HE_CAP	0x0010
#define BG_E_HE_OPER	0x0020
#define BG_E_EHT_CAP	0x0040
#define BG_E_EHT_OPER	0x0080
#define BG_E_ALL	0x00ff
#define BG_MALFORMED	0x8000	/* element list does not parse cleanly */

/* why a beacon was judged the way it was (struct bg_result.reason) */
#define BG_R_FCS	0x01	/* FCS in the frame does not match its contents */
#define BG_R_MALFORMED	0x02	/* element list newly malformed */
#define BG_R_DOWNGRADE	0x04	/* lacks an element this BSSID always sent */
#define BG_R_EXPIRED	0x08	/* suspicious for too long: let it through */

#define BG_TABLE_SIZE	64

struct bg_entry {
	u8 bssid[6];
	u8 used;
	u8 in_run;		/* currently in a run of suspicious beacons */
	u16 base;		/* signature this BSSID normally sends */
	u64 last_seen_ms;
	u64 run_start_ms;
};

struct bg_table {
	struct bg_entry e[BG_TABLE_SIZE];
};

struct bg_result {
	bool drop;
	u8 reason;
	u16 sig;
	u16 base;
};

/*
 * Is this an infrastructure AP beacon laid out the way we expect?
 * On success points *bssid at the 6-byte BSSID and *ies at the element list.
 */
static inline bool bg_frame_is_ap_beacon(const u8 *d, size_t len, size_t fcs_len,
					 const u8 **bssid, const u8 **ies,
					 size_t *ies_len)
{
	static const u8 bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	if (len < BG_MIN_LEN + fcs_len)
		return false;
	/* protocol version 0, type management, subtype beacon */
	if (d[0] != 0x80)
		return false;
	/* no ToDS/FromDS, not protected, no HT-control (would shift the body) */
	if (d[1] & (0x01 | 0x02 | 0x40 | 0x80))
		return false;
	if (memcmp(d + 4, bcast, 6) != 0)		/* addr1: broadcast */
		return false;
	if (memcmp(d + 10, d + 16, 6) != 0)		/* addr2 == addr3: AP */
		return false;

	*bssid = d + 16;
	*ies = d + BG_MIN_LEN;
	*ies_len = len - BG_MIN_LEN - fcs_len;
	return true;
}

/* Walk the element list and compute the beacon's signature. */
static inline u16 bg_signature(const u8 *p, size_t len)
{
	const u8 *end = p + len;
	u16 sig = 0;

	while ((size_t)(end - p) >= 2) {
		u8 id = p[0];
		size_t elen = p[1];

		p += 2;
		if (elen > (size_t)(end - p))
			return sig | BG_MALFORMED;	/* runs off the frame */

		switch (id) {
		case 45:	/* HT Capabilities */
			if (elen >= 26)
				sig |= BG_E_HT_CAP;
			break;
		case 61:	/* HT Operation */
			if (elen >= 22)
				sig |= BG_E_HT_OPER;
			break;
		case 191:	/* VHT Capabilities */
			if (elen >= 12)
				sig |= BG_E_VHT_CAP;
			break;
		case 192:	/* VHT Operation */
			if (elen >= 5)
				sig |= BG_E_VHT_OPER;
			break;
		case 255:	/* Element ID Extension */
			if (elen < 1)
				break;
			switch (p[0]) {
			case 35:	/* HE Capabilities */
				if (elen >= 1 + 21)
					sig |= BG_E_HE_CAP;
				break;
			case 36:	/* HE Operation */
				if (elen >= 1 + 6)
					sig |= BG_E_HE_OPER;
				break;
			case 108:	/* EHT Capabilities */
				if (elen >= 1 + 11)
					sig |= BG_E_EHT_CAP;
				break;
			case 106:	/* EHT Operation */
				if (elen >= 1 + 5)
					sig |= BG_E_EHT_OPER;
				break;
			}
			break;
		}
		p += elen;
	}

	if (p != end)
		sig |= BG_MALFORMED;	/* stray trailing byte */
	return sig;
}

static inline struct bg_entry *bg_find(struct bg_table *t, const u8 *bssid)
{
	int i;

	for (i = 0; i < BG_TABLE_SIZE; i++)
		if (t->e[i].used && memcmp(t->e[i].bssid, bssid, 6) == 0)
			return &t->e[i];
	return NULL;
}

/* Take a free slot, or evict the BSSID we have not heard from the longest. */
static inline struct bg_entry *bg_alloc(struct bg_table *t, const u8 *bssid)
{
	struct bg_entry *victim = &t->e[0];
	int i;

	for (i = 0; i < BG_TABLE_SIZE; i++) {
		if (!t->e[i].used) {
			victim = &t->e[i];
			break;
		}
		if (t->e[i].last_seen_ms < victim->last_seen_ms)
			victim = &t->e[i];
	}
	memset(victim, 0, sizeof(*victim));
	memcpy(victim->bssid, bssid, 6);
	victim->used = 1;
	return victim;
}

/*
 * Decide what to do with one beacon.
 *
 * A beacon is suspicious when, compared to what this BSSID normally sends,
 * it has a bad FCS, a newly malformed element list, or is missing a
 * mode-defining element. Suspicious beacons are dropped.
 *
 * Fail-open guarantees (worst case is always "stock kernel behaviour"):
 *  - a BSSID is only protected after we learned a baseline from it;
 *  - one normal beacon ends a suspicious run;
 *  - if a BSSID sends nothing but suspicious beacons for hold_ms, they are
 *    let through and (unless the FCS is bad) become the new baseline, so a
 *    genuinely reconfigured AP is delayed by at most hold_ms.
 */
static inline void bg_decide(struct bg_table *t, const u8 *bssid, u16 sig,
			     bool fcs_bad, u64 now_ms, u32 hold_ms,
			     struct bg_result *r)
{
	struct bg_entry *e = bg_find(t, bssid);
	u8 reason = 0;

	r->drop = false;
	r->reason = 0;
	r->sig = sig;
	r->base = sig;

	if (!e) {
		/* never learn from (or act on) a frame we cannot trust */
		if (fcs_bad)
			return;
		e = bg_alloc(t, bssid);
		e->base = sig;
		e->last_seen_ms = now_ms;
		return;
	}

	e->last_seen_ms = now_ms;
	r->base = e->base;

	if (fcs_bad)
		reason |= BG_R_FCS;
	if ((sig & BG_MALFORMED) && !(e->base & BG_MALFORMED))
		reason |= BG_R_MALFORMED;
	if (e->base & BG_E_ALL & ~sig)
		reason |= BG_R_DOWNGRADE;

	if (!reason) {
		e->base = sig;		/* same, or strictly richer: (re)learn */
		e->in_run = 0;
		return;
	}

	if (!e->in_run) {
		e->in_run = 1;
		e->run_start_ms = now_ms;
	}

	if (now_ms - e->run_start_ms >= hold_ms) {
		r->reason = reason | BG_R_EXPIRED;
		if (!fcs_bad) {
			e->base = sig;
			e->in_run = 0;
		}
		return;
	}

	r->drop = true;
	r->reason = reason;
}

#endif /* BCN_CORE_H */

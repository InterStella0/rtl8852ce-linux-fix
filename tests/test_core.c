// SPDX-License-Identifier: GPL-2.0
/*
 * Userspace unit tests + fuzzer for module/bcn_core.h.
 * Build with -fsanitize=address,undefined: any out-of-bounds read in the
 * logic that later runs in the kernel RX path fails here instead.
 *
 *   make -C tests && ./tests/test_core
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "../module/bcn_core.h"

static int failures;

#define CHECK(cond)							\
	do {								\
		if (!(cond)) {						\
			printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
			failures++;					\
		}							\
	} while (0)

static const u8 AP1[6] = { 0x02, 0x00, 0x00, 0x00, 0x01, 0x00 };
static const u8 AP2[6] = { 0x02, 0x00, 0x00, 0x00, 0x02, 0x00 };

/* append one element */
static size_t put(u8 *b, size_t off, u8 id, u8 len, u8 fill)
{
	b[off] = id;
	b[off + 1] = len;
	memset(b + off + 2, fill, len);
	return off + 2 + len;
}

/* build a beacon; returns total length (no FCS) */
static size_t mk_beacon(u8 *b, const u8 *bssid, bool ht, bool vht, bool he)
{
	size_t o;

	memset(b, 0, BG_MIN_LEN);
	b[0] = 0x80;
	memset(b + 4, 0xff, 6);
	memcpy(b + 10, bssid, 6);
	memcpy(b + 16, bssid, 6);
	o = BG_MIN_LEN;
	o = put(b, o, 0, 4, 'x');		/* SSID */
	o = put(b, o, 1, 8, 0x8c);		/* rates */
	o = put(b, o, 3, 1, 36);		/* DS */
	if (ht) {
		o = put(b, o, 45, 26, 0x11);
		o = put(b, o, 61, 22, 0x22);
	}
	if (vht) {
		o = put(b, o, 191, 12, 0x33);
		o = put(b, o, 192, 5, 0x44);
	}
	if (he) {
		o = put(b, o, 255, 26, 0);
		b[o - 26] = 35;
		o = put(b, o, 255, 7, 0);
		b[o - 7] = 36;
	}
	o = put(b, o, 221, 24, 0x55);		/* vendor */
	return o;
}

static u16 sig_of(const u8 *b, size_t len)
{
	const u8 *bssid, *ies;
	size_t n;

	if (!bg_frame_is_ap_beacon(b, len, 0, &bssid, &ies, &n))
		return 0xffff;
	return bg_signature(ies, n);
}

static void test_signature(void)
{
	u8 b[512];
	size_t n;

	n = mk_beacon(b, AP1, true, true, false);
	CHECK(sig_of(b, n) == (BG_E_HT_CAP | BG_E_HT_OPER | BG_E_VHT_CAP | BG_E_VHT_OPER));
	n = mk_beacon(b, AP1, true, false, false);
	CHECK(sig_of(b, n) == (BG_E_HT_CAP | BG_E_HT_OPER));
	n = mk_beacon(b, AP1, false, false, false);
	CHECK(sig_of(b, n) == 0);
	n = mk_beacon(b, AP1, true, true, true);
	CHECK(sig_of(b, n) == (BG_E_HT_CAP | BG_E_HT_OPER | BG_E_VHT_CAP |
			       BG_E_VHT_OPER | BG_E_HE_CAP | BG_E_HE_OPER));

	/* truncation in the middle of an element => malformed */
	n = mk_beacon(b, AP1, true, true, false);
	CHECK(sig_of(b, n - 3) & BG_MALFORMED);
	/* one stray byte at the end => malformed */
	b[n] = 0;
	CHECK(sig_of(b, n + 1) & BG_MALFORMED);
	/* undersized HT cap is not counted */
	n = mk_beacon(b, AP1, false, false, false);
	n = put(b, n, 45, 10, 0);
	CHECK(!(sig_of(b, n) & BG_E_HT_CAP));

	/* frame classification */
	n = mk_beacon(b, AP1, true, true, false);
	b[0] = 0x50;				/* probe response */
	CHECK(sig_of(b, n) == 0xffff);
	b[0] = 0x80;
	b[1] = 0x80;				/* HT control present */
	CHECK(sig_of(b, n) == 0xffff);
	b[1] = 0;
	b[16] ^= 1;				/* addr3 != addr2 (IBSS) */
	CHECK(sig_of(b, n) == 0xffff);
	b[16] ^= 1;
	b[4] = 0;				/* not broadcast */
	CHECK(sig_of(b, n) == 0xffff);
	b[4] = 0xff;
	CHECK(sig_of(b, BG_MIN_LEN - 1) == 0xffff);	/* too short */
	CHECK(sig_of(b, BG_MIN_LEN) == 0);		/* empty body is fine */
}

static const u16 VHT = BG_E_HT_CAP | BG_E_HT_OPER | BG_E_VHT_CAP | BG_E_VHT_OPER;
static const u16 HT = BG_E_HT_CAP | BG_E_HT_OPER;

static void test_decide(void)
{
	static struct bg_table t;
	struct bg_result r;
	u64 now = 1000;
	int i;

	memset(&t, 0, sizeof(t));

	/* first beacon: learned, passed */
	bg_decide(&t, AP1, VHT, false, now, 3000, &r);
	CHECK(!r.drop && !r.reason);

	/* THE BUG: single beacons missing VHT / HT+VHT / malformed => dropped */
	bg_decide(&t, AP1, HT, false, now += 100, 3000, &r);
	CHECK(r.drop && r.reason == BG_R_DOWNGRADE && r.base == VHT);
	bg_decide(&t, AP1, VHT, false, now += 100, 3000, &r);
	CHECK(!r.drop);
	bg_decide(&t, AP1, 0, false, now += 100, 3000, &r);
	CHECK(r.drop && r.reason == BG_R_DOWNGRADE);
	bg_decide(&t, AP1, VHT | BG_MALFORMED, false, now += 100, 3000, &r);
	CHECK(r.drop && r.reason == BG_R_MALFORMED);
	bg_decide(&t, AP1, VHT, true, now += 100, 3000, &r);
	CHECK(r.drop && r.reason == BG_R_FCS);
	bg_decide(&t, AP1, VHT, false, now += 100, 3000, &r);
	CHECK(!r.drop);

	/* bad beacons interleaved with good ones are dropped forever */
	for (i = 0; i < 1000; i++) {
		bg_decide(&t, AP1, HT, false, now += 100, 3000, &r);
		CHECK(r.drop);
		bg_decide(&t, AP1, VHT, false, now += 100, 3000, &r);
		CHECK(!r.drop);
	}

	/* fail-open: AP really reconfigured => hidden for hold_ms, then passed */
	for (i = 0; i < 29; i++) {
		bg_decide(&t, AP1, HT, false, now += 100, 3000, &r);
		CHECK(r.drop);
	}
	bg_decide(&t, AP1, HT, false, now += 200, 3000, &r);
	CHECK(!r.drop && (r.reason & BG_R_EXPIRED));
	bg_decide(&t, AP1, HT, false, now += 100, 3000, &r);	/* new baseline */
	CHECK(!r.drop && !r.reason);

	/* upgrade is accepted at once and becomes the baseline */
	bg_decide(&t, AP1, VHT, false, now += 100, 3000, &r);
	CHECK(!r.drop && !r.reason);
	bg_decide(&t, AP1, HT, false, now += 100, 3000, &r);
	CHECK(r.drop);
	bg_decide(&t, AP1, VHT, false, now += 100, 3000, &r);

	/* persistent bad FCS: passed after hold, never learned, keeps passing */
	for (i = 0; i < 30; i++)
		bg_decide(&t, AP1, 0, true, now += 100, 3000, &r);
	bg_decide(&t, AP1, 0, true, now += 100, 3000, &r);
	CHECK(!r.drop && (r.reason & BG_R_EXPIRED));
	bg_decide(&t, AP1, 0, true, now += 100, 3000, &r);
	CHECK(!r.drop);
	bg_decide(&t, AP1, VHT, false, now += 100, 3000, &r);	/* recovers */
	CHECK(!r.drop && !r.reason && r.base == VHT);
	bg_decide(&t, AP1, HT, false, now += 100, 3000, &r);
	CHECK(r.drop);

	/* an AP that always sends malformed beacons is never punished for it */
	bg_decide(&t, AP2, HT | BG_MALFORMED, false, now += 100, 3000, &r);
	CHECK(!r.drop);
	bg_decide(&t, AP2, HT | BG_MALFORMED, false, now += 100, 3000, &r);
	CHECK(!r.drop && !r.reason);

	/* unknown BSSID with bad FCS: untouched and not learned */
	{
		const u8 ap3[6] = { 2, 0, 0, 0, 3, 0 };

		bg_decide(&t, ap3, 0, true, now += 100, 3000, &r);
		CHECK(!r.drop && !bg_find(&t, ap3));
	}

	/* hold_ms = 0 => never drops (documented kill switch) */
	bg_decide(&t, AP1, VHT, false, now += 100, 0, &r);
	bg_decide(&t, AP1, HT, false, now += 100, 0, &r);
	CHECK(!r.drop);

	/* table churn: the AP we hear constantly is never evicted */
	memset(&t, 0, sizeof(t));
	bg_decide(&t, AP1, VHT, false, now += 100, 3000, &r);
	for (i = 0; i < 5000; i++) {
		u8 x[6] = { 2, 1, (u8)(i >> 8), (u8)i, 0, 0 };

		bg_decide(&t, x, HT, false, now += 1, 3000, &r);
		if (i % 50 == 0)
			bg_decide(&t, AP1, VHT, false, now += 1, 3000, &r);
	}
	bg_decide(&t, AP1, HT, false, now += 100, 3000, &r);
	CHECK(r.drop && r.base == VHT);
}

/* Feed random and mutated frames through everything; ASan/UBSan watch. */
static void fuzz(unsigned int rounds)
{
	static struct bg_table t;
	struct bg_result r;
	u64 now = 0;
	unsigned int i;

	srand(12345);
	for (i = 0; i < rounds; i++) {
		size_t cap = (size_t)(rand() % 600) + 1;
		u8 *b = malloc(cap);		/* exact size: overreads trap */
		size_t len, fcs = (rand() & 1) ? BG_FCS_LEN : 0, n, j;
		const u8 *bssid, *ies;

		if (cap >= 400 && (rand() & 1)) {
			len = mk_beacon(b, (rand() & 1) ? AP1 : AP2, rand() & 1,
					rand() & 1, rand() & 1);
			for (j = rand() % 6; j; j--)	/* corrupt some bytes */
				b[rand() % len] = (u8)rand();
			if (rand() & 1)			/* truncate */
				len = (size_t)rand() % (len + 1);
		} else {
			len = cap;
			for (j = 0; j < len; j++)
				b[j] = (u8)rand();
			if (len > 20 && (rand() & 3)) {	/* make it look like a beacon */
				b[0] = 0x80;
				b[1] = 0;
				memset(b + 4, 0xff, 6);
				if (len >= 22)
					memcpy(b + 16, b + 10, 6);
			}
		}

		if (bg_frame_is_ap_beacon(b, len, fcs, &bssid, &ies, &n)) {
			assert(ies >= b && ies + n <= b + len);
			bg_decide(&t, bssid, bg_signature(ies, n), rand() % 7 == 0,
				  now += (u64)(rand() % 500),
				  (u32)(rand() % 5000), &r);
		}
		free(b);
	}
}

int main(void)
{
	test_signature();
	test_decide();
	fuzz(3000000);
	if (failures) {
		printf("%d check(s) FAILED\n", failures);
		return 1;
	}
	printf("all core tests passed (unit + 3,000,000 fuzzed frames)\n");
	return 0;
}

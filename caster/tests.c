#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bitfield.h"
#include "conf.h"
#include "ip.h"
#include "rtcm.h"
#include "util.h"

static int urldecode_test() {
	int fail = 0;
	puts("urldecode");
	struct utest {
		char *send, *expect;
	};
	struct utest testlist[] = {
		{"abcd", "abcd"},
		{"a%20bcd", "a bcd"},
		{"a+bcd", "a bcd"},
		{"efgh%3d%3dijkl", "efgh==ijkl"},
		{"efgh%3D%25ijkl", "efgh=%ijkl"},
		{"%zz", "%zz"},
		{NULL, NULL}
	};
	for (struct utest *s = testlist; s->send; s++) {
		char *src = (char *)strdup(s->send);
		urldecode(src);
		if (!strcmp(src, s->expect))
			putchar('.');
		else {
			printf("\nFAIL: %s vs %s\n", src, s->expect);
			fail++;
		}
		free(src);
	}
	putchar('\n');
	return fail;
}

static int b64_test() {
	puts("b64encode/b64decode");
	struct b64test {
		char *send, *expect;
	};
	int fail = 0;
	struct b64test testlist[] = {
		{"", ""},
		{"f", "Zg=="},
		{"fo", "Zm8="},
		{"foo", "Zm9v"},
		{"foob", "Zm9vYg=="},
		{"fooba", "Zm9vYmE="},
		{"foobar", "Zm9vYmFy"},
		{"tralalaéèèé", "dHJhbGFsYcOpw6jDqMOp"},
		{NULL, NULL}
	};

	for (struct b64test *s = testlist; s->send; s++) {
		char *b64 = b64encode(s->send, strlen(s->send), 1);
		char *b64d = b64decode(b64, strlen(b64), 1);
		if (!strcmp(s->expect, b64))
			putchar('.');
		else {
			printf("\nFAIL: %s vs %s\n", b64, s->expect);
			fail++;
		}
		if (!strcmp(s->send, b64d))
			putchar('.');
		else {
			putchar('X');
			fail++;
		}
	}
	putchar('\n');
	return fail;
}

static int gga_test() {
	puts("parse_gga");
	int fail = 0;

	struct ggatest {
		char *gga;
		float lat, lon;
	};

	struct ggatest ggalist[] = {
	    {"$GPGGA,014822.78,0000.0000000,N,00000.0000000,E,1,00,1.0,-17.162,M,17.162,M,0.0,*5C", 0., 0.},
	    {"$GPGGA,014822.78,9900.0000000,N,00000.0000000,E,1,00,1.0,-17.162,M,17.162,M,0.0,*5C", -1337., -1337.},
	    {"$GPGGA,014822.78,9900.0000000,N,20000.0000000,E,1,00,1.0,-17.162,M,17.162,M,0.0,*5E", -1337., -1337.},
	    {"$GPGGA,014822.78,0060.0000000,N,00000.0000000,E,1,00,1.0,-17.162,M,17.162,M,0.0,*5A", -1337., -1337.},
	    {"$GPGGA,014822.78,0000.0000000,N,00060.0000000,E,1,00,1.0,-17.162,M,17.162,M,0.0,*5A", -1337., -1337.},
	    {"$GNGGA,205655.60,4849.4770477,N,00220.6693234,E,4,12,0.63,60.806,M,46.188,M,14.6,0000*6E", 48.824619, 2.344489},
	    {"$GNGGA,104710.00,4832.5844943,N,00229.8320136,E,5,12,0.84,80.418,M,46.332,M,1.0,0000*5A", 48.543076, 2.497200},
	    {"$GPGGA,182700,4609.8802,N,00056.9231,W,4,10,1,11.8,M,1,M,3,0*50", 46.164669, -0.948718},
	    {"$GPGGA,182700,4609.8802,S,00056.9231,W,4,10,1,11.8,M,1,M,3,0*50", -46.164669, -0.948718},
	    {"$GPGGA,223105.79,4849.4654397,N,00220.6576662,E,1,00,1.0,69.071,M,44.857,M,0.0,*76", 48.824425, 2.344295},
	    {"$GNGGA,103812.00,4511.0814681,N,00544.9383397,E,1,12,0.70,226.973,M,47.399,M,,*4E", 45.184692, 5.748972},
	    {"$GNGGA,103841.00,4511.0762921,N,00544.9783512,E,2,12,0.79,217.897,M,47.399,M,2.0,0000*63", 45.184605, 5.749639},
	    {" $GNGGA,103841.00,4511.0762921,N,00544.9783512,E,2,12,0.79,217.897,M,47.399,M,2.0,0000*63", 45.184605, 5.749639},
	    {"$GNGGA,172829.20,4546.2000000,N,00306.0000000,E,5,12,0.68,158.545,M,47.390,M,1.2,0000*6F", 45.77, 3.1},
	    {"ntrip-gga: $GNGGA,103841.00,4511.0762921,N,00544.9783512,E,2,12,0.79,217.897,M,47.399,M,2.0,0000*63", 45.184605, 5.749639},
	    {NULL, 0., 0.}
	};

	for (struct ggatest *gga = ggalist; gga->gga; gga++) {
		pos_t pos;
		if (parse_gga(gga->gga, &pos) < 0) {
			if (gga->lat != -1337.) {
				printf("Can't parse %s\n", gga->gga);
				fail++;
			}
			continue;
		}
		if (fabs(pos.lat-gga->lat) > 1e-6 || fabs(pos.lon-gga->lon) > 1e-6) {
			printf("FAIL: gga from %s\n-> %f %f\n", gga->gga, pos.lat, pos.lon);
			fail++;
		}
		putchar('.');
	}
	putchar('\n');
	return fail;
}

static int test_setbits() {
	puts("test_setbits");
	int fail = 0;

	uint64_t patterns[] = {0xffffffffffffffff, 0xf0f0f0f0f0f0f0f0, 0x5555555555555555, 0xaaaaaaaaaaaaaaaa, 0x5a5a5a5a5a5a5a5a,
		0x0123456789abcdef, 0xfedcba9876543210, 0x55aa55aa55aa55aa};
	unsigned char datapattern[16];

	memset(datapattern, 0, sizeof datapattern);

	for (int i = 0; i < sizeof patterns / sizeof(patterns[0]); i++) {
		uint64_t p = patterns[i];
		for (int len = 1; len <= 64; len++) {
			for (int beg = 0; beg <= 64; beg++) {
				uint64_t r, expect;
				expect = p >> (64-len);
				setbits(datapattern, beg, len, expect);
				r = getbits(datapattern, beg, len);
				if (r == expect)
					putchar('.');
				else {
					printf("\nFAIL: getbits(data, %d, %d) returned 0x%016lx vs 0x%016lx\n", beg, len, r, expect);
					fail++;
				}
				setbits(datapattern, beg, len, 0x0);
				r = getbits(datapattern, beg, len);
				if (r == 0)
					putchar('.');
				else {
					printf("\nFAIL: getbits(data, %d, %d) returned 0x%016lx vs 0\n", beg, len, r);
					fail++;
				}
			}
		}
	}
	return fail;
}

static int test_getbits() {
	puts("test_getbits");
	int fail = 0;

	unsigned char data[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
				0xff, 0xff};

	struct gbtest {
		char beg, len;
		uint64_t result;
	};
	struct gbtest gblist[] = {
		{0, 24, 0x102}, {1, 23, 0x102}, {2, 22, 0x102}, {3, 21, 0x102},
		{4, 20, 0x102}, {5, 19, 0x102}, {6, 18, 0x102}, {7, 17, 0x102},
		{8, 16, 0x102}, {0, 25, 0x204}, {1, 24, 0x204}, {2, 23, 0x204},
		{3, 22, 0x204}, {4, 21, 0x204}, {5, 20, 0x204}, {6, 19, 0x204},
		{7, 18, 0x204}, {7, 19, 0x408}, {6, 20, 0x408}, {5, 21, 0x408},
		{4, 22, 0x408}, {3, 23, 0x408}, {2, 24, 0x408}, {1, 25, 0x408},
		{0, 26, 0x408},
		{0, 64, 0x01020304050607},
		{1, 64, 0x020406080a0c0e},
		{2, 64, 0x04080c1014181c},
		{0, 1, 0}, {1, 1, 0}, {2, 1, 0}, {3, 1, 0}, {4, 1, 0}, {5, 1, 0}, {6, 1, 0}, {7, 1, 0},
		{8, 1, 0}, {9, 1, 0}, {10, 1, 0}, {11, 1, 0}, {12, 1, 0}, {13, 1, 0}, {14, 1, 0}, {15, 1, 1},
		{16, 1, 0}, {17, 1, 0}, {18, 1, 0}, {19, 1, 0}, {20, 1, 0}, {21, 1, 0}, {22, 1, 1}, {23, 1, 0},
		{24, 1, 0}, {25, 1, 0}, {26, 1, 0}, {27, 1, 0}, {28, 1, 0}, {29, 1, 0}, {30, 1, 1}, {31, 1, 1},
		{32, 1, 0}, {33, 1, 0}, {34, 1, 0}, {35, 1, 0}, {36, 1, 0}, {37, 1, 1}, {38, 1, 0}, {39, 1, 0},
		{40, 1, 0}, {41, 1, 0}, {42, 1, 0}, {43, 1, 0}, {44, 1, 0}, {45, 1, 1}, {46, 1, 0}, {47, 1, 1},
		{0,0,0}
	};

	for (struct gbtest *gb = gblist; gb->len; gb++) {
		uint64_t r = getbits(data, gb->beg, gb->len);
		if (r == gb->result)
			putchar('.');
		else {
			printf("\nFAIL: getbits(data, %d, %d) returned 0x%016lx vs 0x%016lx\n", gb->beg, gb->len, r, gb->result);
			fail++;
		}
	}

	unsigned char datapattern[16];
	uint16_t patterns[] = {0x5555, 0x55aa, 0x1122, 0x1234, 0xffff, 0x0303, 0x0f0f, 0x1f1f, 0xff00, 0};

	for (uint16_t *ppat = patterns; *ppat; ppat++) {
		uint16_t pattern = *ppat;
		for (int k = 0; k < 16; k++) {
			if (k & 1)
				datapattern[k] = pattern;
			else
				datapattern[k] = pattern >> 8;
		}
		for (int len = 0; len <= 64; len++) {
			for (int beg = 0; beg < 64; beg++) {
				uint64_t expect;
				expect = (pattern << (beg & 0xf)) | (pattern >> (16 - (beg & 0xf)));
				expect &= 0xffff;
				expect |= (expect << 16);
				expect |= (expect << 32);
				if (len == 0)
					expect = 0;
				else
					expect >>= (64 - len);
				uint64_t r = getbits(datapattern, beg, len);
				if (r == expect)
					putchar('.');
				else {
					printf("\nFAIL: getbits(data, %d, %d) returned 0x%016lx vs 0x%016lx\n", beg, len, r, expect);
					fail++;
				}
			}
		}
	}
	return fail;
}

static int test_rtcm_typeset_parse() {
	puts("test_rtcm_typeset_parse");
	struct rtcm_typeset tmp;
	int fail = 0;

	struct test {
		const char *parse, *expect;
	};

	struct test testlist[] = {
		{"", ""},
		{"0", NULL},
		{"-1", NULL},
		{"999", NULL},
		{"99999", NULL},
		{"1231", NULL},
		{"3999", NULL},
		{"4096", NULL},
		{",", NULL},
		{"1000,", NULL},
		{"999,1000", NULL},
		{"1000,999", NULL},
		{"1000", "1000"},
		{"1020", "1020"},
		{"4000", "4000"},
		{"4095", "4095"},
		{"1020,1010", "1010,1020"},
		{"1230", "1230"},
		{NULL, NULL}
	};
	for (struct test *tl = testlist; tl->parse; tl++) {
		int r = rtcm_typeset_parse(&tmp, tl->parse);
		if (r < 0) {
			if (tl->expect == NULL)
				putchar('.');
			else {
				printf("\nFAIL: rtcm_typeset_parse(\"%s\") returned %d instead of %s\n", tl->parse, r, tl->expect);
				fail++;
			}
		} else if (r >= 0 && tl->expect == NULL) {
			printf("\nFAIL: rtcm_typeset_parse(\"%s\") returned %d instead of -1\n", tl->parse, r);
			fail++;
		} else {
			char *rstr = rtcm_typeset_str(&tmp);
			if (!strcmp(rstr, tl->expect))
				putchar('.');
			else {
				printf("\nFAIL: rtcm_typeset_str(rtcm_typeset_parse(\"%s\")) returned %s instead of \"%s\"\n", tl->parse, rstr, tl->expect);
				fail++;
			}
			free(rstr);
		}
	}
	putchar('\n');
	return fail;
}

static int test_ip_analyze_prefixquota() {
	puts("prefix_quota_parse");
	int fail = 0;
	struct iptest {
		char *arg1, *arg2, *expect;
	};

	struct iptest iptestlist[] = {
		{ "::0", "0", "::/128 0" },
		{ "::0/0", "0", "::/0 0" },
		{ "::/0", "0", "::/0 0" },
		{ "::1", "32", "::1/128 32" },
		{ "::1/127", "32", NULL },
		{ "127.0.0.1 32", "127.0.0.1/32 32" },
		{ "127.0.0.1", "-32", NULL },
		{ "127.0.0.1/31", "33", NULL },
		{ "255.255.255.255/32", "1", "255.255.255.255/32 1" },
		{ "255.255.255.255/31", "1", NULL },
		{ "255.255.255.255/30", "1", NULL },
		{ "255.255.255.255/29", "1", NULL },
		{ "255.255.255.255/28", "1", NULL },
		{ "255.255.255.255/27", "1", NULL },
		{ "255.255.255.255/26", "1", NULL },
		{ "255.255.255.255/25", "1", NULL },
		{ "255.255.255.255/24", "1", NULL },
		{ "255.255.255.255/23", "1", NULL },
		{ "255.255.255.255/22", "1", NULL },
		{ "255.255.255.255/21", "1", NULL },
		{ "255.255.255.255/20", "1", NULL },
		{ "255.255.255.255/19", "1", NULL },
		{ "255.255.255.255/18", "1", NULL },
		{ "255.255.255.255/17", "1", NULL },
		{ "255.255.255.255/16", "1", NULL },
		{ "255.255.255.255/15", "1", NULL },
		{ "255.255.255.255/14", "1", NULL },
		{ "255.255.255.255/13", "1", NULL },
		{ "255.255.255.255/12", "1", NULL },
		{ "255.255.255.255/11", "1", NULL },
		{ "255.255.255.255/10", "1", NULL },
		{ "255.255.255.255/9", "1", NULL },
		{ "255.255.255.255/8", "1", NULL },
		{ "255.255.255.255/7", "1", NULL },
		{ "255.255.255.255/6", "1", NULL },
		{ "255.255.255.255/5", "1", NULL },
		{ "255.255.255.255/4", "1", NULL },
		{ "255.255.255.255/3", "1", NULL },
		{ "255.255.255.255/2", "1", NULL },
		{ "255.255.255.255/1", "1", NULL },
		{ "255.255.255.255/0", "1", NULL },
		{ "2ffe::ff", "32", "2ffe::ff/128 32" },
		{ "2FFE::2:FF", "32", "2ffe::2:ff/128 32" },
		{ "2FFE::2:FF", "32", "2ffe::2:ff/128 32" },
		{ "2FFE::FF/0", "54", NULL },
		{ "2FFE::FF/12", "54", NULL },
		{ "2FFE::FF/128", "54", "2ffe::ff/128 54"},
		{ "2FFE::FF/129", "54", NULL },
		{ "2FFE::FF/134", "54", NULL },
		{ NULL, NULL, NULL }
	};
	struct prefix_quota *r;
	for (struct iptest *ipt = &iptestlist[0]; ipt->arg1 != NULL; ipt++)  {
		char *r2 = NULL;
		char *ippref = strdup(ipt->arg1);
		char *quota = ipt->arg2;
		char *expect = ipt->expect;
		r = prefix_quota_parse(ippref, quota);
		if (r != NULL)
			r2 = prefix_quota_str(r);
		if (r == NULL && expect == NULL)
			putchar('.');
		else if (r != NULL && expect == NULL) {
			fail++;
			printf("FAIL (%s instead of NULL)\n", r2);
		} else if (r == NULL && expect != NULL) {
			fail++;
			printf(" FAIL (NULL instead of %s)\n", expect);
		} else if (strcmp(r2, expect)) {
			fail++;
			printf(" FAIL (%s instead of %s)\n", r2, expect);
		} else
			putchar('.');
		free(r2);
		free(r);
		free(ippref);
	}
	putchar('\n');
	return fail;
}

static int test_ip_convert() {
	int fail = 0;
	puts("test_ip_convert");

	union sock addr;
	char str[50];

	struct test {
		const char *parse;
		int r_expect;
		const char *str_expect;
	};

	struct test testlist[] = {
		{"192.168.0.0", 1, "192.168.0.0"},
		{"192.168.0.0/12", 0, NULL},
		{"256.168.0.0", 0, NULL},
		{"::", 1},
		{"::/", 0, NULL},
		{"::/128", 0, NULL},
		{"1:2::3:4", 1, "1:2::3:4"},
		{"...", 0, NULL},
		{"9.9.9.9", 1, "9.9.9.9"},
		{"9:9::9:9", 1, "9:9::9:9"},
		{NULL, 0, NULL}
	};

	for (struct test *tl = testlist; tl->parse; tl++) {
		int r;
		char *r_str;
		r = ip_convert(tl->parse, &addr);
		if (r == tl->r_expect)
			r_str = ip_str(&addr, str, sizeof str);
		else
			r_str = NULL;
		if (r != tl->r_expect
			|| (r_str == NULL && tl->str_expect != NULL)
			|| (r_str != NULL && tl->str_expect != NULL && strcmp(r_str, tl->str_expect))) {
			fail++;
			printf("FAIL on %s: (%d, %s) instead of (%d, %s)\n", tl->parse, r, r_str, tl->r_expect, tl->str_expect);
		} else
			putchar('.');
	}

	putchar('\n');
	return fail;
}

static int test_prefix_table() {
	int fail = 0;

	puts("test_prefix_table");

	union sock addr;

	struct test {
		const char *parse;
		int expect;
	};

	struct test testlist[] = {
		{"192.168.1.1", 84},
		{"192.168.1.255", 84},
		{"192.168.0.0", 126},
		{"192.168.0.1", 126},
		{"192.168.0.255", 126},
		{"10.1.1.1", 42},
		{"172.16.8.1", 42},
		{"0.0.0.0", 42},
		{"9.9.9.9", 9999},
		{"9:9::9:9", 9998},
		{NULL, 0}
	};

	struct prefix_table *p = prefix_table_new();
	struct prefix_quota *pq;
	pq = prefix_quota_parse("0.0.0.0/0", "42");
	prefix_table_add(p, pq);
	pq = prefix_quota_parse("192.168.0.0/16", "84");
	prefix_table_add(p, pq);
	pq = prefix_quota_parse("192.168.0.0/24", "126");
	prefix_table_add(p, pq);
	pq = prefix_quota_parse("9.9.9.9", "9999");
	prefix_table_add(p, pq);
	pq = prefix_quota_parse("::0/0", "6666");
	prefix_table_add(p, pq);
	pq = prefix_quota_parse("9:9::9:9/128", "9998");
	prefix_table_add(p, pq);
	prefix_table_sort(p);

	for (struct test *tl = testlist; tl->parse; tl++) {
		ip_convert(tl->parse, &addr);
		int quota = prefix_table_get_quota(p, &addr);
		if (quota != tl->expect) {
			fail++;
			printf("FAIL on %s: %d instead of %d\n", tl->parse, quota, tl->expect);
		} else
			putchar('.');
	}

	putchar('\n');
	return fail;
}

static int test_msm7_msm4() {
	int fail = 0;

	puts("test_msm7_msm4");

	struct test {
		int type7;
		int len7;
		char *data7;
		int type4;
		int len4;
		char *data4;
	};

	struct test testlist[] = {
	    {
		1077, 295, "\xd3\x01\x21\x43\x50\x00\x5a\xf0\x07\x82\x00\x00\x00\x2f\x53\xc0\x80\x00\x00\x00\x20\x00\x40\x00\x7d\xfd\x7f\xa7\x24\xa6\x28\x23\x26\x25\x26\xa5\xa1\x29\xab\x00\x00\x00\x00\x00\x00\x60\x2f\xc0\xc3\x95\x68\x2c\x0e\x09\x67\xb1\x70\xf9\x82\x41\xff\x89\xf0\xb0\x5e\xc1\x70\x05\x1e\x06\x2f\xe9\x21\x54\x83\x69\xff\x3f\xae\xde\xde\x07\xc4\xa8\x7b\x6a\x65\x78\x0e\x4d\x2a\x1f\x54\x2e\xb5\x27\x6b\x7e\x9f\x2c\xa5\x72\x52\x57\x28\x9e\xf1\xee\x31\xc0\xc6\x1b\xa9\x46\x6a\xf9\xe6\x37\x28\x5f\x4b\x85\xb0\xdf\x32\x99\x73\xe4\x20\xd7\x46\x0d\x61\xb7\xb1\x12\x0f\xc8\x7d\x5f\x45\xc0\xff\x7e\x3d\x38\xde\x89\x0f\xce\xf5\x3f\xf3\x53\x7f\xb6\x14\x40\x2d\x6d\x98\x1f\xfb\x6f\x6e\x28\x98\xa2\x4f\x60\x16\x12\x57\xd2\xb2\x27\x5a\xd8\x68\x68\xe0\x50\x2a\xb1\x37\xf0\x3b\xf7\x91\x23\x10\x03\x0a\xf0\x6a\xa4\xec\x95\x24\xc9\x52\x55\x0f\x41\x50\x53\xec\xf9\x2e\x4b\xf2\x9c\xf9\x34\x4d\x13\x4c\xd2\xe2\x39\x6d\x2b\x56\x00\x00\x0b\x02\x60\xc0\x2b\x0b\x42\x70\x94\x2f\x0b\x02\xe0\x9c\x2d\x0b\x02\xc0\xac\x31\x0c\x02\x00\x70\x28\x08\xc0\x7e\x11\x11\xe0\xa9\x61\x8b\x41\x54\xfb\x6d\xf3\x78\x10\x60\x1e\x4f\xbe\x9f\x59\xa4\x22\x81\x27\x90\xbb\x1f\xed\xd6\x6b\xab\x78\x7a\xd1\xdb\xc3\x28\xc6\x54\x00\x0b\x40\x77",
		1074, 184, "\xd3\x00\xb2\x43\x20\x00\x5a\xf0\x07\x82\x00\x00\x00\x2f\x53\xc0\x80\x00\x00\x00\x20\x00\x40\x00\x7d\xfd\x7f\xa7\x24\xa6\x28\x23\x26\x25\x26\xa5\xa1\x29\xab\x60\x2f\xc0\xc3\x95\x68\x2c\x0e\x09\x67\xb1\x70\xf9\x82\x41\x87\xc5\x0f\x6f\x95\xe3\x26\x99\xf5\x4d\x6a\x5a\xdf\xf9\x65\x72\x52\xe5\x15\xc7\xb8\xe0\x61\xba\x9c\xd6\x19\x8d\xc2\xfa\x85\xb1\xe6\x55\xcf\x90\x6b\xa0\xd6\x2f\x62\x24\x3e\x43\xeb\xe8\xb8\x23\xbf\x1e\xa1\xbd\x12\x3e\x77\xaa\xfe\x6a\x73\xdb\x0a\x20\x5a\xdb\x40\xff\xdb\xed\xc5\x14\x51\x27\xb0\x2c\x24\xfe\x95\x91\xeb\x5b\x0c\x34\x70\x30\x55\x62\xbf\x81\xe0\xf2\x24\x64\x01\x85\x80\xd5\x49\xff\xff\xff\xff\xff\xff\xff\xff\xff\xbb\x74\x00\x00\x16\x4d\x85\x76\xcf\x2d\xf6\x5d\x3d\xb6\x59\x5e\x38\x40\xe5\x11\x80\x40\x01\x88"},
	    {
		1087, 280, "\xd3\x01\x12\x43\xf0\x00\x8b\x1c\x5c\x42\x00\x00\x61\xf8\x38\x00\x00\x00\x00\x00\x20\x80\x00\x00\x5f\xf7\xfe\x84\x9c\xa0\x86\x9a\x84\x84\xa0\x9e\x9a\xa1\x07\x9a\xa0\xec\x95\x2c\xb1\xc0\x3a\x20\x81\xec\x02\xb8\x4c\x12\x00\xba\xca\x7e\x9d\xea\x80\x77\xe1\x38\x06\x28\x0e\xc7\xe3\xfe\xd2\x83\xa9\xfb\x77\xb7\x83\x17\x5c\x7b\x65\xa7\xd1\xcf\xf0\x4d\x5f\x46\x29\xbf\xaf\x1b\xd8\xa8\x35\x8e\x83\x86\x6b\xa6\x46\xa5\xae\x02\x59\xa5\x79\x09\xb7\x95\x74\xe0\x95\x18\x0c\xa7\x45\xee\x76\x5e\xe1\x3e\xa1\x85\xed\xbc\x81\x91\x49\x82\xc5\xb8\x03\x34\x9b\x7f\xb0\x61\xbe\x97\x04\x5d\xbd\x9c\xfe\xfe\xad\xdf\x09\x0d\xdf\x70\x9a\x5d\x90\xe5\x3f\xe7\x56\x9f\xf2\x7c\xdf\x61\x2c\x5f\xe6\x05\x01\x41\x6e\x9e\x87\xba\xc1\xf0\x88\x63\x81\xd7\xa0\x88\x7b\x40\xf0\x7a\x52\xc4\x17\x05\xd1\x34\x44\xed\x3b\x50\x54\x14\xe3\x2c\xcb\x2f\x3b\xb7\x29\x48\x11\xb4\x6c\xec\xbc\x40\x00\x01\x90\x5c\x14\x85\x41\x30\x64\x18\x85\xa1\x60\x60\x1a\x86\x41\x50\x48\x15\x84\xe1\x70\x52\x16\x04\xe1\xe8\x83\xa0\xf7\x21\x11\x70\x63\x65\xb8\xae\x71\xd4\x13\x3c\x2a\x00\x26\x29\x1b\x22\x31\xbb\x6b\xf2\x3d\x00\xba\x00\x87\xc4\xd7\x93\x70\xf4\xa1\xf6\x20\x11\xe6\x37",
		1084, 175, "\xd3\x00\xa9\x43\xc0\x00\x8b\x1c\x5c\x42\x00\x00\x61\xf8\x38\x00\x00\x00\x00\x00\x20\x80\x00\x00\x5f\xf7\xfe\x84\x9c\xa0\x86\x9a\x84\x84\xa0\x9e\x9a\xa0\xcb\x1c\x03\xa2\x08\x1e\xc0\x2b\x84\xc1\x20\x0b\xac\xa0\xc5\xd3\xdb\x27\xd1\xfe\x09\xfd\x19\xdf\xd9\xbd\x8c\x6b\x20\xe1\xad\x32\x45\xae\x0b\x34\xe4\x27\xca\xba\x09\x50\x19\x51\x7b\xa2\xf7\x1e\xa1\xbd\xb7\x86\x45\x26\x2c\x5b\x80\xcd\x26\xff\xb0\x61\xfa\x5c\x13\xdb\xd9\xd7\xbf\xab\x9f\x09\x0e\x7d\xc2\x6b\xd9\x0e\x57\xf9\xd5\xbf\xf2\x7d\x7d\x84\xb3\xfe\x60\x50\x50\x5b\xbe\x87\xbb\x07\xc2\x22\x38\x1d\x78\x22\x1e\xe0\xf0\x7a\xff\xff\xff\xff\xff\xff\xff\x7f\xff\xf7\x80\x00\x06\x57\x53\x54\xd9\x63\x6d\x98\x6b\x95\x52\x57\x3d\xd4\xd9\x38\x57\x7c\xd9"},
	    {
		1097, 275, "\xd3\x01\x0d\x44\x90\x00\x5a\xf0\x07\x82\x00\x00\x21\x30\x34\x16\x00\x00\x00\x00\x04\x00\x80\x00\x7f\xff\xfa\xfa\x93\x02\xda\xb2\xa2\xda\x7a\x72\x88\x00\x00\x00\x00\x02\xca\xc4\x24\x17\x22\x2b\xf7\x0b\x94\x8a\xdf\x68\x85\x20\x0f\xe0\x2b\xc0\x41\xfb\xd5\xf3\xd7\xc5\x3f\xbb\x7f\xf8\x0c\x18\x0f\x3c\x02\xb7\x8f\xdb\x5f\xfe\xa4\xb1\x17\xfd\x12\x3a\xc0\xa9\x9a\x0a\xe3\xf0\x56\x14\x86\x10\x6f\x2a\xbd\xf3\x48\xa0\xe7\x0b\x8f\xf7\x0e\x6e\x63\x67\x9d\x86\x28\x87\x62\xd6\xe9\x6b\x85\x97\x6e\xc0\x4a\xc8\xd8\x63\xe3\x98\x5d\x1b\x87\xef\xd9\xf8\x36\xff\x00\xaa\xff\x80\x6b\xc8\x78\x52\x6f\x7f\xc4\xe4\x5f\xa5\x7b\x9f\xf7\xdd\x3f\xf7\x1a\x60\xa5\x78\x28\x5d\xea\xdf\x7d\x63\xa7\x52\x32\xe7\xd5\xc6\x17\x49\x99\xe0\xae\xa9\x08\x58\xdd\x45\x0d\x43\xd1\xd4\x74\x49\x28\xc3\xb1\x74\xc7\x31\xc8\x32\x25\x31\x12\xcc\xd3\x3c\xeb\x3b\x4f\xb3\xe8\x00\x00\x48\x12\x05\xe1\x90\x46\x12\x84\x61\x10\x58\x16\x84\x81\x30\x52\x16\x06\x01\xa0\x60\x1a\x06\x01\x98\x0a\x0f\x0f\x16\x05\x97\xff\x28\xe1\xa1\xa5\x7b\x6d\x74\xf0\x89\xce\x14\x06\x06\xbf\xf5\x40\x04\x5f\xfe\x40\x32\x00\x9f\xef\xb1\xdf\x24\x0c\x64\x1c\x78\x5f\xde\xfd",
		1094, 173, "\xd3\x00\xa7\x44\x60\x00\x5a\xf0\x07\x82\x00\x00\x21\x30\x34\x16\x00\x00\x00\x00\x04\x00\x80\x00\x7f\xff\xfa\xfa\x93\x02\xda\xb2\xa2\xda\x7a\x72\x8a\xca\xc4\x24\x17\x22\x2b\xf7\x0b\x94\x8a\xdf\x68\x80\xf4\x05\x71\xf6\xdb\xf5\x29\x18\x02\x47\x62\xa6\x85\x72\x05\x61\x0c\x21\xca\xb3\x9a\x48\xe7\x11\xfe\xf9\xb9\xb3\xcf\x62\x88\xc5\xae\x5a\xe0\xbb\x78\x4a\xc8\xe1\x8f\x8e\x85\xd1\xb9\xfb\xf6\x80\x36\xff\x02\xab\xfe\x06\xbc\x88\x14\x9b\xe7\xc4\xe4\x7e\x95\xee\xff\x7d\xd5\xfd\xc6\x98\xa5\x78\x21\x77\xab\xf7\xd6\x3b\xd4\x8c\xbf\xd5\xc6\x3d\x26\x67\x8a\xea\x90\x16\x37\x57\xff\xff\xff\xff\xff\xff\xff\xff\xff\xf8\x00\x00\x49\x25\xf9\x47\x2c\x71\x59\x6c\x93\x53\x66\x1a\x61\xa6\x19\x80\xb6\xe8\xb3"},
	    {0, 0, NULL, 0, 0, NULL}
	};

	for (struct test *tl = testlist; tl->data7; tl++) {
		struct packet *p7 = packet_new(tl->len7);
		memcpy(p7->data, tl->data7, tl->len7);
		if (!rtcm_crc_check(p7)) {
			fail++;
			printf("FAIL on %d: bad checksum\n", tl->type7);
		}
		p7->is_rtcm = 1;
		struct packet *p = rtcm_convert_msm7(p7, 4);
		if (p == NULL) {
			fail++;
			printf("FAIL on %d: unable to convert\n", tl->type7);
		} else if (p->datalen != tl->len4) {
			fail++;
			printf("FAIL on %d: bad length %ld expected %d\n", tl->type7, p->datalen, tl->type7);
		} else if (memcmp(p->data, tl->data4, tl->len4)) {
			fail++;
			printf("FAIL on %d: bad conversion\n", tl->type7);
		} else
			putchar('.');
		packet_decref(p7);
		if (p)
			packet_decref(p);
	}

	putchar('\n');

	return fail;
}

#if 0
static void sourcetable_test(struct sourcetable *sourcetable) {
	char *ggalist[] = {
	    "$GPGGA,014822.78,0000.0000000,N,00000.0000000,E,1,00,1.0,-17.162,M,17.162,M,0.0,*5C\r\n",
	    "$GNGGA,205655.60,4849.4770477,N,00220.6693234,E,4,12,0.63,60.806,M,46.188,M,14.6,0000*6E\r\n",
	    "$GNGGA,104710.00,4832.5844943,N,00229.8320136,E,5,12,0.84,80.418,M,46.332,M,1.0,0000*5A\r\n",
	    "$GPGGA,182700,4609.8802,N,00056.9231,W,4,10,1,11.8,M,1,M,3,0*50\r\n",
	    NULL
	};

	for (char **gga = ggalist; *gga; gga++) {
		pos_t pos;
		if (parse_gga(*gga, &pos) < 0) {
			continue;
		}
		printf("sourcetable test from %s -> %.3f %.3f\n", *gga, pos.lat, pos.lon);
		struct dist_table *s = sourcetable_find_pos(sourcetable, &pos);
		if (s == NULL) {
			continue;
		}
		dist_table_display(stdout, s, 10);
		dist_table_free(s);
	}
}
#endif

int main() {
	int fail = 0;
	fail += gga_test();
	fail += b64_test();
	fail += test_ip_analyze_prefixquota();
	fail += urldecode_test();
	fail += test_getbits();
	fail += test_setbits();
	fail += test_rtcm_typeset_parse();
	fail += test_prefix_table();
	fail += test_ip_convert();
	fail += test_msm7_msm4();
	return fail != 0;
}

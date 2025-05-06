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
	    {"$GNGGA,205655.60,4849.4770477,N,00220.6693234,E,4,12,0.63,60.806,M,46.188,M,14.6,0000*6E", 48.824619, 2.344489},
	    {"$GNGGA,104710.00,4832.5844943,N,00229.8320136,E,5,12,0.84,80.418,M,46.332,M,1.0,0000*5A", 48.543076, 2.497200},
	    {"$GPGGA,182700,4609.8802,N,00056.9231,W,4,10,1,11.8,M,1,M,3,0*50", 46.164669, -0.948718},
	    {"$GPGGA,182700,4609.8802,S,00056.9231,W,4,10,1,11.8,M,1,M,3,0*50", -46.164669, -0.948718},
	    {"$GPGGA,223105.79,4849.4654397,N,00220.6576662,E,1,00,1.0,69.071,M,44.857,M,0.0,*76", 48.824425, 2.344295},
	    {"$GNGGA,103812.00,4511.0814681,N,00544.9383397,E,1,12,0.70,226.973,M,47.399,M,,*4E", 45.184692, 5.748972},
	    {"$GNGGA,103841.00,4511.0762921,N,00544.9783512,E,2,12,0.79,217.897,M,47.399,M,2.0,0000*63", 45.184605, 5.749639},
	    {" $GNGGA,103841.00,4511.0762921,N,00544.9783512,E,2,12,0.79,217.897,M,47.399,M,2.0,0000*63", 45.184605, 5.749639},
	    {"ntrip-gga: $GNGGA,103841.00,4511.0762921,N,00544.9783512,E,2,12,0.79,217.897,M,47.399,M,2.0,0000*63", 45.184605, 5.749639},
	    {NULL, 0., 0.}
	};

	for (struct ggatest *gga = ggalist; gga->gga; gga++) {
		pos_t pos;
		if (parse_gga(gga->gga, &pos) < 0) {
			printf("Can't parse %s\n", gga->gga);
			fail++;
			continue;
		}
		if (fabs(pos.lat-gga->lat) > 1e-6 || fabs(pos.lon-gga->lon) > 1e6) {
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
	fail += test_ip_convert();
	return fail != 0;
}

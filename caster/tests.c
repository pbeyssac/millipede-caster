#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf.h"
#include "ip.h"
#include "util.h"

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
	return fail != 0;
}

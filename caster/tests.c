#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf.h"
#include "ip.h"
#include "util.h"

static void b64_test() {
	char *testlist[] = {"", "f", "fo", "foo", "foob", "fooba", "foobar", "tralalaéèèé", NULL};
	for (char **s = testlist; *s; s++) {
		char *b64 = b64encode(*s, strlen(*s), 1);
		char *b64d = b64decode(b64, strlen(b64), 1);
		printf("%s -> %s -> %s\n", *s, b64, b64d);
	}
}

static void gga_test() {
	char *ggalist[] = {
	    "$GPGGA,014822.78,0000.0000000,N,00000.0000000,E,1,00,1.0,-17.162,M,17.162,M,0.0,*5C\r\n",
	    "$GNGGA,205655.60,4849.4770477,N,00220.6693234,E,4,12,0.63,60.806,M,46.188,M,14.6,0000*6E\r\n",
	    "$GNGGA,104710.00,4832.5844943,N,00229.8320136,E,5,12,0.84,80.418,M,46.332,M,1.0,0000*5A\r\n",
	    "$GPGGA,182700,4609.8802,N,00056.9231,W,4,10,1,11.8,M,1,M,3,0*50\r\n",
	    "$GPGGA,182700,4609.8802,S,00056.9231,W,4,10,1,11.8,M,1,M,3,0*50\r\n",
	    "$GPGGA,223105.79,4849.4654397,N,00220.6576662,E,1,00,1.0,69.071,M,44.857,M,0.0,*76",
	    "$GNGGA,103812.00,4511.0814681,N,00544.9383397,E,1,12,0.70,226.973,M,47.399,M,,*4E",
	    "$GNGGA,103841.00,4511.0762921,N,00544.9783512,E,2,12,0.79,217.897,M,47.399,M,2.0,0000*63",
	    NULL
	};

	for (char **gga = ggalist; *gga; gga++) {
		pos_t pos;
		if (parse_gga(*gga, &pos) < 0) {
			printf("Can't parse %s\n", *gga);
			continue;
		}
		printf("gga from %s\n-> %.3f %.3f\n", *gga, pos.lat, pos.lon);
	}
}

static void test_ip_analyze_prefixquota() {
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
		printf("%s %s => ", ippref, quota);
		r = prefix_quota_parse(ippref, quota);
		if (r == NULL) {
			printf("NULL");
		} else {
			r2 = prefix_quota_str(r);
			printf("%s", r2);
		}
		if (r == NULL && expect == NULL)
			puts(" OK");
		else if (r != NULL && expect == NULL)
			printf(" FAIL (%s instead of NULL)\n", r2);
		else if (r == NULL && expect != NULL)
			printf(" FAIL (NULL instead of %s)\n", expect);
		else if (strcmp(r2, expect))
			printf(" FAIL (%s instead of %s)\n", r2, expect);
		else
			printf(" OK (%s)\n", r2);
		free(r2);
		free(r);
		free(ippref);
	}
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
	gga_test();
	b64_test();
	test_ip_analyze_prefixquota();
}

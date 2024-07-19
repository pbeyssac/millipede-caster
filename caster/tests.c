#include <stdio.h>
#include <string.h>

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
}

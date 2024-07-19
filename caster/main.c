#include <stdio.h>
#include <unistd.h>

#include "caster.h"
#include "config.h"

/*
 * Default configuration file name
 */
static char *conf_filename = "/usr/local/etc/millipede/caster.yaml";

int
main(int argc, char **argv) {
	char *config_file = conf_filename;
	int ch;

	while ((ch = getopt(argc, argv, "c:")) != -1) {
		switch (ch) {
		case 'c':
			config_file = optarg;
			break;
		default:
			fprintf(stderr, "Usage: %s [config file]\n", argv[0]);
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0) {
		fprintf(stderr, "Usage: %s [config file]\n", argv[0]);
		exit(1);
	}
	return caster_main(config_file);
}

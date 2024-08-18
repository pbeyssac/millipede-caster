#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "conf.h"
#include "caster.h"
#include "config.h"


/*
 * Default configuration file name
 */
static char *conf_filename = "/usr/local/etc/millipede/caster.yaml";

static void usage(char **argv) {
	fprintf(stderr, "Usage: %s [-c config file] [-d][-t nthreads]\n"
		"\t-c path\t\tconfig file path\n"
		"\t-d\t\trun as a daemon\n"
		"\t-t nthreads\tnumber of threads (1-1024, default 1)\n", argv[0]);
}

int
main(int argc, char **argv) {
	char *config_file = conf_filename;
	int start_daemon = 0;
	int ch, nt;
	char *endarg;

	while ((ch = getopt(argc, argv, "c:dt:")) != -1) {
		switch (ch) {
		case 'c':
			config_file = optarg;
			break;
		case 'd':
			start_daemon = 1;
			break;
		case 't':
			nt = strtol(optarg, &endarg, 10);
			if (!*optarg || *endarg != '\0' || nt <= 0 || nt > 1024) {
				usage(argv);
				exit(1);
			}
			if (nt > 1) {
				threads = 1;
				nthreads = nt-1;
			} else {
				threads = 0;
			}
			break;
		default:
			usage(argv);
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0) {
		usage(argv);
		exit(1);
	}

	if (start_daemon) {
		int pid = fork();
		if (pid != 0) {
			fprintf(stderr, "Starting daemon as pid %d\n", pid);
			exit(0);
		}
		daemon(1, 1);
	}
	return caster_main(config_file);
}

/*
 * SO2 Lab - Linux device drivers (#4)
 * User-space test file
 */

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include "./tracer.h"

#define DEVICE_PATH	"/dev/tracer"

/*
 * prints error message and exits
 */

static void error(const char *message)
{
	perror(message);
	exit(EXIT_FAILURE);
}

/*
 * print use case
 */

static void usage(const char *argv0)
{
	printf("Usage: %s <options> <PID>\n options:\n"
			"\ta - add PID process to monitoring\n"
			"\tr - remove PID process from monitoring\n", argv0);
	exit(EXIT_FAILURE);
}

/*
 * Sample run:
 *  ./tracer_user a		; add process
 *  ./tracer_user r		; remove process
 */

int main(int argc, char **argv)
{
	int fd, pid;
	char buffer[BUFFER_SIZE];

	if (argc < 3)
		usage(argv[0]);

	if (strlen(argv[1]) != 1)
		usage(argv[0]);
	
	pid = atoi(argv[2]);
    
	fd = open(DEVICE_PATH, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	switch (argv[1][0]) {
	case 'a':				/* add process */
		if (ioctl(fd, TRACER_ADD_PROCESS, &pid) < 0) {
			perror("ioctl");
			exit(EXIT_FAILURE);
		}

		break;
	case 'r':				/* remove process */
		if (ioctl(fd, TRACER_REMOVE_PROCESS, &pid) < 0) {
			perror("ioctl");
			exit(EXIT_FAILURE);
		}

		break;
	default:
		error("Wrong parameter");
	}

	close(fd);

	return 0;
}

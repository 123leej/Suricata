#include <stdio.h>
#include <signal.h>

void accepted(int signum) {
	printf("the packet is accepted");
} /* todo change the printf part if needed */

void dropped(int signum) {
	printf("the packet is dropped");
} /* todo change the printf part if needed */

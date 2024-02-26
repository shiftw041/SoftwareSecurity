#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

void print_desc()
{
	printf("###\n");
	printf("### Welcome to ./pwntools-tutorials-level1.0!\n");
	printf("###\n");
	printf("\n");
	printf("This challenge will leverage pwntools to bypass some conditions, and then print the flag if successful\n");
	printf("Enter your input> \n");
}

void print_flag()
{
	char *p;
	FILE *fp;
	char flag[100];

	fp = fopen("/flag", "r");

	if (!fp) {
		perror("[-] fopen failed");
	}

	p = fgets(flag, sizeof(flag), fp);
	if (!p) {
		perror("[-] fgets failed");
		fclose(fp);
	}
	
	printf("%s", flag);

	fclose(fp);
}

int bypass_me(char *buf)
{
	unsigned int magic = 0xdeadbeef;
	
	if (!strncmp(buf, (char *)&magic, 4)) {
		return 1;
	}
	
	return 0;
}

int main()
{
	char buffer[100];

	print_desc();

	fgets(buffer, sizeof(buffer), stdin);

	if (bypass_me(buffer)) {
		print_flag();
	} else {
		printf("You need to bypass some conditions to get the flag: \n");
		printf("Please refer to the source code to understand these conditions\n");	
	}
	return 0;
}

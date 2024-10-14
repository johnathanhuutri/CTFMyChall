#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void init()
{
	setbuf(stdin, 0);
	setbuf(stdout, 0);
	setbuf(stderr, 0);
}

void readline(char* buf)
{
	char c, i = 0;
	while (1)
	{
		read(0, &c, 1);
		if (c=='\n')
			break;
		buf[i] = c;
		i++;
	}
	buf[i] = '\0';
}

int main()
{
	char cmd[0x200];

	init();
	puts("Chatbot v1.0");
	do
	{
		printf("Command: ");
		readline(cmd);
		if (!strcmp(cmd, "hello"))
			printf("Reply: hi\n");
		else if (!strcmp(cmd, "address"))
			printf("Reply: %p\n", &cmd);
		else if (!strcmp(cmd, "whoami"))
			system(cmd);
		else if (!strcmp(cmd, "id"))
			system(cmd);
		else if (!strcmp(cmd, "ls"))
			system(cmd);
		else if (!strcmp(cmd, "pwd"))
			system(cmd);
		else
			puts("Invalid command!");
	}while (strcmp(cmd, "exit"));

}
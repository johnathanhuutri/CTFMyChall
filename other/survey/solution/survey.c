#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char name[0x50], feedback[0x100];
int convenient, quality, difficulty, addmore, addition_len;

void init()
{
	char tmp[0x50];

	convenient = -1;
	quality = -1;
	difficulty = -1;
	addmore = -1;
	addition_len = sizeof(feedback);

	setbuf(stdin, 0);
	setbuf(stdout, 0);
	setbuf(stderr, 0);

	puts("CTF Survey");
	puts("Thank you for playing CTF. We would love to hear construction feedback in preparation for next year!");
}

void run()
{
	char tmp_feedback[0x100], tmp_name[0x50];
	int size;

	do
	{
		printf("Your name?\n> ");
		size = read(0, tmp_name, sizeof(tmp_name));
		if (tmp_name[size-1] == '\n')
			tmp_name[size-1] = '\0';
		strcpy(name, tmp_name);
		printf("Hello %s\n", name);
		do
		{
			printf("Was CTF running during a convenient time for you?\n1. Yes\n2. No\n> ");
			scanf("%d", &convenient);
			getchar();
		}while (convenient <= 0 || 3 <= convenient);
		do
		{
			printf("How would you rate the quality of challenges?\n1. Very Low\n2. Low\n3. High\n4. Very High\n> ");
			scanf("%d", &quality);
			getchar();
		}while (quality <= 0 || 5 <= quality);
		do
		{
			printf("How difficult do you find about CTF this year?\n1. Too Easy\n2. Easy\n3. Medium\n4. Hard\n5. Insane\n> ");
			scanf("%d", &difficulty);
			getchar();
		}while (difficulty <= 0 || 6 <= difficulty);
		printf("Any additional comments?\n> ");
		// for (int i=0; i<addition_len; i++)
		// {
		// 	read(0, &c, 1);
		// 	if (c=='\n')
		// 		break;
		// 	feedback[i] = c;
		// }
		size = read(0, tmp_feedback, addition_len);
		if (tmp_feedback[size-1] == '\n')
			tmp_feedback[size-1] = '\0';
		strcpy(feedback, tmp_name);
		puts("Thanks for your feedback!");
		printf("Do you want to add another survey?\n1. Yes\n2. No\n> ");
		scanf("%d", &addmore);
	} while(addmore!=2);
}

int main()
{
	init();
	run();
}
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <seccomp.h>

void install_seccomp_filter()
{
    scmp_filter_ctx ctx32, ctx64;
    ctx32 = seccomp_init(SCMP_ACT_KILL); // default action: kill
    ctx64 = seccomp_init(SCMP_ACT_KILL); // default action: kill
    seccomp_arch_remove(ctx32, SCMP_ARCH_NATIVE);
    seccomp_arch_remove(ctx64, SCMP_ARCH_NATIVE);
    seccomp_arch_add(ctx32, SCMP_ARCH_X86);
    seccomp_arch_add(ctx64, SCMP_ARCH_X86_64);
    
    // setup basic whitelist
    seccomp_rule_add(ctx64, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx64, SCMP_ACT_ALLOW, SCMP_SYS(lgetxattr), 0);
    seccomp_rule_add(ctx64, SCMP_ACT_ALLOW, SCMP_SYS(chmod), 0);
    seccomp_rule_add(ctx64, SCMP_ACT_ALLOW, SCMP_SYS(getpriority), 0);
    seccomp_rule_add(ctx64, SCMP_ACT_ALLOW, SCMP_SYS(setpriority), 0);
    
    seccomp_rule_add(ctx64, SCMP_ACT_ALLOW, SCMP_SYS(clock_nanosleep), 0);
    seccomp_rule_add(ctx64, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    seccomp_rule_add(ctx64, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx64, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx64, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);

    seccomp_rule_add(ctx32, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    seccomp_rule_add(ctx32, SCMP_ACT_ALLOW, SCMP_SYS(mmap2), 0);
    seccomp_rule_add(ctx32, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx32, SCMP_ACT_ALLOW, SCMP_SYS(_llseek), 0);
    seccomp_rule_add(ctx32, SCMP_ACT_ALLOW, SCMP_SYS(getdents), 0);

    seccomp_merge(ctx64, ctx32);

    // build and load the filter
    seccomp_load(ctx64);  
}

void exit_program(int code)
{
    __asm__(
        "mov $0x3c, %rax\n"
        "syscall\n"
    );
}

void printcolor(char *color, char *msg)
{
    if (!strcmp(color, "red"))
    {
        printf("\033[0;31m");
        printf("%s", msg);
        printf("\033[0m");
    }
    else if (!strcmp(color, "cyan"))
    {
        printf("\033[0;36m");
        printf("%s", msg);
        printf("\033[0m");
    }
    else if (!strcmp(color, "white"))
    {
        printf("\033[0;37m");
        printf("%s", msg);
        printf("\033[0m");
    }
    else if (!strcmp(color, "green"))
    {
        printf("\033[0;32m");
        printf("%s", msg);
        printf("\033[0m");
    }
}

void init()
{
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
}

void license()
{
    unsigned int option;
    printcolor("green", "\nPlease read the following License Agreement carefully\n");
    printcolor("cyan", "Keep in mind that this is a challenge, not a real setup wizard\n");
    printcolor("cyan", "1. I accept the agreement\n");
    printcolor("cyan", "2. I do not accept the agreement\n");
    printf("\033[0;36m");
    printf("> ");
    scanf("%u", &option);
    getchar();
    printf("\033[0m");
    if (option==2)
        exit_program(0);
}

void destination(char *dst)
{
    printcolor("green", "\nDestination Folder\n");
    printcolor("cyan", "Install Hello World to: ");
    read(0, dst, 0x27);
}

void install()
{
    unsigned int option;
    char dst[0x40];
    char *path = malloc(0x50);

    license();
    destination(dst);

    do
    {
        printcolor("green", "\nReady to install Hello World\n");
        printcolor("cyan", "1. Begin the installation.\n");
        printcolor("cyan", "2. Review or change any of your settings.\n");
        printf("\033[0;36m");
        printf("> ");
        scanf("%u", &option);
        getchar();
        printf("\033[0m");
        if (option==2)
            destination(dst);
    }
    while (option!=1);

    printcolor("cyan", "Validating install...\n");
    sleep(1);
    printcolor("cyan", "\t--> Done\n");
    sleep(1);
    printcolor("cyan", "Removing files...\n");
    sleep(1);
    printcolor("cyan", "\t--> Done\n");
    sleep(1);
    printcolor("cyan", "Copying new files...\n");
    sleep(1);
    printcolor("cyan", "\t--> Done\n");
    sleep(1);
    printcolor("cyan", "Updating component registration...\n");
    sleep(1);
    printcolor("cyan", "\t--> Done\n");
    sleep(1);
    printcolor("cyan", "Copying new files...\n");
    sleep(2);
    printcolor("red", "\t--> [Errno 2] No such file or directory: 'configure.conf'\n");
    sleep(1);

    printcolor("white", "\nWelcome to File Creating Wizard\n");
    printcolor("green", "\nCurrent path: ");
    printcolor("green", dst);
    printcolor("cyan", "\nFile name: ");
    printf("\033[0;36m");
    read(0, (char *)&path, 0x78);
    printf("\033[0m");
    
    printcolor("cyan", "Data: ");
    printf("\033[0;36m");
    read(0, path, 0x8);
    printf("\033[0m");
    printcolor("white", "End of File Creating Wizard\n");

    printcolor("cyan", "Continue installing...\n");
    sleep(2);
    printcolor("cyan", "\t--> Done\n");
    printcolor("white", "End of Hello World Setup Wizard\n");
}

void execute()
{
    printcolor("white", "\nExecuting...\n");
    printf("Hello world!\n");
}

int main()
{
    init();
    install_seccomp_filter();

    printcolor("white", "Welcome to the Hello World Setup Wizard\n");
    printcolor("cyan", "Initializing...\n");
    sleep(1);

    install();
    execute();

    exit_program(0);
}
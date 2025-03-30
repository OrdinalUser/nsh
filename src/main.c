#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "nsh.h"

int main(int argc, char** argv, char** envp)
{
    printf("sizeof connection: %lu\n", sizeof(nsh_conn_t));
    //return 0;
    signal(SIGINT, nsh_exit);
    nsh(argc, argv);
    return 0;
}
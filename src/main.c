#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "nsh.h"

int main(int argc, char** argv, char** envp)
{
    signal(SIGINT, nsh_exit);
    nsh(argc, argv);
    return 0;
}
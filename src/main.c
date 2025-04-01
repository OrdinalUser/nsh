#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "nsh.h"

int main(int argc, char** argv, char** envp)
{
    nsh(argc, argv);
    return 0;
}
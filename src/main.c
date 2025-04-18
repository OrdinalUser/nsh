#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "nsh.h"

#include "nsh_lexer.h"
#include "nsh_parser.h"

#include "array.h"

int main(int argc, char** argv, char** envp)
{
    nsh(argc, argv);
    //fprintf(stderr, "[Debug]: Shell exited with %d\n", err);

    return 0;
}
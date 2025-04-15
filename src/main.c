#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "nsh.h"

#include "nsh_lexer.h"
int main(int argc, char** argv, char** envp)
{
    //nsh(argc, argv);
    char buff[1024];
    while (1)
    {
        fgets(buff, 1024, stdin);
        buff[strlen(buff)] = 0;
        lexer(buff);
    }

    return 0;
}
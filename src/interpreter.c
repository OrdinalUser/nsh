#include "interpreter.h"
#include <stdio.h>

#include <unistd.h>

#define BUFF_SIZE 65536
static char buff[BUFF_SIZE];

int nsh_interpreter()
{
    while (1)
    {
        getcwd(buff, BUFF_SIZE);
        printf("%s# ", buff);
        fgets(buff, BUFF_SIZE, stdin);
        puts(buff);
        sleep(2);
    }
    return 0;
}
#include "interpreter.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <unistd.h>

#define BUFF_SIZE 65536
static char buff[BUFF_SIZE];

int nsh_interpreter()
{
    while (1)
    {
        getcwd(buff, BUFF_SIZE);
        size_t cwdLen = strlen(buff);
        buff[cwdLen] = '#'; buff[cwdLen+1] = ' '; buff[cwdLen+2] = 0; 
        write(fileno(stdout), buff, strlen(buff));
        fflush(stdout);

        ssize_t readBytes = read(fileno(stdin), buff, BUFF_SIZE);
        buff[readBytes] = 0;
        if (readBytes == 0) break;
        fflush(stdin);

        if (strcmp(buff, "quit\n") == 0) break;
        write(fileno(stdout), buff, readBytes);
        fflush(stdout);
    }
    return 0;
}
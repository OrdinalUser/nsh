#include "interpreter.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include <unistd.h>

#define BUFF_SIZE 65536
static char buff[BUFF_SIZE];
static char command_buff[BUFF_SIZE];
static size_t command_buff_size = 0;
static char write_buff[BUFF_SIZE];
static char temp_buff[BUFF_SIZE];

struct InterpreterState
{
    bool running;
};

struct InterpreterState state;

nsh_shell_e nsh_run_command()
{
    if (strcmp(command_buff, "quit") == 0)
        { state.running = false; return SHELL_EXIT; }
    else if (strcmp(command_buff, "reset") == 0)
        { state.running = false; return SHELL_RESET; }
    sprintf(write_buff, "\n> cmd: %s\n", command_buff);
    write(fileno(stdout), write_buff, strlen(write_buff));

    memset(command_buff, 0, BUFF_SIZE);
    command_buff_size = 0;

    return SHELL_OK;
}

int nsh_interpreter()
{
    command_buff_size = 0;
    state.running = true;
    
    fflush(stdin);
    fflush(stdout);
    setbuf(stdin, NULL);

    while (state.running)
    {
        memset(buff, 0, BUFF_SIZE);
        ssize_t readBytes = read(fileno(stdin), buff, BUFF_SIZE);
        
        if (readBytes == 0) break; // Connection closed on us
        else
        {
            // Buffer command input untill '\n' or '\0'
            for (size_t i = 0; i < readBytes; i++)
            {
                if (buff[i] == '\n' || buff[i] == '\0')
                {
                    command_buff[command_buff_size] = '\0';
                    nsh_shell_e err = nsh_run_command(command_buff);
                    if (err != SHELL_OK) return err;

                    getcwd(temp_buff, BUFF_SIZE);
                    sprintf(write_buff, "%s# ", temp_buff);
                    write(fileno(stdout), write_buff, strlen(write_buff));
                }
                else
                {
                    if ((buff[i] == '\b' || buff[i] == 127) && command_buff_size > 0)
                        command_buff[--command_buff_size] = 0;
                    else
                        command_buff[command_buff_size++] = buff[i];
                    
                    // Send prompt over so the client knows it's their time to shine
                    // Server side echo for when gathering queries
                    getcwd(temp_buff, BUFF_SIZE);
                    sprintf(write_buff, "\r%s# ", temp_buff);
                    snprintf(write_buff + strlen(write_buff), command_buff_size+1, "%s", command_buff);
                    write(fileno(stdout), write_buff, strlen(write_buff));
                }
            }
        }
    }

    return SHELL_RESET;
}
#include "interpreter.h"
#include "nsh_lexer.h"
#include "nsh_parser.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include <unistd.h>

#include "array.h"

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

nsh_shell_e nsh_exec(char* program, int* exit_code)
{
    pid_t pid, wpid;
    int status = -69;
    char* args[] = {program, NULL};

    // Save nsh signals - there must always be at least one retarded thing
    nsh_signals_reset();
    struct sigaction sa = {0};
    sa.sa_handler = SIG_DFL;
    sa.sa_flags = 0;
    sigaction(SIGCHLD, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    pid = fork();
    switch (pid)
    {
    case -1:
        nsh_signals_set();
        return SHELL_FORK_FAILED;
    case 0:
        execvp(program, args);
        exit((int)SHELL_EXEC_FAIL); // Indicates command not found on POSIX & Bash
    default:
        wpid = waitpid(pid, &status, 0);
        if (wpid == -1)
        {
            perror("waitpid failed????\n");
        }
        nsh_signals_set();

        if (WIFEXITED(status))
        {
            // This branch literally never gets called even if ls returns 0?
            const int code = WEXITSTATUS(status);
            *exit_code = code;
            if (code == (int)SHELL_EXEC_FAIL) return SHELL_EXEC_FAIL;
        } else if (WIFSIGNALED(status))
        {
            const int sig = WTERMSIG(status);
        }
        return SHELL_OK;
    }
    return SHELL_OK; // This should be unreachable
}

nsh_shell_e nsh_exec_native(nsh_command_t* cmd)
{
    if (strcmp(cmd->cmd, "quit") == 0)
        { state.running = false; return SHELL_EXIT; }
    else if (strcmp(cmd->cmd, "reset") == 0)
        { state.running = false; return SHELL_RESET; }
    else if (strcmp(cmd->cmd, "cd") == 0)
    {
        if (*cmd->flags == NULL) {
            fprintf(stdout, "-nsh: cd has no destination\n");
        }
        else if (chdir(*cmd->flags) != 0) {
            fprintf(stdout, "-nsh: cd failed to change directory\n");
        }
        return SHELL_OK;
    }

    return SHELL_NOT_NATIVE;
}

nsh_shell_e nsh_run_command()
{
    write(fileno(stdout), "\n", 1);
    //printf("cmd buff: %s\n", command_buff);

    char* saveptr1;
    nsh_command_chain_t chain = parser_advance(command_buff, &saveptr1);
    while (chain.count)
    {
        // printf("Chain - %d --------------------\n", chain.count);
        // for (size_t i = 0; i < chain.count; i++)
        // {
        //     nsh_command_t* cmd = &chain.commands[i];
        //     printf("> Command ------\n");
        //     printf(">> Path: %s\n", cmd->cmd);
        //     printf(">> Flags: ");
        //     for (char** flag = cmd->flags; *flag; flag++)
        //     {
        //         printf("%s", *flag);
        //         if (*(flag+1)) putchar(' ');
        //     }
        //     putchar('\n');
            
        //     if (cmd->input_file) printf(">> Input: %s\n", cmd->input_file);
        //     if (cmd->output_file) printf(">> Output: %s\n", cmd->output_file);
        // }
        
        bool validChain = parser_chain_validate(&chain);
        if (!validChain)
        {
            parser_chain_free(&chain);
            chain = parser_advance(NULL, &saveptr1);
            continue;
        }

        int pipefd[2], prev_fd = -1;

        // Try to run native command
        for (size_t i = 0; i < chain.count; i++)
        {
            nsh_command_t* cmd = chain.commands + i;
            if (chain.count == 1)
            {
                nsh_shell_e isBuiltIn = nsh_exec_native(cmd);
                if (isBuiltIn == SHELL_OK) continue;
                else if (isBuiltIn != SHELL_NOT_NATIVE) return isBuiltIn;
            }

            if (i < chain.count - 1)
            {
                if (pipe(pipefd) < 0)
                {
                    perror("pipe failed????\n");
                    memset(command_buff, 0, BUFF_SIZE);
                    command_buff_size = 0;
                    return SHELL_PIPELINE_FAIL;
                }
            }
            
            // Forge program args
            array_t args; array_create(&args, 16, sizeof(char*));
            size_t argc = 1;
            char* dupedName = strdup(cmd->cmd); array_push(&args, &dupedName);
            char* nullFlag = 0;
            for (char** flag = cmd->flags; *flag; flag++)
            {
                char* flg = strdup(*flag);
                array_push(&args, &flg);
                argc++;
            }
            array_push(&args, &nullFlag);

            nsh_signals_reset();

            // Run external command
            pid_t pid = fork();
            switch (pid)
            {
            case -1:
                perror("We're cooked");
                return SHELL_FORK_FAILED;
            case 0:
                // Piping fun
                if (prev_fd != -1) {
                    dup2(prev_fd, STDIN_FILENO);
                    close(prev_fd);
                }
                if (cmd->input_file && i == 0)
                {
                    int fd = open(cmd->input_file, O_RDONLY);
                    if (fd == -1)
                    {
                        fprintf("-nsh: couldn't open file \"%s\" during redirection\n", cmd->input_file);
                        exit(-1);
                    }
                    dup2(fd, STDIN_FILENO);
                    close(fd);
                }

                if (i < chain.count - 1) {
                    close(pipefd[0]);
                    dup2(pipefd[1], STDOUT_FILENO);
                    close(pipefd[1]);
                }
                if (cmd->output_file && i == chain.count -1)
                {
                    int fd = open(cmd->output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                    if (fd == -1)
                    {
                        fprintf("-nsh: couldn't create file \"%s\" for redirection\n", cmd->output_file);
                        goto loop_end;
                    }
                    dup2(fd, STDOUT_FILENO);
                    close(fd);
                }

                execvp(cmd->cmd, args.base);
                exit((int)SHELL_EXEC_FAIL);
                break;
            default:
            
                if (prev_fd != -1)
                close(prev_fd);
                if (i < chain.count - 1)
                {
                    close(pipefd[1]);
                    prev_fd = pipefd[0];
                }
                
                int status = -69;
                pid_t wpid = waitpid(pid, &status, 0);
                if (wpid == -1)
                {
                    perror("waitpid failed????\n");
                }
                nsh_signals_set();
        
                if (WIFEXITED(status))
                {
                    // This branch literally never gets called even if ls returns 0?
                    const int code = WEXITSTATUS(status);
                    if (code == (int)SHELL_EXEC_FAIL) return SHELL_EXEC_FAIL;
                }
                else if (WIFSIGNALED(status))
                {
                    const int sig = WTERMSIG(status);
                }
                break;
            }

            // Free arguments
            // for (size_t i = 0; i < argc; i++)
            // {
            //     free(array_at(&args, i));
            // }
            // array_destroy(&args);
        }
loop_end:
        parser_chain_free(&chain);
        chain = parser_advance(NULL, &saveptr1);
    }

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
                    if (err != SHELL_OK) { printf("shell err: %d\n", err); return err; }

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
#include "globals.h"

#include "interpreter.h"
#include "nsh_lexer.h"
#include "nsh_parser.h"
#include <sys/mman.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include <arpa/inet.h>
#include <sys/stat.h>

#include <unistd.h>

#include "array.h"

#include <poll.h>

#define BUFF_SIZE 65536
static char buff[BUFF_SIZE];
static char command_buff[BUFF_SIZE];
static size_t command_buff_size = 0;
static char temp_buff[BUFF_SIZE];

struct InterpreterState
{
    bool running;
};

struct InterpreterState state;

nsh_shell_e nsh_command_stat()
{
    char msgbuff[256];

    printf("|=== NSH : Stat =========================================================|\n");
    printf("| ID  | State  | Type    | Additional info                               |\n");
    printf("|-----|--------|---------|-----------------------------------------------|\n");
    
    pthread_mutex_lock(&shared_mem->lock);
    for (size_t i = 0; i < shared_mem->count; i++)
    {
        nsh_conn_t* conn = shared_mem->connections + i;
        const char* conn_type_str = NSH_CONNECTION_TYPE_STR[conn->type];
        const char* state_str = conn->state == STATE_INACTIVE ? "Idle" : "Active";

        if (conn->type == CONSOLE)
        {
            printf("| %-3.3d | %-6.6s | %-7.7s | %-45.45s |\n", conn->id, state_str, conn_type_str, "");
        }
        else if (conn->type == NETWORK)
        {
            if (conn->state == STATE_ACTIVE)
                snprintf(msgbuff, 256, "%s:%d -> %s:%d", conn->network.ip_from, conn->network.port_from, conn->network.ip_to, conn->network.port_to);
            else
                snprintf(msgbuff, 256, "Listening at %s:%d", conn->network.ip_to, conn->network.port_to);
            printf("| %-3.3d | %-6.6s | %-7.7s | %-45.45s |\n", conn->id, state_str, conn_type_str, msgbuff);
        }
        else if (conn->type == DOMAIN)
        {
            printf("| %-3.3d | %-6.6s | %-7.7s | %-45.45s |\n", conn->id, state_str, conn_type_str, conn->domain.path);
        }
        else
        {
            printf("| %-3.3d | %-6.6s | %-7.7s | %-45.45s |\n", conn->id, state_str, conn_type_str, "Expect a crash :)");
        }
    }
    printf("|========================================================================|\n");
    
    pthread_mutex_unlock(&shared_mem->lock);
    return SHELL_OK;
}

nsh_shell_e nsh_command_abort(int connId)
{
    bool found = false;
    pthread_mutex_lock(&shared_mem->lock);
    for (size_t i = 0; i < shared_mem->count; i++)
    {
        nsh_conn_t* conn = shared_mem->connections + i;
        if (conn->id == connId) {
            if (conn->pid == getpid())
                printf("-nsh: Cannot abort your own connection, use 'reset'\n");
            else
                kill(conn->pid, SIGUSR1);
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&shared_mem->lock);
    if (!found) printf("-nsh: Failed to find connection with ID %d\n", connId);
    return SHELL_OK;
}

nsh_shell_e nsh_command_close(int connId)
{
    bool found = false;
    pthread_mutex_lock(&shared_mem->lock);
    for (size_t i = 0; i < shared_mem->count; i++)
    {
        nsh_conn_t* conn = shared_mem->connections + i;
        if (conn->id == connId) {
            if (conn->pid == getpid())
                printf("-nsh: Cannot close your own connection, use 'quit'\n");
            else {
                found = true;
                kill(conn->pid, SIGTERM);
            }
            break;
        }
    }
    pthread_mutex_unlock(&shared_mem->lock);
    if (!found) printf("-nsh: Failed to find connection with ID %d\n", connId);
    return SHELL_OK;
}

nsh_shell_e nsh_command_halt()
{
    if (instance.connection.type != CONSOLE)
    {
        printf("-nsh: halt may only be called by console connections\n");
        return SHELL_OK;
    }

    const pid_t thisPid = getpid();
    pthread_mutex_unlock(&shared_mem->lock);
    pthread_mutex_lock(&shared_mem->lock);
    for (size_t i = 0; i < shared_mem->count; i++)
    {
        nsh_conn_t* conn = shared_mem->connections + i;
        if (conn->pid == thisPid) continue;
        kill(conn->pid, SIGTERM);
    }
    pthread_mutex_unlock(&shared_mem->lock);
    
    shm_unlink(NSH_SHARED_MEM_NAME);
    munmap(shared_mem, NSH_SHARED_MEM_SIZE);
    shared_mem = 0;
    
    nsh_exit(0);

    // Should be unreachable anyway
    return SHELL_EXIT;
}

static char nsh_exec_native_path_buff[PATH_MAX];
nsh_shell_e nsh_command_listen(const char* param)
{
    int port = atoi(param);
    printf("[Debug]: decoded port as : %d\n", port);
    bool valid = false;
    nsh_conn_t conn = {0};
    
    if (port > 0 && port < 65536)
    {
        // Valid network port
        conn.type = NETWORK;
        if (conn.network.ip_to[0] == 0)
            strcpy(conn.network.ip_to, NSH_INITIAL_IP_INTERFACE);
        else
            strncpy(conn.network.ip_to, instance.connection.network.ip_to, INET_ADDRSTRLEN);
        conn.network.port_to = port;
        valid = true;
    }
    else
    {
        // Maybe it's domain path
        memset(nsh_exec_native_path_buff, 0, PATH_MAX);
        char* validPath = realpath(param, nsh_exec_native_path_buff);
        printf("[Debug]: realpath \"%s\"\n", nsh_exec_native_path_buff);
        if (strlen(param) < DOMAIN_FILEPATH_LENGTH)
        {
            // Valid path for domain sock
            conn.type = DOMAIN;
            strcpy(conn.domain.path, param);
            valid = true;
        }
    }
    if (!valid)
    {
        printf("-nsh: Listen has invalid parameter \"%s\"\n", param);
        return SHELL_OK;
    }

    pid_t pid = nsh_internal_start_instance(conn);
    if (pid == 0)
    {
        nsh_err_e err = nsh_register_instance();
        if (err != CODE_OK) nsh_exit((int)err);
        err = nsh_internal_reset_connection();
        if (err != CODE_OK) nsh_exit((int)err);
        err = nsh_instance_accept();
        if (err != CODE_OK) nsh_exit((int)err);
    }
    return SHELL_OK;
}

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
            fprintf(stderr, "[Error]: Killed by signal %d\n", sig);
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
    else if (strcmp(cmd->cmd, "stat") == 0) {
        nsh_command_stat();
        return SHELL_OK;
    }
    else if (strcmp(cmd->cmd, "help") == 0) {
        nsh_internal_help();
        return SHELL_OK;
    }
    else if (strcmp(cmd->cmd, "halt") == 0) {
        nsh_command_halt();
        // Shouldn't return anyway..
        return SHELL_OK;
    }
    else if (strcmp(cmd->cmd, "abort") == 0) {
        if (*cmd->flags == NULL)
        {
            printf("-nsh: Abort has no connection ID to terminate\n");
            return SHELL_OK;
        }
        
        int abortPid = atoi(*cmd->flags);
        nsh_command_abort(abortPid);

        return SHELL_OK;
    }
    else if (strcmp(cmd->cmd, "close") == 0) {
        if (*cmd->flags == NULL)
        {
            printf("-nsh: Close has no connection ID to terminate\n");
            return SHELL_OK;
        }
        
        int abortPid = atoi(*cmd->flags);
        nsh_command_close(abortPid);

        return SHELL_OK;
    }
    else if (strcmp(cmd->cmd, "listen") == 0) {
        if (*cmd->flags == NULL)
        {
            printf("-nsh: Listen is missing parameter\n");
            return SHELL_OK;
        }

        const char* param = *cmd->flags;

        return nsh_command_listen(param);
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
                if (isBuiltIn == SHELL_OK) break;
                else if (isBuiltIn != SHELL_NOT_NATIVE) { parser_chain_free(&chain); return isBuiltIn; }
            }

            if (i < chain.count - 1)
            {
                if (pipe(pipefd) < 0)
                {
                    perror("pipe failed????\n");
                    memset(command_buff, 0, BUFF_SIZE);
                    command_buff_size = 0;
                    parser_chain_free(&chain);
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
                        fprintf(stderr, "-nsh: couldn't open file \"%s\" during redirection\n", cmd->input_file);
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
                        fprintf(stderr, "-nsh: couldn't create file \"%s\" for redirection\n", cmd->output_file);
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
                    fprintf(stderr, "[Error]: Killed by signal %d\n", sig);
                }
                break;
            }

            // Free arguments
            for (size_t i = 0; i < args.length-1; i++)
                free(*(char**)array_at(&args, i));
            array_destroy(&args);
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

        struct pollfd fds[1];
        fds[0].fd = fileno(stdin);
        fds[0].events = POLLIN | POLLHUP | POLLERR | POLLNVAL;

        int ret = poll(fds, 1, g_args.timeout);
        if (ret == 0) return SHELL_RESET; // Timedout
        if (ret == -1) return SHELL_POLL_FAIL; // Possibly external abort
        if (fds[0].revents & POLLHUP || fds[0].revents & POLLERR || fds[0].revents & POLLNVAL) return 8;

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
                    
                    write(fileno(stdout), temp_buff, strlen(temp_buff));
                    write(fileno(stdout), "# ", 2);
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
                    write(fileno(stdout), "\r", 1);
                    write(fileno(stdout), temp_buff, strlen(temp_buff));
                    write(fileno(stdout), "# ", 2);
                    write(fileno(stdout), command_buff, strlen(command_buff));
                }
            }
        }
    }

    return SHELL_RESET;
}
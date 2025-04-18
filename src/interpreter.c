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

#include <errno.h>

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include <arpa/inet.h>
#include <sys/stat.h>
#include <pwd.h>

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
    
    pthread_mutex_lock(&shared_mem->lock);
    printf("| ID  | State  | Type    | Additional info                               |\n");
    printf("|-----|--------|---------|-----------------------------------------------|\n");
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
    pthread_mutex_unlock(&shared_mem->lock);
    printf("|========================================================================|\n");
    //fflush(stdout);
    
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
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&shared_mem->lock);
    if (!found) printf("-nsh: Failed to find connection with ID %d\n", connId);
    return SHELL_OK;
}

nsh_shell_e nsh_command_help()
{
    printf("Network SHell\n> Author: Tomas Tytykalo\n> Good luck using this :/\n");
    printf("Native commands:\n");
    printf("\thelp | Help screen\n");
    printf("\tcd   | Change directory\n");
    printf("\tquit | Closes this connection\n");
    printf("\texit | Alias for quit\n");
    printf("NSH - specific\n");
    printf("\treset                   | Disconnects client, but connection persists\n");
    printf("\tstat                    | List all active NSH connections\n");
    printf("\tabort <conn_id>         | Resets target connection\n");
    printf("\tclose <conn_id>         | Closes target connection\n");
    printf("\tpurge <conn_id>         | Forceful removal of target connection\n");
    printf("\tlisten <port> or <file> | Opens a new network or domain connection\n");
    printf("\thalt                    | Attempts to close all connections and clean up shared memory\n");
    return SHELL_OK;
}

int try_acquire_mutex_with_timeout(pthread_mutex_t* mutex, int timeout_sec) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_sec;

    int res = pthread_mutex_timedlock(mutex, &ts);
    if (res == 0) return 0;
    else if (res == ETIMEDOUT) return 1;
    else return -1;
}

nsh_shell_e nsh_command_halt()
{
    if (instance.connection.type != CONSOLE)
    {
        printf("-nsh: halt may only be called by console connections\n");
        return SHELL_OK;
    }

    const pid_t thisPid = getpid();

    // Contingency nuke:
    //      Assuming no one else cares and we destroy the shared_memory anyway
    //      killing anyone and everyone mentioned with a name on the death list

    for (size_t niceAttempts = 0; niceAttempts < 3; niceAttempts++)
    {
        int res = try_acquire_mutex_with_timeout(&shared_mem->lock, 1);
        if (res != 0)
            pthread_mutex_unlock(&shared_mem->lock);
    }
    
    for (size_t i = 0; i < shared_mem->count; i++)
    {
        nsh_conn_t* conn = shared_mem->connections + i;
        if (conn->pid == thisPid) continue;
        kill(conn->pid, SIGTERM);
    }
    // This has no reason to be here, but we're professionals, right?
    pthread_mutex_unlock(&shared_mem->lock);
    
    shm_unlink(NSH_SHARED_MEM_NAME);
    munmap(shared_mem, NSH_SHARED_MEM_SIZE);
    shared_mem = 0;
    
    nsh_exit(0);

    // Should be unreachable anyway
    return SHELL_EXIT;
}

nsh_shell_e nsh_command_purge(int connId)
{
    pthread_mutex_lock(&shared_mem->lock);

    if (shared_mem->count >= 1)
    {
        // Unregister our instance from shared mem WHERE we're present
        for (size_t i = 0; i < shared_mem->count; i++)
        {
            nsh_conn_t* conn = shared_mem->connections + i;
            int procId = conn->pid;
            if (conn->id == connId)
            {
                nsh_conn_t* last = shared_mem->connections + shared_mem->count - 1;
                if (conn == last)
                {
                    // Zero out our entry if we're the last entry
                    //printf("deleting record id %d pid %d\n", conn->id, conn->pid);
                    memset(conn, 0, sizeof(nsh_conn_t));
                    //VERBOSE_LOG("[Log]: Deleting shared record for %d owned by %d\n", conn->id, conn->pid);
                    shared_mem->count--;
                }
                else
                {
                    // Found our entry, move last entry into our position
                    // effectively deleting ours and keeping the array dense
                    //VERBOSE_LOG("[Log]: Deleting shared record for %d owned by %d\n", conn->id, conn->pid);
                    memcpy(conn, last, sizeof(nsh_conn_t));
                    shared_mem->count--;
                }
                kill(procId, SIGTERM);
            }
        }
    }
    pthread_mutex_unlock(&shared_mem->lock);
    return SHELL_OK;
}

//static char nsh_exec_native_path_buff[PATH_MAX];
nsh_shell_e nsh_command_listen(const char* param)
{
    int port = atoi(param);
    //printf("[Debug]: decoded port as : %d\n", port);
    bool valid = false;
    nsh_conn_t conn = {0};
    
    if (port > 0 && port < 65536)
    {
        // Valid network port
        conn.type = NETWORK;
        strcpy(conn.network.ip_to, g_args.ip_address);
        conn.network.port_to = port;
        valid = true;
    }
    else
    {
        // Maybe it's domain path
        //memset(nsh_exec_native_path_buff, 0, PATH_MAX);
        //char* validPath = realpath(param, nsh_exec_native_path_buff);
        //printf("[Debug]: realpath \"%s\"\n", nsh_exec_native_path_buff);
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
    if (strcmp(cmd->cmd, "quit") == 0 || strcmp(cmd->cmd, "exit") == 0)
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
        nsh_command_help();
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
        
        int connId = atoi(*cmd->flags);
        nsh_command_abort(connId);

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
    else if (strcmp(cmd->cmd, "purge") == 0) {
        if (*cmd->flags == NULL)
        {
            printf("-nsh: Purge has no connection ID to terminate\n");
            return SHELL_OK;
        }
        
        int connId = atoi(*cmd->flags);
        if (connId == instance.connection.id)
            printf("-nsh: Cannot purge your own connection, use 'quit'\n");
        else
            nsh_command_purge(connId);

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
    fflush(stdout);

    memset(command_buff, 0, BUFF_SIZE);
    command_buff_size = 0;

    return SHELL_OK;
}

void nsh_make_prompt(char* buff, size_t buffSize)
{
    // '16:34 user17@student#'
    
    // Get time
    time_t rawTime;
    struct tm* timeInfo;
    char time_str[6];

    time(&rawTime);
    timeInfo = localtime(&rawTime);
    strftime(time_str, sizeof(time_str), "%H:%M", timeInfo);

    // Get username
    const char* username = getenv("USER");
    if (!username)
    {
        struct passwd* pw = getpwuid(getuid());
        if (pw) username = pw->pw_name;
        else username = "unknown";
    }

    // Get hostname
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    snprintf(buff, buffSize, "%s %s@%s# ", time_str, username, hostname);
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
        if (ret == -1) {
            if (instance.got_aborted) {
                // Possibly external abort, ignore once
                instance.got_aborted = false;
                return SHELL_POLL_FAIL;
            }
            return SHELL_EXIT;
        };
        if (fds[0].revents & POLLHUP || fds[0].revents & POLLERR || fds[0].revents & POLLNVAL) return SHELL_EXIT;

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
                    //if (err != SHELL_OK) { printf("shell err: %d\n", err); return err; }
                    if (err != SHELL_OK) return err;

                    // getcwd(temp_buff, BUFF_SIZE);
                    
                    // write(fileno(stdout), temp_buff, strlen(temp_buff));
                    // write(fileno(stdout), "# ", 2);
                    nsh_make_prompt(temp_buff, BUFF_SIZE);
                    write(fileno(stdout), temp_buff, strlen(temp_buff));
                }
                else
                {
                    if ((buff[i] == '\b' || buff[i] == 127)) {
                        if (command_buff_size > 0) {
                            command_buff[--command_buff_size] = 0;
                            write(fileno(stdout), "\b\0", 2);
                        }
                    }
                    else {
                        command_buff[command_buff_size++] = buff[i];
                        write(fileno(stdout), &buff[i], 1);
                    }
                    
                    // Send prompt over so the client knows it's their time to shine
                    // Server side echo for when gathering queries
                    // getcwd(temp_buff, BUFF_SIZE);
                    // write(fileno(stdout), "\r", 1);
                    // write(fileno(stdout), temp_buff, strlen(temp_buff));
                    // write(fileno(stdout), "# ", 2);
                    // write(fileno(stdout), command_buff, strlen(command_buff));
                    
                    //nsh_make_prompt(temp_buff, BUFF_SIZE);
                    //write(fileno(stdout), temp_buff, strlen(temp_buff));
                }
            }
        }
    }

    return SHELL_RESET;
}
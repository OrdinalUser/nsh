#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define LOG_FILE_MAX_LENGTH 256
#define LOCK_FILE_FMT "/tmp/nsh_daemon_%d.lock"

bool nsh_daemon_process_exists()
{
    int fd = open()  
}


void nsh_daemon_process_create(char* log_filepath)
{
    pid_t pid;
    pid = fork();
    if (pid < 0)
    {
        perror("[Daemon Init]: Fork failed");
        exit(1);
    }
    if (pid > 0)
    {
        fprintf(stderr, "[Daemon Init]: Parent process exits\n");
        return;
    }

    if (setsid() < 0)
    {
        perror("[Daemon]: Failed to create a new session");
        exit(1);
    }

    if (chdir("/") < 0)
    {
        perror("[Daemon]: Failed to change to root dir");
        exit(1);
    }

    // Good night world, going dark
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    freopen("/dev/null", "r", stdin);
    char err_file[LOG_FILE_MAX_LENGTH];
    freopen("/dev/null", "w", stdout);
    if (log_filepath)
    {
        snprintf(err_file, LOG_FILE_MAX_LENGTH, "/tmp/nsh_%d.log", getuid());
        freopen(err_file, "w+", stderr);
    }
    else freopen("/dev/null", "w", stderr);

    for (int i = 0; i < 10; i++)
    {
        fprintf(stderr, "Logging test %d\n", i);
        sleep(1);
    }
}
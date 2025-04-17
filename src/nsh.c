#include "nsh.h"
#include "interpreter.h"
#include "globals.h"

/* libc includes */
#include <stddef.h>
#include <stdbool.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>

#include <assert.h>
#include <errno.h>

/* linux includes*/
#include <poll.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <pthread.h>
#include <termios.h>

/* Logging, macros and debug things */
#define VERBOSE_LOG(format, ...) \
do { if(g_args.verbose) {fprintf(stderr, format, ##__VA_ARGS__); fflush(stderr); }} while (0)

#define DEBUG
#ifdef DEBUG
#define DEBUG_BUFF_SIZE 1024
char DEBUG_BUFF[DEBUG_BUFF_SIZE];
#define ERROR_LOG(format, ...) \
    do { fprintf(stderr, format, ##__VA_ARGS__); fflush(stderr); } while (0)

#define ERROR_SYS_LOG(format, ...) \
    do { sprintf(DEBUG_BUFF, format, ##__VA_ARGS__); perror(DEBUG_BUFF); fflush(stderr); } while (0)
#else
#define ERROR_LOG(format, ...)
#define ERROR_SYS_LOG(format, ...)
#endif

#define ZERO_MEMORY(var) do { memset(&var, 0, sizeof(var)); } while (0)

/* Signal land */
void nsh_sig_abort()
{
    VERBOSE_LOG("[Instance]: External abort at connection %d\n", instance.connection.id);
    if (instance.connection.state == STATE_INACTIVE) return;
    nsh_internal_reset_connection();
    nsh_instance_accept();
}

void nsh_signals_reset()
{
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
    signal(SIGUSR1, SIG_DFL);

    // Allow zombies, say Yes! to outbreaks
    struct sigaction sa = {0};
    sa.sa_handler = SIG_DFL;
    sa.sa_flags = 0;
    sigaction(SIGCHLD, &sa, NULL);
}

void nsh_signals_set()
{
    signal(SIGINT, nsh_exit);
    signal(SIGTERM, nsh_exit);
    signal(SIGUSR1, nsh_sig_abort);

    // Prevent zombies, no outbreaks
    struct sigaction sa = {0};
    sa.sa_handler = SIG_DFL;
    sa.sa_flags = SA_NOCLDWAIT;
    sigaction(SIGCHLD, &sa, NULL);
}

// Needs to be mutex locked!
nsh_conn_t* shared_mem_get_this_instance_entry()
{
    pid_t pid = getpid();
    assert(instance.connection.pid == pid);
    for (int i = 0; i < shared_mem->count; i++)
    {
        if (shared_mem->connections[i].pid == pid)
        {
            pthread_mutex_unlock(&shared_mem->lock);
            return &shared_mem->connections[i];
        }
    }
    // THIS SHOULD NEVER HAPPEN
    assert(0);
    return NULL;
}

void shared_mem_update_instance()
{
    pthread_mutex_lock(&shared_mem->lock);
    nsh_conn_t* conn = shared_mem_get_this_instance_entry();
    memcpy(conn, &instance.connection, sizeof(nsh_conn_t));
    pthread_mutex_unlock(&shared_mem->lock);
}

/* Internal functions of NSHell */
void nsh_internal_help()
{
    printf("Network SHell\n> Author: Tomas Tytykalo\n> Good luck using this :/\n");
}

/* Internal functions */
pid_t nsh_internal_start_instance(nsh_conn_t conn)
{
    // Allow zombies, say Yes! to outbreaks
    struct sigaction sa = {0};
    sa.sa_handler = SIG_DFL;
    sa.sa_flags = SA_NOCLDWAIT | SA_RESETHAND;
    sigaction(SIGCHLD, &sa, NULL);

    pid_t pid = fork();
    switch (pid)
    {
    case -1:
        ERROR_SYS_LOG("[Error]: nsh_internal_start_instance::fork() ");
        return -1;
    case 0:
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        instance.connection = conn;
        instance.connection.pid = getpid();
        return 0;
    default:
        return pid;
    }
}

nsh_err_e nsh_register_instance()
{
    if (instance.connection.type == CONSOLE)
    {
        instance.connection.id = -1;
        return CODE_OK;
    }

    pthread_mutex_lock(&shared_mem->lock);
    if (shared_mem->count >= shared_mem->capacity)
    {
        pthread_mutex_unlock(&shared_mem->lock);
        return CODE_CONNECTION_LIMIT;
    }
    
    instance.connection.id = shared_mem->next_id++;
    memcpy(&shared_mem->connections[shared_mem->count++], &instance.connection, sizeof(nsh_conn_t));

    pthread_mutex_unlock(&shared_mem->lock);
    VERBOSE_LOG("[Internal]: Registered new connection into shared memory\n");
    return CODE_OK;
}

nsh_err_e nsh_internal_reset_connection()
{
    struct sockaddr_un addr_un = {0};
    struct sockaddr_in addr_in = {0};
    int sock_fd = 0;
    
    switch (instance.connection.type)
    {
    case CONSOLE:
        instance.connection.state = STATE_ACTIVE;
        return CODE_OK;
    case DOMAIN:
        if (instance.connection.state == STATE_ACTIVE)
        {
            if (shutdown(instance.sock_fd, SHUT_RDWR)) ERROR_SYS_LOG("[Warning]: Failed to shutdown connection %d\n", instance.connection.id);
            if (close(instance.sock_fd)) { ERROR_SYS_LOG("[Warning]: Failed to close connection %d\n", instance.connection.id); }
            pthread_mutex_lock(&shared_mem->lock);
            nsh_conn_t* shared_instance = shared_mem_get_this_instance_entry();
            shared_instance->state = STATE_INACTIVE;
            pthread_mutex_unlock(&shared_mem->lock);
            instance.connection.state = STATE_INACTIVE;
        }
        unlink(instance.connection.domain.path);
        addr_un.sun_family = AF_UNIX;
        strcpy(addr_un.sun_path, instance.connection.domain.path);

        instance.sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock_fd < 0) { ERROR_LOG("[Error]: Failed to create domain socket\n"); return CODE_SOCKET; }
        if (bind(instance.sock_fd, (struct sockaddr*)&addr_un, sizeof(addr_un)) == -1)
        {
            close(instance.sock_fd);
            ERROR_SYS_LOG("[Error]: Failed to bind domain socket \"%s\" at connection %d\n", instance.connection.domain.path, instance.connection.id);
            return CODE_BIND;
        }
        if (listen(instance.sock_fd, 1) == -1)
        {
            close(instance.sock_fd);
            ERROR_SYS_LOG("[Error]: Failed to listen on domain socket \"%s\" at connection %d\n", instance.connection.domain.path, instance.connection.id);
            return CODE_LISTEN;
        }

        VERBOSE_LOG("[Log]: Opened domain connection \"%s\" at id %d\n", instance.connection.domain.path, instance.connection.id);
        return CODE_OK;
    case NETWORK:
        if (instance.connection.state == STATE_ACTIVE)
        {
            if (shutdown(instance.sock_fd, SHUT_RDWR)) ERROR_SYS_LOG("[Warning]: Failed to shutdown connection %d\n", instance.connection.id);
            if (close(instance.sock_fd)) { ERROR_SYS_LOG("[Warning]: Failed to close connection %d\n", instance.connection.id); }
            pthread_mutex_lock(&shared_mem->lock);
            nsh_conn_t* shared_instance = shared_mem_get_this_instance_entry();
            shared_instance->state = STATE_INACTIVE;
            pthread_mutex_unlock(&shared_mem->lock);
            instance.connection.state = STATE_INACTIVE;
        }

        addr_in.sin_family = AF_INET;
        if (strcmp(instance.connection.network.ip_to, NSH_INITIAL_IP_INTERFACE) == 0)
            addr_in.sin_addr.s_addr = htonl(INADDR_ANY);
        else
            inet_pton(AF_INET, instance.connection.network.ip_to, &addr_in.sin_addr);
        addr_in.sin_port = htons(instance.connection.network.port_to);

        instance.sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (sock_fd < 0) { ERROR_LOG("[Error]: Failed to create network socket\n"); return CODE_SOCKET; }
        int opt = 1;
        setsockopt(instance.sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        if (bind(instance.sock_fd, (struct sockaddr*)&addr_in, sizeof(addr_in)) == -1)
        {
            close(instance.sock_fd);
            ERROR_SYS_LOG("[Error]: Failed to bind network socket %s:%d at connection %d\n", instance.connection.network.ip_to, instance.connection.network.port_to, instance.connection.id);
            return CODE_BIND;
        }
        if (listen(instance.sock_fd, 1) == -1)
        {
            close(instance.sock_fd);
            ERROR_SYS_LOG("[Error]: Failed to listen on network socket %s:%d at connection %d\n", instance.connection.network.ip_to, instance.connection.network.port_to, instance.connection.id);
            return CODE_LISTEN;
        }
        
        VERBOSE_LOG("[Log]: Waiting for network connection %s:%d at id %d\n", instance.connection.network.ip_to, instance.connection.network.port_to, instance.connection.id);
        return CODE_OK;
    default:
        ERROR_LOG("[Error]: Instance has invalid connection type %d ... this is a nightmare.\n", instance.connection.type);
        assert(0);
        return CODE_OK;
    }
}

/* Argument parsing */
void nsh_args_parse(int argc, char** argv)
{
    g_args.timeout = NSH_INITIAL_TIMEOUT;
    g_args.port = NSH_INITIAL_PORT;
    g_args.ip_address = NSH_INITIAL_IP_INTERFACE;
    memset(g_args.script_file, 0, PATH_MAX);

    int unnamed_arg = 0;
    char* arg_value = 0;
    int port_val = 0;
    int timeout_val = 0;

    int ip4;
    FILE* temp_fd;
    for (int argi = 0; argi < argc; argi++)
    {
        char* arg = argv[argi];
        if (*arg == '-')
        {
            // Deal with flags
            switch(*(arg+1))
            {
                case 'h':
                    printf("Help\n");
                    g_args.help = true;
                    break;
                case 'v':
                    printf("Verbose on\n");
                    g_args.verbose = true;
                    break;
                case 'i':
                    if (argi+1 >= argc || *argv[argi+1] == '-') { fprintf(stderr, "Missing value after %s flag\n", arg); break; }
                    arg_value = argv[++argi];
                    g_args.ip_address = arg_value;
                    if (inet_pton(AF_INET, arg_value, &ip4) != 1) { fprintf(stderr, "Invalid IP address \"%s\"\n", arg_value); break; }
                    printf("ip address: %s\n", arg_value);
                    g_args.network = true;
                    break;
                case 'p':
                    if (argi+1 >= argc || *argv[argi+1] == '-') { fprintf(stderr, "Missing value after %s flag\n", arg); break; }
                    arg_value = argv[++argi];
                    port_val = atoi(arg_value);
                    if (port_val == 0 || port_val > 65535) { fprintf(stderr, "Invalid port number \"%s\" doesn't belong in range (0, 65536)\n", arg_value); break; }
                    g_args.port = port_val;
                    g_args.network = true;
                    printf("network port: %d\n", port_val);
                    break;
                case 'c':
                    g_args.client = true;
                    printf("client mode set\n");
                    break;
                case 'l':
                    if (argi+1 >= argc || *argv[argi+1] == '-') { fprintf(stderr, "Missing value after %s flag\n", arg); break; }
                    arg_value = argv[++argi];
                    if (!(temp_fd = fopen(arg_value, "w+")))
                    {
                        fprintf(stderr, "Inaccessible log file \"%s\"\n", arg_value);
                        break;
                    }
                    fclose(temp_fd);
                    g_args.log_file = arg_value;
                    printf("log file: %s\n", arg_value);
                    break;
                case 'u':
                    if (argi+1 >= argc || *argv[argi+1] == '-') { fprintf(stderr, "Missing value after %s flag\n", arg); break; }
                    arg_value = argv[++argi];
                    if (strlen(arg_value) > DOMAIN_FILEPATH_STR_MAX)
                    {
                        fprintf(stderr, "Domain filepath too long \"%s\"\n", arg_value);
                        break;
                    }
                    g_args.domain_sock_path = arg_value;
                    printf("domain socket: %s\n", g_args.domain_sock_path);
                    break;
                case 't':
                    if (argi+1 >= argc || *argv[argi+1] == '-') { fprintf(stderr, "Missing value after %s flag\n", arg); break; }
                    arg_value = argv[++argi];
                    timeout_val = atoi(arg_value);
                    if (timeout_val <= 0) { fprintf(stderr, "Invalid timeout value \"%s\" in seconds\n", arg_value); break; }
                    g_args.timeout = atoi(arg_value);
                    printf("timeout set to: %d milliseconds\n", g_args.timeout);
                    break;
            }
        }
        else
        {
            if (unnamed_arg++ == 0)
            {
                struct stat stats;
                realpath(argv[argi], g_args.script_file);
                if (stat(g_args.script_file, &stats) == 0)
                {
                    if (S_ISREG(stats.st_mode)) fprintf(stderr, "Treating \"%s\" as a script file\n", g_args.script_file);
                    else fprintf(stderr, "Script file \"%s\" is not a regular file\n", g_args.script_file);
                }
                else
                {
                    fprintf(stderr, "Script file \"%s\" doesn't exist or cannot access\n", g_args.script_file);
                    memset(g_args.script_file, 0, PATH_MAX);
                }
            }
            else fprintf(stderr, "Encountered unknown arg: '%s', use - to prefix flags\n", arg);
        }
    }
}

/* Core of NSHell */
// Initializes client connection
nsh_err_e nsh_client_init()
{
    if (g_args.log_file)
    {
        FILE* flog = fopen(g_args.log_file, "w+");
        if (!flog)
        {
            fprintf(stderr, "[Error]: Couldn't open file \"%s\" for logging purposes\n", g_args.log_file);
            nsh_exit(CODE_INVALID_FILE);
        }
        fclose(flog);
        freopen(g_args.log_file, "w+", stderr);
        VERBOSE_LOG("[State]: Set log file to \"%s\"\n", g_args.log_file);
    }
    if (g_args.help) { nsh_internal_help(); nsh_exit(CODE_OK); }

    struct timeval timeout = {0};
    timeout.tv_sec = g_args.timeout;

    nsh_conn_t* conn = &client.connection;
    int sock_fd = 0;
    if (g_args.domain_sock_path)
    {
        if (strlen(g_args.domain_sock_path) > DOMAIN_FILEPATH_STR_MAX)
        {
            ERROR_LOG("[Error]: Filepath \"%s\" exceeds 107 characters limit for domain sockets\n", g_args.domain_sock_path);
            return CODE_DOMAIN_PATH_LIMIT;
        }

        sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock_fd == 1)
        {
            ERROR_SYS_LOG("[Error]: Failed to create a socket ");
            return CODE_SOCKET;
        }
        if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
        {
            ERROR_SYS_LOG("[Error]: Failed to adjust receive timeout on a socket ");
            return CODE_SOCKET;
        }

        struct sockaddr_un addr = {0};
        addr.sun_family = AF_UNIX;
        strcpy(addr.sun_path, g_args.domain_sock_path);

        if (connect(sock_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1)
        {
            close(sock_fd);
            ERROR_SYS_LOG("[Error]: Failed to connect to domain socket \"%s\" ", g_args.domain_sock_path);
            return CODE_CONNECT;
        }

        conn->type = DOMAIN;
        strcpy(conn->domain.path, g_args.domain_sock_path);
        VERBOSE_LOG("[Connection]: Connected to domain socket at \"%s\"\n", conn->domain.path);
    }
    else
    {
        sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (sock_fd == -1)
        {
            ERROR_SYS_LOG("[Error]: Failed to create a socket ");
            return CODE_SOCKET;
        }
        if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
        {
            ERROR_SYS_LOG("[Error]: Failed to adjust receive timeout on a socket ");
            return CODE_SOCKET;
        }

        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(g_args.port);

        if (strcmp(g_args.ip_address, NSH_INITIAL_IP_INTERFACE) == 0)
            g_args.ip_address = "127.0.0.1";
        inet_pton(AF_INET, g_args.ip_address, &addr.sin_addr);

        if (connect(sock_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1)
        {
            close(sock_fd);
            ERROR_SYS_LOG("[Error]: Failed to connect to remote socket \"%s:%d\" ", g_args.ip_address, g_args.port);
            return CODE_CONNECT;
        }

        conn->type = NETWORK;
        strcpy(conn->network.ip_to, g_args.ip_address);
        conn->network.port_to = g_args.port;
        VERBOSE_LOG("[Connection]: Connected to network socket at %s:%d\n", conn->network.ip_to, conn->network.port_to);
    }

    conn->last_active = time(0);
    conn->id = 0;
    conn->state = STATE_ACTIVE;
    client.fd = sock_fd;

    client.buffer = malloc(sizeof(char) * NSH_CLIENT_BUFFER_SIZE);
    return CODE_OK;
}

static struct termios termios_original;
static bool termios_rewritten = false;
void nsh_set_terminal_raw()
{
    tcgetattr(fileno(stdin), &termios_original);
    
    struct termios raw = termios_original;
    raw.c_lflag &= ~(ICANON | ECHO);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    
    tcsetattr(fileno(stdin), TCSANOW, &raw);
    termios_rewritten = true;
}

void nsh_terminal_restore()
{
    if (termios_rewritten)
    {
        tcsetattr(fileno(stdin), TCSANOW, &termios_original);
        termios_rewritten = false;
    }
}

// Takes care of connecting to target specified by args
// and sending back and forth data between target and local console
nsh_err_e nsh_client()
{
    VERBOSE_LOG("[State]: Remote client mode\n");
    nsh_err_e err = nsh_client_init();
    if (err != CODE_OK) return err;
    
    nsh_set_terminal_raw();
    fflush(stdin);
    fflush(stdout);
    setbuf(stdin, NULL);
    send(client.fd, "\n", 1, 0); // So we get a prompt at the start

    client.running = true;
    while (client.running)
    {
        struct pollfd fds[2] = {{fileno(stdin), POLLIN, 0}, {client.fd, POLLIN, 0}};
        memset(client.buffer, 0, NSH_CLIENT_BUFFER_SIZE);

        poll(fds, 2, g_args.timeout);
        if (fds[0].revents & POLLIN)
        {
            // Send over client data from stdin
            ssize_t readBytes = read(fileno(stdin), client.buffer, NSH_CLIENT_BUFFER_SIZE);
            send(client.fd, client.buffer, readBytes, 0);
        }
        if (fds[1].revents & POLLIN)
        {
            ssize_t readBytes = recv(client.fd, client.buffer, NSH_CLIENT_BUFFER_SIZE-1, 0);
            client.buffer[readBytes] = 0;
            client.connection.last_active = time(0);

            if (readBytes == -1)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    ERROR_SYS_LOG("[Error]: recv() error ");
                    continue;
                }
                else
                {
                    printf(">> Connection timed out <<\n");
                    break;
                }
            }
            else if (readBytes == 0)
            { printf(">> Connection terminated <<\n"); break; }
            
            // Display data from remote connection
            write(fileno(stdout), client.buffer, readBytes);
            fflush(stdout);
        }
    }
    //printf("-- [ Shell Response ] ------------\n");
    nsh_terminal_restore();

    return CODE_OK;
}

// Prepares shared memory for global connections access
nsh_err_e nsh_instance_shm_init()
{
    if (shared_mem != NULL) return CODE_ALREADY_INITIALIZED;

    int shm_fd;
    if ((shm_fd = shm_open(NSH_SHARED_MEM_NAME, O_RDWR | O_CREAT | O_EXCL, S_IRWXU)) == -1)
    {
        // It already exists, great!
        if ((shm_fd = shm_open(NSH_SHARED_MEM_NAME, O_RDWR | O_EXCL, S_IRWXU)) == -1)
        {
            // Something went horribly wrong
            ERROR_LOG("[Shared]: Shared memory both exists and doesn't exist?\n");
            return CODE_WTF;
        }
        // Get access to shared mem
        shared_mem = mmap(NULL, NSH_SHARED_MEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
        VERBOSE_LOG("[Shared]: Successfully mapped existing shared memory object\n");
    }
    else
    {
        // It didn't exist and we get to initiate it..
        ftruncate(shm_fd, NSH_SHARED_MEM_SIZE);
        shared_mem = mmap(NULL, NSH_SHARED_MEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
        
        // Init mutex lock
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
        pthread_mutex_init(&shared_mem->lock, &attr);

        // Init connections array
        pthread_mutex_lock(&shared_mem->lock);
        memset(shared_mem->connections, 0, sizeof(nsh_conn_t) * NSH_MAX_CONNECTIONS_COUNT);
        shared_mem->count = 0;
        shared_mem->capacity = NSH_MAX_CONNECTIONS_COUNT;
        shared_mem->next_id = 0;
        pthread_mutex_unlock(&shared_mem->lock);

        VERBOSE_LOG("[Shared]: Initialized new shared memory object\n");
    }

    return CODE_OK;
}

// Prepares connections and starts instances for each additional connections
nsh_err_e nsh_instance_init()
{
    if (g_args.script_file[0] != 0) freopen(g_args.script_file, "r", stdin);

    if (g_args.log_file)
    {
        FILE* flog = fopen(g_args.log_file, "w+");
        if (!flog)
        {
            fprintf(stderr, "[Error]: Couldn't open file \"%s\" for logging purposes\n", g_args.log_file);
            nsh_exit(CODE_INVALID_FILE);
        }
        fclose(flog);
        freopen(g_args.log_file, "w+", stderr);
        VERBOSE_LOG("[State]: Set log file to \"%s\"\n", g_args.log_file);
    }
    if (g_args.help) { nsh_internal_help(); nsh_exit(CODE_OK); }

    nsh_err_e err = nsh_instance_shm_init();
    if (err != CODE_OK) return err;

    // Spawns additional instances
    nsh_conn_t instances[2] = {0};
    size_t instCnt = 0;
    if (g_args.domain_sock_path)
    {
        // Prepare domain socket connection
        nsh_conn_t* inst = &(instances[instCnt++]);
        inst->type = DOMAIN;
        strcpy(inst->domain.path, g_args.domain_sock_path);
    }
    if (g_args.network)
    {
        // Prepare network socket connection
        nsh_conn_t* inst = &(instances[instCnt++]);
        inst->type = NETWORK;
        strcpy(inst->network.ip_to, g_args.ip_address);
        inst->network.port_to = g_args.port;
    }

    instance.connection = instances[0];
    instance.connection.pid = getpid();

    if (instCnt == 2) nsh_internal_start_instance(instances[1]);
    
    err = nsh_register_instance();
    if (err != CODE_OK) return err;

    err = nsh_internal_reset_connection();
    return err;
}

// Deals with accepting our connectee and demolishing the listening socket
nsh_err_e nsh_instance_accept()
{
    struct sockaddr_un addr_un;
    struct sockaddr_in addr_in;

    int sock_fd;
    socklen_t clientLen;
    switch (instance.connection.type)
    {
    case CONSOLE:
        return CODE_OK;
    case DOMAIN:
        clientLen = sizeof(addr_un);
        sock_fd = accept(instance.sock_fd, (struct sockaddr*)&addr_un, &clientLen);
        if (sock_fd < 0) { ERROR_SYS_LOG("[Error]: Failed to accept new connection at %d ", instance.connection.id); return CODE_ACCEPT; }
        if (shutdown(instance.sock_fd, SHUT_RDWR)) { ERROR_SYS_LOG("[Error]: Failed to shutdown socket at %d ", instance.connection.id); return CODE_SHUTDOWN; }
        if (close(instance.sock_fd)) { ERROR_SYS_LOG("[Error]: Failed to close listen socket when promoting connection at %d ", instance.connection.id); return CODE_CLOSE; } // fd_write should be the same since we promoted the listening socket to well another listening socket
        
        instance.sock_fd = sock_fd;
        instance.connection.state = STATE_ACTIVE;
        dup2(instance.sock_fd, STDIN_FILENO);
        dup2(instance.sock_fd, STDOUT_FILENO);

        shared_mem_update_instance();
        VERBOSE_LOG("[Log]: Accepted domain connection at %d\n", instance.connection.id);
        break;
    case NETWORK:
        clientLen = sizeof(addr_in);
        sock_fd = accept(instance.sock_fd, (struct sockaddr*)&addr_in, &clientLen);
        if (sock_fd < 0) { ERROR_SYS_LOG("[Error]: Failed to accept new connection at %d ", instance.connection.id); return CODE_ACCEPT; }
        if (shutdown(instance.sock_fd, SHUT_RDWR)) { ERROR_SYS_LOG("[Error]: Failed to shutdown socket at %d ", instance.connection.id); return CODE_SHUTDOWN; }
        if (close(instance.sock_fd)) { ERROR_SYS_LOG("[Error]: Failed to close listen socket when promoting connection at %d ", instance.connection.id); return CODE_CLOSE; } // fd_write should be the same since we promoted the listening socket to well another listening socket
        
        instance.sock_fd = sock_fd;
        instance.connection.state = STATE_ACTIVE;
        dup2(instance.sock_fd, STDIN_FILENO);
        dup2(instance.sock_fd, STDOUT_FILENO);

        const char* ipStr = inet_ntoa(addr_in.sin_addr);
        strcpy(instance.connection.network.ip_from, ipStr);
        instance.connection.network.port_from = ntohs(addr_in.sin_port);

        shared_mem_update_instance();
        VERBOSE_LOG("[Log]: Accepted network connection at %d\n", instance.connection.id);
        break;
    default:
        assert(0);
        return CODE_WTF;
    }

    // Init stdin & stdout for the interpreter to be pretty
    fflush(stdin);
    fflush(stdout);
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    fdopen(STDIN_FILENO, "r");
    fdopen(STDOUT_FILENO, "w");

    return CODE_OK;
}

// Closes our connection, we don't care for errors as we're done
nsh_err_e nsh_instance_close()
{
    if (instance.connection.type == CONSOLE) return CODE_OK;
    shutdown(instance.sock_fd, SHUT_RDWR);
    close(instance.sock_fd);
    if (instance.connection.type == DOMAIN) unlink(instance.connection.domain.path);

    VERBOSE_LOG("[Log]: Closed instance connection at %d\n", instance.connection.id);
    return CODE_OK;
}

nsh_err_e nsh_instance()
{
    nsh_err_e err = nsh_instance_init();
    if (err != CODE_OK) return err;

    err = nsh_instance_accept();
    if (err != CODE_OK) return err;

    if (instance.connection.type == CONSOLE) nsh_set_terminal_raw();
    do
    {
        fflush(stdin);
        fflush(stdout);
        nsh_shell_e shErr = nsh_interpreter();
        fprintf(stderr, "[Debug]: Shell exit with %d\n", shErr);
        if (shErr == SHELL_RESET)
        {
            // We've finished the script, exit
            if (g_args.script_file[0] != 0) return SHELL_OK;

            VERBOSE_LOG("[Instance]: Client disconnected from connection %d\n", instance.connection.id);
            shErr = nsh_internal_reset_connection();
            if (shErr != SHELL_OK) return (int)err;
            shErr = nsh_instance_accept();
            if (shErr != SHELL_OK) return (int)err;
        }
        else if (shErr == SHELL_EXIT) return CODE_OK;
    } while (true);

    return err;
}

/* Flow functions */
void nsh_cleanup()
{
    nsh_signals_reset();
    nsh_terminal_restore();
    if (g_args.client)
    {
        // Cleanup client resources
        close(client.fd);
        free(client.buffer);
        VERBOSE_LOG("[Cleanup]: Client cleanup\n");
    }
    else
    {
        // Close our instance connection
        nsh_instance_close();

        //assert(instance.connection.type != CONSOLE);
        //if (instance.connection.type == CONSOLE) return;
        
        if (!shared_mem) return;

        pid_t us = getpid();
        pthread_mutex_lock(&shared_mem->lock);
        if (shared_mem->count <= 1)
        {
            // We were the last active instance, cleanup shared resource
            shm_unlink(NSH_SHARED_MEM_NAME);
            VERBOSE_LOG("[Shared]: Shared memory cleanup by last exiting instance\n");   
        }
        else if (instance.connection.type != CONSOLE)
        {
            // Unregister our instance from shared mem WHERE we're present
            for (size_t i = 0; i < shared_mem->count; i++)
            {
                nsh_conn_t* conn = shared_mem->connections + i;
                if (conn->pid == us)
                {
                    nsh_conn_t* last = shared_mem->connections + shared_mem->count - 1;
                    if (conn == last)
                    {
                        // Zero out our entry if we're the last entry
                        //printf("deleting record id %d pid %d\n", conn->id, conn->pid);
                        memset(conn, 0, sizeof(nsh_conn_t));
                        VERBOSE_LOG("[Log]: Deleting shared record for %d owned by %d\n", conn->id, conn->pid);
                        shared_mem->count--;
                        break;
                    }
                    else
                    {
                        // Found our entry, move last entry into our position
                        // effectively deleting ours and keeping the array dense
                        VERBOSE_LOG("[Log]: Deleting shared record for %d owned by %d\n", conn->id, conn->pid);
                        memcpy(conn, last, sizeof(nsh_conn_t));
                        shared_mem->count--;
                        break;
                    }
                }
            }
        }
        pthread_mutex_unlock(&shared_mem->lock);

        munmap(shared_mem, NSH_SHARED_MEM_SIZE);
        shared_mem = 0;
        VERBOSE_LOG("[Cleanup]: Instance cleanup\n");
    }
}

void nsh_exit(int code)
{
    nsh_cleanup();
    exit(code);
}

int nsh(int argc, char** argv)
{
    nsh_signals_set();

    nsh_args_parse(argc-1, argv+1);
    nsh_err_e err = g_args.client ? nsh_client() : nsh_instance();

    nsh_signals_reset();
    nsh_cleanup();

    return (int)err;
}
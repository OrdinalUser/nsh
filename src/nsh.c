#include "nsh.h"
#include "interpreter.h"

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
#include <sys/stat.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <pthread.h>

/* Default config */
#define NSH_INITIAL_PORT 8888
#define NSH_INITIAL_IP_INTERFACE "255.255.255.255"
#define NSH_INITIAL_TIMEOUT 60

#define NSH_MAX_CONNECTIONS_COUNT 64
#define NSH_CLIENT_BUFFER_SIZE 65536
#define NSH_SHARED_MEM_NAME "/nsh"

/* Types */
struct nsh_args
{
    char* ip_address;
    int port;
    char script_file[PATH_MAX];
    char* log_file;
    char* domain_sock_path;
    int timeout;
    bool help, verbose;
    bool network, client;
};

struct nsh_client_state
{
    nsh_conn_t connection;
    int fd;
    bool running;
    char* buffer;
};

struct nsh_shared_connections
{
    pthread_mutex_t lock;
    size_t next_id;
    size_t count, capacity;
    nsh_conn_t connections[NSH_MAX_CONNECTIONS_COUNT];
};
#define NSH_SHARED_MEM_SIZE sizeof(struct nsh_shared_connections)

struct nsh_instance_state
{
    nsh_conn_t connection;
    int sock_fd;
};

/* Lookups */
const char* NSH_CONNECTION_TYPE_STR[] = {
    "CONSOLE", "NETWORK", "DOMAIN"
};

/* Globals */
struct nsh_args g_args = {0};
struct nsh_client_state client = {.running = true };
struct nsh_instance_state instance = {0}; // Contains the original connection entry for each instance
struct nsh_shared_connections* shared_mem;

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

/* Various helpers */
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
    struct sockaddr_un addr_un;
    struct sockaddr_in addr_in;
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

        instance.sock_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
        if (sock_fd < 0) { ERROR_LOG("[Error]: Failed to create domain socket\n"); return CODE_SOCKET; }
        if (bind(instance.sock_fd, (struct sockaddr*)&addr_un, sizeof(addr_un)) == -1)
        {
            close(instance.sock_fd);
            ERROR_SYS_LOG("[Error]: Failed to bind domain socket \"%s\" at connection %d\n", g_args.domain_sock_path, instance.connection.id);
            return CODE_BIND;
        }
        if (listen(instance.sock_fd, 1) == -1)
        {
            close(instance.sock_fd);
            ERROR_SYS_LOG("[Error]: Failed to listen on domain socket \"%s\" at connection %d\n", g_args.domain_sock_path, instance.connection.id);
            return CODE_LISTEN;
        }

        VERBOSE_LOG("[Log]: Opened domain connection \"%s\" at id %d\n", instance.connection.domain.path, instance.connection.id);
        return CODE_OK;
    case NETWORK:
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
                    printf("timeout set to: %d seconds\n", g_args.timeout);
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
    if (argc == 0 || (argc == 1 && g_args.script_file[0]))
    {
        g_args.client = true;
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

        sock_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
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
        sock_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
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

// Takes care of connecting to target specified by args
// and sending back and forth data between target and local console
nsh_err_e nsh_client()
{
    if (!g_args.domain_sock_path && !g_args.network)
    {
        return nsh_interpreter();
    }

    VERBOSE_LOG("[State]: Remote client mode\n");
    nsh_err_e err = nsh_client_init();
    if (err != CODE_OK) return err;

    while (client.running)
    {
        //printf("-- [ Frame ] ------------\n");
        memset(client.buffer, 0, NSH_CLIENT_BUFFER_SIZE);
        recv(client.fd, client.buffer, NSH_CLIENT_BUFFER_SIZE, 0);
        printf("%s", client.buffer);
        fflush(stdout);

        fgets(client.buffer, NSH_CLIENT_BUFFER_SIZE, stdin);
        size_t payloadLen = strlen(client.buffer);
        fflush(stdin);

        int sent = send(client.fd, client.buffer, payloadLen, 0);
        if (sent == -1) { ERROR_SYS_LOG("[Error]: nsh_client::send() produced "); continue; }

        //printf("-- [ Shell Response ] ------------\n");
        ssize_t readBytes = recv(client.fd, client.buffer, NSH_CLIENT_BUFFER_SIZE, 0);
        client.connection.last_active = time(0);
        
        if (readBytes == 1 && client.buffer[0] == '\n') continue;
        if (readBytes == -1)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                ERROR_SYS_LOG("[Error]: recv() error ");
            else
                printf(">> Connection timed out <<\n");
            break;
        }
        if (readBytes == 0)
            { printf(">> Connection terminated <<\n"); break; }
        printf("%s", client.buffer);
        fflush(stdout);
    }

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

    // Prevent zombies, no outbreaks
    struct sigaction sa = {0};
    sa.sa_handler = SIG_DFL;
    sa.sa_flags = SA_NOCLDWAIT;
    sigaction(SIGCHLD, &sa, NULL);

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
        if (close(instance.sock_fd)) { ERROR_SYS_LOG("[Error]: Failed to close listen socket when promoting connection at %d ", instance.connection.id); return CODE_CLOSE; } // fd_write should be the same since we promoted the listening socket to well another listening socket
        
        instance.sock_fd = sock_fd;
        instance.connection.state = STATE_ACTIVE;
        dup2(instance.sock_fd, STDIN_FILENO);
        dup2(instance.sock_fd, STDOUT_FILENO);

        shared_mem_update_instance();
        VERBOSE_LOG("[Log]: Accepted connection at %d\n", instance.connection.id);
        break;
    case NETWORK:
        return CODE_WTF;
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

    err = nsh_interpreter();

    return err;
}

/* Flow functions */
void nsh_cleanup()
{
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

        assert(instance.connection.type != CONSOLE);
        //if (instance.connection.type == CONSOLE) return;
        
        pid_t us = getpid();
        pthread_mutex_lock(&shared_mem->lock);
        if (shared_mem->count <= 1)
        {
            // We were the last active instance, cleanup shared resource
            shm_unlink(NSH_SHARED_MEM_NAME);
            VERBOSE_LOG("[Shared]: Shared memory cleanup by last exiting instance\n");   
        }
        else
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
    signal(SIGINT, nsh_exit);
    signal(SIGTERM, nsh_exit);

    nsh_args_parse(argc-1, argv+1);
    nsh_err_e err = g_args.client ? nsh_client() : nsh_instance();

    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
    nsh_cleanup();

    return (int)err;
}

/* Deal with later */

// err_code_e nsh_internal_init_network(char* interface_ip, int port, nsh_conn_t* conn)
// {
//     conn->type = NETWORK;
//     conn->state = STATE_INACTIVE;
//     memset(&conn->network.remote, 0, sizeof(struct sockaddr_in));

//     int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
//     if (sock_fd < 0) { ERROR_LOG("[Error]: Failed to create internet socket\n"); return CODE_SOCKET_ERROR; }
    
//     conn->network.local.sin_family = AF_INET;
//     inet_pton(AF_INET, interface_ip, &conn->network.local.sin_addr);
//     conn->network.local.sin_port = htons(port);

//     int opt = 1;
//     setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
//     if (bind(sock_fd, (struct sockaddr*)&conn->network.local, sizeof(conn->network.local)) < 0)
//     { 
//         close(sock_fd);
//         ERROR_LOG("[Error]: Failed to bind internet socket to %s:%d\n", interface_ip, port);
//         return CODE_BIND_ERROR;
//     }

//     if (listen(sock_fd, 1) < 0)
//     {
//         close(sock_fd);
//         ERROR_LOG("[Error]: Failed to listen at bound socket %s:%d\n", interface_ip, port);
//         return CODE_LISTEN_ERROR;
//     }

//     conn->fd_read = sock_fd;
//     conn->fd_write = sock_fd;

//     VERBOSE_LOG("[Internal]: Initialized network socket %s:%d\n", interface_ip, port);
//     return CODE_OK;
// }

// err_code_e nsh_internal_init_domain(char* path, nsh_conn_t* conn)
// {
//     pthread_mutex_lock(&g_connections->lock);
//     if (g_connections->count >= g_connections->capacity)
//     {
//         return CODE_CONNECTION_LIMIT;
//     }
//     conn->id = g_connections->next_id++;
//     if (strlen(path) > DOMAIN_FILEPATH_MAX_LENGTH)
//     {
//         ERROR_LOG("[Error]: Filepath \"%s\" exceeds 107 characters limit for domain sockets\n", g_args.domain_sock_path);
//         return CODE_DOMAIN_PATH_LIMIT;
//     }
//     conn->type = DOMAIN;
//     conn->state = STATE_INACTIVE;

//     int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
//     if (sock_fd < 0) { ERROR_LOG("[Error]: Failed to create domain socket\n"); return CODE_SOCKET_ERROR; }

//     conn->domain.addr.sun_family = AF_UNIX;
//     strcpy(conn->domain.addr.sun_path, g_args.domain_sock_path);
//     unlink(g_args.domain_sock_path);

//     if (bind(sock_fd, (struct sockaddr*)&conn->domain.addr, sizeof(conn->domain.addr)) == -1)
//     {
//         close(sock_fd);
//         ERROR_LOG("[Error]: Failed to bind domain socket \"%s\"\n", g_args.domain_sock_path);
//         return CODE_BIND_ERROR;
//     }
//     if (listen(sock_fd, 1) < 0)
//     {
//         close(sock_fd);
//         ERROR_LOG("[Error]: Failed to listen at bound domain socket %s:%d\n", g_args.ip_address, g_args.port);
//         return CODE_LISTEN_ERROR;
//     }

//     conn->fd_read = sock_fd;
//     conn->fd_write = sock_fd;

//     memcpy(g_connections->connections + g_connections->count, conn, sizeof(nsh_conn_t));
//     g_connections->count++;

//     VERBOSE_LOG("[Internal]: Initialized domain socket \"%s\"\n", g_args.domain_sock_path);
//     pthread_mutex_unlock(&g_connections->lock);
//     return CODE_OK;
// }

// err_code_e nsh_internal_abort_connection(nsh_conn_t* conn)
// {
//     if (conn->type == CONSOLE) { VERBOSE_LOG("[Notice]: Trying to abort CONSOLE connection, you can only close it\n"); return CODE_OK; }
    
//     if (shutdown(conn->fd_read, SHUT_RDWR)) { ERROR_LOG("[Warning]: Failed to shutdown connection %d\n", conn->id); }
//     if (close(conn->fd_read)) { ERROR_LOG("[Warning]: Failed to close connection %d\n", conn->id); }
//     VERBOSE_LOG("[Internal]: Aborted connection %d\n", conn->id);
    
//     err_code_e err = CODE_OK;
//     conn->state = STATE_INACTIVE;
//     if (conn->type == NETWORK)
//     {
//         char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &conn->network.local.sin_addr, ip, INET_ADDRSTRLEN);
//         int port = ntohs(conn->network.local.sin_port);
//         err = nsh_internal_init_network(ip, port, conn);
//     }
//     else if (conn->type == DOMAIN)
//     {
//         char path[PATH_MAX]; strcpy(path, conn->domain.addr.sun_path);
//         err = nsh_internal_init_domain(path, conn);
//     }

//     return err;
// }

// err_code_e nsh_internal_accept(nsh_conn_t* conn)
// {
//     socklen_t client_length = sizeof(conn->network.remote);
//     int sock_fd = accept(conn->fd_read, (struct sockaddr*)&conn->network.remote, &client_length);
//     if (sock_fd < 0) { ERROR_LOG("[Error]: Failed to accept new connection at %d\n", conn->id); return CODE_ACCEPT; }
//     if (close(conn->fd_read)) { ERROR_LOG("[Error]: Failed to close socket when promoting connection at %d\n", conn->id); return CODE_CLOSE; } // fd_write should be the same since we promoted the listening socket to well another listening sockete
//     conn->state = STATE_ACTIVE;
//     conn->fd_write = sock_fd;
//     conn->fd_read = sock_fd;
//     VERBOSE_LOG("[Log]: Accepted connection at %d\n", conn->id);
//     return CODE_OK;
// }

// /* Commands exposed to the interpreter */
// err_code_e nsh_command_abort(int conn_id)
// {
//     nsh_conn_t* conn = array_find_first(&g_connections->array, (array_find_func)find_connection_by_id, &conn_id);
//     if (!conn) { VERBOSE_LOG("[Command]: Trying to abort nonexistant connection %d\n", conn_id); return CODE_OK; }
//     return nsh_internal_abort_connection(conn);
// }

// err_code_e nsh_command_stat()
// {
//     char fd_read_buff[32], fd_write_buff[32];

//     printf("|=== NSH : Stat =========================================================|\n");
//     printf("| ID  | State  | Type    | From                  | To                    |\n");
//     printf("|-----|--------|---------|-----------------------|-----------------------|\n");
//     for (size_t i = 0; i < g_connections->array.length; i++)
//     {
//         nsh_conn_t* conn = array_at(&g_connections->array, i);
//         const char* conn_type_str = NSH_CONNECTION_TYPE_STR[conn->type];
//         const char* fd_read_name, *fd_write_name;
//         const char* state_str = conn->state == STATE_INACTIVE ? "Idle" : "Active";

//         if (conn->type == CONSOLE)
//         {
//             if (conn->fd_read == 0) fd_read_name = "STDIN";
//             else {sprintf(fd_read_buff, "%d", conn->fd_read); fd_read_name = fd_read_buff; }
//             if (conn->fd_write == 1) fd_write_name = "STDOUT ";
//             else if (conn->fd_write == 2) fd_write_name = "STDERR";
//             else {sprintf(fd_write_buff, "%d", conn->fd_write); fd_write_name = fd_write_buff; }
//         }
//         else if (conn->type == NETWORK)
//         {
//             inet_ntop(AF_INET, &conn->network.local.sin_addr, fd_read_buff, INET_ADDRSTRLEN);
//             sprintf(fd_read_buff+strlen(fd_read_buff), ":%d", ntohs(conn->network.local.sin_port));
//             inet_ntop(AF_INET, &conn->network.remote.sin_addr, fd_write_buff, INET_ADDRSTRLEN);
//             sprintf(fd_write_buff+strlen(fd_write_buff), ":%d", ntohs(conn->network.remote.sin_port));
//             fd_read_name = fd_write_buff    ;
//             fd_write_name = fd_read_buff;
//         }
//         else if (conn->type == DOMAIN)
//         {
//             fd_read_name = conn->domain.addr.sun_path;
//             fd_write_name = conn->domain.addr.sun_path;
//         }
//         else
//         {
//             fd_read_name = "Expect a crash :/";
//             fd_write_name = "Expect a crash :/";
//         }

//         printf("| %-3.3d | %-6.6s | %-7.7s | %-21.21s | %-21.21s |\n", conn->id, state_str, conn_type_str, fd_read_name, fd_write_name);
//     }
//     printf("|========================================================================|\n");
//     return CODE_OK;
// }
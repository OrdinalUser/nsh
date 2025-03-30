#include "nsh.h"
#include "array.h"

#include <stddef.h>
#include <limits.h>

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdlib.h>

#include <poll.h>

#include <sys/stat.h>
#include <arpa/inet.h>
#include <unistd.h>

/* Initial config */
#define NSH_INITIAL_MAX_CONNECTIONS 8
#define NSH_INITIAL_TIMEOUT 60
#define NSH_INITIAL_PORT 8888
const char* NSH_INITIAL_IP_ADDRESS = "127.0.0.1";

#define BUFFER_SIZE 65536
char BUFFER[BUFFER_SIZE];

/* Lookups */
const char* NSH_CONNECTION_TYPE_STR[] = {
    "CONSOLE", "NETWORK", "DOMAIN"
};

/* Types */
typedef enum ERROR_CODE
{
    CODE_OK = 0,
    CODE_INVALID_FILE,
    CODE_BIND_ERROR, CODE_LISTEN_ERROR, CODE_SOCKET_ERROR, CODE_SHUTDOWN, CODE_CLOSE, CODE_ACCEPT,
    CODE_WTF
} err_code_e;

/* Globals */
static struct {
    array_t array;
    size_t next_id;
} g_connections = {0};

static nsh_conn_t* g_client_connection = NULL;
static bool g_running = true;

static struct nsh_args
{
    char* ip_address;
    int port;
    char script_file[PATH_MAX];
    char* log_file;
    char* domain_sock_path;
    int timeout;
    bool help, verbose, client, server;
    bool network, force_terminal;
} g_args = {0};

/* Logging macros */
#define VERBOSE_LOG(format, ...) \
    do { if(g_args.verbose) {fprintf(stderr, format, ##__VA_ARGS__); fflush(stderr); }} while (0)

#define ERROR_LOG(format, ...) \
    do { fprintf(stderr, format, ##__VA_ARGS__); fflush(stderr); } while (0)

/* Helper functions for g_connections.array */
bool find_connection_by_fd(nsh_conn_t* connection, int* fd)
{
    return connection->fd_read == *fd;
}

bool find_connection_by_id(nsh_conn_t* conn, int* id)
{
    return conn->id == *id;
}

/* Internal commands */
void nsh_internal_help()
{
    printf("Network SHell\n> Author: Tomas Tytykalo\n> Good luck using this :/\n");
}

// Doesn't check for duplicates!
// conn->id MUST BE SET!!
err_code_e nsh_internal_init_console(nsh_conn_t* conn)
{
    conn->type = CONSOLE;
    conn->state = STATE_ACTIVE;
    conn->fd_read = fileno(stdin);
    conn->fd_write = fileno(stdout);
    
    VERBOSE_LOG("[Internal]: Initialized terminal as a connection\n");
    return CODE_OK;    
}

err_code_e nsh_internal_init_network(char* interface_ip, int port, nsh_conn_t* conn)
{
    conn->type = NETWORK;
    memset(&conn->network.remote, 0, sizeof(struct sockaddr_in));

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) { ERROR_LOG("[Error]: Failed to create internet socket\n"); return CODE_SOCKET_ERROR; }
    
    conn->network.local.sin_family = AF_INET;
    inet_pton(AF_INET, interface_ip, &conn->network.local.sin_addr);

    conn->network.local.sin_port = htons(port);
    if (bind(sock_fd, (struct sockaddr*)&conn->network.local, sizeof(conn->network.local)) < 0)
    { 
        close(sock_fd);
        ERROR_LOG("[Error]: Failed to bind internet socket to %s:%d\n", interface_ip, port);
        return CODE_BIND_ERROR;
    }

    if (listen(sock_fd, 1) < 0)
    {
        close(sock_fd);
        ERROR_LOG("[Error]: Failed to listen at bound socket %s:%d\n", interface_ip, port);
        return CODE_LISTEN_ERROR;
    }

    conn->fd_read = sock_fd;
    conn->fd_write = sock_fd;

    VERBOSE_LOG("[Internal]: Initialized network socket %s:%d\n", interface_ip, port);
    return CODE_OK;
}

err_code_e nsh_internal_init_domain(char* path, nsh_conn_t* conn)
{
    conn->type = DOMAIN;

    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) { ERROR_LOG("[Error]: Failed to create domain socket\n"); return CODE_SOCKET_ERROR; }

    conn->domain.addr.sun_family = AF_UNIX;
    strcpy(conn->domain.addr.sun_path, g_args.domain_sock_path);
    strcpy(conn->domain.path, g_args.domain_sock_path);
    unlink(g_args.domain_sock_path);

    if (bind(sock_fd, (struct sockaddr*)&conn->domain.addr, sizeof(conn->domain.addr)) == -1)
    {
        close(sock_fd);
        ERROR_LOG("[Error]: Failed to bind domain socket \"%s\"\n", g_args.domain_sock_path);
        return CODE_BIND_ERROR;
    }
    if (listen(sock_fd, 1) < 0)
    {
        close(sock_fd);
        ERROR_LOG("[Error]: Failed to listen at bound domain socket %s:%d\n", g_args.ip_address, g_args.port);
        return CODE_LISTEN_ERROR;
    }

    conn->fd_read = sock_fd;
    conn->fd_write = sock_fd;

    VERBOSE_LOG("[Internal]: Initialized domain socket \"%s\"\n", g_args.domain_sock_path);
    return CODE_OK;
}

err_code_e nsh_internal_abort_connection(nsh_conn_t* conn)
{
    if (conn->type == CONSOLE) { VERBOSE_LOG("[Notice]: Trying to abort CONSOLE connection, you can only close it\n"); return CODE_OK; }
    
    if (shutdown(conn->fd_read, SHUT_RDWR)) { ERROR_LOG("[Error]: Failed to shutdown connection %d\n", conn->id); return CODE_SHUTDOWN; }
    if (close(conn->fd_read)) { ERROR_LOG("[Error]: Failed to close connection %d\n", conn->id); return CODE_CLOSE; }
    VERBOSE_LOG("[Internal]: Aborted connection %d\n", conn->id);
    
    err_code_e err = CODE_OK;
    conn->state = STATE_INACTIVE;
    if (conn->type == NETWORK)
    {
        char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &conn->network.local.sin_addr, ip, INET_ADDRSTRLEN);
        int port = ntohs(conn->network.local.sin_port);
        err = nsh_internal_init_network(ip, port, conn);
    }
    else if (conn->type == DOMAIN)
    {
        char path[PATH_MAX]; strcpy(path, conn->domain.path);
        err = nsh_internal_init_domain(path, conn);
    }

    return err;
}

err_code_e nsh_internal_accept(nsh_conn_t* connection)
{
    socklen_t client_length = sizeof(connection->network.remote);
    int sock_fd = accept(connection->fd_read, (struct sockaddr*)&connection->network.remote, &client_length);
    if (sock_fd < 0) { ERROR_LOG("[Error]: Failed to accept new connection at %d\n", connection->id); return CODE_ACCEPT; }
    if (close(connection->fd_read)) { ERROR_LOG("[Error]: Failed to close socket when promoting connection at %d\n", connection->id); return CODE_CLOSE; } // fd_write should be the same since we promoted the listening socket to well another listening sockete
    connection->state = STATE_ACTIVE;
    connection->fd_write = sock_fd;
    connection->fd_read = sock_fd;
    VERBOSE_LOG("[Log]: Accepted connection at %d\n", connection->id);
    return CODE_OK;
}

/* Commands exposed to the interpreter */
err_code_e nsh_command_abort(int conn_id)
{
    nsh_conn_t* conn = array_find_first(&g_connections.array, (array_find_func)find_connection_by_id, &conn_id);
    if (!conn) { VERBOSE_LOG("[Command]: Trying to abort nonexistant connection %d\n", conn_id); return CODE_OK; }
    return nsh_internal_abort_connection(conn);
}

err_code_e nsh_command_stat()
{
    char fd_read_buff[32], fd_write_buff[32];

    printf("|=== NSH : Stat =========================================================|\n");
    printf("| ID  | State  | Type    | From                  | To                    |\n");
    printf("|-----|--------|---------|-----------------------|-----------------------|\n");
    for (size_t i = 0; i < g_connections.array.length; i++)
    {
        nsh_conn_t* conn = array_at(&g_connections.array, i);
        const char* conn_type_str = NSH_CONNECTION_TYPE_STR[conn->type];
        const char* fd_read_name, *fd_write_name;
        const char* state_str = conn->state == STATE_INACTIVE ? "Idle" : "Active";

        if (conn->type == CONSOLE)
        {
            if (conn->fd_read == 0) fd_read_name = "STDIN";
            else {sprintf(fd_read_buff, "%d", conn->fd_read); fd_read_name = fd_read_buff; }
            if (conn->fd_write == 1) fd_write_name = "STDOUT ";
            else if (conn->fd_write == 2) fd_write_name = "STDERR";
            else {sprintf(fd_write_buff, "%d", conn->fd_write); fd_write_name = fd_write_buff; }
        }
        else if (conn->type == NETWORK)
        {
            inet_ntop(AF_INET, &conn->network.local.sin_addr, fd_read_buff, INET_ADDRSTRLEN);
            sprintf(fd_read_buff+strlen(fd_read_buff), ":%d", ntohs(conn->network.local.sin_port));
            inet_ntop(AF_INET, &conn->network.remote.sin_addr, fd_write_buff, INET_ADDRSTRLEN);
            sprintf(fd_write_buff+strlen(fd_write_buff), ":%d", ntohs(conn->network.remote.sin_port));
            fd_read_name = fd_write_buff    ;
            fd_write_name = fd_read_buff;
        }
        else if (conn->type == DOMAIN)
        {
            fd_read_name = conn->domain.path;
            fd_write_name = conn->domain.path;
        }
        else
        {
            fd_read_name = "Expect a crash :/";
            fd_write_name = "Expect a crash :/";
        }

        printf("| %-3.3d | %-6.6s | %-7.7s | %-21.21s | %-21.21s |\n", conn->id, state_str, conn_type_str, fd_read_name, fd_write_name);
    }
    printf("|========================================================================|\n");
    return CODE_OK;
}

/* Argument parsing and state preparation */
void nsh_parse_args(int argc, char** argv)
{
    g_args.server = true;
    g_args.timeout = NSH_INITIAL_TIMEOUT;
    g_args.port = NSH_INITIAL_PORT;
    g_args.ip_address = (char*)NSH_INITIAL_IP_ADDRESS;

    int unnamed_arg = 0;
    char* arg_value = 0;
    int port_val = 0;
    int timeout_val = 0;

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
                case 'i':
                    if (argi+1 >= argc || *argv[argi+1] == '-') { fprintf(stderr, "Missing value after %s flag\n", arg); break; }
                    g_args.ip_address = argv[argi+1];
                    arg_value = argv[++argi];
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
                    printf("listening network port: %d\n", port_val);
                    break;
                case 'c':
                    g_args.server = false;
                    g_args.client = true;
                    g_args.network = true;
                    printf("client mode set\n");
                    break;
                case 's':
                    g_args.server = true;
                    g_args.client = false;
                    g_args.network = true;
                    printf("explicit server mode\n");
                    break;
                case 'v':
                    printf("Verbose on\n");
                    g_args.verbose = true;
                    break;
                case 'l':
                    if (argi+1 >= argc || *argv[argi+1] == '-') { fprintf(stderr, "Missing value after %s flag\n", arg); break; }
                    g_args.log_file = argv[argi+1];
                    arg_value = argv[++argi];
                    printf("log file: %s\n", arg_value);
                    break;
                case 'u':
                    if (argi+1 >= argc || *argv[argi+1] == '-') { fprintf(stderr, "Missing value after %s flag\n", arg); break; }
                    arg_value = argv[++argi];
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
                case 'T':
                    g_args.force_terminal = true;
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

int nsh_evaluate_client()
{
    VERBOSE_LOG("[State]: Client mode\n");
    g_client_connection = calloc(1, sizeof(nsh_conn_t));

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

    if (g_args.domain_sock_path)
    {
        g_client_connection->type = DOMAIN;
        int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        g_client_connection->domain.addr.sun_family = AF_UNIX;
        strcpy(g_client_connection->domain.addr.sun_path, g_args.domain_sock_path);
        strcpy(g_client_connection->domain.path, g_args.domain_sock_path);
        
        if (connect(sock_fd, (struct sockaddr*)&g_client_connection->domain.addr, sizeof(g_client_connection->domain.addr)) == -1)
        {
            close(sock_fd);
            ERROR_LOG("[Error]: Failed to bind domain socket \"%s\"\n", g_args.domain_sock_path);
            nsh_exit(CODE_BIND_ERROR);
        }
        g_client_connection->fd_read = sock_fd;
        g_client_connection->fd_write = sock_fd;

        VERBOSE_LOG("[Connection]: Opened domain socket \"%s\"\n", g_args.domain_sock_path);
    }
    else if (g_args.network)
    {
        g_client_connection->type = NETWORK;
        int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (sock_fd < 0) { ERROR_LOG("[Error]: Failed to create internet socket\n"); nsh_exit(CODE_SOCKET_ERROR); }
        
        g_client_connection->network.remote.sin_family = AF_INET;
        g_client_connection->network.remote.sin_port = htons(g_args.port);
        inet_pton(AF_INET, g_args.ip_address, &g_client_connection->network.remote.sin_addr);

        if (connect(sock_fd, (struct sockaddr*)&g_client_connection->network.remote, sizeof(g_client_connection->network.remote)) < 0)
        { 
            close(sock_fd);
            ERROR_LOG("[Error]: Failed to connect to %s:%d\n", g_args.ip_address, g_args.port);
            nsh_exit(CODE_BIND_ERROR);
        }

        g_client_connection->fd_read = sock_fd;
        g_client_connection->fd_write = sock_fd;

        VERBOSE_LOG("[Connection]: Opened network socket %s:%d\n", g_args.ip_address, g_args.port);
    }
    else
    {
        ERROR_LOG("[Notice]: You cannot be a client to your own terminal.. how did this even happen?\n");
        nsh_exit(CODE_WTF);
    }

    return CODE_OK;
}

int nsh_evaluate_server()
{
    VERBOSE_LOG("[State]: Server mode\n");

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

    // Prepare the server
    if (g_args.domain_sock_path)
    {
        nsh_conn_t conn = {.id = g_connections.next_id++};
        err_code_e err = nsh_internal_init_domain(g_args.domain_sock_path, &conn);
        if (err != CODE_OK) nsh_exit(err);
        array_push(&g_connections.array, &conn);
    }
    if (g_args.network)
    {
        nsh_conn_t conn = {.id = g_connections.next_id++};
        err_code_e err = nsh_internal_init_network(g_args.ip_address, g_args.port, &conn);
        if (err != CODE_OK) nsh_exit(err);
        array_push(&g_connections.array, &conn);
    }
    if (g_args.force_terminal || g_connections.array.length == 0)
    {
        nsh_conn_t conn = {.id = g_connections.next_id++};
        nsh_internal_init_console(&conn);
        VERBOSE_LOG("[Connection]: Using terminal as connection\n");
        array_push(&g_connections.array, &conn);
    }

    return CODE_OK;
}

err_code_e nsh_interpret(nsh_conn_t* connection)
{
    VERBOSE_LOG("[Log]: Interpreting commands on connection %d\n", connection->id);

    ssize_t readBytes;
    if (connection->type == CONSOLE) readBytes = read(connection->fd_read, BUFFER, BUFFER_SIZE);
    else readBytes = recv(connection->fd_read, BUFFER, BUFFER_SIZE, 0);

    // Reset this connection if the client already closed on us
    if (readBytes == 0)
    {
        VERBOSE_LOG("[Notice]: Read 0 bytes from connection %d\n", connection->id);
        return CODE_OK;
    }

    ssize_t writtenBytes;
    if (connection->type == CONSOLE) writtenBytes = write(connection->fd_write, BUFFER, readBytes);
    else writtenBytes = send(connection->fd_write, BUFFER, readBytes, 0);
    return CODE_OK;
}

int nsh_server()
{
    int valid_args = nsh_evaluate_server();
    if (valid_args != CODE_OK) return valid_args;
    
    array_t poll_fds; array_create(&poll_fds, g_connections.array.capacity, sizeof(struct pollfd));
    while (g_running)
    {
        nsh_command_stat();

        array_clear(&poll_fds);
        if (poll_fds.capacity < g_connections.array.length) array_resize(&poll_fds, g_connections.array.capacity);
        for (size_t i = 0; i < g_connections.array.length; i++)
        {
            const nsh_conn_t* conn = array_at(&g_connections.array, i);
            struct pollfd* pfd = array_index(&poll_fds, i);
            pfd->fd = conn->fd_read;
            pfd->events = POLLIN | POLLHUP | POLLERR | POLLNVAL;
            pfd->revents = 0;
            poll_fds.length++;
        }
        poll(poll_fds.base, poll_fds.length, -1);
        
        for (size_t i = 0; i < poll_fds.length; i++)
        {
            struct pollfd* pfd = array_at(&poll_fds, i);
            nsh_conn_t* conn = array_find_first(&g_connections.array, (array_find_func)find_connection_by_fd, &pfd->fd);
            printf("fd %d | events %d | revents %d\n", pfd->fd, pfd->events, pfd->revents); // DEBUG
            
            if (pfd->revents & POLLNVAL)
            {
                ERROR_LOG("[Error]: Invalid file descriptor on %d", conn->id);
            }
            else if (pfd->revents & POLLERR)
            {
                ERROR_LOG("[Poll]: Straight up POLLERR, what the fuck do I do? - conn %d\n", conn->id);
                nsh_internal_abort_connection(conn);
            }
            else if (pfd->revents & POLLHUP)
            {
                VERBOSE_LOG("[Notice]: Client disconnected from %d\n", conn->id);
                nsh_internal_abort_connection(conn);
            }
            else if (pfd->revents & POLLIN)
            {

                if (conn->state == STATE_ACTIVE)
                {
                    err_code_e err = nsh_interpret(conn);
                    if (err != CODE_OK) { ERROR_LOG("[Interpret Error]: %d\n", err); continue; }
                }
                else
                {
                    err_code_e err = nsh_internal_accept(conn);
                    if (err != CODE_OK) { ERROR_LOG("[Interpret Error]: %d\n", err); continue; }
                }
                conn->last_active = time(0);
            }
            else if (pfd->revents)
            {
                ERROR_LOG("[Poll]: Something happened and it was not processed.. hmm - %d\n", pfd->revents);
            }
        }
    }
    array_clear(&poll_fds);

    return CODE_OK;
}

int nsh_client()
{
    int valid_args = nsh_evaluate_client();
    if (valid_args != CODE_OK) return valid_args;

    while (g_running)
    {
        printf("- Frame ----------------\n");
        fgets(BUFFER, BUFFER_SIZE-1, stdin);
        size_t payloadlen = strlen(BUFFER);
        BUFFER[payloadlen] = 0;
        int sent = send(g_client_connection->fd_write, BUFFER, payloadlen, 0);

        printf("- Response --------------\n");
        ssize_t readBytes = recv(g_client_connection->fd_read, BUFFER, BUFFER_SIZE-1, 0);
        BUFFER[BUFFER_SIZE-1] = 0;
        write(fileno(stdout), BUFFER, readBytes);
    }

    return CODE_OK;
}

/* Essentially main */
/* Exit functions */
void nsh_cleanup()
{
    static bool cleanup = false;
    if (cleanup) { ERROR_LOG("[Error]: Called cleanup multiple times!\n"); return; }
    if (g_args.client)
    {
        shutdown(g_client_connection->fd_read, SHUT_RDWR);
        close(g_client_connection->fd_read);
        VERBOSE_LOG("[Cleanup]: Client cleanup\n");
    }
    else
    {
        for (size_t i = 0; i < g_connections.array.length; i++)
        {
            nsh_conn_t* conn = array_at(&g_connections.array, i);
            if (conn->type == CONSOLE) continue;
            shutdown(conn->fd_read, SHUT_RDWR);
            close(conn->fd_read);
            if (conn->fd_read != conn->fd_write) { shutdown(conn->fd_read, SHUT_RDWR); close(conn->fd_write); }
            if (g_args.server && conn->type == DOMAIN) unlink(conn->domain.path);
        }
        free(g_client_connection);
        VERBOSE_LOG("[Cleanup]: Server cleanup\n");
    }
    cleanup = true;
}

void nsh_exit(int code)
{
    nsh_cleanup();
    exit(code);
}

int nsh_init(int argc, char** argv)
{
    static bool initialized = false;
    if (initialized) return CODE_OK;

    array_create(&g_connections.array, NSH_INITIAL_MAX_CONNECTIONS, sizeof(nsh_conn_t));

    nsh_parse_args(argc, argv);
    return CODE_OK;
}

int nsh(int argc, char** argv)
{
    int init = nsh_init(argc-1, argv+1);
    if (init != CODE_OK) return init;

    int err = CODE_OK;
    if (g_args.server) err = nsh_server();
    else err = nsh_client();

    nsh_cleanup();
    return err;
}
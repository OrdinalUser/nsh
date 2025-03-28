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

#define NSH_INITIAL_MAX_CONNECTIONS 8
#define NSH_INITIAL_TIMEOUT 60
#define NSH_INITIAL_PORT 8888
const char* NSH_INITIAL_IP_ADDRESS = "127.0.0.1";

#define BUFFER_SIZE 65536
char BUFFER[BUFFER_SIZE];

enum EXIT_CODE
{
    CODE_OK = 0, CODE_INVALID_FILE, CODE_BIND_ERROR, CODE_LISTEN_ERROR, SOCKET_ERROR, CODE_WTF
};

bool find_connection_by_fd(nsh_conn_t* connection, int* fd)
{
    return connection->fd_read == *fd;
}

static array_t g_connections;
static int g_next_id = 0;
static nsh_conn_t* g_client_connection = NULL;

static bool g_running = true;

const char* NSH_CONNECTION_TYPE_STR[] = {
    "CONSOLE", "NETWORK", "DOMAIN"
};

#define VERBOSE_LOG(format, ...) \
    do { if(main_args.verbose) {fprintf(stderr, format, ##__VA_ARGS__); fflush(stderr); }} while (0)

#define ERROR_LOG(format, ...) \
    do { fprintf(stderr, format, ##__VA_ARGS__); fflush(stderr); } while (0)

struct main_args
{
    char* ip_address;
    int port;
    char script_file[PATH_MAX];
    char* log_file;
    char* domain_sock_path;
    int timeout;
    bool help, verbose, client, server;
    bool network, force_terminal;
} main_args = {0};

void nsh_cleanup()
{
    for (size_t i = 0; i < g_connections.length; i++)
    {
        nsh_conn_t* conn = array_at(&g_connections, i);
        close(conn->fd_read);
        if (conn->fd_read != conn->fd_write) close(conn->fd_write);
        if (main_args.server && conn->type == DOMAIN) unlink(conn->domain.path);
    }
    free(g_client_connection);
}

void nsh_exit(int code)
{
    nsh_cleanup();
    exit(code);
}

void nsh_parse_args(int argc, char** argv)
{
    main_args.server = true;
    main_args.timeout = NSH_INITIAL_TIMEOUT;
    main_args.port = NSH_INITIAL_PORT;
    main_args.ip_address = (char*)NSH_INITIAL_IP_ADDRESS;

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
                    main_args.help = true;
                    break;
                case 'i':
                    if (argi+1 >= argc || *argv[argi+1] == '-') { fprintf(stderr, "Missing value after %s flag\n", arg); break; }
                    main_args.ip_address = argv[argi+1];
                    arg_value = argv[++argi];
                    printf("ip address: %s\n", arg_value);
                    main_args.network = true;
                    break;
                case 'p':
                    if (argi+1 >= argc || *argv[argi+1] == '-') { fprintf(stderr, "Missing value after %s flag\n", arg); break; }
                    arg_value = argv[++argi];
                    port_val = atoi(arg_value);
                    if (port_val == 0 || port_val > 65535) { fprintf(stderr, "Invalid port number \"%s\" doesn't belong in range (0, 65536)\n", arg_value); break; }
                    main_args.port = port_val;
                    printf("listening port: %d\n", port_val);
                    main_args.network = true;
                    break;
                case 'c':
                    main_args.server = false;
                    main_args.client = true;
                    printf("client mode set\n");
                    break;
                case 's':
                    main_args.server = true;
                    main_args.client = false;
                    main_args.network = true;
                    printf("explicit server mode\n");
                    break;
                case 'v':
                    printf("Verbose on\n");
                    main_args.verbose = true;
                    break;
                case 'l':
                    if (argi+1 >= argc || *argv[argi+1] == '-') { fprintf(stderr, "Missing value after %s flag\n", arg); break; }
                    main_args.log_file = argv[argi+1];
                    arg_value = argv[++argi];
                    printf("log file: %s\n", arg_value);
                    break;
                case 'u':
                    if (argi+1 >= argc || *argv[argi+1] == '-') { fprintf(stderr, "Missing value after %s flag\n", arg); break; }
                    arg_value = argv[++argi];
                    main_args.domain_sock_path = arg_value;
                    printf("domain socket: %s\n", main_args.domain_sock_path);
                    break;
                case 't':
                    if (argi+1 >= argc || *argv[argi+1] == '-') { fprintf(stderr, "Missing value after %s flag\n", arg); break; }
                    arg_value = argv[++argi];
                    timeout_val = atoi(arg_value);
                    if (timeout_val <= 0) { fprintf(stderr, "Invalid timeout value \"%s\" in seconds\n", arg_value); break; }
                    main_args.timeout = atoi(arg_value);
                    printf("timeout set to: %d seconds\n", main_args.timeout);
                    break;
                case 'T':
                    main_args.force_terminal = true;
                    break;
            }
        }
        else
        {
            if (unnamed_arg++ == 0)
            {
                struct stat stats;
                realpath(argv[argi], main_args.script_file);
                if (stat(main_args.script_file, &stats) == 0)
                {
                    if (S_ISREG(stats.st_mode)) fprintf(stderr, "Treating \"%s\" as a script file\n", main_args.script_file);
                    else fprintf(stderr, "Script file \"%s\" is not a regular file\n", main_args.script_file);
                }
                else
                {
                    fprintf(stderr, "Script file \"%s\" doesn't exist or cannot access\n", main_args.script_file);
                    memset(main_args.script_file, 0, PATH_MAX);
                }
            }
            else fprintf(stderr, "Encountered unknown arg: '%s', use - to prefix flags\n", arg);
        }
    }
}

void nsh_print_help()
{
    printf("Network SHell\n> Author: Tomas Tytykalo\n> Good luck using this :/\n");
}


int nsh_evaluate_client()
{
    VERBOSE_LOG("[State]: Client mode\n");
    g_client_connection = calloc(1, sizeof(nsh_conn_t));

    if (main_args.log_file)
    {
        FILE* flog = fopen(main_args.log_file, "w+");
        if (!flog)
        {
            fprintf(stderr, "[Error]: Couldn't open file \"%s\" for logging purposes\n", main_args.log_file);
            nsh_exit(CODE_INVALID_FILE);
        }
        fclose(flog);
        freopen(main_args.log_file, "w+", stderr);
        VERBOSE_LOG("[State]: Set log file to \"%s\"\n", main_args.log_file);
    }
    if (main_args.help) { nsh_print_help(); nsh_exit(CODE_OK); }

    if (main_args.domain_sock_path)
    {
        g_client_connection->type = DOMAIN;
        int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        g_client_connection->domain.addr.sun_family = AF_UNIX;
        strcpy(g_client_connection->domain.addr.sun_path, main_args.domain_sock_path);
        strcpy(g_client_connection->domain.path, main_args.domain_sock_path);
        
        if (connect(sock_fd, (struct sockaddr*)&g_client_connection->domain.addr, sizeof(g_client_connection->domain.addr)) == -1)
        {
            close(sock_fd);
            ERROR_LOG("[Error]: Failed to bind domain socket \"%s\"\n", main_args.domain_sock_path);
            nsh_exit(CODE_BIND_ERROR);
        }
        g_client_connection->fd_read = sock_fd;
        g_client_connection->fd_write = sock_fd;

        VERBOSE_LOG("[Connection]: Opened domain socket \"%s\"\n", main_args.domain_sock_path);
    }
    else if (main_args.network)
    {
        g_client_connection->type = NETWORK;
        int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (sock_fd < 0) { ERROR_LOG("[Error]: Failed to create internet socket\n"); nsh_exit(SOCKET_ERROR); }
        
        g_client_connection->network.remote.sin_family = AF_INET;
        g_client_connection->network.remote.sin_port = htons(main_args.port);
        inet_pton(AF_INET, main_args.ip_address, &g_client_connection->network.remote.sin_addr);

        if (connect(sock_fd, (struct sockaddr*)&g_client_connection->network.remote, sizeof(g_client_connection->network.remote)) < 0)
        { 
            close(sock_fd);
            ERROR_LOG("[Error]: Failed to connect to %s:%d\n", main_args.ip_address, main_args.port);
            nsh_exit(CODE_BIND_ERROR);
        }

        g_client_connection->fd_read = sock_fd;
        g_client_connection->fd_write = sock_fd;

        VERBOSE_LOG("[Connection]: Opened network socket %s:%d\n", main_args.ip_address, main_args.port);
    }
    else
    {
        ERROR_LOG("[Notice]: You cannot be a client to your own terminal.. how did this even happen?\n");
        nsh_exit(CODE_WTF);
    }

    return CODE_OK;
}

void nsh_connection_add_console()
{
    nsh_conn_t conn = {0};
    conn.id = g_next_id++;
    conn.type = CONSOLE;
    conn.state = STATE_ACTIVE;
    conn.fd_read = fileno(stdin);
    conn.fd_write = fileno(stdout);
    array_push(&g_connections, &conn);
}

int nsh_evaluate_server()
{
    VERBOSE_LOG("[State]: Server mode\n");

    nsh_conn_t initial_connection = {0};
    initial_connection.id = g_next_id++;
    initial_connection.last_active = time(0);

    if (main_args.log_file)
    {
        FILE* flog = fopen(main_args.log_file, "w+");
        if (!flog)
        {
            fprintf(stderr, "[Error]: Couldn't open file \"%s\" for logging purposes\n", main_args.log_file);
            nsh_exit(CODE_INVALID_FILE);
        }
        fclose(flog);
        freopen(main_args.log_file, "w+", stderr);
        VERBOSE_LOG("[State]: Set log file to \"%s\"\n", main_args.log_file);
    }
    if (main_args.help) { nsh_print_help(); nsh_exit(CODE_OK); }

    // Prepare the server
    if (main_args.domain_sock_path)
    {
        initial_connection.type = DOMAIN;
        int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        initial_connection.domain.addr.sun_family = AF_UNIX;
        strcpy(initial_connection.domain.addr.sun_path, main_args.domain_sock_path);
        strcpy(initial_connection.domain.path, main_args.domain_sock_path);
        unlink(main_args.domain_sock_path);
        if (bind(sock_fd, (struct sockaddr*)&initial_connection.domain.addr, sizeof(initial_connection.domain.addr)) == -1)
        {
            close(sock_fd);
            ERROR_LOG("[Error]: Failed to bind domain socket \"%s\"\n", main_args.domain_sock_path);
            nsh_exit(CODE_BIND_ERROR);
        }
        if (listen(sock_fd, SOMAXCONN) < 0)
        {
            close(sock_fd);
            ERROR_LOG("[Error]: Failed to listen at bound socket %s:%d\n", main_args.ip_address, main_args.port);
            nsh_exit(CODE_LISTEN_ERROR);
        }

        initial_connection.fd_read = sock_fd;
        initial_connection.fd_write = sock_fd;

        VERBOSE_LOG("[Connection]: Opened domain socket \"%s\"\n", main_args.domain_sock_path);
    }
    else if (main_args.network)
    {
        initial_connection.type = NETWORK;
        int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (sock_fd < 0) { ERROR_LOG("[Error]: Failed to create internet socket\n"); nsh_exit(SOCKET_ERROR); }
        
        initial_connection.network.local.sin_family = AF_INET;

        inet_pton(AF_INET, main_args.ip_address, &initial_connection.network.local.sin_addr);

        initial_connection.network.local.sin_port = htons(main_args.port);
        if (bind(sock_fd, (struct sockaddr*)&initial_connection.network.local, sizeof(initial_connection.network.local)) < 0)
        { 
            close(sock_fd);
            ERROR_LOG("[Error]: Failed to bind internet socket to %s:%d\n", main_args.ip_address, main_args.port);
            nsh_exit(CODE_BIND_ERROR);
        }

        if (listen(sock_fd, SOMAXCONN) < 0)
        {
            close(sock_fd);
            ERROR_LOG("[Error]: Failed to listen at bound socket %s:%d\n", main_args.ip_address, main_args.port);
            nsh_exit(CODE_LISTEN_ERROR);
        }

        initial_connection.fd_read = sock_fd;
        initial_connection.fd_write = sock_fd;

        VERBOSE_LOG("[Connection]: Opened network socket %s:%d\n", main_args.ip_address, main_args.port);
    }
    if (main_args.force_terminal || g_connections.length == 0)
    {
        nsh_connection_add_console();
        VERBOSE_LOG("[Connection]: Using terminal as connection\n");
    }

    array_push(&g_connections, &initial_connection);

    return CODE_OK;
}

void nsh_cmd_stat()
{
    char fd_read_buff[32], fd_write_buff[32];

    printf("|=== NSH : Stat =========================================================|\n");
    printf("| ID  | State  | Type    | From                  | To                    |\n");
    printf("|-----|--------|---------|-----------------------|-----------------------|\n");
    for (size_t i = 0; i < g_connections.length; i++)
    {
        nsh_conn_t* conn = array_at(&g_connections, i);
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
            fd_read_name = fd_read_buff;
            fd_write_name = fd_write_buff;
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
}

int nsh_init(int argc, char** argv)
{
    static bool initialized = false;
    if (initialized) return CODE_OK;

    array_create(&g_connections, NSH_INITIAL_MAX_CONNECTIONS, sizeof(nsh_conn_t));

    nsh_parse_args(argc, argv);
    return CODE_OK;
}

void nsh_interpret(nsh_conn_t* connection)
{
    VERBOSE_LOG("[Log]: Interpreting commands on connection ID %d\n", connection->id);
    ssize_t readBytes;
    if (connection->type == CONSOLE) readBytes = read(connection->fd_read, BUFFER, BUFFER_SIZE);
    else readBytes = recv(connection->fd_read, BUFFER, BUFFER_SIZE, 0);

    ssize_t writtenBytes;
    if (connection->type == CONSOLE) writtenBytes = write(connection->fd_write, BUFFER, readBytes);
    else writtenBytes = send(connection->fd_write, BUFFER, readBytes, 0);
}

void nsh_accept_connection(nsh_conn_t* connection)
{
    socklen_t client_length = sizeof(connection->network.remote);
    int sock_fd = accept(connection->fd_read, (struct sockaddr*)&connection->network.remote, &client_length);
    if (sock_fd < 0) { ERROR_LOG("[Error]: Failed to accept new connection on ID %d\n", connection->id); return; }
    connection->state = STATE_ACTIVE;
    close(connection->fd_read); // fd_write should be the same since we promoted the listening socket to well another listening sockete
    connection->fd_write = sock_fd;
    connection->fd_read = sock_fd;
    VERBOSE_LOG("[Log]: Accepted connection on ID %d\n", connection->id);
}

int nsh_server()
{
    int valid_args = nsh_evaluate_server();
    if (valid_args != CODE_OK) return valid_args;
    
    array_t poll_fds; array_create(&poll_fds, g_connections.capacity, sizeof(struct pollfd));
    while (g_running)
    {
        nsh_cmd_stat();

        array_clear(&poll_fds);
        if (poll_fds.capacity < g_connections.length) array_resize(&poll_fds, g_connections.capacity);
        for (size_t i = 0; i < g_connections.length; i++)
        {
            const nsh_conn_t* conn = array_at(&g_connections, i);
            struct pollfd* pfd = array_index(&poll_fds, i);
            pfd->fd = conn->fd_read;
            pfd->events = POLLIN;
            pfd->revents = 0;
            poll_fds.length++;
        }
        poll(poll_fds.base, poll_fds.length, -1);
        
        for (size_t i = 0; i < poll_fds.length; i++)
        {
            struct pollfd* pfd = array_at(&poll_fds, i);
            printf("fd %d | events %d | revents %d\n", pfd->fd, pfd->events, pfd->revents); // DEBUG
            if (pfd->revents & POLLIN)
            {
                nsh_conn_t* conn = array_find_first(&g_connections, (array_find_func)find_connection_by_fd, &pfd->fd);
                if (conn->state == STATE_ACTIVE) nsh_interpret(conn);
                else nsh_accept_connection(conn);
                conn->last_active = time(0);
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

int nsh(int argc, char** argv)
{
    int init = nsh_init(argc-1, argv+1);
    if (init != CODE_OK) return init;

    int err = CODE_OK;
    if (main_args.server) err = nsh_server();
    else err = nsh_client();

    nsh_cleanup();
    return err;
}
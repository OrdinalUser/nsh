#ifndef NSH_H
#define NSH_H

#include <stddef.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <stdbool.h>
#include <limits.h>
#include <time.h>

#define DOMAIN_FILEPATH_LENGTH ((sizeof((struct sockaddr_un*)0)->sun_path))
#define DOMAIN_FILEPATH_STR_MAX ((sizeof((struct sockaddr_un*)0)->sun_path) - 1)

/* Default config */
#define NSH_INITIAL_PORT 8888
#define NSH_INITIAL_IP_INTERFACE "0.0.0.0"
#define NSH_INITIAL_TIMEOUT -1

#define NSH_MAX_CONNECTIONS_COUNT 64
#define NSH_CLIENT_BUFFER_SIZE 65536
#define NSH_SHARED_MEM_NAME "/nsh"

typedef enum NshError
{
    CODE_OK = 0,
    CODE_INVALID_FILE,
    CODE_BIND, CODE_LISTEN, CODE_SOCKET, CODE_SHUTDOWN, CODE_CLOSE, CODE_ACCEPT, CODE_CONNECT,
    CODE_DOMAIN_PATH_LIMIT, CODE_USER_ERROR,
    CODE_CONNECTION_LIMIT,
    CODE_FORK, CODE_EXEC,
    CODE_ALREADY_INITIALIZED,
    CODE_WTF
} nsh_err_e;

typedef enum NSH_CONNECTION_TYPE {
    CONSOLE, NETWORK, DOMAIN
} nsh_conn_type_e;

typedef enum NSH_CONNECTION_STATE {
    STATE_INACTIVE, STATE_ACTIVE
} nsh_conn_state_e;

typedef struct NshConnection
{
    nsh_conn_type_e type;
    nsh_conn_state_e state;
    int id;
    time_t last_active;
    pid_t pid;

    union
    {
        struct {
            char ip_from[INET_ADDRSTRLEN], ip_to[INET_ADDRSTRLEN];
            unsigned short port_from, port_to;
        } network;
        struct
        {
            char path[DOMAIN_FILEPATH_LENGTH];
        } domain;
    };

} nsh_conn_t;

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
    volatile bool got_aborted;
};

void nsh_internal_help();

void nsh_exit(int code);
int nsh(int argc, char** argv);

pid_t nsh_internal_start_instance(nsh_conn_t conn);
nsh_err_e nsh_instance_close();
nsh_err_e nsh_register_instance();
nsh_err_e nsh_internal_reset_connection();
nsh_err_e nsh_instance_accept();

#endif
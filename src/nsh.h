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
            short port_from, port_to;
        } network;
        struct
        {
            char path[DOMAIN_FILEPATH_LENGTH];
        } domain;
    };

} nsh_conn_t;

void nsh_exit();
int nsh(int argc, char** argv);

#endif
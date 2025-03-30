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
    int fd_read, fd_write; // fd_read may be RW
    time_t last_active;
    
    // Dependant on type
    union
    {
        struct 
        {
            struct sockaddr_in local;
            struct sockaddr_in remote;
        } network;
        struct {
            struct sockaddr_un addr;
            char path[PATH_MAX];
        } domain;
    };
    
} nsh_conn_t;

void nsh_atexit();
int nsh(int argc, char** argv);

#endif
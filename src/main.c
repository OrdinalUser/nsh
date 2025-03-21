#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <unistd.h>
#include <arpa/inet.h>

#include "daemon.h"
#include "nsh.h"

#define DEFAULT_LISTEN_PORT 8888
#define DEFAULT_MAX_LISTEN_CLIENTS 5
#define CONN_LISTEN_BUFF_SIZE 256

void critical_error(const char* msg, int err)
{
    fprintf(stderr, "[Critical]: ");
    fprintf(stderr, msg);
    exit(err);
}

void noncritical_error(const char* msg, int err)
{
    fprintf(stderr, "[Error]: ");
    fprintf(stderr, msg);
}

int listen_for_new_connections()
{
    int sockfd;
    struct sockaddr_in server_listen_socket;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) critical_error("[Listener]: Failed to server connection listen socket\n", -1);

    server_listen_socket.sin_family = AF_INET;
    server_listen_socket.sin_addr.s_addr = INADDR_ANY; // Listen on all network interface; TODO: -i flag to specify ip-interface
    server_listen_socket.sin_port = htons(DEFAULT_LISTEN_PORT); // TODO: -p flag to change listening port
    if (bind(sockfd, (struct sockaddr*)&server_listen_socket, sizeof(server_listen_socket)) < 0) { close(sockfd); critical_error("[Listener]: Failed to bind server listen socket\n", -1); }

    if (listen(sockfd, DEFAULT_MAX_LISTEN_CLIENTS) < 0) { close(sockfd); critical_error("[Listener]: Failed to listen on server listen socket\n", -1); }
    printf("Waiting for client connections at port %d\n", DEFAULT_LISTEN_PORT);
    return sockfd;
}

void handle_new_connections(int listen_fd)
{
    char buff[CONN_LISTEN_BUFF_SIZE];
    char client_ip[INET_ADDRSTRLEN];

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd;

    while (true)
    {
        client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) { noncritical_error("Failed to accept new connection\n", 1); continue; }
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        int client_port = ntohs(client_addr.sin_port);
        printf("New connection from: %s:%d\n", client_ip, client_port);
        close(client_fd);
    }

    close(listen_fd);
}

struct main_args
{
    char* ip_add;
    char* listen_port;
    char* remote_port;
    bool help, daemon;
};

void main_parse_args(int argc, char** argv)
{
    struct main_args args = {0};
    for (int argi = 1; argi < argc; argi++)
    {
        char* arg = argv[argi];
        char* arg_value = 0;
        if (*arg == '-')
        {
            // Deal with flags
            switch(*(arg+1))
            {
                case 'h':
                    printf("Help\n");
                    args.help = true;
                    break;
                case 'i':
                    if (argi+1 >= argc || *argv[argi+1] == '-') { printf("Missing value after %s flag\n", arg); break; }
                    args.ip_add = argv[argi+1];
                    arg_value = argv[++argi];
                    printf("ip address: %s\n", arg_value);
                    break;
                case 'p':
                    if (argi+1 >= argc || *argv[argi+1] == '-') { printf("Missing value after %s flag\n", arg); break; }
                    args.listen_port = argv[argi+1];
                    arg_value = argv[++argi];
                    printf("listening port: %s\n", arg_value);
                    break;
                case 'c':
                    if (argi+1 >= argc || *argv[argi+1] == '-') { printf("Missing value after %s flag\n", arg); break; }
                    args.remote_port = argv[argi+1];
                    arg_value = argv[++argi];
                    printf("connection port: %s\n", arg_value);
                    break;
                case 'd':
                    printf("Daemon only, no interactive shell provided\n");
                    nsh_daemon_process_create(true);
                    args.daemon = true;
                    break;
            }
        }
        else
        {
            printf("Encountered unknown arg: '%s', use - to prefix flags\n", arg);
        }
    }
}

int main(int argc, char** argv, char** envp)
{
    main_parse_args(argc, argv);
//     int listen_fd = listen_for_new_connections();
//     handle_new_connections(listen_fd);

//     for (char** env = envp; *env; env++)
//     {
//         printf("%s\n", *env);
//     }
    return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>

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
    int listen_port, remote_port;
    char* log_file;
    char script_file[PATH_MAX];
    bool help, daemon, verbose;
} main_args = {0};

void main_parse_args(int argc, char** argv)
{
    int unnamed_arg = 0;
    char* arg_value = 0;
    int port_val = 0;
    for (int argi = 1; argi < argc; argi++)
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
                    main_args.ip_add = argv[argi+1];
                    arg_value = argv[++argi];
                    printf("ip address: %s\n", arg_value);
                    break;
                case 'p':
                    if (argi+1 >= argc || *argv[argi+1] == '-') { fprintf(stderr, "Missing value after %s flag\n", arg); break; }
                    arg_value = argv[++argi];
                    port_val = atoi(arg_value);
                    if (port_val == 0 || port_val > 65535) { fprintf(stderr, "Invalid port number \"%s\" doesn't belong in range (0, 65536)\n", arg_value); break; }
                    main_args.listen_port = port_val;
                    printf("listening port: %d\n", port_val);
                    break;
                case 'c':
                    if (argi+1 >= argc || *argv[argi+1] == '-') { fprintf(stderr, "Missing value after %s flag\n", arg); break; }
                    arg_value = argv[++argi];
                    port_val = atoi(arg_value);
                    if (port_val == 0 || port_val > 65535) { fprintf(stderr, "Invalid port number \"%s\" doesn't belong in range (0, 65536)\n", arg_value); break; }
                    main_args.remote_port = port_val;
                    printf("connection port: %d\n", port_val);
                    break;
                case 'd':
                    printf("Daemon only, no interactive shell provided\n");
                    main_args.daemon = true;
                    break;
                case 'v':
                    printf("Verbose on\n");
                    main_args.verbose = true;
                    break;
                case 'l':
                    if (argi+1 >= argc || *argv[argi+1] == '-') { fprintf(stderr, "Missing value after %s flag\n", arg); break; }
                    main_args.log_file = argv[argi+1];
                    arg_value = argv[++argi];
                    printf("connection port: %s\n", arg_value);
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
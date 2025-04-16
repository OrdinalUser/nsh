#include "globals.h"

struct nsh_args g_args = {0};
struct nsh_client_state client = {.running = true };
struct nsh_instance_state instance = {0}; // Contains the original connection entry for each instance
struct nsh_shared_connections* shared_mem;

/* Lookups */
const char* NSH_CONNECTION_TYPE_STR[] = {
    "CONSOLE", "NETWORK", "DOMAIN"
};
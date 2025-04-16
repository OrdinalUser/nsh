#ifndef NSH_GLOBALS_H
#define NSH_GLOBALS_H

#include "nsh.h"

extern struct nsh_args g_args;
extern struct nsh_client_state client;
extern struct nsh_instance_state instance; // Contains the original connection entry for each instance
extern struct nsh_shared_connections* shared_mem;
extern const char* NSH_CONNECTION_TYPE_STR[];

#endif
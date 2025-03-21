#include <stdbool.h>

// Check if there's a daemon out there to haunt us
bool nsh_daemon_process_exists();

// Create daemon process for our user
bool nsh_daemon_process_create();
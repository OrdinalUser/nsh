#ifndef NSH_INTERPRETER_H
#define NSH_INTERPRETER_H

typedef enum NSH_SHELL_ERROR
{
    SHELL_OK, SHELL_EXIT, SHELL_RESET
} nsh_shell_e;

int nsh_interpreter();

#endif
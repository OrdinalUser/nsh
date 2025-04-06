#ifndef NSH_INTERPRETER_H
#define NSH_INTERPRETER_H

typedef enum NSH_SHELL_ERROR
{
    SHELL_OK, SHELL_EXIT, SHELL_RESET,
    SHELL_FORK_FAILED, SHELL_EXEC_FAIL = 127
} nsh_shell_e;

int nsh_interpreter();
void nsh_signals_reset();
void nsh_signals_set();

#endif
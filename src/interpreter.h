#ifndef NSH_INTERPRETER_H
#define NSH_INTERPRETER_H

typedef enum NSH_SHELL_ERROR
{
    SHELL_OK, SHELL_EXIT, SHELL_RESET,
    SHELL_FORK_FAILED, SHELL_EXEC_FAIL = 127,
    SHELL_NOT_NATIVE, SHELL_PIPELINE_FAIL,
    SHELL_POLL_FAIL
} nsh_shell_e;

int nsh_interpreter();
void nsh_signals_reset();
void nsh_signals_set();

#endif
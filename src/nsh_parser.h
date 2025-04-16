#ifndef NSH_PARSER_H
#define NSH_PARSER_H

#include <stddef.h>
#include "nsh_lexer.h"

typedef struct NSH_COMMAND {
    char* cmd;
    char** flags;
    char* input_file;
    char* output_file;
} nsh_command_t;

typedef struct NSH_COMMAND_CHAIN {
    nsh_command_t* commands;
    size_t count;
} nsh_command_chain_t;

nsh_command_chain_t parser_advance(char* command, char** saveptr);
bool parser_chain_validate(nsh_command_chain_t* chain);
void parser_chain_free(nsh_command_chain_t* chain);

#endif
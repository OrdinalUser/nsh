#include "nsh_lexer.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

// Needs to support
// <cmd> <flag> <file_as_stdin> <end> <pipe> <fd_redirect>
// grep -n < file.txt | cat > f.txt

#include "array.h"

void* lexer(const char* command)
{
    char* saveptr;
    char* token = strtok_r(command, " ", &saveptr);

    array_t tokens; array_create(&tokens, 64, sizeof(nsh_token_t));
    bool cmd_tokenized = false;
    while (token)
    {
        nsh_token_t tok = {.type = NSH_TOKEN_EOF, .value = token};
        if (strcmp(token, "<") == 0)
        {
            tok.type = NSH_TOKEN_INPUT_REDIRECTION;
            array_push(&tokens, &tok);d
        }
        // printf("%s ", token);
        token = strtok_r(NULL, " ", &saveptr);
    }
    return NULL;
}
#ifndef NSH_LEXER_H
#define NSH_LEXER_H

typedef enum NSH_TOKEN_ENUM
{
    NSH_TOKEN_EOF, NSH_TOKEN_CMD_END, NSH_TOKEN_COMMENT,
    NSH_TOKEN_CMD, NSH_TOKEN_FLAG,
    NSH_TOKEN_PIPE, NSH_TOKEN_INPUT_REDIRECTION, NSH_TOKEN_OUTPUT_REDIRECTION
} nsh_token_e;

typedef struct NSH_TOKEN
{
    nsh_token_e type;
    char* value;
} nsh_token_t;

// Returns a list of tokens
// Consumer is liable for freeing the memory
nsh_token_t* lexer(const char* command);

#endif
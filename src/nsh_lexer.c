#include "nsh_lexer.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>

// Needs to support
// <cmd> <flag> <file_as_stdin> <end> <pipe> <fd_redirect>
// grep -n < file.txt | cat > f.txt

static const char* NSH_TOKEN_ENUM_STR[] = {
    "EOF", "END", "COMMENT",
    "CMD", "FLAG",
    "PIPE", "INPUT", "OUTPUT"
};

const char* nsh_lexer_enum_str(nsh_token_e tokenType)
{
    return NSH_TOKEN_ENUM_STR[tokenType];
}

#include "array.h"

// Replacement for strtok
char* advance(const char* start, char delim, char** saveptr)
{
    if (start) *saveptr = start;
    if (**saveptr == 0) return NULL;

    int quote_count = 0;
    char* c = *saveptr;
    char* tok_start = c;
    for (; *c; c++)
    {
        if (*c == '"') quote_count++;
        else if  ((*c == delim && (quote_count % 2 == 0)))
        {
            *saveptr = *c ? c+1 : c;
            *c = 0;
            break;
        }
    }
    if (quote_count % 2 == 1)
    {
        *saveptr = *c ? c+1 : c;
    }
    return tok_start;
}

nsh_token_t* lexer(const char* command)
{
    char* saveptr;
    //char* token = strtok_r(command, " ", &saveptr);

    array_t tokens; array_create(&tokens, 64, sizeof(nsh_token_t));
    bool cmd_tokenized = false;
    char* token = advance(command, ' ', &saveptr);
    while (token)
    {
        size_t len = strlen(token);
        if (token[len-1] == '\n') token[len---1] = 0; 

        nsh_token_t tok = {.type = NSH_TOKEN_EOF, .value = token};
        if (strcmp(token, "<") == 0) { tok.type = NSH_TOKEN_INPUT_REDIRECTION; tok.value = advance(NULL, ' ', &saveptr); }
        else if (strcmp(token, ">") == 0) { tok.type = NSH_TOKEN_OUTPUT_REDIRECTION; tok.value = advance(NULL, ' ', &saveptr); }
        else if (strcmp(token, "|") == 0) { tok.type = NSH_TOKEN_PIPE; cmd_tokenized = false; }
        else if (strcmp(token, ";") == 0) { tok.type = NSH_TOKEN_CMD_END; cmd_tokenized = false; }
        else {
            // String value token
            if (token[0] == '#') {tok.type = NSH_TOKEN_COMMENT; continue; }

            int start = 0, end = strlen(token);
            if (token[0] == '"' && token[end-1] == '"')
            {
                token[0] = 0;
                token[end-1] = 0;
                tok.value++;
            }
            if (cmd_tokenized) tok.type = NSH_TOKEN_FLAG;
            else { tok.type = NSH_TOKEN_CMD; cmd_tokenized = true; }
        }
        array_push(&tokens, &tok);
        //token = strtok_r(NULL, " ", &saveptr);
        token = advance(NULL, ' ', &saveptr);
    }
    nsh_token_t end_tok = {.value = "", .type = NSH_TOKEN_EOF};
    array_push(&tokens, &end_tok);

    return tokens.base;
}

char* next_string(char* start, char delim, char** saveptr)
{
    if (start) *saveptr = start;
    if (**saveptr == 0) return NULL;

    char* curr = *saveptr;
    while (*curr == delim) { curr++; }
    if (!(*curr)) {*saveptr = curr; return NULL; };
    char* tokStart = curr;

    bool quoted = false;
    quoted = *tokStart == '"';

    for (; *curr; curr++)
    {
        if (isprint(*curr) && *curr == delim && (!quoted || ((*(curr-1) == '"') && tokStart != curr-1)))
        {
            *curr = 0;
            curr++;
            break;
        }
    }

    *saveptr = curr;
    return tokStart;
}

char* string_sanitize_quotes(char* str)
{
    size_t strLen = strlen(str);
    if (str[0] == '"' && str[strLen-1] == '"')
    {
        str[0] = 0;
        str[strLen-1] = 0;
        str++;
    }
    return str;
}

// ls -l < "input/a.txt" | grep abc > "output files/dump.txt" ; echo < "output files/dump.txt"

// Will modify the input string
nsh_token_t lexer_advance(char* start, char** saveptr, bool* cmdFlag)
{
    if (start) *cmdFlag = false;
    nsh_token_t tok = {.type = NSH_TOKEN_EOF, .value = ""};
    char* value = next_string(start, ' ', saveptr);

    if (!value) return tok;
    char* val = string_sanitize_quotes(value);
    
    if (strcmp(val, "<") == 0) {
        tok.type = NSH_TOKEN_INPUT_REDIRECTION;
        tok.value = string_sanitize_quotes(next_string(start, ' ', saveptr));
    }
    else if (strcmp(val, ">") == 0) {
        tok.type = NSH_TOKEN_OUTPUT_REDIRECTION;
        tok.value = string_sanitize_quotes(next_string(start, ' ', saveptr));
    }
    else if (strcmp(val, "|") == 0) {
        tok.type = NSH_TOKEN_PIPE;
        *cmdFlag = false;
    }
    else if (strcmp(val, "#") == 0) {
        tok.type = NSH_TOKEN_COMMENT;
        tok.value = string_sanitize_quotes(next_string(start, ' ', saveptr));
    }
    else if (val[0] == '#')
    {
        tok.type = NSH_TOKEN_COMMENT;
        val[0] = 0;
        tok.value = ++val;
    }
    else if (strcmp(val, ";") == 0) {
        tok.type = NSH_TOKEN_CMD_END;
        *cmdFlag = false;
    }
    else if (val[0] == '\n') {
        tok.type = NSH_TOKEN_CMD_END;
    }
    else {
        if (!*cmdFlag) { tok.type = NSH_TOKEN_CMD; *cmdFlag = true; }
        else tok.type = NSH_TOKEN_FLAG;
        tok.value = val;
    }

    return tok;
}
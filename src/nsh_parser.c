#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "nsh_lexer.h"
#include "nsh_parser.h"
#include "array.h"

#include <stdlib.h>
#include <limits.h>
#include <unistd.h>

const char* nsh_native_commands[] = {
    "quit", "reset", "cd", "stat"
};

nsh_command_chain_t* parser(nsh_token_t* tokens)
{
    array_t cmd_chains; array_create(&cmd_chains, 1, sizeof(nsh_command_chain_t));

    array_t cmds; array_create(&cmds, 1, sizeof(nsh_command_t));
    nsh_command_chain_t chain = {0};
    for (nsh_token_t* tok = tokens; tok->type != NSH_TOKEN_EOF; tok++)
    {
        array_t cmd_flags; array_create(&cmd_flags, 1, sizeof(char*));
        nsh_command_t cmd = {0};
        
        for (; tok->type != NSH_TOKEN_EOF; tok++)
        {
            printf("Processing: %d - %s\n", tok->type, tok->value);
            switch (tok->type)
            {
            case NSH_TOKEN_CMD:
                cmd.cmd = tok->value;
                break;
            case NSH_TOKEN_FLAG:
                array_push(&cmd_flags, tok->value);
                break;
            case NSH_TOKEN_COMMENT:
                break;
            case NSH_TOKEN_INPUT_REDIRECTION:
                cmd.input_file = ++tok->value;
                break;
            case NSH_TOKEN_OUTPUT_REDIRECTION:
                cmd.output_file = ++tok->value;
                break;
            case NSH_TOKEN_PIPE:
            case NSH_TOKEN_EOF:
            case NSH_TOKEN_CMD_END:
                const char* null_flag = 0;
                array_push(&cmd_flags, &null_flag);
                cmd.flags = cmd_flags.base;
                array_push(&cmds, &cmd);
                memset(&cmd, 0, sizeof(cmd));
                array_create(&cmd_flags, 16, sizeof(char*));
                chain.count++;
                break;
            default:
                printf("Invalid token type: %d\n", tok->type);
                assert(0 != 0);
                break;
            }
        }
        nsh_command_t null_cmd = {0};
        array_push(&cmds, &null_cmd);
        chain.commands = cmds.base;
        array_push(&cmd_chains, &chain);
        if (tok->type == NSH_TOKEN_CMD_END)
        {
            array_create(&cmds, 16, sizeof(nsh_command_t));
            chain.commands = cmds.base;
            chain.count =  0;
        }
    }

    nsh_command_chain_t null_end = {0};
    array_push(&cmd_chains, &null_end);
    return cmd_chains.base;
}

nsh_command_chain_t parser_advance(const char* command, char** saveptr)
{
    const char* null_flag = 0;
    bool cmdFlag = false;
    array_t cmds; array_create(&cmds, 8, sizeof(nsh_command_t));
    
    array_t cmdFlags; array_create(&cmdFlags, 16, sizeof(char*));
    nsh_command_t cmd = {0};

    nsh_token_t tok = lexer_advance(command, saveptr, &cmdFlag);

    nsh_command_chain_t null_chain = {.commands = NULL, .count = 0};
    if (tok.type == NSH_TOKEN_EOF) return null_chain;
    
    while (true)
    {
        //printf(">< tok: %s - %s\n", nsh_lexer_enum_str(tok.type), tok.value);
        if (tok.type == NSH_TOKEN_CMD) {
            cmd.cmd = tok.value;
        }
        else if (tok.type == NSH_TOKEN_FLAG) {
            array_push(&cmdFlags, &tok.value);
        }
        else if (tok.type == NSH_TOKEN_INPUT_REDIRECTION) {
            cmd.input_file = tok.value;
        }
        else if (tok.type == NSH_TOKEN_OUTPUT_REDIRECTION) {
            cmd.output_file = tok.value;
        }
        else if (tok.type == NSH_TOKEN_PIPE || tok.type == NSH_TOKEN_EOF || tok.type == NSH_TOKEN_CMD_END) {
            array_push(&cmdFlags, &null_flag);
            cmd.flags = cmdFlags.base;
            array_push(&cmds, &cmd);
            array_create(&cmdFlags, 16, sizeof(char*));
            memset(&cmd, 0, sizeof(nsh_command_t));
            if (tok.type == NSH_TOKEN_EOF || tok.type == NSH_TOKEN_CMD_END) break;
        }
        tok = lexer_advance(NULL, saveptr, &cmdFlag);
    }
    //printf("<last token> tok: %s - %s\n", nsh_lexer_enum_str(tok.type), tok.value);
    
    nsh_command_chain_t chain = {.commands = cmds.base, .count = cmds.length};
    return chain;
}

bool isValidProgram(const char* filepath)
{
    if (!filepath) return false;
    
    for (size_t i = 0; i < sizeof(nsh_native_commands) / sizeof(nsh_native_commands[0]); i++)
    {
        if (strcmp(filepath, nsh_native_commands[i]) == 0) return true;
    }
    
    bool exists = false;
    if (access(filepath, X_OK) == 0)
    {
        exists = true;
    }
    
    char prog[PATH_MAX] = {0};

    char* paths = strdup(getenv("PATH"));
    char* s = paths;
    char* p = NULL;
    do {
        p = strchr(s, ':');
        if (p != NULL) {
            p[0] = 0;
        }
        memset(prog, 0, PATH_MAX);
        strcat(prog, s); strcat(prog, "/"); strcat(prog, filepath);
        //printf("Looking for %s in %s as %s\n", filepath, s, prog);
        if (access(prog, X_OK) == 0)
        {
            //printf("Found program %s in %s\n", prog, s);
            exists = true;
            break;
        }
        s = p + 1;
    } while (p != NULL);

    free(paths);

    return exists;
}

// find . -type f "\( -iname "*.c" -o -iname "*.h" \)" -exec wc -l {} + | sort -n -r
// find -type f \( -name *.c -or -name *.h \)
bool parser_chain_validate(nsh_command_chain_t* chain)
{
    bool valid = true;
    for (size_t i = 0; i < chain->count; i++)
    {
        nsh_command_t* cmd = chain->commands + i;
        if (!isValidProgram(cmd->cmd))
        {
            fprintf(stdout, "-nsh: Command not found \"%s\"\n", cmd->cmd);
            valid = false;
        }
        if (i == 0)
        {
            if (cmd->output_file && chain->count != 1)
            {
                fprintf(stdout, "Piped command cannot output to file \"%s\"\n", cmd->output_file);
                valid = false;
            }
            if (cmd->input_file)
            {
                if (access(cmd->input_file, R_OK) != 0)
                {
                    fprintf(stdout, "Cannot open file \"%s\"\n", cmd->input_file);
                    valid = false;
                }
            }
        }
        else if (i != chain->count-1)
        {
            if (cmd->input_file)
            {
                fprintf(stdout, "Piped command cannot take file input \"%s\"\n", cmd->input_file);
                valid = false;
            }
            if (cmd->output_file)
            {
                fprintf(stdout, "Piped command cannot output to file \"%s\"\n", cmd->output_file);
                valid = false;
            }
        }
        else
        {
            if (cmd->input_file)
            {
                fprintf(stdout, "Piped command cannot take file input \"%s\"\n", cmd->input_file);
                valid = false;
            }
        }
    }
    return valid;
}

void parser_chain_free(nsh_command_chain_t* chain)
{
    for (size_t i = 0; i < chain->count; i++)
        free(chain->commands[i].flags);
    free(chain->commands);
}
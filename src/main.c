#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "nsh.h"

#include "nsh_lexer.h"
#include "nsh_parser.h"

#include "array.h"

int main(int argc, char** argv, char** envp)
{
    int err = nsh(argc, argv);
    printf("Shell exited with %d\n", err);
    // char buff[1024];
    // while (1)
    // {
    //     fgets(buff, 1024, stdin);
    //     buff[strlen(buff)-1] = 0;

    //     // char* saveptr; bool flag = false;
    //     // nsh_token_t tok = lexer_advance(buff, &saveptr, &flag);
    //     // array_t tokens; array_create(&tokens, 32, sizeof(nsh_token_t));
    //     // while (tok.type != NSH_TOKEN_EOF)
    //     // {
    //     //     printf("tok: %s - %s\n", nsh_lexer_enum_str(tok.type), tok.value);
    //     //     tok = lexer_advance(NULL, &saveptr, &flag);
    //     // }
    //     // printf("tok: %s - %s\n", nsh_lexer_enum_str(tok.type), tok.value);

    //     // Parsing
    //     char* saveptr1;
    //     nsh_command_chain_t chain = parser_advance(buff, &saveptr1);
    //     while (chain.count)
    //     {
    //         printf("Chain ------------------------\n");
    //         for (size_t i = 0; i < chain.count; i++)
    //         {
    //             nsh_command_t* cmd = &chain.commands[i];
    //             printf("> Command ------\n");
    //             printf(">> Path: %s\n", cmd->cmd);
    //             printf(">> Flags: ");
    //             for (char** flag = cmd->flags; *flag; flag++)
    //             {
    //                 printf("%s", *flag);
    //                 if (*(flag+1)) putchar(' ');
    //             }
    //             putchar('\n');
                
    //             if (cmd->input_file) printf(">> Input: %s\n", cmd->input_file);
    //             if (cmd->output_file) printf(">> Output: %s\n", cmd->output_file);
    //         }
    //         bool validChain = parser_chain_validate(&chain);

    //         parser_chain_free(&chain);
    //         chain = parser_advance(NULL, &saveptr1);
    //     }

    //     // Freeing
    //     //free(tokens);
    //     //free(chains);
    // }

    return 0;
}
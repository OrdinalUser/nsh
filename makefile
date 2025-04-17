CC = gcc
CFFLAGS = -Wall -g -fsanitize=address,undefined -fno-omit-frame-pointer -O1

PROJECT_NAME=nsh
SRC=src
SRCS=$(SRC)/main.c $(SRC)/nsh.c $(SRC)/array.c $(SRC)/interpreter.c $(SRC)/nsh_lexer.c $(SRC)/nsh_parser.c $(SRC)/globals.c
BIN_FOLDER=bin
PROJECT_EXE=$(BIN_FOLDER)/$(PROJECT_NAME)

PROG_FLAGS=-v

$(PROJECT_EXE): $(SRCS)
	$(CC) $(CFFLAGS) -o $(PROJECT_EXE) $(SRCS)

clean:
	rm -f $(PROJECT_EXE)

run: $(PROJECT_EXE)
	./$(PROJECT_EXE)

run-server: $(PROJECT_EXE)
	./$(PROJECT_EXE) -v -u ~/domain -l log.txt

run-client-domain: $(PROJECT_EXE)
	./$(PROJECT_EXE) -v -c -u ~/domain

run-client-network: $(PROJECT_EXE)
	./$(PROJECT_EXE) -v -c

sync:
	git fetch
	git reset --hard HEAD
	git pull

debug: $(PROJECT_EXE)
	ASAN_OPTIONS=fast_unwind_on_malloc=0:abort_on_error=1 ./$(PROJECT_EXE)

run-server-debug: $(PROJECT_EXE)
	ASAN_OPTIONS=fast_unwind_on_malloc=0:abort_on_error=1 ./$(PROJECT_EXE) -v -u ~/domain -p 8080
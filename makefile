CC = gcc
CFFLAGS = -Wall -Werror -g -fsanitize=address,undefined -fno-omit-frame-pointer -O1
RELEASE_CFLAGS = -Wall -Werror -O2
DEBUG_CFLAGS = -Wall -Werror -g -fsanitize=address,undefined -fno-omit-frame-pointer -O1

PROJECT_NAME=nsh
SRC=src
SRCS=$(SRC)/main.c $(SRC)/nsh.c $(SRC)/array.c $(SRC)/interpreter.c $(SRC)/nsh_lexer.c $(SRC)/nsh_parser.c $(SRC)/globals.c
BIN_FOLDER=bin

PROJECT_EXE=$(BIN_FOLDER)/$(PROJECT_NAME)
DEBUG_EXE=$(BIN_FOLDER)/$(PROJECT_NAME)_debug

# Project build
$(PROJECT_EXE): $(SRCS)
	$(CC) $(RELEASE_CFLAGS) -o $(PROJECT_EXE) $(SRCS)

# Debug build
$(DEBUG_EXE): $(SRCS)
	$(CC) $(DEBUG_CFLAGS) -o $(DEBUG_EXE) $(SRCS)

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

debug: $(DEBUG_EXE)
	ASAN_OPTIONS=fast_unwind_on_malloc=0:abort_on_error=1 ./$(DEBUG_EXE)

run-server-debug: $(DEBUG_EXE)
	ASAN_OPTIONS=fast_unwind_on_malloc=0:abort_on_error=1 ./$(DEBUG_EXE) -v -u ~/domain -p 8080
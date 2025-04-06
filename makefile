CC = gcc
CFFLAGS = -Wall

PROJECT_NAME=nsh
SRC=src
SRCS=$(SRC)/main.c $(SRC)/nsh.c $(SRC)/array.c $(SRC)/interpreter.c
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
CC = gcc
CFFLAGS = -Wall

PROJECT_NAME=nsh
SRC=src
SRCS=$(SRC)/main.c $(SRC)/nsh.c $(SRC)/array.c
BIN_FOLDER=bin
PROJECT_EXE=$(BIN_FOLDER)/$(PROJECT_NAME)

PROG_FLAGS=-v

$(PROJECT_EXE): $(SRCS)
	$(CC) $(CFFLAGS) -o $(PROJECT_EXE) $(SRCS)

clean:
	rm -f $(PROJECT_EXE)

run: $(PROJECT_EXE)
	./$(PROJECT_EXE) $(PROG_FLAGS)

run-server: $(PROJECT_EXE)
	./$(PROJECT_EXE) -v -s -T -u ~/domain

run-client-domain: $(PROJECT_EXE)
	./$(PROJECT_EXE) -v -c -u ~/domain

run-client-network: $(PROJECT_EXE)
	./$(PROJECT_EXE) -v -c
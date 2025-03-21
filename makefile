CC = gcc
CFFLAGS = -Wall

PROJECT_NAME=nsh
SRC=src
SRCS=$(SRC)/main.c $(SRC)/daemon.c $(SRC)/nsh.c
BIN_FOLDER=bin
PROJECT_EXE=$(BIN_FOLDER)/$(PROJECT_NAME)

$(PROJECT_EXE): $(SRCS)
	$(CC) $(CFFLAGS) -o $(PROJECT_EXE) $(SRCS)

clean:
	rm -f $(PROJECT_EXE)

run: $(PROJECT_EXE)
	./$(PROJECT_EXE)
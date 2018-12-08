## Name: Ckyever Gaviola 756550
## Login id: cgaviola
## Adapted from http://www.cs.colby.edu/maxwell/courses/tutorials/maketutor/
CC = gcc
CFLAGS = -Wall -Wextra -std=gnu99 -I. -lssl -lcrypto
OBJ = certcheck.o 
EXE = certcheck

## Create .o files from .c files. Searches for .c files with same .o names given in OBJ
%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

## Create executable linked file from object files. 
$(EXE): $(OBJ)
	gcc -o $@ $^ $(CFLAGS)

## Delete object files
clean:
	/bin/rm $(OBJ)

## Performs clean (i.e. delete object files) and deletes executable
clobber: clean
	/bin/rm $(EXE) 

CC=gcc
CFLAGS=-Wall -Wextra -std=c99 -g

decrypter: main.o pcapreader.o decrypt.o sqliteout.o tools.o
	$(CC) -o $@ $^ -lssl -lsqlite3
clean:
	rm -v *.o decrypter

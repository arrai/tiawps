CC=gcc
CFLAGS=-Wall -Wextra -std=c99

decrypter: main.o pcapreader.o decrypt.o sqliteout.o
	$(CC) -o $@ $^ -lssl -lsqlite3
clean:
	rm -v *.o decrypter

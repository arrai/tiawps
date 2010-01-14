CC=gcc
CFLAGS=-Wall -Wextra -std=c99

decrypter: main.o pcapreader.o decrypt.o
	$(CC) -o $@ $^ -lssl


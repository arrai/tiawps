#include <stdio.h>
#include <stdlib.h>

#define uchar  unsigned char
#define SESSION_KEY_LENGTH  40

static uchar SESSIONKEY[SESSION_KEY_LENGTH];

void readSessionkey(const char* file)
{
}

int main(int argc, char *argv[])
{
    if(argc != 3)
    {
        printf("Usage: %s $dumpfile.cap $keyfile.txt\n", argv[0]);
        exit(1);
    }
    
    readSessionkey(argv[2]);
}

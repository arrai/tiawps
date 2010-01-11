#include <stdio.h>
#include <stdlib.h>

#include "pcapreader.h"
#define SESSION_KEY_LENGTH  40

static uint8_t SESSIONKEY[SESSION_KEY_LENGTH];

void readSessionkey(const char* file)
{
    FILE *fp = fopen(file, "r");
    if(!fp)
    {
        printf("Couldn't open keyfile %s\n", file);
        exit(1);
    }
    const int expectedBytes = sizeof(SESSIONKEY);
    int readBytes = fread(SESSIONKEY, 1, expectedBytes, fp);
    if(readBytes != expectedBytes)
    {
        printf("Couldn't read %u bytes from keyfile %s\n", expectedBytes, file);
        exit(1);
    }
    fclose(fp);
}

void parsePcapFile(const char* filename)
{
    FILE *fd = fopen(filename, "r");
    if(!fd)
    {
        printf("Couldn't open pcap file %s\n", filename);
        exit(1);
    }
    pcap_hdr_t *header = readPcapHeader(fd);
    if(!header)
        exit(1);

    pcaprec_hdr_t *packet;

    while(packet = readNextPacket(fd))
    {
        free(packet);
    }

    free(header);
}

int main(int argc, char *argv[])
{
    if(argc != 3)
    {
        printf("Usage: %s $dumpfile.cap $keyfile.txt\n", argv[0]);
        return 1;
    }
    
    readSessionkey(argv[2]);
    parsePcapFile(argv[1]);
}

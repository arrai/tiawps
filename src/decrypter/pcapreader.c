#include <stdio.h>
#include <stdlib.h>

#include "pcapreader.h"

#define FREE_RETURN free(header);return NULL;

pcap_hdr_t* readPcapHeader(FILE *f)
{
    pcap_hdr_t *header = malloc(sizeof(pcap_hdr_t));
    int readElements= fread(header, sizeof(pcap_hdr_t), 1, f);
    if(readElements< 1)
    {
        printf("pcap file doesn't have enough bytes to read header\n");
        FREE_RETURN
    }
    if(header->magic_number != PCAP_MAGIC)
    {
        printf("pcap file has invalid magic number 0x%X\n", header->magic_number);
        FREE_RETURN
    }
    if(header->version_major != 2 ||
            header->version_minor !=4)
    {
        printf("WARNING: pcap format version %u.%u, only 2.4 is supported\n", header->version_major, header->version_minor);
    }
    return header;
}

pcaprec_hdr_t* readNextPacket(FILE *f)
{
    pcaprec_hdr_t *header = malloc(sizeof(pcaprec_hdr_t));
    if(fread(header, sizeof(pcaprec_hdr_t), 1, f)!=1)
    {
        FREE_RETURN
    }
    return header;
}

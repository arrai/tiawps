#include <stdio.h>
#include <stdlib.h>

#include "pcapreader.h"

#define FREE_RETURN free(header);return NULL;

struct pcap_hdr_t* readPcapHeader(FILE *f)
{
    struct pcap_hdr_t *header = malloc(sizeof(struct pcap_hdr_t));
    int readElements= fread(header, sizeof(struct pcap_hdr_t), 1, f);
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

int readNextPacket(FILE *f, struct pcaprec_hdr_t* header, uint8_t **data)
{
    if(fread(header, sizeof(struct pcaprec_hdr_t), 1, f)!=1)
    {
        return 0;
    }
    *data = malloc(header->incl_len);
    if(*data == NULL)
    {
        printf("couldn't allocate %u bytes of memory\n", header->incl_len);
        return 0;
    }
    if(fread(*data, header->incl_len, 1, f) != 1)
    {
        printf("Couldn't read packet data\n");
        free(*data);
        return 0;
    }
    return 1;
}

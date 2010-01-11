#define PCAP_MAGIC          0xa1b2c3d4

#include "structs.h"
pcap_hdr_t* readPcapHeader(FILE *f);
pcaprec_hdr_t* readNextPacket(FILE *f);

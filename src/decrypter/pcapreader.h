#define PCAP_MAGIC          0xa1b2c3d4
#define DLT_EN10MB          1
#define ETHER_TYPE_IP       8
#define TRANSPORT_TYPE_TCP  6

#include "structs.h"
pcap_hdr_t* readPcapHeader(FILE *f);
int readNextPacket(FILE *f, pcaprec_hdr_t* header, uint8_t **data);

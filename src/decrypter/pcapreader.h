#ifndef PCAPREADER_H
#define PCAPREADER_H

#include <stdint.h>


#ifdef _WIN32
#include <Winsock2.h>
#else
#include <netinet/in.h>
#endif

#define PCAP_MAGIC          0xa1b2c3d4

#define DLT_EN10MB          1
#define WTAP_ENCAP_SCCP     101

#define ETHER_TYPE_IP       8
#define ETHER_ADDR_LEN  6

#define TRANSPORT_TYPE_TCP  6


struct pcap_hdr_t {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
};

struct pcaprec_hdr_t {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
};

struct sniff_ethernet_t {
    uint8_t ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    uint8_t ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    uint16_t ether_type; /* IP? ARP? RARP? etc */
};

struct sniff_ip_t {
    uint8_t ip_vhl;      /* version << 4 | header length >> 2 */
    uint8_t ip_tos;      /* type of service */
    uint16_t ip_len;     /* total length */
    uint16_t ip_id;      /* identification */
    uint16_t ip_off;     /* fragment offset field */
    uint8_t ip_ttl;      /* time to live */
    uint8_t ip_p;        /* protocol */
    uint16_t ip_sum;     /* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};

#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)


struct sniff_tcp_t {
    uint16_t th_sport;   /* source port */
    uint16_t th_dport;   /* destination port */
    uint32_t th_seq;     /* sequence number */
    uint32_t th_ack;     /* acknowledgement number */

    uint8_t th_offx2;    /* data offset, rsvd */
#define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
    uint8_t th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    uint16_t th_win;     /* window */
    uint16_t th_sum;     /* checksum */
    uint16_t th_urp;     /* urgent pointer */
};


struct pcap_hdr_t* readPcapHeader(FILE *f);
int readNextPacket(FILE *f, struct pcaprec_hdr_t* header, uint8_t **data);

#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <sqlite3.h>
#include <openssl/bn.h>
//#include <openssl/rsa.h>

#include "pcapreader.h"
#include "structs.h"
#include "decrypt.h"
#include "sqliteout.h"

#define DEBUG               0

                                // SIZE  SIZE  CMD   CMD
//const uint8_t MAGIC_WOW_START[] = {0x00, 0x2A, 0xEC, 0x01};
const uint8_t MAGIC_WOW_START[] = {0x00, 0x27, 0x00, 0x85};

static uint8_t SESSIONKEY[SESSION_KEY_LENGTH];

static int merge_files = 0;

void readSessionkeyFile(const char* file)
{
    FILE *fp = fopen(file, "r");
    if(!fp)
    {
        printf("Couldn't open keyfile %s\n", file);
        exit(1);
    }

    char buffer[1024];
    uint32_t sessionKeyIdx = 0;
    uint8_t startedNibble =0x0F;
    while(1)
    {
        uint32_t readCount = fread(buffer, 1, sizeof(buffer), fp);
        if(!readCount)
        {
            printf("Couldn't read sessionkey from keyfile %s, got only %u of %u keybytes\n", file, sessionKeyIdx, SESSION_KEY_LENGTH);
            exit(1);
        }
        for(uint32_t i=0; i<readCount; ++i)
        {
            char c = tolower(buffer[i]);
            uint8_t value = 0;
            if(c >='0' && c <= '9')
            {
                value = c-'0';
            }
            else if(c>='a' && c<='f')
            {
                value = c-'a'+0xa;
            }
            else
                continue;
            if(startedNibble == 0x0F)
                startedNibble = value<<4;
            else
            {
                SESSIONKEY[sessionKeyIdx] = startedNibble | value;
                startedNibble = 0x0F;
                sessionKeyIdx++;
                if(sessionKeyIdx == SESSION_KEY_LENGTH)
                {
                    printf("read sessionkey: ");
                    for(uint32_t i=0; i<SESSION_KEY_LENGTH; ++i)
                    {
                        printf("%02X ", SESSIONKEY[i]);
                    }
                    printf("\n\n");
                    fclose(fp);
                    return;
                }
            }
        }
    }
    fclose(fp);
}

const char* addrToStr(int addr)
{
    static char buffer[3+1+3+1+3+1+3];
    sprintf(buffer, "%d.%d.%d.%d", 0xFF&(addr>>3*8), 0xFF&(addr>>2*8), 0xFF&(addr>>8), 0xFF&(addr));
    return buffer;
}

void addTimeInfo(struct time_information_array *info_array, uint32_t seq, uint64_t epoch_micro_secs)
{
    for(int32_t i=info_array->entries-1; i>=0; --i)
    {
        if(info_array->info[i].sequence < seq)
        {
            if(i == info_array->entries-1)
            {
                // append to end of list
                break;
            }
            info_array->entries++;
            info_array->info = realloc(info_array->info, info_array->entries*sizeof(struct time_information));

            memmove(&info_array->info[i+2],
                    &info_array->info[i+1],
                    sizeof(struct time_information)*(info_array->entries-(i+1)-1));
            info_array->info[i+1].sequence = seq;
            info_array->info[i+1].epoch_micro = epoch_micro_secs;
            return;
        }
        else if(info_array->info[i].sequence == seq)
        {
            info_array->info[i].epoch_micro = epoch_micro_secs;
            return;
        }
    }
    info_array->entries++;
    // append to end
    info_array->info = realloc(info_array->info, info_array->entries*sizeof(struct time_information));
    info_array->info[info_array->entries-1].sequence = seq;
    info_array->info[info_array->entries-1].epoch_micro = epoch_micro_secs;
}

void addPayload(struct growing_array *array, uint32_t arrayIndex, uint8_t *payload, uint16_t payload_size)
{
    if(array->buffersize < arrayIndex+payload_size)
    {
        array->buffersize = arrayIndex+payload_size;
        array->buffer = realloc(array->buffer, array->buffersize);
    }
    memcpy(array->buffer+arrayIndex, payload, payload_size);
}

void registerTcpPayload(struct tcp_participant *participant, uint64_t epoch_micro_secs, uint16_t payload_size, uint8_t *payload, uint32_t seq)
{
    uint32_t arrayIndex = seq-(participant->start_seq+1);
    addTimeInfo(&participant->timeinfo, arrayIndex, epoch_micro_secs);
    addPayload(&participant->data, arrayIndex, payload, payload_size);
}

static struct tcp_connection **connections = NULL;
static uint32_t connection_count = 0;
void removeConnection(struct tcp_connection *connection)
{
    // remove pointer from connections
    uint8_t foundConnection = 0;
    for(uint32_t i=0; i<connection_count; ++i)
    {
        if(connections[i] == connection)
        {
            foundConnection = 1;
            memmove(&connections[i], &connections[i+1], sizeof(struct tcp_connection*)*(connection_count-i-1));
            connection_count--;
            connections = realloc(connections, sizeof(struct tcp_connection*)*connection_count);
            free(connection);
            break;
        }
    }
    if(!foundConnection)
    {
        printf("removeConnection: connection could not be found\n");
        exit(1);
    }
}

void handleTcpPacket(uint32_t from, uint32_t to, uint16_t tcp_len, struct sniff_tcp_t *tcppacket, uint64_t epoch_micro_secs)
{
    struct tcp_connection *connection = NULL;
    for(uint32_t i=0; i< connection_count; ++i)
    {
        if((connections[i]->from.address == from && connections[i]->to.address == to &&
                    connections[i]->from.port == tcppacket->th_sport && connections[i]->to.port == tcppacket->th_dport)
            ||
            (connections[i]->from.address == to && connections[i]->to.address == from &&
             connections[i]->from.port == tcppacket->th_dport && connections[i]->to.port == tcppacket->th_sport))
        {
            connection = connections[i];
            break;
        }
    }
    // not found, create new?
    if(connection == NULL)
    {
        if(tcppacket->th_flags == TH_SYN)
        {
            connection = malloc(sizeof(struct tcp_connection));
            connection_count++;
            connections = realloc(connections, sizeof(struct tcp_connection*)*connection_count);
            connections[connection_count-1] = connection;

            connection->from.address = from;
            connection->to.address = to;
            connection->from.port= tcppacket->th_sport;
            connection->to.port= tcppacket->th_dport;
            connection->from.start_seq = ntohl(tcppacket->th_seq);
            printf("start_seq = %u\n", connection->from.start_seq);

            connection->state = SYNED;

            connection->forwarded = 0;

            connection->from.data.buffer= NULL;
            connection->from.data.buffersize= 0;
            connection->to.data.buffer= NULL;
            connection->to.data.buffersize= 0;

            connection->from.timeinfo.info = NULL;
            connection->from.timeinfo.entries= 0;
            connection->to.timeinfo.info = NULL;
            connection->to.timeinfo.entries= 0;

            printf("New connection, now tracking %u\n", connection_count);
        }
        else
        {
            printf("got non-initial tcppacket and couldn't find any associated connection - ignored\n");
        }
        return;
    }
    switch(connection->state)
    {
        case SYNED:
            if(connection->to.address == from && tcppacket->th_flags == (TH_SYN|TH_ACK) &&
                    ntohl(tcppacket->th_ack) == connection->from.start_seq+1)
            {
                printf("connection changed state: SYNACKED\n");
                connection->state = SYNACKED;
                connection->to.start_seq = ntohl(tcppacket->th_seq);
                return;
            }
            break;
        case SYNACKED:
            if(connection->to.address == to && tcppacket->th_flags == (TH_ACK) &&
                    ntohl(tcppacket->th_ack)==connection->to.start_seq+1)
            {
                printf("connection changed state: ESTABLISHED\n");
                connection->state = ESTABLISHED;
                return;
            }
            break;
        case ESTABLISHED:
        case ACTIVE:
        {
            uint8_t tcp_header_size = TH_OFF(tcppacket)*4;
            uint8_t *payload = (uint8_t*)tcppacket;
            payload += tcp_header_size;
            uint32_t payload_size = tcp_len - tcp_header_size;
            if(connection->state != ACTIVE)
            {
                // check if we got the wow magic bytes
                if(payload_size >= sizeof(MAGIC_WOW_START) && memcmp(payload, MAGIC_WOW_START, sizeof(MAGIC_WOW_START))==0)
                {
                    connection->state = ACTIVE;
                    printf("connection changed state: ACTIVE\n");
                }
                else
                {
                    removeConnection(connection);
                    return;
                }
            }
            if(DEBUG)
                printf("    payload_size : %u\n", payload_size);
            if(payload_size)
            {
                struct tcp_participant *participant;
                if(from == connection->from.address && tcppacket->th_sport == connection->from.port)
                    participant = &connection->from;
                else
                    participant = &connection->to;
                registerTcpPayload(participant, epoch_micro_secs, payload_size, payload, ntohl(tcppacket->th_seq));
            }
            break;
        }
    }
}

void parsePcapFile(const char* filename)
{
    FILE *fd = fopen(filename, "rb");
    if(!fd)
    {
        printf("Couldn't open pcap file %s\n", filename);
        exit(1);
    }
    struct pcap_hdr_t *header = readPcapHeader(fd);
    if(!header)
        exit(1);

    if(header->network != DLT_EN10MB && header->network != WTAP_ENCAP_SCCP)
    {
        printf("network link layer %u is not supported, currently only ethernet and SCCP are implemented\n", header->network);
        exit(1);
    }

    struct pcaprec_hdr_t packet;
    uint8_t *data;
    while(readNextPacket(fd, &packet, &data))
    {
        uint32_t ip_data_offset = 0;
        switch(header->network)
        {
            case DLT_EN10MB:
            {
                struct sniff_ethernet_t *etherframe = (struct sniff_ethernet_t*)data;
                if(etherframe->ether_type == ETHER_TYPE_IP)
                {
                    ip_data_offset = sizeof(struct sniff_ethernet_t);
                }
                else
                {
                    printf("Skipping non-ip ethernet payload\n");
                    free(data);
                    continue;
                }
            }
            break;
            // no additional handling required, ip header is next
            case WTAP_ENCAP_SCCP:
            break;
        }

        struct sniff_ip_t *ipframe = (struct sniff_ip_t*)(data+ip_data_offset);
        if(IP_V(ipframe)!=4)
        {
            printf("skipped ip v%u frame\n", IP_V(ipframe));
        }
        else
        {
            if(DEBUG)
            {
                printf("ip packet len=%u from %s", ntohs(ipframe->ip_len), addrToStr(ntohl(ipframe->ip_src.s_addr)));
                printf(" to %s\n", addrToStr(ntohl(ipframe->ip_dst.s_addr)));
            }
            uint32_t size_ip = IP_HL(ipframe)*4;
            if(size_ip<20)
            {
                printf("size_ip is %u, <20\n", size_ip);
            }
            else if(ipframe->ip_p != TRANSPORT_TYPE_TCP)
            {
                printf("skipping non-tcp frame\n");
            }
            else
            {
                struct sniff_tcp_t *tcppacket = (struct sniff_tcp_t*)(data+ip_data_offset+size_ip);
                if(DEBUG)
                {
                    printf("    th_sport: %u\n", ntohs(tcppacket->th_sport));
                    printf("    th_dport: %u\n", ntohs(tcppacket->th_dport));
                }
                uint64_t micro_epoch = packet.ts_sec;
                micro_epoch *= 1000000;
                micro_epoch += packet.ts_usec;
                handleTcpPacket(ntohl(ipframe->ip_src.s_addr), ntohl(ipframe->ip_dst.s_addr), ntohs(ipframe->ip_len)-size_ip, tcppacket, micro_epoch);
            }
        }
        free(data);
    }
    free(header);
}

void dumpConnections()
{
    printf("Finished parsing file, filtered %u connection%s\n", connection_count, connection_count==1?"":"s");
    for(uint32_t i=0; i<connection_count; ++i)
    {
        struct tcp_connection *connection = connections[i];
        printf("Connection %u:\n", i);
        printf("  From: %s:%u\n", addrToStr(connection->from.address), ntohs(connection->from.port));
        printf("      Data sent: %u bytes\n", connection->from.data.buffersize);
        printf("  To: %s:%u\n", addrToStr(connection->to.address), ntohs(connection->to.port));
        printf("      Data sent: %u bytes\n", connection->to.data.buffersize);
    }
}

void removeInvalidConnections()
{
    printf("Removing invalid connections\n");
    for(uint32_t i=0; i<connection_count; ++i)
    {
        struct tcp_connection *connection = connections[i];
        if(connection->state != ACTIVE)
        {
            removeConnection(connection);
            i=0;
        }
    }
}

struct tcp_connection *currentDecryptedConnection;

static BIGNUM *my_BN_bin2bn(const uint8_t *s, int len, BIGNUM *ret)
{
    uint8_t tmp[1024] = {0};
    for (int i = 0; i < len; i++)
        tmp[i] = s[len-1-i];
    return BN_bin2bn(tmp, len, ret);
}

static int my_BN_bn2bin(const BIGNUM *a, unsigned char *to)
{
    uint8_t tmp[1024] = {0};
    int len = BN_bn2bin(a, tmp);
    for (int i = 0; i < len; i++)
        to[i] = tmp[len-1-i];
    return len;
}

static int parse_SMSG_REDIRECT_CLIENT(const uint8_t *in, uint8_t *out)
{
    uint8_t b_e[] = { 0x01, 0x00, 0x01, 0x00 }; // private-key exp
    uint8_t b_m[] = { // modulus
        0x91, 0xD5, 0x9B, 0xB7, 0xD4, 0xE1, 0x83, 0xA5, 0x22, 0x2B, 0x5F, 0x38, 0xF4, 0xB8, 0x86, 0xFF,
        0x32, 0x84, 0x38, 0x2D, 0x99, 0x38, 0x8F, 0xBA, 0xF3, 0xC9, 0x22, 0x5D, 0x51, 0x73, 0x1E, 0x28,
        0x87, 0x24, 0x8F, 0xB5, 0xC9, 0xB0, 0x7C, 0x95, 0xD0, 0x6B, 0x5B, 0xF4, 0x94, 0xC5, 0x94, 0x9D,
        0xFA, 0x6F, 0x47, 0x3A, 0xA3, 0x86, 0xC0, 0xA8, 0x37, 0xF3, 0x9B, 0xEF, 0x2F, 0xC1, 0xFB, 0xB3,
        0xF4, 0x1C, 0x2B, 0x0E, 0xD3, 0x6D, 0x88, 0xBB, 0x02, 0xE0, 0x4E, 0x63, 0xFA, 0x76, 0xE3, 0x43,
        0xF9, 0x01, 0xFD, 0x23, 0x5E, 0x6A, 0x0B, 0x14, 0xEC, 0x5E, 0x91, 0x34, 0x0D, 0x0B, 0x4F, 0xA3,
        0x5A, 0x46, 0xC5, 0x5E, 0xDC, 0xB5, 0xCD, 0xC1, 0x47, 0x6B, 0x59, 0xCA, 0xFA, 0xA9, 0xBE, 0x24,
        0x9F, 0xF5, 0x05, 0x6B, 0xBB, 0x67, 0x8B, 0xB7, 0xE4, 0x3A, 0x43, 0x00, 0x5C, 0x1C, 0xB7, 0xCA,
        0x98, 0x90, 0x79, 0x77, 0x6D, 0x05, 0x4F, 0x83, 0xCC, 0xAC, 0x06, 0x2E, 0x50, 0x11, 0x87, 0x23,
        0xD8, 0xA6, 0xF7, 0x6F, 0x7A, 0x59, 0x87, 0xA6, 0xDE, 0x5D, 0xD8, 0xEC, 0x44, 0xBE, 0x45, 0x31,
        0x7F, 0x8A, 0xF0, 0x58, 0x89, 0x53, 0x74, 0xDF, 0xCC, 0xAD, 0x01, 0x24, 0xD8, 0x19, 0x65, 0x1C,
        0x25, 0xD3, 0xE1, 0x6B, 0x8B, 0xDA, 0xFE, 0x1D, 0xA4, 0x2C, 0x8B, 0x25, 0xED, 0x7C, 0xFF, 0x6A,
        0xE0, 0x63, 0xD0, 0x52, 0x20, 0x7E, 0x62, 0x49, 0xD2, 0xB3, 0x6B, 0xCC, 0x91, 0x69, 0xA5, 0x08,
        0x8B, 0x69, 0x65, 0xFF, 0xB9, 0xC9, 0x17, 0x02, 0x5D, 0xD8, 0x8E, 0x1A, 0x63, 0xD9, 0x2A, 0x7F,
        0xDB, 0xE3, 0xF8, 0x76, 0x6D, 0xEA, 0x0E, 0x36, 0x98, 0x78, 0x19, 0xC5, 0x87, 0xBA, 0x6C, 0x20,
        0xB6, 0x08, 0x44, 0x04, 0x4C, 0xA8, 0xD5, 0xB6, 0x9D, 0x4D, 0x00, 0x20, 0x40, 0x00, 0x90, 0x04
    };

    // decrypt data (RSA-decrypt)
    BIGNUM r, a, e, m;
    BN_init(&r);
    BN_init(&a);
    BN_init(&e);
    BN_init(&m);
    my_BN_bin2bn(in, 256, &a);
    my_BN_bin2bn(b_e, 4, &e);
    my_BN_bin2bn(b_m, 256, &m);
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_exp(&r, &a, &e, &m, ctx); //FIXME: use RSA-decrypt
    BN_CTX_free(ctx);

    uint8_t d_out[256] = {0};
    int len = my_BN_bn2bin(&r, d_out);
    if (len < 0)
        return len;

    // make data ordered
    uint8_t *p = d_out;
    memcpy(out+89, p, 1); p++;
    memcpy(out+94, p, 1); p++;
    memcpy(out+151, p, 1); p++;
    memcpy(out+159, p, 1); p++;
    memcpy(out+155, p, 1); p++;
    memcpy(out+118, p, 1); p++;
    memcpy(out+46, p, 2); p+=2;
    memcpy(out+129, p, 1); p++;
    memcpy(out+127, p, 1); p++;
    memcpy(out+44, p, 2); p+=2;
    memcpy(out+32, p, 2); p+=2;
    memcpy(out+157, p, 1); p++;
    memcpy(out+164, p, 1); p++;
    memcpy(out+134, p, 1); p++;
    memcpy(out+124, p, 1); p++;
    memcpy(out+83, p, 1); p++;
    memcpy(out+122, p, 1); p++;
    memcpy(out+96, p, 1); p++;
    memcpy(out+71, p, 1); p++;
    memcpy(out+50, p, 2); p+=2;
    memcpy(out+17, p, 1); p++;
    memcpy(out+4, p, 1); p++;
    memcpy(out+132, p, 1); p++;
    memcpy(out+112, p, 1); p++;
    memcpy(out+156, p, 1); p++;
    memcpy(out+220, p, 4); p+=4;
    memcpy(out+59, p, 1); p++;
    memcpy(out+72, p, 1); p++;
    memcpy(out+130, p, 1); p++;
    memcpy(out+182, p, 1); p++;
    memcpy(out+154, p, 1); p++;
    memcpy(out+138, p, 1); p++;
    memcpy(out+61, p, 1); p++;
    memcpy(out+166, p, 1); p++;
    memcpy(out+139, p, 1); p++;
    memcpy(out+186, p, 1); p++;
    memcpy(out+10, p, 1); p++;
    memcpy(out+137, p, 1); p++;
    memcpy(out+68, p, 1); p++;
    memcpy(out+36, p, 2); p+=2;
    memcpy(out+115, p, 1); p++;
    memcpy(out+87, p, 1); p++;
    memcpy(out+175, p, 1); p++;
    memcpy(out+172, p, 1); p++;
    memcpy(out+252, p, 4); p+=4;
    memcpy(out+16, p, 1); p++;
    memcpy(out+88, p, 1); p++;
    memcpy(out+248, p, 4); p+=4;
    memcpy(out+180, p, 1); p++;
    memcpy(out+18, p, 1); p++;
    memcpy(out+78, p, 1); p++;
    memcpy(out+11, p, 1); p++;
    memcpy(out+24, p, 2); p+=2;
    memcpy(out+162, p, 1); p++;
    memcpy(out+204, p, 4); p+=4;
    memcpy(out+54, p, 2); p+=2;
    memcpy(out+125, p, 1); p++;
    memcpy(out+98, p, 1); p++;
    memcpy(out+102, p, 1); p++;
    memcpy(out+114, p, 1); p++;
    memcpy(out+216, p, 4); p+=4;
    memcpy(out+20, p, 1); p++;
    memcpy(out+136, p, 1); p++;
    memcpy(out+116, p, 1); p++;
    memcpy(out+185, p, 1); p++;
    memcpy(out+224, p, 4); p+=4;
    memcpy(out+146, p, 1); p++;
    memcpy(out+109, p, 1); p++;
    memcpy(out+106, p, 1); p++;
    memcpy(out+244, p, 4); p+=4;
    memcpy(out+135, p, 1); p++;
    memcpy(out+62, p, 1); p++;
    memcpy(out+60, p, 1); p++;
    memcpy(out+84, p, 1); p++;
    memcpy(out+91, p, 1); p++;
    memcpy(out+48, p, 2); p+=2;
    memcpy(out+144, p, 1); p++;
    memcpy(out+108, p, 1); p++;
    memcpy(out+63, p, 1); p++;
    memcpy(out+121, p, 1); p++;
    memcpy(out+145, p, 1); p++;
    memcpy(out+19, p, 1); p++;
    memcpy(out+13, p, 1); p++;
    memcpy(out+12, p, 1); p++;
    memcpy(out+52, p, 2); p+=2;
    memcpy(out+6, p, 1); p++;
    memcpy(out+74, p, 1); p++;
    memcpy(out+176, p, 1); p++;
    memcpy(out+69, p, 1); p++;
    memcpy(out+5, p, 1); p++;
    memcpy(out+99, p, 1); p++;
    memcpy(out+97, p, 1); p++;
    memcpy(out+14, p, 1); p++;
    memcpy(out+140, p, 1); p++;
    memcpy(out+177, p, 1); p++;
    memcpy(out+149, p, 1); p++;
    memcpy(out+101, p, 1); p++;
    memcpy(out+107, p, 1); p++;
    memcpy(out+228, p, 4); p+=4;
    memcpy(out+82, p, 1); p++;
    memcpy(out+184, p, 1); p++;
    memcpy(out+119, p, 1); p++;
    memcpy(out+158, p, 1); p++;
    memcpy(out+143, p, 1); p++;
    memcpy(out+196, p, 4); p+=4;
    memcpy(out+86, p, 1); p++;
    memcpy(out+38, p, 2); p+=2;
    memcpy(out+142, p, 1); p++;
    memcpy(out+240, p, 4); p+=4;
    memcpy(out+104, p, 1); p++;
    memcpy(out+77, p, 1); p++;
    memcpy(out+168, p, 1); p++;
    memcpy(out+150, p, 1); p++;
    memcpy(out+9, p, 1); p++;
    memcpy(out+22, p, 1); p++;
    memcpy(out+7, p, 1); p++;
    memcpy(out+95, p, 1); p++;
    memcpy(out+110, p, 1); p++;
    memcpy(out+34, p, 2); p+=2;
    memcpy(out+161, p, 1); p++;
    memcpy(out+117, p, 1); p++;
    memcpy(out+141, p, 1); p++;
    memcpy(out+111, p, 1); p++;
    memcpy(out+212, p, 4); p+=4;
    memcpy(out+179, p, 1); p++;
    memcpy(out+200, p, 4); p+=4;
    memcpy(out+147, p, 1); p++;
    memcpy(out+66, p, 1); p++;
    memcpy(out+70, p, 1); p++;
    memcpy(out+67, p, 1); p++;
    memcpy(out+100, p, 1); p++;
    memcpy(out+128, p, 1); p++;
    memcpy(out+133, p, 1); p++;
    memcpy(out+28, p, 2); p+=2;
    memcpy(out+15, p, 1); p++;
    memcpy(out+188, p, 4); p+=4;
    memcpy(out, p, 4); p+=4;
    memcpy(out+165, p, 1); p++;
    memcpy(out+169, p, 1); p++;
    memcpy(out+76, p, 1); p++;
    memcpy(out+65, p, 1); p++;
    memcpy(out+163, p, 1); p++;
    memcpy(out+85, p, 1); p++;
    memcpy(out+148, p, 1); p++;
    memcpy(out+23, p, 1); p++;
    memcpy(out+208, p, 4); p+=4;
    memcpy(out+183, p, 1); p++;
    memcpy(out+56, p, 2); p+=2;
    memcpy(out+73, p, 1); p++;
    memcpy(out+21, p, 1); p++;
    memcpy(out+120, p, 1); p++;
    memcpy(out+152, p, 1); p++;
    memcpy(out+113, p, 1); p++;
    memcpy(out+232, p, 4); p+=4;
    memcpy(out+170, p, 1); p++;
    memcpy(out+64, p, 1); p++;
    memcpy(out+81, p, 1); p++;
    memcpy(out+80, p, 1); p++;
    memcpy(out+123, p, 1); p++;
    memcpy(out+8, p, 1); p++;
    memcpy(out+79, p, 1); p++;
    memcpy(out+26, p, 2); p+=2;
    memcpy(out+236, p, 4); p+=4;
    memcpy(out+92, p, 1); p++;
    memcpy(out+30, p, 2); p+=2;
    memcpy(out+42, p, 2); p+=2;
    memcpy(out+174, p, 1); p++;
    memcpy(out+131, p, 1); p++;
    memcpy(out+75, p, 1); p++;
    memcpy(out+93, p, 1); p++;
    memcpy(out+40, p, 2); p+=2;
    memcpy(out+167, p, 1); p++;
    memcpy(out+171, p, 1); p++;
    memcpy(out+173, p, 1); p++;
    memcpy(out+160, p, 1); p++;
    memcpy(out+105, p, 1); p++;
    memcpy(out+178, p, 1); p++;
    memcpy(out+103, p, 1); p++;
    memcpy(out+192, p, 4); p+=4;
    memcpy(out+58, p, 1); p++;
    memcpy(out+90, p, 1); p++;
    memcpy(out+126, p, 1); p++;
    memcpy(out+181, p, 1); p++;
    memcpy(out+153, p, 1); p++;

    // verify data
    if (*(uint32_t*)out != 0x77177AB3)
        return -1;

    return len;
}

void decryptCallback(uint8_t s2c, uint64_t time, uint16_t opcode, uint8_t *data, uint32_t data_len, void *db)
{
    insertPacket(s2c, time, opcode, data, data_len, db);

    if(!s2c)
        return;

    // some packets need some extra treatment

    switch(opcode)
    {
        // forwarding connection
        case 0x8400: //SMSG_REDIRECT_CLIENT //1293:
        {
            const uint32_t expected_size = 4+256+1; //4+2+4+20;
            if(data_len != expected_size)
            {
                printf("WARNING: packet 1293 is %u bytes long, but we expected %u\n", data_len, expected_size);
                return;
            }
            uint8_t ordered_data[256] = {0};
            if (parse_SMSG_REDIRECT_CLIENT(data+4, ordered_data) < 0)
            {
                printf("WARNING: decrypt/parse packet SMSG_REDIRECT_CLIENT fail\n");
                break;
            }
            //uint32_t fwd_addr = *(data)<<24 | *(data+1)<<16 | *(data+2) << 8 | *(data+3);
            //uint16_t fwd_port = ntohs(*((uint16_t*)(data+4)));
            uint32_t fwd_addr = ntohl(*((uint32_t*)(ordered_data+252)));
            uint16_t fwd_port = ntohs(*((uint16_t*)(ordered_data+24)));
            // find the connection
            for(uint32_t i=0; i<connection_count; ++i)
            {
                struct tcp_connection *connection = connections[i];
                if(connection->to.address == fwd_addr &&
                    connection->to.port == fwd_port)
                {
                    printf("Set connection forwarding bit on %s:%u\n", addrToStr(fwd_addr), ntohs(fwd_port));
                    connection->forwarded = 1;
                    currentDecryptedConnection->forwarded = 2;
                    return;
                }
            }
            printf("WARNING: couldn't find referenced forward connection to %s:%u\n", addrToStr(fwd_addr), ntohs(fwd_port));
            break;
        }
    }
}

void decrypt()
{
    sqlite3 *db=NULL;
    for(uint32_t i=0; i<connection_count; ++i)
    {
        struct tcp_connection *connection = connections[i];
        currentDecryptedConnection = connection;
        if(connection->to.timeinfo.entries <1)
        {
            continue;
        }
        char format[50];
        sprintf(format, "%%Y_%%m_%%d__%%H_%%M_%%S_%02i.sqlite", i);
        char filename[sizeof(format)];
        time_t time = connection->to.timeinfo.info[0].epoch_micro/1000000;
        struct tm* timestruct = localtime(&time);
        strftime (filename, sizeof(filename), format, timestruct);

        if(!merge_files || (merge_files && !connection->forwarded))
            initDatabase(filename, &db);

        struct decryption_state client_state, server_state;
        uint8_t custom_serverseed[16];
        uint8_t custom_clientseed[16];

        if(connection->forwarded)
        {
            const uint32_t expected_size = 2+4+1+2*16;//2+2*4+2*16;
            uint8_t* data = connection->to.data.buffer;
            uint32_t size = data[0]<<8 | data[1];
            uint32_t opcode = data[3]<<8 | data[2];
            if(opcode != 0x8500) //SMSG_AUTH_CHALLENGE //492)
            {
                printf("WARNING: first packet in stream is not 492 but %u\n", opcode);
                continue;
            }
            if(size != expected_size)
            {
                printf("WARNING: packet 492 is %u bytes long, but we expected %u\n", size, expected_size);
                continue;
            }
            //memcpy(custom_serverseed, data+4+2*4, 16);
            //memcpy(custom_clientseed, data+4+2*4+16, 16);
            memcpy(custom_serverseed+0*4, data+4+1*4, 4);
            memcpy(custom_serverseed+1*4, data+4+4*4+1, 4);
            memcpy(custom_serverseed+2*4, data+4+3*4+1, 4);
            memcpy(custom_serverseed+3*4, data+4+7*4+1, 4);
            memcpy(custom_clientseed+0*4, data+4+5*4+1, 4);
            memcpy(custom_clientseed+1*4, data+4+6*4+1, 4);
            memcpy(custom_clientseed+2*4, data+4+0*4, 4);
            memcpy(custom_clientseed+3*4, data+4+8*4+1, 4);
            printf("Using custom seeds for forwarded connection\n");

            init_decryption_state_server(&server_state, SESSIONKEY, custom_serverseed);
            init_decryption_state_client(&client_state, SESSIONKEY, custom_clientseed);

            connection->forwarded = 0;
        }
        else
        {
            init_decryption_state_server(&server_state, SESSIONKEY, NULL);
            init_decryption_state_client(&client_state, SESSIONKEY, NULL);
        }


        uint32_t client_ti_counter=0, server_ti_counter=0;
        while(client_ti_counter < connection->from.timeinfo.entries ||
                server_ti_counter < connection->to.timeinfo.entries)
        {
            uint64_t nextServerPacketTime, nextClientPacketTime;
            nextServerPacketTime = server_ti_counter < connection->to.timeinfo.entries?connection->to.timeinfo.info[server_ti_counter].epoch_micro:UINT64_MAX;
            nextClientPacketTime = client_ti_counter < connection->from.timeinfo.entries?connection->from.timeinfo.info[client_ti_counter].epoch_micro:UINT64_MAX;

            struct decryption_state *nextState;
            uint32_t ti_counter;
            struct tcp_participant *participant;
            if(nextServerPacketTime < nextClientPacketTime)
            {
                nextState = &server_state;
                ti_counter = server_ti_counter++;
                participant = &connection->to;
            }
            else
            {
                nextState = &client_state;
                ti_counter = client_ti_counter++;
                participant = &connection->from;
            }
            uint8_t *data = &participant->data.buffer[participant->timeinfo.info[ti_counter].sequence];
            uint32_t datalen;
            if(ti_counter < participant->timeinfo.entries-1)
            {
                datalen = participant->timeinfo.info[ti_counter+1].sequence - participant->timeinfo.info[ti_counter].sequence;
            }
            else
            {
                datalen = participant->data.buffersize - participant->timeinfo.info[ti_counter].sequence;
            }
            update_decryption(nextState, participant->timeinfo.info[ti_counter].epoch_micro, data, datalen, db, decryptCallback);
        }
        if(!merge_files || (merge_files && !connection->forwarded))
            freeDatabase(&db);

        free_decryption_state(&server_state);
        free_decryption_state(&client_state);
        printf("Finished decrypting %u of %u connections\n", i+1, connection_count);
    }
}

int main(int argc, char *argv[])
{
    if(argc < 3)
    {
        printf("Usage: %s [-m] $dumpfile.cap $keyfile.txt\n", argv[0]);
        printf("                [-m] merge output files\n");
        return 1;
    }
    char* pcapFile = argv[1];
    char* keyFile = argv[2];
    if (!strcmp(argv[1], "-m"))
    {
        merge_files = 1;
        pcapFile = argv[2];
        keyFile = argv[3];
    }

    // maybe switched arguments?
    char* magicKeyfileEnd = "txt";
    if(strlen(keyFile) >= 3 && memcmp(keyFile+strlen(keyFile)-3, magicKeyfileEnd, 3))
    {
        char *temp = pcapFile;
        pcapFile = keyFile;
        keyFile = temp;
    }

    readSessionkeyFile(keyFile);
    parsePcapFile(pcapFile);
    removeInvalidConnections();
    dumpConnections();
    decrypt();
    return 0;
}

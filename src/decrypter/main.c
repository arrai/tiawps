#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "pcapreader.h"
#include "structs.h"
#include "decrypt.h"
#include "sqliteout.h"

#define DEBUG               0

const uint8_t MAGIC_WOW_START[] = {0x00, 0x1A, 0xEC, 0x01};

static uint8_t SESSIONKEY[SESSION_KEY_LENGTH];

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
    for(uint32_t i=0; i<info_array->entries; ++i)
    {
        if(info_array->info[i].sequence > seq)
        {
            info_array->entries++;
            info_array->info = realloc(info_array->info, info_array->entries*sizeof(struct time_information));

            memmove(info_array->info+(i+1)*sizeof(struct time_information),
                    info_array->info+i*sizeof(struct time_information),
                    sizeof(struct time_information)*(info_array->entries-i));
            info_array->info[i].sequence = seq;
            info_array->info[i].epoch_micro = epoch_micro_secs;
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
    for(uint8_t i=0; i< connection_count; ++i)
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
            if(connection->state != ACTIVE)
            {
                // check if we got the wow magic bytes
                if(memcmp(payload, MAGIC_WOW_START, sizeof(MAGIC_WOW_START))==0)
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
            uint32_t payload_size = tcp_len - tcp_header_size;
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
    FILE *fd = fopen(filename, "r");
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

void decrypt()
{
    for(uint32_t i=0; i<connection_count; ++i)
    {
        struct tcp_connection *connection = connections[i];
        if(connection->to.timeinfo.entries <1)
        {
            continue;
        }
        char filename[28];
        time_t time = connection->to.timeinfo.info[0].epoch_micro/1000000;
        struct tm* timestruct = localtime(&time);
        strftime (filename, sizeof(filename), "%Y_%m_%d__%H_%M_%S.sqlite", timestruct);

        initDatabase(filename);

        struct decryption_state client_state, server_state;
        init_decryption_state_server(&server_state, SESSIONKEY);
        init_decryption_state_client(&client_state, SESSIONKEY);

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
            update_decryption(nextState, participant->timeinfo.info[ti_counter].epoch_micro, data, datalen, insertPacket);
        }
        free_decryption_state(&server_state);
        free_decryption_state(&client_state);
    }
}

int main(int argc, char *argv[])
{
    if(argc != 3)
    {
        printf("Usage: %s $dumpfile.cap $keyfile.txt\n", argv[0]);
        return 1;
    }
    
    readSessionkeyFile(argv[2]);
    parsePcapFile(argv[1]);
    removeInvalidConnections();
    dumpConnections();
    decrypt();
    return 0;
}

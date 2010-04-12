#ifndef STRUCTS_H
#define STRUCTS_H

#include <stdint.h>


#define SESSION_KEY_LENGTH  40

enum tcp_state
{
    SYNED,          // SYN has been sent
    SYNACKED,       // SYN + SYN/ACK has been sent
    ESTABLISHED,    // SYN + SYN/ACK + ACK has been sent
    ACTIVE          // 3 way handshake completed + SMSG_AUTH_CHALLENGE
};

struct growing_array
{
    uint8_t *buffer;
    uint32_t buffersize;
};

struct time_information
{
    uint32_t sequence;
    uint64_t epoch_micro;
};

struct time_information_array
{
    struct time_information *info;
    uint32_t entries;
};

struct tcp_participant
{
    uint32_t address;
    uint16_t port;
    uint32_t start_seq;
    struct growing_array data;
    struct time_information_array timeinfo;
};

struct tcp_connection
{
    struct tcp_participant from, to;
    enum tcp_state state;
    uint8_t forwarded;
};

#endif

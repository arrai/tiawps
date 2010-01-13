#include <stdint.h>
#include <netinet/in.h> 

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
    uint32_t epoch_secs;
    uint32_t epoch_micro;
};

struct time_information_array
{
    struct time_information *info;
    uint32_t entries;
};

struct tcp_connection
{
    uint32_t from, to;
    uint16_t src_port, dst_port;
    uint32_t src_start_seq, dst_start_seq;
    enum tcp_state state;
    struct growing_array src_data, dst_data;
    struct time_information_array src_timeinfo, dst_timeinfo;
};


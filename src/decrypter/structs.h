#include <stdint.h>
#include <netinet/in.h> 

enum tcp_state
{
    SYNED,
    SYNACKED,
    ESTABLISHED,
    ACTIVE
};

struct tcp_connection
{
    uint32_t from, to;
    uint16_t src_port, dst_port;
    enum tcp_state state;
};


#include "tools.h"

const char* hexEncode(const uint8_t *data, const uint32_t data_len)
{
    static char* buffer = NULL;

    buffer=realloc(buffer, data_len*2+1);

    buffer[data_len*2] = '\0';
    for(uint32_t i=0; i<data_len; ++i)
    {
        uint8_t byte = data[i];
        buffer[i*2] = encodeNibble(byte>>4);
        buffer[i*2+1] = encodeNibble(0x0F&byte);
    }
    return buffer;
}


#include <stdlib.h>
#include <stdint.h>

void initDatabase(const char* filename);

void insertPacket(uint8_t s2c, uint64_t time, uint16_t opcode, uint8_t *data, uint32_t data_len);


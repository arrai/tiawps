#ifndef SQLITEOUT_H
#define SQLITEOUT_H

#include <stdlib.h>
#include <stdint.h>
#include <sqlite3.h>

void initDatabase(const char* filename, sqlite3 **db);
void freeDatabase(sqlite3 **db);

void insertPacket(uint8_t s2c, uint64_t time, uint16_t opcode, uint8_t *data, uint32_t data_len, void* db);

#endif

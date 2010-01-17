#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

char encodeNibble(uint8_t nibble);
const char* hexEncode(const uint8_t *data, const uint32_t data_len);

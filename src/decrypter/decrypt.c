#include <openssl/hmac.h>
#include <string.h>

#include "decrypt.h"
#include "structs.h"

const uint8_t serverSeed[] = { 0x22, 0xBE, 0xE5, 0xCF, 0xBB, 0x07, 0x64, 0xD9, 0x00, 0x45, 0x1B, 0xD0, 0x24, 0xB8, 0xD5, 0x45 };
const uint8_t clientSeed[] = { 0xF4, 0x66, 0x31, 0x59, 0xFC, 0x83, 0x6E, 0x31, 0x31, 0x02, 0x51, 0xD5, 0x44, 0x31, 0x67, 0x98 };

#define HMAC_RESULT_LEN     32

void init_decryption_state_server(struct decryption_state *this, uint8_t *sessionkey)
{
    this->s2c = 1;
    init_decryption_state(this, sessionkey, serverSeed);
}

void init_decryption_state_client(struct decryption_state *this, uint8_t *sessionkey)
{
    this->s2c = 0;
    init_decryption_state(this, sessionkey, clientSeed);
}

void init_decryption_state(struct decryption_state *this, uint8_t *sessionkey, const uint8_t *seed)
{
    this->buffer = NULL;
    this->bufferSize = 0;
    this->decryptedHeaderBytes = 0;
    this->firstPacket = 1;

    uint8_t rc4_key[HMAC_RESULT_LEN];
    uint32_t len = HMAC_RESULT_LEN;
    HMAC(EVP_sha1(), seed, sizeof(serverSeed), sessionkey, SESSION_KEY_LENGTH, rc4_key, &len);

    RC4_set_key(&this->key, len, rc4_key);

    // drop first 1024 bytes
    uint8_t trash;
    for(uint16_t i=0; i<1024; ++i)
    {
        RC4(&this->key, 1, &trash, &trash);
    }
}

void update_decryption(struct decryption_state *this, uint64_t time, uint8_t *data, uint32_t data_len,
        void(*callback)(uint8_t s2c, uint64_t time, uint16_t opcode, uint8_t *data, uint32_t data_len))
{
    if(data_len == 0)
        return;
    printf("data_len = %u\n", data_len);
    this->buffer = realloc(this->buffer, this->bufferSize+data_len);
    if(this->buffer == NULL)
    {
        printf("Failed to allocate %u bytes in update_decryption\n", data_len);
        exit(1);
    }
    memcpy(this->buffer+this->bufferSize, data, data_len);
    this->bufferSize += data_len;

    if(this->bufferSize < 4)
        return;

    if(this->firstPacket)
    {
        this->firstPacket = 0;
        this->decryptedHeaderBytes = 4;
    }

    if(this->decryptedHeaderBytes == 0)
        RC4(&this->key, 4, data, data);
    if(this->decryptedHeaderBytes == 4)
    {
        // large packet
        if(this->buffer[0]&0x80)
        {
            if(this->bufferSize < 5)
                return;
            RC4(&this->key, 1, data+4, data+4);
            this->decryptedHeaderBytes = 5;
        }
    }
    uint8_t i=0;
    uint16_t opcode = 0;
    uint32_t payloadLen = 0;

    if(this->decryptedHeaderBytes == 5)
        payloadLen = this->buffer[i++]&0x7F;
    payloadLen = (payloadLen<<8)|this->buffer[i++];
    payloadLen = (payloadLen<<8)|this->buffer[i++];
    opcode = this->buffer[i++];
    opcode = (this->buffer[i++]<<8) | opcode;

    if(this->bufferSize+2-this->decryptedHeaderBytes >= payloadLen)
    {
        callback(this->s2c, time, opcode, this->buffer+this->decryptedHeaderBytes, payloadLen-2);

        uint32_t remainingBufferSize = this->bufferSize-this->decryptedHeaderBytes-(payloadLen-2);
        memmove(this->buffer, this->buffer+this->decryptedHeaderBytes+(payloadLen-2), remainingBufferSize);
        this->buffer = realloc(this->buffer, remainingBufferSize);
        this->bufferSize = remainingBufferSize;
        this->decryptedHeaderBytes = 0;
    }
    printf("buffer size at leave: %u\n", this->bufferSize);
}


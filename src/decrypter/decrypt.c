#include <openssl/hmac.h>
#include <string.h>

#include "decrypt.h"
#include "structs.h"

#define SEED_KEY_SIZE       16
#define SHA_DIGEST_LENGTH   20

const uint8_t serverSeed[SEED_KEY_SIZE] = { 0x22, 0xBE, 0xE5, 0xCF, 0xBB, 0x07, 0x64, 0xD9, 0x00, 0x45, 0x1B, 0xD0, 0x24, 0xB8, 0xD5, 0x45 };
const uint8_t clientSeed[SEED_KEY_SIZE] = { 0xF4, 0x66, 0x31, 0x59, 0xFC, 0x83, 0x6E, 0x31, 0x31, 0x02, 0x51, 0xD5, 0x44, 0x31, 0x67, 0x98 };

void decryptData(int len, uint8_t *data, struct decryption_state *this)
{
    int outlen = 0;
    EVP_EncryptUpdate(&this->key, data, &outlen, data, len);
    EVP_EncryptFinal_ex(&this->key, data, &outlen);
}

void free_decryption_state(struct decryption_state *this)
{
    EVP_CIPHER_CTX_cleanup(&this->key);
    free(this->buffer);
}

void init_decryption_state(struct decryption_state *this, uint8_t *sessionkey, const uint8_t *seed)
{
    this->buffer = NULL;
    this->bufferSize = 0;
    this->decryptedHeaderBytes = 0;
    this->firstPacket = 1;

    uint8_t m_digest[SHA_DIGEST_LENGTH] = {0};
    {
        // constructor
        HMAC_CTX m_ctx;
        HMAC_CTX_init(&m_ctx);
        HMAC_Init_ex(&m_ctx, seed, SEED_KEY_SIZE, EVP_sha1(), NULL);

        // compute hash
        HMAC_Update(&m_ctx, sessionkey, SESSION_KEY_LENGTH);

        // finalize
        uint32_t length = 0;
        HMAC_Final(&m_ctx, m_digest, &length);
        if(length != SHA_DIGEST_LENGTH)
        {
            printf("%u = length != SHA_DIGEST_LENGTH = %u\n", length, SHA_DIGEST_LENGTH);
            exit(1);
        }
        HMAC_CTX_cleanup(&m_ctx);
    }

    printf("m_digest: ");
    for(int i=0; i<SHA_DIGEST_LENGTH; ++i)
        printf("%02X ", m_digest[i]);
    printf("\n");
    // constructor
    EVP_CIPHER_CTX_init(&this->key);
    EVP_EncryptInit_ex(&this->key, EVP_rc4(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_set_key_length(&this->key, SHA_DIGEST_LENGTH);

    // init
    EVP_EncryptInit_ex(&this->key, NULL, NULL, m_digest, NULL);

    // drop first 1024 bytes
    printf("\nsyncbuffer!\n");
    uint8_t trash;
    for(uint16_t i=0; i<1024; ++i)
    {
        trash = 0;
        decryptData(1, &trash, this);
        printf("%02X ", trash);
    }
    printf("\n");
}

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

void update_decryption(struct decryption_state *this, uint64_t time, uint8_t *data, uint32_t data_len,
        void(*callback)(uint8_t s2c, uint64_t time, uint16_t opcode, uint8_t *data, uint32_t data_len))
{
    if(data_len == 0)
        return;
    //printf("update_decryption data=0x%02X...0x%02X\n", data[0], data[data_len-1]);
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
    {
        decryptData(4, this->buffer, this);
        this->decryptedHeaderBytes = 4;
    }
    if(this->decryptedHeaderBytes == 4)
    {
        // large packet
        if(this->buffer[0]&0x80)
        {
            printf("Large packet detected\n");
            if(this->bufferSize < 5)
                return;
            decryptData(1, this->buffer+4, this);
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

    if(payloadLen <= 2)
    {
        printf("FATAL: got a packet with payloadLen=%u which is <= 2\n", payloadLen);
        exit(1);
    }

    opcode = this->buffer[i++];
    opcode = (this->buffer[i++]<<8) | opcode;

    printf("payload: %u, opcode: 0x%x\n", payloadLen-2, opcode);

    if(this->bufferSize+2-this->decryptedHeaderBytes >= payloadLen)
    {
        callback(this->s2c, time, opcode, this->buffer+this->decryptedHeaderBytes, payloadLen-2);

        uint32_t remainingBufferSize = this->bufferSize-this->decryptedHeaderBytes-(payloadLen-2);
        memmove(this->buffer, this->buffer+this->decryptedHeaderBytes+(payloadLen-2), remainingBufferSize);
        this->buffer = realloc(this->buffer, remainingBufferSize);
        this->bufferSize = remainingBufferSize;
        this->decryptedHeaderBytes = 0;
        printf("bufferSize at end: %u\n", this->bufferSize);
        if(this->bufferSize)
            printf("update_decryption at end: data=0x%02X...0x%02X\n", this->buffer[0], this->buffer[this->bufferSize-1]);
    }
}


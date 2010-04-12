#include <openssl/hmac.h>
#include <string.h>

#include "decrypt.h"
#include "structs.h"

#define SEED_KEY_SIZE       16
#define SHA_DIGEST_LENGTH   20

const uint8_t serverSeed[SEED_KEY_SIZE] = { 0xCC, 0x98, 0xAE, 0x04, 0xE8, 0x97, 0xEA, 0xCA, 0x12, 0xDD, 0xC0, 0x93, 0x42, 0x91, 0x53, 0x57 };
const uint8_t clientSeed[SEED_KEY_SIZE] = { 0xC2, 0xB3, 0x72, 0x3C, 0xC6, 0xAE, 0xD9, 0xB5, 0x34, 0x3C, 0x53, 0xEE, 0x2F, 0x43, 0x67, 0xCE };

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
    printf("seed: ");
    for(int i=0; i<SEED_KEY_SIZE; ++i)
        printf("%02X ", seed[i]);
    printf("\n");
    this->buffer = NULL;
    this->bufferSize = 0;
    this->decryptedHeaderBytes = 0;
    this->skipDecryptCount = 1;

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

    // constructor
    EVP_CIPHER_CTX_init(&this->key);
    EVP_EncryptInit_ex(&this->key, EVP_rc4(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_set_key_length(&this->key, SHA_DIGEST_LENGTH);

    // init
    EVP_EncryptInit_ex(&this->key, NULL, NULL, m_digest, NULL);

    // drop first 1024 bytes
    uint8_t trash;
    for(uint16_t i=0; i<1024; ++i)
    {
        decryptData(1, &trash, this);
    }
}

void init_decryption_state_server(struct decryption_state *this, uint8_t *sessionkey, uint8_t *customseed)
{
    this->s2c = 1;
    this->opcodeLen = 2;
    init_decryption_state(this, sessionkey, customseed?customseed:serverSeed);
}

void init_decryption_state_client(struct decryption_state *this, uint8_t *sessionkey, uint8_t *customseed)
{
    this->s2c = 0;
    this->opcodeLen = 4;
    init_decryption_state(this, sessionkey, customseed?customseed:clientSeed);
}

void update_decryption(struct decryption_state *this, uint64_t time, uint8_t *data, uint32_t data_len, void *db,
        void(*callback)(uint8_t s2c, uint64_t time, uint16_t opcode, uint8_t *data, uint32_t data_len, void *db))
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

    while(1)
    {
        if(this->bufferSize < this->opcodeLen+2)
            return;
        if(this->skipDecryptCount)
        {
            this->skipDecryptCount--;
            this->decryptedHeaderBytes = this->opcodeLen+2;
        }

        if(this->decryptedHeaderBytes == 0)
        {
            decryptData(this->opcodeLen+2, this->buffer, this);
            this->decryptedHeaderBytes = this->opcodeLen+2;
        }
        if(this->decryptedHeaderBytes == this->opcodeLen+2)
        {
            // large packet
            if(this->buffer[0]&0x80)
            {
                printf("Large packet detected\n");
                if(this->bufferSize < this->opcodeLen+3)
                    return;
                decryptData(1, this->buffer+this->opcodeLen+2, this);
                this->decryptedHeaderBytes = this->opcodeLen+3;
            }
        }
        uint8_t i=0;
        uint32_t opcode = 0;
        uint32_t payloadLen = 0;

        if(this->decryptedHeaderBytes == this->opcodeLen+3)
            payloadLen = this->buffer[i++]&0x7F;
        payloadLen = (payloadLen<<8)|this->buffer[i++];
        payloadLen = (payloadLen<<8)|this->buffer[i++];

        if(payloadLen < this->opcodeLen)
        {
            printf("FATAL: got a packet with payloadLen=%u which is < %u = opcodeLen\n", payloadLen, this->opcodeLen);
            exit(1);
        }

        for(uint8_t j=0; j< this->opcodeLen; j++)
        {
            opcode |= (this->buffer[i++]<<(8*j));
        }


        if(this->bufferSize+this->opcodeLen-this->decryptedHeaderBytes >= payloadLen)
        {
            callback(this->s2c, time, opcode, this->buffer+this->decryptedHeaderBytes, payloadLen-this->opcodeLen, db);

            uint32_t remainingBufferSize = this->bufferSize - this->decryptedHeaderBytes-(payloadLen-this->opcodeLen);
            memmove(this->buffer, this->buffer+this->decryptedHeaderBytes+(payloadLen-this->opcodeLen), remainingBufferSize);
            this->buffer = realloc(this->buffer, remainingBufferSize);
            this->bufferSize = remainingBufferSize;
            this->decryptedHeaderBytes = 0;
            if(0)
            {
                printf("bufferSize at end: %u\n", this->bufferSize);
                if(this->bufferSize)
                    printf("update_decryption at end: data=0x%02X...0x%02X\n", this->buffer[0], this->buffer[this->bufferSize-1]);
                else
                    printf("update_decryption at end is empty\n");
            }
        }
        else
            return;
    }
}


#include <stdint.h>
#include <openssl/evp.h>

struct decryption_state
{
    uint8_t *buffer;
    uint32_t bufferSize;

    uint8_t firstPacket;

    uint8_t decryptedHeaderBytes;
    uint8_t s2c;
    EVP_CIPHER_CTX key;
};

void init_decryption_state_server(struct decryption_state *state, uint8_t *sessionkey);
void init_decryption_state_client(struct decryption_state *state, uint8_t *sessionkey);
void free_decryption_state(struct decryption_state *);

void update_decryption(struct decryption_state *state, uint64_t time, uint8_t *data, uint32_t data_len, void *arg,
        void(*callback)(uint8_t s2c, uint64_t time, uint16_t opcode, uint8_t *data, uint32_t data_len, void *arg));


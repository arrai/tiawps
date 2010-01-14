#include <stdint.h>
#include <openssl/rc4.h>

struct decryption_state
{
    uint8_t *buffer;
    RC4_KEY key;
};

void init_decryption_state_server(struct decryption_state *state, uint8_t *sessionkey);
void init_decryption_state_client(struct decryption_state *state, uint8_t *sessionkey);
void init_decryption_state(struct decryption_state *state, uint8_t *sessionkey, const uint8_t *seed);

void update_decryption(struct decryption_state *state, uint64_t time, uint8_t *data, uint32_t data_len,
        void(*callback)(uint8_t s2c, uint64_t time, uint16_t opcode, uint8_t data, uint32_t data_len));


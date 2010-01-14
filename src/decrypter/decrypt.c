#include <openssl/hmac.h>

#include "decrypt.h"
#include "structs.h"

const uint8_t serverSeed[] = { 0x22, 0xBE, 0xE5, 0xCF, 0xBB, 0x07, 0x64, 0xD9, 0x00, 0x45, 0x1B, 0xD0, 0x24, 0xB8, 0xD5, 0x45 };
const uint8_t clientSeed[] = { 0xF4, 0x66, 0x31, 0x59, 0xFC, 0x83, 0x6E, 0x31, 0x31, 0x02, 0x51, 0xD5, 0x44, 0x31, 0x67, 0x98 };

#define HMAC_RESULT_LEN     32

void init_decryption_state_server(struct decryption_state *state, uint8_t *sessionkey)
{
    init_decryption_state(state, sessionkey, serverSeed);
}

void init_decryption_state_client(struct decryption_state *state, uint8_t *sessionkey)
{
    init_decryption_state(state, sessionkey, clientSeed);
}

void init_decryption_state(struct decryption_state *state, uint8_t *sessionkey, const uint8_t *seed)
{

    uint8_t rc4_key[HMAC_RESULT_LEN];
    uint32_t len = HMAC_RESULT_LEN;
    HMAC(EVP_sha1(), sessionkey, SESSION_KEY_LENGTH, seed, sizeof(serverSeed), rc4_key, &len);

    RC4_set_key(&state->key, len, rc4_key);

    // drop first 1024 bytes
    uint8_t trash;
    for(uint16_t i=0; i<1024; ++i)
    {
        RC4(&state->key, 1, &trash, &trash);
    }
}

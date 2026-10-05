#ifndef BELT_H
#define BELT_H

#include <cstdint>
#include "gfc.h"

class beltCipher {
public:
    beltCipher() = default;
    beltCipher(const beltCipher&) = default;
    beltCipher& operator=(const beltCipher&) = default;

    void set_key(const uint8_t key[32]);
    void encrypt_block(const uint8_t in[16], uint8_t out[16]) const;
    void decrypt_block(const uint8_t in[16], uint8_t out[16]) const;

private:
    static uint32_t rotHi(uint32_t x, unsigned int shift);
    static uint32_t load32_le(const uint8_t* p);
    static void     store32_le(uint8_t* p, uint32_t v);

    uint32_t H(uint32_t w) const;
    uint32_t G(uint32_t w, unsigned int shift) const;

    uint32_t K[8] = {0};
    gfc calc;
};

#endif // BELT_H
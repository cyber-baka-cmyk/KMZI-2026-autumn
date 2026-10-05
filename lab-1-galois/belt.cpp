#include "belt.h"

uint32_t beltCipher::rotHi (uint32_t x, unsigned int shift) {
    return (x << shift) | (x >> (32u - shift));
}

uint32_t beltCipher::load32_le (const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | 
    (static_cast<uint32_t>(p[1]) << 8)  |
    (static_cast<uint32_t>(p[2]) << 16) | 
    (static_cast<uint32_t>(p[3]) << 24);
}

void beltCipher::store32_le (uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v & 0xFF);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

uint32_t beltCipher::H (uint32_t w) const {
    uint8_t b0 = calc.sbox(static_cast<uint8_t>(w & 0xFF));
    uint8_t b1 = calc.sbox(static_cast<uint8_t>((w >> 8) & 0xFF));
    uint8_t b2 = calc.sbox(static_cast<uint8_t>((w >> 16) & 0xFF));
    uint8_t b3 = calc.sbox(static_cast<uint8_t>((w >> 24) & 0xFF));

    return static_cast<uint32_t>(b0) | 
    (static_cast<uint32_t>(b1) << 8)  |
    (static_cast<uint32_t>(b2) << 16) |
    (static_cast<uint32_t>(b3) << 24);
}

uint32_t beltCipher::G (uint32_t w, unsigned int shift) const {
    return rotHi(H(w), shift);
}

void beltCipher::set_key (const uint8_t key[32]) {
    for (int i = 0; i < 8; i++) {
        K[i] = load32_le(key + i * 4);
    }
}

void beltCipher::encrypt_block (const uint8_t in[16], uint8_t out[16]) const {
    uint32_t a = load32_le(in + 0);
    uint32_t b = load32_le(in + 4);
    uint32_t c = load32_le(in + 8);
    uint32_t d = load32_le(in + 12);

    for (int i = 1; i <= 8; i++) {
        const uint32_t k1 = K[(7 * i - 7) & 7];
        const uint32_t k2 = K[(7 * i - 6) & 7];
        const uint32_t k3 = K[(7 * i - 5) & 7];
        const uint32_t k4 = K[(7 * i - 4) & 7];
        const uint32_t k5 = K[(7 * i - 3) & 7];
        const uint32_t k6 = K[(7 * i - 2) & 7];
        const uint32_t k7 = K[(7 * i - 1) & 7];

        b ^= G(a + k1, 5);
        c ^= G(d + k2, 21);
        a -= G(b + k3, 13);

        const uint32_t e = G(b + c + k4, 21) ^ static_cast<uint32_t>(i);

        b += e;
        c -= e;

        d += G(c + k5, 13);
        b ^= G(a + k6, 21);
        c ^= G(d + k7, 5);

        uint32_t na = b;
        uint32_t nb = d;
        uint32_t nc = a;
        uint32_t nd = c;

        a = na;
        b = nb;
        c = nc;
        d = nd;
    }

    store32_le(out + 0, b);
    store32_le(out + 4, d);
    store32_le(out + 8, a);
    store32_le(out + 12, c);
}

void beltCipher::decrypt_block(const uint8_t in[16], uint8_t out[16]) const {
    uint32_t b = load32_le(in +  0);
    uint32_t d = load32_le(in +  4);
    uint32_t a = load32_le(in +  8);
    uint32_t c = load32_le(in + 12);

    for (int i = 8; i >= 1; i--) {
        const uint32_t k1 = K[(7 * i - 7) & 7];
        const uint32_t k2 = K[(7 * i - 6) & 7];
        const uint32_t k3 = K[(7 * i - 5) & 7];
        const uint32_t k4 = K[(7 * i - 4) & 7];
        const uint32_t k5 = K[(7 * i - 3) & 7];
        const uint32_t k6 = K[(7 * i - 2) & 7];
        const uint32_t k7 = K[(7 * i - 1) & 7];

        uint32_t na = c;
        uint32_t nb = a;
        uint32_t nc = d;
        uint32_t nd = b;
        a = na;
        b = nb;
        c = nc;
        d = nd;

        c ^= G(d + k7, 5);
        b ^= G(a + k6, 21);
        d -= G(c + k5, 13);

        const uint32_t e = G(b + c + k4, 21) ^ static_cast<uint32_t>(i);
        c += e;
        b -= e;

        a += G(b + k3, 13);
        c ^= G(d + k2, 21);
        b ^= G(a + k1, 5);
    }

    store32_le(out +  0, a);
    store32_le(out +  4, b);
    store32_le(out +  8, c);
    store32_le(out + 12, d);
}

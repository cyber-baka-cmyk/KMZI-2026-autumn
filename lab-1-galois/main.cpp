#include "gfc.h"
#include "belt.h"
#include "gcm.h"
#include <cstdio>
#include <cstring>
#include <array>
#include <vector>

static void hexdump(const char* label, const uint8_t* p, std::size_t n) {
    std::printf("%-20s", label);
    for (std::size_t i = 0; i < n; ++i) {
        std::printf("%02X", p[i]);
        if ((i + 1) % 16 == 0 && i + 1 < n) std::printf(" ");
    }
    std::printf("\n");
}

int main() {
    std::printf("============================================================\n");
    std::printf(" BelT (STB 34.101.31) + GCM AEAD\n");
    std::printf(" Field GF(2^8), p(x) = 0x11D\n");
    std::printf(" GHASH modulus  f(x) = x^128 + x^7 + x^2 + x + 1\n");
    std::printf(" Constant-time task: Karatsuba in GF(2^8)\n");
    std::printf("============================================================\n\n");

    {
        std::printf("[GF(2^8) calculator, p = 0x11D]\n");
        gfc calc;

        const uint8_t a = 0x57, b = 0x83;
        std::printf("  add(%02X, %02X) = %02X\n", a, b, calc.add(a, b));
        std::printf("  multiply(%02X, %02X) = %02X\n", a, b, calc.multiply(a, b, gfc::BELT_PX));
        std::printf("  karatsuba(%02X, %02X) = %02X (same result)\n",
                    a, b, calc.karatsuba(a, b, gfc::BELT_PX));
        std::printf("  inverse(0x00) = %02X  (0 without division by zero)\n",
                    calc.inverse(0x00, gfc::BELT_PX));
        const uint8_t inv57 = calc.inverse(0x57, gfc::BELT_PX);
        std::printf("  inverse(0x57) = %02X\n", inv57);
        std::printf("  0x57 * inverse(0x57) = %02X  (must be 01)\n",
                    calc.karatsuba(0x57, inv57, gfc::BELT_PX));
        std::printf("\n");
    }
    
    beltCipher cipher;
    static const uint8_t key[32] = {
        0xE9,0xDE,0xE7,0x2C, 0x8F,0x0C,0x0F,0xA6,
        0x2D,0xDB,0x49,0xF4, 0x6F,0x73,0x96,0x47,
        0x06,0x07,0x53,0x16, 0xED,0x24,0x7A,0x37,
        0x39,0xCB,0xA3,0x83, 0x03,0xA9,0x8B,0xF6
    };
    cipher.set_key(key);

    std::printf("[BelT single block]\n");
    hexdump("Key", key, 32);

    static const uint8_t pt_block[16] = {
        0xB1,0x94,0xBA,0xC8, 0x0A,0x08,0xF5,0x3B,
        0x36,0x6D,0x00,0x8E, 0x58,0x4A,0x5D,0xE4
    };
    uint8_t ct_block[16]   = {0};
    uint8_t back_block[16] = {0};

    cipher.encrypt_block(pt_block, ct_block);
    cipher.decrypt_block(ct_block, back_block);

    hexdump("Plaintext block", pt_block,   16);
    hexdump("Ciphertext block", ct_block,   16);
    hexdump("Decrypted block", back_block, 16);
    std::printf("Roundtrip: %s\n\n",
                std::memcmp(pt_block, back_block, 16) == 0 ? "OK" : "FAIL");

    std::printf("[GCM AEAD]\n");
    GCM gcm(cipher);

    const char* msg = "BelT-GCM: authenticated encryption demo.";
    std::vector<uint8_t> plaintext(msg, msg + std::strlen(msg));
    std::vector<uint8_t> aad = {0xDE,0xAD,0xBE,0xEF, 0x00,0x01,0x02,0x03};
    std::array<uint8_t, 12> nonce = {
        0xCA,0xFE,0xBA,0xBE, 0x00,0x11,0x22,0x33,
        0x44,0x55,0x66,0x77
    };

    hexdump("Nonce", nonce.data(),     nonce.size());
    hexdump("AAD", aad.data(),       aad.size());
    hexdump("Plaintext", plaintext.data(), plaintext.size());

    auto enc = gcm.encrypt(plaintext, aad, nonce);
    hexdump("Ciphertext", enc.first.data(), enc.first.size());
    hexdump("Tag (16 B)", enc.second.data(), 16);
    std::printf("\n");

    const bool tag_ok  = GCM::verify_tag(enc.second, enc.second);
    std::printf("verify_tag (correct)        : %s\n",
                tag_ok ? "VALID" : "INVALID");

    Block tampered = enc.second;
    tampered[15] ^= 0x01;
    const bool tag_bad = GCM::verify_tag(enc.second, tampered);
    std::printf("verify_tag (1-bit tampered) : %s\n", tag_bad ? "VALID (BUG!)" : "INVALID (expected)");
    std::printf("\n");

    auto dec = gcm.decrypt(enc.first, nonce);
    hexdump("Decrypted", dec.data(), dec.size());
    std::printf("GCM roundtrip: %s\n", dec == plaintext ? "OK" : "FAIL");

    return 0;
}
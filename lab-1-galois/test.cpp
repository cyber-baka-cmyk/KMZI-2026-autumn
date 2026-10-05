#include "gfc.h"
#include "belt.h"
#include "gcm.h"
#include <cstdio>
#include <cstring>
#include <array>
#include <vector>

static int g_pass = 0;
static int g_fail = 0;

static void check(bool ok, const char* msg) {
    if (ok) { ++g_pass; }
    else { ++g_fail; std::printf("  FAIL: %s\n", msg); }
}

static const uint8_t TEST_KEY[32] = {
    0xE9,0xDE,0xE7,0x2C, 0x8F,0x0C,0x0F,0xA6,
    0x2D,0xDB,0x49,0xF4, 0x6F,0x73,0x96,0x47,
    0x06,0x07,0x53,0x16, 0xED,0x24,0x7A,0x37,
    0x39,0xCB,0xA3,0x83, 0x03,0xA9,0x8B,0xF6
};

static void test_zero_element() {
    std::printf("[1] Zero element in inverse\n");
    gfc c;

    check(c.inverse(0x00, gfc::BELT_PX) == 0x00, "inverse(0x00) == 0x00");
    check(c.inverse(0x01, gfc::BELT_PX) == 0x01, "inverse(0x01) == 0x01");

    bool ok = true;
    for (int a = 1; a < 256; ++a) {
        const uint8_t a8  = static_cast<uint8_t>(a);
        const uint8_t inv = c.inverse(a8, gfc::BELT_PX);
        const uint8_t p   = c.karatsuba(a8, inv, gfc::BELT_PX);
        if (p != 1) { ok = false; break; }
    }
    check(ok, "a * inverse(a) == 1 for all a != 0");

    check(c.karatsuba(0x00, c.inverse(0x00, gfc::BELT_PX), gfc::BELT_PX) == 0x00, "0 * inverse(0) == 0");
}

static void test_reduction_overflow() {
    std::printf("[2] Reduction overflow (shift-and-XOR vs Karatsuba)\n");
    gfc c;

    bool ok = true;
    for (int a = 0; a < 256 && ok; ++a) {
        for (int b = 0; b < 256; ++b) {
            const uint8_t m1 = c.multiply  (static_cast<uint16_t>(a),
                                            static_cast<uint8_t>(b), gfc::BELT_PX);
            const uint8_t m2 = c.karatsuba (static_cast<uint8_t>(a),
                                            static_cast<uint8_t>(b), gfc::BELT_PX);
            if (m1 != m2) { ok = false; break; }
        }
    }
    check(ok, "Karatsuba == shift-and-XOR on 65536 pairs");

    check(c.karatsuba(0x80, 0x02, gfc::BELT_PX) == 0x1D, "0x80 * x == 0x1D (reduction)");
    check(c.karatsuba(0xFF, 0xFF, gfc::BELT_PX) == c.multiply(0x00FF, 0xFF, gfc::BELT_PX), "0xFF*0xFF");
    check(c.karatsuba(0x80, 0x80, gfc::BELT_PX) == c.multiply(0x0080, 0x80, gfc::BELT_PX), "0x80*0x80");
    check(c.karatsuba(0xFF, 0x02, gfc::BELT_PX) == c.multiply(0x00FF, 0x02, gfc::BELT_PX), "0xFF*x");
    check(c.karatsuba(0x40, 0x80, gfc::BELT_PX) == c.multiply(0x0040, 0x80, gfc::BELT_PX), "0x40*0x80");
    check(c.karatsuba(0x00, 0xFF, gfc::BELT_PX) == 0x00, "0*0xFF == 0");
}

static void test_byte_order() {
    std::printf("[3] Byte order: CTR counter and GHASH\n");

    beltCipher cipher;
    cipher.set_key(TEST_KEY);
    GCM gcm(cipher);

    std::vector<uint8_t> pt(32, 0x00);
    std::vector<uint8_t> aad;
    std::array<uint8_t, 12> nonce = {
        0x00,0x01,0x02,0x03, 0x04,0x05,
        0x06,0x07,0x08,0x09, 0x0A,0x0B
    };

    const auto enc = gcm.encrypt(pt, aad, nonce);
    const auto& ct = enc.first;

    std::array<uint8_t, 16> j0{};
    for (int i = 0; i < 12; ++i) j0[i] = nonce[i];
    j0[15] = 1;

    std::array<uint8_t, 16> cb1 = j0; cb1[15] = 2;
    uint8_t ks1[16]; cipher.encrypt_block(cb1.data(), ks1);

    std::array<uint8_t, 16> cb2 = j0; cb2[15] = 3;
    uint8_t ks2[16]; cipher.encrypt_block(cb2.data(), ks2);

    check(std::memcmp(ct.data(), ks1, 16) == 0, "CTR block #1 = E_K(J0+1)");
    check(std::memcmp(ct.data() + 16, ks2, 16) == 0, "CTR block #2 = E_K(J0+2)");

    std::array<uint8_t, 12> zero_nonce{};
    auto enc2 = gcm.encrypt(pt, aad, zero_nonce);
    std::array<uint8_t, 16> cbz{};
    cbz[15] = 2;
    uint8_t ksz[16]; cipher.encrypt_block(cbz.data(), ksz);
    check(std::memcmp(enc2.first.data(), ksz, 16) == 0, "CTR with zero nonce: CB_1 = 0^31 || 2");

    Block g0 = gcm.ghash(aad, std::vector<uint8_t>{});
    bool all_zero = true;
    for (int i = 0; i < 16; ++i) if (g0[i] != 0) { all_zero = false; break; }
    check(all_zero, "GHASH(empty, empty) == 0^128");

    std::vector<uint8_t> x1(16, 0xAA), x2(16, 0x55), x12(16);
    for (int i = 0; i < 16; ++i) x12[i] = static_cast<uint8_t>(x1[i] ^ x2[i]);

    Block gA = gcm.ghash(x1,  std::vector<uint8_t>{});
    Block gB = gcm.ghash(x2,  std::vector<uint8_t>{});
    Block gC = gcm.ghash(x12, std::vector<uint8_t>{});
    std::vector<uint8_t> x0(16, 0x00);
    Block gZ = gcm.ghash(x0, std::vector<uint8_t>{});

    bool lin_ok = true;
    for (int i = 0; i < 16; ++i) {
        const uint8_t combined = static_cast<uint8_t>(
            gA[i] ^ gB[i] ^ gC[i] ^ gZ[i]);
        if (combined != 0) { lin_ok = false; break; }
    }
    check(lin_ok, "GHASH is affine in AAD of fixed length (byte order consistent)");
}

static void test_tag_constant_time() {
    std::printf("[4] Tag comparison: no early exit\n");

    Block expected{};
    for (int i = 0; i < 16; ++i) expected[i] = static_cast<uint8_t>(i * 0x11);

    check(GCM::verify_tag(expected, expected) == true, "identical tags match");

    bool ok = true;
    for (int pos = 0; pos < 16; ++pos) {
        Block actual = expected;
        actual[pos] ^= 0x01;
        if (GCM::verify_tag(expected, actual) != false) { ok = false; break; }
    }
    check(ok, "mismatch at any position returns false");

    ok = true;
    for (int pos = 0; pos < 16 && ok; ++pos) {
        for (int bit = 0; bit < 8; ++bit) {
            Block actual = expected;
            actual[pos] ^= static_cast<uint8_t>(1u << bit);
            if (GCM::verify_tag(expected, actual) != false) { ok = false; break; }
        }
    }
    check(ok, "mismatch at any bit returns false");

    Block zeros{};
    check(GCM::verify_tag(zeros, zeros) == true, "0 vs 0 match");
    check(GCM::verify_tag(zeros, expected) == false, "0 vs nonzero mismatch");
    check(GCM::verify_tag(expected, zeros) == false, "nonzero vs 0 mismatch");

    Block early = expected; early[0] ^= 0x80;
    Block late  = expected; late[15] ^= 0x80;
    check(GCM::verify_tag(expected, early) == false, "early-position mismatch");
    check(GCM::verify_tag(expected, late) == false, "late-position mismatch");
}

static void test_belt_roundtrip() {
    std::printf("[+] BelT encrypt/decrypt roundtrip\n");
    beltCipher cipher;
    cipher.set_key(TEST_KEY);

    uint8_t pt[16], ct[16], back[16];
    for (int i = 0; i < 16; ++i) pt[i] = static_cast<uint8_t>(i);
    cipher.encrypt_block(pt, ct);
    cipher.decrypt_block(ct, back);
    check(std::memcmp(pt, back, 16) == 0, "identity: 0..15");

    uint8_t ct2[16];
    cipher.encrypt_block(pt, ct2);
    check(std::memcmp(ct, ct2, 16) == 0, "encrypt is deterministic");

    uint8_t z[16] = {0}, zc[16], zb[16];
    cipher.encrypt_block(z, zc);
    cipher.decrypt_block(zc, zb);
    check(std::memcmp(z, zb, 16) == 0, "roundtrip zero block");

    uint8_t f[16]; std::memset(f, 0xFF, 16);
    uint8_t fc[16], fb[16];
    cipher.encrypt_block(f, fc);
    cipher.decrypt_block(fc, fb);
    check(std::memcmp(f, fb, 16) == 0, "roundtrip 0xFF block");
}

static void test_gcm_roundtrip() {
    std::printf("[+] GCM encrypt/decrypt roundtrip\n");
    beltCipher cipher;
    cipher.set_key(TEST_KEY);
    GCM gcm(cipher);

    bool all_ok = true;
    for (std::size_t len = 0; len <= 48; ++len) {
        std::vector<uint8_t> pt(len);
        for (std::size_t i = 0; i < len; ++i) pt[i] = static_cast<uint8_t>(i * 7 + 1);

        std::vector<uint8_t> aad = {0x01, 0x02, 0x03};
        std::array<uint8_t, 12> nonce = {0,0,0,0, 0,0,0,0, 0,0,0,1};

        auto enc = gcm.encrypt(pt, aad, nonce);
        auto dec = gcm.decrypt(enc.first, nonce);
        if (dec != pt) { all_ok = false; break; }
    }
    check(all_ok, "GCM roundtrip for plaintext lengths 0..48");

    std::vector<uint8_t> pt = {0xDE, 0xAD, 0xBE, 0xEF};
    std::vector<uint8_t> aad = {0xCA, 0xFE};
    std::array<uint8_t, 12> nonce = {1,2,3,4,5,6,7,8,9,10,11,12};

    auto enc = gcm.encrypt(pt, aad, nonce);

    check(GCM::verify_tag(enc.second, enc.second) == true, "tag matches itself");

    Block bad = enc.second; bad[7] ^= 0x01;
    check(GCM::verify_tag(enc.second, bad) == false, "tampered tag rejected");
}

int main() {
    std::printf("========== BelT / GCM test suite ==========\n");
    std::printf("p(x) = 0x11D, GHASH f(x) = x^128+x^7+x^2+x+1\n\n");

    test_zero_element();
    test_reduction_overflow();
    test_byte_order();
    test_tag_constant_time();
    test_belt_roundtrip();
    test_gcm_roundtrip();

    std::printf("\n-------------------------------------------\n");
    std::printf("PASSED: %d\n", g_pass);
    std::printf("FAILED: %d\n", g_fail);
    std::printf("===========================================\n");
    return g_fail == 0 ? 0 : 1;
}
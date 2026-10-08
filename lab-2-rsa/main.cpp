#include "rsa_math.h"
#include "rsa_crt.h"
#include "oaep.h"
#include <cstdio>
#include <cstring>
#include <vector>
#include <chrono>

using namespace rsa_math;
using namespace rsa_crt;

static void int_to_bytes(const cpp_int& x, uint8_t* out, size_t n) {
    std::memset(out, 0, n);
    cpp_int t = x;
    for (size_t i = 0; i < n; ++i) {
        out[n - 1 - i] = (uint8_t)(t & 0xFF);
        t >>= 8;
    }
}
static cpp_int bytes_to_int(const uint8_t* in, size_t n) {
    cpp_int r = 0;
    for (size_t i = 0; i < n; ++i) r = (r << 8) | in[i];
    return r;
}

int main() {
    const int K_BITS = 4096;
    const size_t K_BYTES = K_BITS / 8;   // 512

    RNG rng;
    RSAKey key;
    std::printf("Generating %d-bit RSA key (variant 12: equal-length primes)...\n", K_BITS);
    generate_keypair(key, K_BITS, cpp_int(65537), rng);
    std::printf("N bits = %d\n", (int)boost::multiprecision::msb(key.N) + 1);

    const char* text = "Lab 2 variant 12: 4096-bit RSA-CRT + OAEP(Streebog-512)";
    size_t mlen = std::strlen(text);
    const size_t max_msg = K_BYTES - 2*oaep::HASH_LEN - 2;
    std::printf("Plaintext len = %zu, max = %zu\n", mlen, max_msg);
    uint8_t seed[oaep::HASH_LEN];
    for (size_t i = 0; i < oaep::HASH_LEN; ++i) seed[i] = (uint8_t)rng.next();

    uint8_t EM[512];
    int rc = oaep::oaep_encode((const uint8_t*)text, mlen, K_BYTES,
                               nullptr, 0, seed, EM);
    std::printf("oaep_encode rc = %d\n", rc);

    cpp_int m = bytes_to_int(EM, K_BYTES);
    cpp_int c;
    rsa_encrypt(m, key, c);

    uint8_t ct[512];
    int_to_bytes(c, ct, K_BYTES);

    cpp_int m2;
    rsa_decrypt_crt(c, key, m2);
    uint8_t EM2[512];
    int_to_bytes(m2, EM2, K_BYTES);

    uint8_t out[512];
    size_t outLen = 0;
    int drc = oaep::oaep_decode(EM2, K_BYTES, nullptr, 0, out, &outLen);
    std::printf("oaep_decode rc = %d, outLen = %zu\n", drc, outLen);
    if (drc == 0) {
        std::printf("Recovered: %.*s\n", (int)outLen, out);
    }

    {
        uint8_t em[512]; uint8_t s2[64];
        for (size_t i = 0; i < 64; ++i) s2[i] = (uint8_t)rng.next();
        int r = oaep::oaep_encode(nullptr, 0, K_BYTES, nullptr, 0, s2, em);
        std::printf("oaep_encode(empty) rc = %d\n", r);
        cpp_int mm = bytes_to_int(em, K_BYTES);
        cpp_int cc; rsa_encrypt(mm, key, cc);
        cpp_int dd; rsa_decrypt_crt(cc, key, dd);
        uint8_t em2[512]; int_to_bytes(dd, em2, K_BYTES);
        uint8_t buf[512]; size_t l = 0;
        int rr = oaep::oaep_decode(em2, K_BYTES, nullptr, 0, buf, &l);
        std::printf("empty: rc=%d len=%zu\n", rr, l);
    }

    {
        const size_t MAX_M = K_BYTES - 2*oaep::HASH_LEN - 2;
        uint8_t big[512];
        std::memset(big, 0xAB, MAX_M);

        uint8_t em[512];
        uint8_t s2[oaep::HASH_LEN];
        for (size_t i = 0; i < oaep::HASH_LEN; ++i) s2[i] = (uint8_t)rng.next();

        int r = oaep::oaep_encode(big, MAX_M, K_BYTES, nullptr, 0, s2, em);
        std::printf("oaep_encode(max) rc = %d\n", r);

        if (r == 0) {
            cpp_int mm = bytes_to_int(em, K_BYTES);
            cpp_int cc; rsa_encrypt(mm, key, cc);
            cpp_int dd; rsa_decrypt_crt(cc, key, dd);
            uint8_t em2[512]; int_to_bytes(dd, em2, K_BYTES);

            uint8_t buf[512]; size_t l = 0;
            int rr = oaep::oaep_decode(em2, K_BYTES, nullptr, 0, buf, &l);
            bool same = (l == MAX_M) && (std::memcmp(buf, big, l) == 0);
            std::printf("max: rc=%d len=%zu same=%d\n", rr, l, (int)same);
        } else {
            std::printf("max: encode failed, skipping roundtrip\n");
        }
    }

    {
        uint8_t bad[512];
        std::memcpy(bad, EM2, 512);
        bad[100] ^= 0x5A;
        uint8_t buf[512]; size_t l = 0;
        int rr = oaep::oaep_decode(bad, K_BYTES, nullptr, 0, buf, &l);
        std::printf("tampered: rc=%d len=%zu (constant-time path)\n", rr, l);
    }

        {
        uint8_t valid[512];
        std::memcpy(valid, EM2, 512);
        uint8_t bad[512];
        std::memcpy(bad, EM2, 512);
        bad[100] ^= 0x5A;
        bad[1]   ^= 0x01;

        auto bench = [&](const char* label, const uint8_t* em, int runs){
            uint8_t buf[512]; size_t l = 0;
            volatile int sink = 0;
            for (int i = 0; i < 50; ++i) sink ^= oaep::oaep_decode(em, K_BYTES, nullptr, 0, buf, &l);
            auto t0 = std::chrono::high_resolution_clock::now();
            for (int i = 0; i < runs; ++i)
                sink ^= oaep::oaep_decode(em, K_BYTES, nullptr, 0, buf, &l);
            auto t1 = std::chrono::high_resolution_clock::now();
            double ns = (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t1-t0).count() / runs;
            std::printf("%-10s : %10.0f ns/op  (sink=%d)\n", label, ns, (int)sink);
            return ns;
        };

        std::printf("--- constant-time benchmark (1000 runs each) ---\n");
        double nv = bench("valid",    valid, 1000);
        double nt = bench("tampered", bad,   1000);
        double diff = (nv > nt ? (nv-nt) : (nt-nv)) / nv * 100.0;
        std::printf("relative difference: %.2f%%\n", diff);
    }

    return 0;
}
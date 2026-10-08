#pragma once
#include <boost/multiprecision/cpp_int.hpp>
#include <cstdint>
#include <cstddef>
#include <random>
#include <stdexcept>

namespace rsa_math {

using boost::multiprecision::cpp_int;

inline void mod_pow_ladder(const cpp_int& base, const cpp_int& exp,
                           const cpp_int& mod, cpp_int& out) {
    cpp_int R0 = 1 % mod;
    cpp_int R1 = base % mod;
    if (exp == 0) { out = R0; return; }
    int bits = (int)boost::multiprecision::msb(exp) + 1;
    for (int i = bits - 1; i >= 0; --i) {
        int bit = (int)boost::multiprecision::bit_test(exp, i);
        cpp_int prod = (R0 * R1) % mod;
        cpp_int sq0  = (R0 * R0) % mod;
        cpp_int sq1  = (R1 * R1) % mod;
        cpp_int newR0 = sq0 + bit * (prod - sq0);
        cpp_int newR1 = prod + bit * (sq1 - prod);
        R0 = newR0;
        R1 = newR1;
    }
    out = R0;
}

inline cpp_int mod_pow(const cpp_int& base, const cpp_int& exp, const cpp_int& mod) {
    cpp_int result = 1;
    cpp_int b = base % mod;
    cpp_int e = exp;
    while (e > 0) {
        if ((e & 1) != 0) result = (result * b) % mod;
        b = (b * b) % mod;
        e >>= 1;
    }
    return result;
}

inline cpp_int ext_gcd(const cpp_int& a, const cpp_int& b, cpp_int& x, cpp_int& y) {
    if (b == 0) { x = 1; y = 0; return a; }
    cpp_int x1, y1;
    cpp_int g = ext_gcd(b, a % b, x1, y1);
    x = y1;
    y = x1 - (a / b) * y1;
    return g;
}

inline cpp_int mod_inverse(const cpp_int& a, const cpp_int& m) {
    cpp_int x, y;
    cpp_int g = ext_gcd(a, m, x, y);
    if (g != 1) throw std::runtime_error("mod_inverse: not coprime");
    return ((x % m) + m) % m;
}

inline cpp_int lcm(const cpp_int& a, const cpp_int& b) {
    cpp_int x, y;
    cpp_int g = ext_gcd(a, b, x, y);
    return (a / g) * b;
}

inline bool miller_rabin(const cpp_int& n, int rounds) {
    if (n < 2) return false;
    if (n == 2 || n == 3) return true;
    if ((n & 1) == 0) return false;

    cpp_int d = n - 1;
    int s = 0;
    while ((d & 1) == 0) { d >>= 1; ++s; }

    std::random_device rd;
    std::mt19937_64 gen(rd());

    for (int i = 0; i < rounds; ++i) {
        cpp_int a = 2 + (cpp_int(gen()) % (n - 3));
        cpp_int x = mod_pow(a, d, n);
        if (x == 1 || x == n - 1) continue;
        bool witness = true;
        for (int r = 1; r < s; ++r) {
            x = (x * x) % n;
            if (x == n - 1) { witness = false; break; }
        }
        if (witness) return false;
    }
    return true;
}

struct RNG {
    std::mt19937_64 gen;
    RNG() : gen(std::random_device{}()) {}
    uint64_t next() { return gen(); }
};

inline cpp_int random_bits(int bits, RNG& rng) {
    cpp_int r = 0;
    int words = (bits + 63) / 64;
    for (int i = 0; i < words; ++i) r = (r << 64) | rng.next();
    int excess = words * 64 - bits;
    if (excess > 0) r >>= excess;
    return r;
}

inline cpp_int generate_prime_equal_bits(int bits, RNG& rng) {
    for (;;) {
        cpp_int candidate = random_bits(bits, rng);
        candidate |= (cpp_int(1) << (bits - 1));
        candidate |= (cpp_int(1) << (bits - 2));
        candidate |= 1;                       // odd
        if (miller_rabin(candidate, 40)) return candidate;
    }
}

struct RSAKey {
    cpp_int N, e, d;
    cpp_int p, q, dp, dq, qinv;
    int bits = 0;
};

inline void generate_keypair(RSAKey& key, int bits, const cpp_int& e, RNG& rng) {
    int half = bits / 2;
    cpp_int p, q, N, lambda;
    for (;;) {
        p = generate_prime_equal_bits(half, rng);
        q = generate_prime_equal_bits(half, rng);
        if (p == q) continue;
        N = p * q;
        if ((int)boost::multiprecision::msb(N) + 1 != bits) continue;
        lambda = lcm(p - 1, q - 1);
        cpp_int x, y;
        if (ext_gcd(e, lambda, x, y) == 1) break;
    }
    key.N = N;
    key.e = e;
    key.p = p;
    key.q = q;
    key.bits = bits;
    key.d = mod_inverse(e, lambda);
    key.dp = key.d % (p - 1);
    key.dq = key.d % (q - 1);
    key.qinv = mod_inverse(q, p);
}

}
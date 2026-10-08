#pragma once
#include "rsa_math.h"

namespace rsa_crt {

using rsa_math::cpp_int;
using rsa_math::RSAKey;
using rsa_math::mod_pow;
using rsa_math::mod_pow_ladder;

inline void rsa_encrypt(const cpp_int& m, const RSAKey& key, cpp_int& c) {
    c = mod_pow(m, key.e, key.N);
}

inline void rsa_decrypt_crt(const cpp_int& c, const RSAKey& key, cpp_int& m) {
    cpp_int m1, m2;
    mod_pow_ladder(c, key.dp, key.p, m1);
    mod_pow_ladder(c, key.dq, key.q, m2);

    cpp_int diff = m1 - m2;
    diff = ((diff % key.p) + key.p) % key.p;
    cpp_int h = (key.qinv * diff) % key.p;

    m = m2 + h * key.q;
}

}
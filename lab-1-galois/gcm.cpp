#include "gcm.h"
#include <algorithm>

GCM::GCM(const beltCipher& cipher) : cipher_(cipher) {
    Block zero{};
    hash_subkey_ = encrypt_block(zero);   // H = E_K(0^128)
}

Block GCM::encrypt_block(const Block& in) const {
    Block out{};
    cipher_.encrypt_block(in.data(), out.data());
    return out;
}

std::pair<std::vector<std::uint8_t>, Block> GCM::encrypt(
    const std::vector<std::uint8_t>& plaintext,
    const std::vector<std::uint8_t>& aad,
    const std::array<std::uint8_t, 12>& nonce) const {

    Block j0{};
    for (unsigned i = 0; i < 12; ++i) j0[i] = nonce[i];
    j0[15] = 1;

    std::vector<std::uint8_t> ciphertext(plaintext.size());
    Block counter = j0;

    for (std::size_t offset = 0; offset < plaintext.size(); offset += 16) {
        increment(counter);
        const Block stream = encrypt_block(counter);
        const std::size_t count = std::min<std::size_t>(16, plaintext.size() - offset);
        for (std::size_t i = 0; i < count; ++i) {
            ciphertext[offset + i] = static_cast<std::uint8_t>(plaintext[offset + i] ^ stream[i]);
        }
    }

    const Block tag = xor_block(encrypt_block(j0), ghash(aad, ciphertext));
    return {ciphertext, tag};
}

std::vector<std::uint8_t> GCM::decrypt(
    const std::vector<std::uint8_t>& ciphertext,
    const std::array<std::uint8_t, 12>& nonce) const {

    Block counter{};
    for (unsigned i = 0; i < 12; ++i) counter[i] = nonce[i];
    counter[15] = 1;

    std::vector<std::uint8_t> plaintext(ciphertext.size());
    for (std::size_t offset = 0; offset < ciphertext.size(); offset += 16) {
        increment(counter);
        const Block stream = encrypt_block(counter);
        const std::size_t count = std::min<std::size_t>(16, ciphertext.size() - offset);
        for (std::size_t i = 0; i < count; ++i) {
            plaintext[offset + i] = static_cast<std::uint8_t>(ciphertext[offset + i] ^ stream[i]);
        }
    }
    return plaintext;
}

bool GCM::verify_tag(const Block& expected, const Block& actual) {
    std::uint8_t diff = 0;
    for (unsigned i = 0; i < 16; ++i) {
        diff |= static_cast<std::uint8_t>(expected[i] ^ actual[i]);
    }

    return static_cast<std::uint8_t>(((static_cast<std::uint32_t>(diff) - 1u) >> 8) & 0x01u) == 1u;
}

Block GCM::xor_block(const Block& a, const Block& b) {
    Block r{};
    for (unsigned i = 0; i < 16; ++i) r[i] = static_cast<std::uint8_t>(a[i] ^ b[i]);
    return r;
}

void GCM::increment(Block& counter) {
    std::uint32_t v = (static_cast<std::uint32_t>(counter[12]) << 24) |
                      (static_cast<std::uint32_t>(counter[13]) << 16) |
                      (static_cast<std::uint32_t>(counter[14]) <<  8) |
                       static_cast<std::uint32_t>(counter[15]);
    ++v;
    counter[12] = static_cast<std::uint8_t>(v >> 24);
    counter[13] = static_cast<std::uint8_t>(v >> 16);
    counter[14] = static_cast<std::uint8_t>(v >>  8);
    counter[15] = static_cast<std::uint8_t>(v);
}

Block GCM::load_block(const std::vector<std::uint8_t>& data, std::size_t offset) {
    Block b{};
    const std::size_t count = std::min<std::size_t>(16, data.size() - offset);
    for (std::size_t i = 0; i < count; ++i) b[i] = data[offset + i];
    return b;
}

Block GCM::multiply128(const Block& x, const Block& y) const {
    Block z{};
    Block v = y;
    for (unsigned bit = 0; bit < 128; ++bit) {
        const std::uint8_t x_bit =
            static_cast<std::uint8_t>((x[bit / 8] >> (7 - bit % 8)) & 1U);
        const std::uint8_t mask = static_cast<std::uint8_t>(0U - x_bit);  // 0x00/0xFF
        for (unsigned i = 0; i < 16; ++i)
            z[i] = static_cast<std::uint8_t>(z[i] ^ (v[i] & mask));

        const std::uint8_t lsb = static_cast<std::uint8_t>(v[15] & 1U);
        for (int i = 15; i > 0; --i)
            v[i] = static_cast<std::uint8_t>((v[i] >> 1) | (v[i - 1] << 7));
        v[0] = static_cast<std::uint8_t>(v[0] >> 1);

        const std::uint8_t red_mask = static_cast<std::uint8_t>(0U - lsb);
        v[0] = static_cast<std::uint8_t>(v[0] ^ (0xE1U & red_mask));
    }
    return z;
}

Block GCM::ghash(const std::vector<std::uint8_t>& aad,
                 const std::vector<std::uint8_t>& ciphertext) const {
    Block y{};
    auto absorb = [&](const std::vector<std::uint8_t>& data) {
        for (std::size_t offset = 0; offset < data.size(); offset += 16) {
            y = multiply128(xor_block(y, load_block(data, offset)), hash_subkey_);
        }
    };
    absorb(aad);
    absorb(ciphertext);

    Block lengths{};
    const std::uint64_t aad_bits = static_cast<std::uint64_t>(aad.size()) * 8;
    const std::uint64_t ct_bits  = static_cast<std::uint64_t>(ciphertext.size()) * 8;
    for (unsigned i = 0; i < 8; ++i) {
        lengths[7 - i]  = static_cast<std::uint8_t>(aad_bits >> (8 * i));
        lengths[15 - i] = static_cast<std::uint8_t>(ct_bits  >> (8 * i));
    }
    return multiply128(xor_block(y, lengths), hash_subkey_);
}
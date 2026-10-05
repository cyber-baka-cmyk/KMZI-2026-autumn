#ifndef GCM_H
#define GCM_H

#include <cstdint>
#include <vector>
#include <array>
#include <utility>
#include "belt.h"

using Block = std::array<std::uint8_t, 16>;

class GCM {
public:
    explicit GCM(const beltCipher& cipher);

    std::pair<std::vector<std::uint8_t>, Block> encrypt(
        const std::vector<std::uint8_t>& plaintext,
        const std::vector<std::uint8_t>& aad,
        const std::array<std::uint8_t, 12>& nonce) const;

    std::vector<std::uint8_t> decrypt(
        const std::vector<std::uint8_t>& ciphertext,
        const std::array<std::uint8_t, 12>& nonce) const;

    Block ghash(const std::vector<std::uint8_t>& aad,
                const std::vector<std::uint8_t>& ciphertext) const;

    static Block xor_block(const Block& a, const Block& b);
    static bool  verify_tag(const Block& expected, const Block& actual);

private:
    const beltCipher& cipher_;
    Block hash_subkey_;

    static void  increment(Block& counter);
    static Block load_block(const std::vector<std::uint8_t>& data, std::size_t offset);
    Block multiply128(const Block& x, const Block& y) const;
    Block encrypt_block(const Block& in) const;
};

#endif // GCM_H
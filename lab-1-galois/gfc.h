#ifndef GFC_H
#define GFC_H

#include <cstdint>

class gfc {
public:
    gfc() = default;
    static constexpr uint16_t BELT_PX = 0x11Du;
    static const uint8_t beltSbox[256];

    uint8_t add(uint8_t a, uint8_t b) const;
    uint8_t multiply(uint16_t a, uint8_t b, uint16_t p_x) const;
    uint8_t xtime(uint8_t a, uint16_t p_x) const;
    uint8_t inverse(uint8_t a, uint16_t p_x) const;
    uint8_t sbox(uint8_t x) const;
    uint8_t karatsuba(uint8_t a, uint8_t b, uint16_t p_x) const;

private:
    static uint8_t mul4(uint8_t a, uint8_t b);
};

#endif // GFC_H

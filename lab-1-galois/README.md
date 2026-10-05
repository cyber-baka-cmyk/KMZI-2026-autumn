<p align="center">Министерство образования Республики Беларусь</p>
<p align="center">Учреждение образования</p>
<p align="center">“Брестский Государственный технический университет”</p>
<p align="center">Кафедра ИИТ</p>
<br><br><br><br><br><br><br>
<p align="center">Лабораторная работа №1</p>
<p align="center">По дисциплине “Криптографические методы защиты информации”</p>
<p align="center">Тема: “Низкоуровневая арифметика полей Галуа и блочные шифры в режиме AEAD”</p>
<br><br><br><br><br>
<p align="right">Выполнил:</p>
<p align="right">Студент 3 курса</p>
<p align="right">Группы ИИ-27</p>
<p align="right">Юшкевич А.Ю.</p>
<p align="right">Проверила:</p>
<p align="right">Хацкевич А.С.</p>
<br><br><br><br><br>
<p align="center">Брест 2026</p>

**Цель работы:** автоматизация алгебраических вычислений путем создания универсального калькулятора конечных полей $\mathbb{GF}(2^8)$, реализация на его базе блочного шифра (AES / СТБ 34.101.31) в режиме аутентифицированного шифрования GCM и освоение техник программирования с постоянным временем исполнения (Constant-time).

# Ход работы
1. [Математическая часть](#1-математическая-часть)
2. [Архитектурная схема](#2-архитектурная-схема)
3. [Анализ безопасности (Constant-time)](#3-анализ-безопасности-constant-time)
4. [Результаты тестирования](#4-результаты-тестирования)

## 1. Математическая часть

### 1.1 Представление элементов поля $\mathbb{GF}(2^8)$

Элементы поля $\mathbb{GF}(2^8)$ — многочлены степени не выше 7 над полем $\mathbb{GF}(2)$:

$$
A(x) = a_7 x^7 + a_6 x^6 + a_5 x^5 + a_4 x^4 + a_3 x^3 + a_2 x^2 + a_1 x + a_0, \quad a_i \in \{0, 1\}
$$

Каждому элементу однозначно соответствует байт $(a_7 a_6 a_5 a_4 a_3 a_2 a_1 a_0)_2$.

**Неприводимый многочлен варианта:**

$$
p(x) = x^8 + x^4 + x^3 + x^2 + 1 = \text{0x11D}
$$

Младшие 8 бит (без старшего члена $x^8$):

$$
p_{\text{byte}} = \text{0x1D}
$$

---

## 1.2. Вывод операции сложения

Сложение двух элементов выполняется покоэффициентно над $\mathbb{GF}(2)$. Поскольку характеристика поля равна 2, справедливо $1 + 1 = 0$, то есть сложение коэффициентов совпадает с операцией XOR:

$$
C(x) = A(x) + B(x) = \sum_{i=0}^{7} (a_i \oplus b_i)\, x^i
$$

**Пример.** Пусть

$$
A = \text{0x57} = x^6 + x^4 + x^2 + x + 1, \qquad B = \text{0x83} = x^7 + x + 1.
$$

Тогда

$$
A \oplus B = \text{0x57} \oplus \text{0x83} = \text{0xD4}.
$$

**Вывод:** операция сложения реализуется побитовым XOR:

```cpp
uint8_t gfc::add(uint8_t a, uint8_t b) const {
    return static_cast<uint8_t>(a ^ b);
}
```

Обратный элемент по сложению совпадает с самим элементом:

$$
A \oplus A = 0.
$$

---

## 1.3. Вывод операции умножения (shift-and-XOR)

Умножение выполняется в два этапа.

### Этап 1. Полиномиальное умножение

Произведение двух многочленов степени ≤ 7 даёт многочлен степени ≤ 14:

$$
P(x) = A(x) \cdot B(x) = \sum_{i=0}^{14} c_i x^i, \qquad c_k = \bigoplus_{i+j=k} a_i b_j.
$$

### Этап 2. Редукция по модулю $p(x)$

Так как

$$
x^8 \equiv x^4 + x^3 + x^2 + 1 \pmod{p(x)},
$$

то для каждого $i \in \{8, \dots, 14\}$:

$$
x^i \equiv x^{i-8} \cdot (x^4 + x^3 + x^2 + 1) \pmod{p(x)}.
$$

Алгоритмически редукция реализуется как **shift-and-XOR**: если бит результата в позиции $i \geq 8$ равен 1, выполняется

$$
R \leftarrow R \oplus \bigl(p_{\text{byte}} \ll (i - 8)\bigr).
$$

**Реализация:**

```cpp
uint8_t gfc::multiply(uint16_t a, uint8_t b, uint16_t p_x) const {
    uint16_t result = 0;
    for (unsigned i = 0; i < 8; ++i) {
        const uint16_t bit  = static_cast<uint16_t>(b & 1u);
        const uint16_t mask = static_cast<uint16_t>(0u - bit);
        result ^= static_cast<uint16_t>(a & mask);
        b >>= 1;
        a <<= 1;
    }
    for (int i = 15; i >= 8; --i) {
        const uint16_t bit  = static_cast<uint16_t>((result >> i) & 1u);
        const uint16_t mask = static_cast<uint16_t>(0u - bit);
        result ^= static_cast<uint16_t>(p_x << (i - 8)) & mask;
    }
    return static_cast<uint8_t>(result);
}
```

### Умножение на $x$ (функция `xtime`)

$$
\text{xtime}(b) =
\begin{cases}
b \ll 1, & b_7 = 0 \\
(b \ll 1) \oplus \text{0x1D}, & b_7 = 1
\end{cases}
$$

В Constant-time форме — через маску $m = -(b_7 \wedge 1) \in \{\text{0x00}, \text{0xFF}\}$:

$$
\text{xtime}(b) = (b \ll 1) \oplus (m \wedge \text{0x1D})
$$

---

## 1.4. Умножение через алгоритм Карацубы (задача варианта)

Полиномы представляются в виде двух половин степени 3:

$$
A(x) = A_1 x^4 + A_0, \qquad B(x) = B_1 x^4 + B_0,
$$

где

$$
A_0 = a \wedge \text{0x0F}, \qquad A_1 = (a \gg 4) \wedge \text{0x0F}
$$

(аналогично для $B$).

### Вывод

Прямое перемножение требует 4 умножения 4×4:

$$
A \cdot B = A_1 B_1\, x^8 + (A_0 B_1 + A_1 B_0)\, x^4 + A_0 B_0.
$$

Замечая, что

$$
A_0 B_1 + A_1 B_0 = (A_0 + A_1)(B_0 + B_1) + A_0 B_0 + A_1 B_1
$$

(в характеристике 2 знаки совпадают с XOR), получаем **три** умножения:

$$
P_0 = A_0 B_0, \qquad P_1 = (A_0 \oplus A_1)(B_0 \oplus B_1), \qquad P_2 = A_1 B_1.
$$

Сборка результата:

$$
P(x) = P_2\, x^8 \oplus (P_0 \oplus P_1 \oplus P_2)\, x^4 \oplus P_0.
$$

**Реализация:**

```cpp
uint8_t gfc::mul4(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    for (unsigned i = 0; i < 4; ++i) {
        const uint8_t bit  = static_cast<uint8_t>(b & 1u);
        const uint8_t mask = static_cast<uint8_t>(0u - bit);
        r ^= static_cast<uint8_t>(a & mask);
        b >>= 1;
        a <<= 1;
    }
    return r;
}

uint8_t gfc::karatsuba(uint8_t a, uint8_t b, uint16_t p_x) const {
    const uint8_t a0 = static_cast<uint8_t>(a & 0x0Fu);
    const uint8_t a1 = static_cast<uint8_t>((a >> 4) & 0x0Fu);
    const uint8_t b0 = static_cast<uint8_t>(b & 0x0Fu);
    const uint8_t b1 = static_cast<uint8_t>((b >> 4) & 0x0Fu);

    const uint8_t P0 = mul4(a0, b0);
    const uint8_t P1 = mul4(static_cast<uint8_t>(a0 ^ a1),
                            static_cast<uint8_t>(b0 ^ b1));
    const uint8_t P2 = mul4(a1, b1);

    uint16_t r = static_cast<uint16_t>(P0)
               ^ (static_cast<uint16_t>(P0 ^ P1 ^ P2) << 4)
               ^ (static_cast<uint16_t>(P2) << 8);

    for (int i = 15; i >= 8; --i) {
        const uint16_t bit  = static_cast<uint16_t>((r >> i) & 1u);
        const uint16_t mask = static_cast<uint16_t>(0u - bit);
        r ^= static_cast<uint16_t>(p_x << (i - 8)) & mask;
    }
    return static_cast<uint8_t>(r);
}
```

**Сложность:** 3 умножения 4×4 вместо 4 — экономия ≈ 25 % операций умножения.

---

## 1.5. Вывод операции нахождения обратного элемента

Для любого ненулевого $A \in \mathbb{GF}(2^8)$ существует единственный $A^{-1}$, для которого

$$
A \cdot A^{-1} \equiv 1 \pmod{p(x)}.
$$

### Через малую теорему Ферма

Мультипликативная группа $\mathbb{GF}(2^8)^{\ast}$ имеет порядок $2^8 - 1 = 255$, поэтому $A^{255} = 1$ и

$$
A^{-1} = A^{254} \pmod{p(x)}.
$$

**Цепочка квадратов (7 умножений) и перемножений (6 умножений):**

$$
a^2, \quad a^4 = (a^2)^2, \quad a^8 = (a^4)^2, \quad a^{16}, \quad a^{32}, \quad a^{64}, \quad a^{128}
$$

$$
a^{254} = a^{128} \cdot a^{64} \cdot a^{32} \cdot a^{16} \cdot a^8 \cdot a^4 \cdot a^2.
$$

**Реализация (через Карацубу):**

```cpp
uint8_t gfc::inverse(uint8_t a, uint16_t p_x) const {
    uint8_t result = 1;
    uint8_t base   = a;
    for (int i = 0; i < 8; ++i) {
        const uint8_t bit  = static_cast<uint8_t>((254u >> i) & 1u);
        const uint8_t mask = static_cast<uint8_t>(0u - bit);
        const uint8_t mul  = static_cast<uint8_t>((base & mask) | (1u & ~mask));
        result = karatsuba(result, mul, p_x);
        base   = karatsuba(base,   base, p_x);
    }
    return result;
}
```

**Частный случай $a = 0$.** Явной проверки `if (a == 0)` нет. Все умножения с нулём дают $0$, поэтому возвращается `0x00`, что соответствует определению (нулевой элемент не имеет обратного, но по соглашению возвращается он же). Деления на ноль не возникает, Constant-time сохраняется.

---

## 1.6. Арифметика GHASH в $\mathbb{GF}(2^{128})$

**Полином:**

$$
f(x) = x^{128} + x^7 + x^2 + x + 1
$$

**Редукционная константа:** `0xE1`.

Умножение $X \cdot Y$ реализуется за 128 итераций сдвига с маскированием:

```cpp
Block GCM::multiply128(const Block& x, const Block& y) const {
    Block z{};
    Block v = y;
    for (unsigned bit = 0; bit < 128; ++bit) {
        const std::uint8_t x_bit =
            static_cast<std::uint8_t>((x[bit / 8] >> (7 - bit % 8)) & 1U);
        const std::uint8_t mask = static_cast<std::uint8_t>(0U - x_bit);
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
```

**Свойства:**

- цикл `bit` — ровно 128 итераций;
- циклы копирования и сдвига — ровно 16 итераций каждый;
- отсутствуют условные переходы, зависящие от данных;
- редукция выполняется через маску $\text{red\_mask} = \text{0U} - \text{lsb}$.

---

## Вывод по разделу 1

Математически обоснованы и программно реализованы:

| Операция | Формула | Реализация |
|---|---|---|
| Сложение | $A \oplus B$ | `gfc::add` |
| Умножение (эталон) | $A \cdot B \bmod p(x)$ (shift-and-XOR) | `gfc::multiply` |
| Умножение (Карацуба) | $P_2 x^8 \oplus (P_0 \oplus P_1 \oplus P_2) x^4 \oplus P_0$ | `gfc::karatsuba` |
| Умножение на $x$ | $\text{xtime}(b)$ | `gfc::xtime` |
| Обратный элемент | $A^{-1} = A^{254}$ | `gfc::inverse` |
| Умножение в $\mathbb{GF}(2^{128})$ | $X \cdot Y \bmod f(x)$ | `GCM::multiply128` |

Все операции для $p(x) = \text{0x11D}$ реализованы через **алгоритм Карацубы** (задача варианта) и полностью **Constant-time** — без условных ветвлений и без обращений к памяти по секретным индексам.

## 2. Архитектурная схема

### 2.1. Логическое взаимодействие трёх модулей

```
┌───────────────────────────────────────────────────────────┐
│  Модуль 1. Калькулятор Галуа (gfc.h / gfc.cpp)            │
│                                                           │
│  • add(a, b)                                              │
│  • multiply(a, b, p_x)      — эталонный shift-and-XOR     │
│  • karatsuba(a, b, p_x)     — задача варианта             │
│  • mul4(a, b)               — базовая операция Карацубы   │
│  • xtime(a, p_x)            — умножение на x (Constant-time) │
│  • inverse(a, p_x)          — через a^254                 │
│  • sbox(b)                  — Constant-time доступ к LUT │
│  • beltSbox[256]            — стандартный H-блок БелТ     │
│                                                           │
│  p(x) = 0x11D = x^8 + x^4 + x^3 + x^2 + 1                 │
└──────────────────────┬────────────────────────────────────┘
                       │ sbox()
                       ▼
┌───────────────────────────────────────────────────────────┐
│  Модуль 2. Блочный шифр БелТ (belt.h / belt.cpp)          │
│                                                           │
│  • set_key(key[32])                                       │
│  • encrypt_block(in[16], out[16])                         │
│  • decrypt_block(in[16], out[16])                         │
│  • H(w)   — побайтовая подстановка через calc.sbox()      │
│  • G(w, shift) = ROTL(H(w), shift)                        │
│  • K[8]   — 8 подключей по 32 бита (little-endian)        │
│                                                           │
│  Блок: 128 бит, ключ: 256 бит, 8 раундов                  │
└──────────────────────┬────────────────────────────────────┘
                       │ encrypt_block()
                       ▼
┌───────────────────────────────────────────────────────────┐
│  Модуль 3. AEAD-режим GCM (gcm.h / gcm.cpp)               │
│                                                           │
│  • GCM(cipher)       — H = E_K(0^128)                     │
│  • encrypt(pt, aad, nonce) → ct, tag                      │
│  • decrypt(ct, nonce)      → pt                           │
│  • ghash(aad, ct)          — функция GHASH                │
│  • multiply128(x, y)       — GF(2^128)                    │
│  • verify_tag(a, b)        — Constant-time сравнение      │
│  • xor_block, increment, load_block                       │
│                                                           │
│  f(x) = x^128 + x^7 + x^2 + x + 1                          │
└──────────────────────┬────────────────────────────────────┘
                       ▼
        ┌──────────────────────────────────┐
        │  Шифротекст CT + Тег Tag (16 б)  │
        └──────────────────────────────────┘
```

## 2.2. Раундовые преобразования БелТ

Блок шифрования представляется как четыре 32-битных слова $(a, b, c, d)$. Ключ $K[8]$ циклически перебирается в порядке $7i - 7, \dots, 7i - 1 \pmod 8$.

**Структура одного раунда (всего 8 раундов):**

```text
для i = 1..8:
    k1 = K[(7i − 7) mod 8]
    k2 = K[(7i − 6) mod 8]
    k3 = K[(7i − 5) mod 8]
    k4 = K[(7i − 4) mod 8]
    k5 = K[(7i − 3) mod 8]
    k6 = K[(7i − 2) mod 8]
    k7 = K[(7i − 1) mod 8]

    b ← b ⊕ G(a + k1, 5)
    c ← c ⊕ G(d + k2, 21)
    a ← a ⊖ G(b + k3, 13)

    e ← G(b + c + k4, 21) ⊕ i

    b ← b ⊕ e
    c ← c ⊕ e

    d ← d ⊕ G(c + k5, 13)
    b ← b ⊕ G(a + k6, 21)
    c ← c ⊕ G(d + k7, 5)

    (a, b, c, d) ← (b, d, a, c)      — циклическая перестановка
```

Все операции $+$, $-$ — по модулю $2^{32}$.

**Раундовая функция:**

$$
G(w, \text{shift}) = \text{ROTL}\bigl(H(w), \text{shift}\bigr)
$$

где $H(w)$ — побайтовая подстановка через стандартный H-блок СТБ 34.101.31:

```cpp
uint32_t beltCipher::H(uint32_t w) const {
    uint8_t b0 = calc.sbox(static_cast<uint8_t>( w        & 0xFF));
    uint8_t b1 = calc.sbox(static_cast<uint8_t>((w >>  8) & 0xFF));
    uint8_t b2 = calc.sbox(static_cast<uint8_t>((w >> 16) & 0xFF));
    uint8_t b3 = calc.sbox(static_cast<uint8_t>((w >> 24) & 0xFF));
    return static_cast<uint32_t>(b0)
         | (static_cast<uint32_t>(b1) <<  8)
         | (static_cast<uint32_t>(b2) << 16)
         | (static_cast<uint32_t>(b3) << 24);
}

uint32_t beltCipher::G(uint32_t w, unsigned int shift) const {
    return rotHi(H(w), shift);
}
```

Значения сдвигов $5$, $13$, $21$ — жёстко зафиксированные константы стандарта. Вращение:

$$
\text{rotHi}(x, s) = (x \ll s) \;|\; (x \gg (32 - s))
$$

---

## 2.3. Расширение ключа БелТ

В отличие от AES, в БелТ **отсутствует процедура Key Schedule**: 256-битный ключ просто разбивается на 8 32-битных подключей в little-endian:

```cpp
void beltCipher::set_key(const uint8_t key[32]) {
    for (int i = 0; i < 8; i++) {
        K[i] = load32_le(key + i * 4);
    }
}
```

где `load32_le` собирает 32-битное слово из 4 байт в порядке младший → старший:

```cpp
uint32_t beltCipher::load32_le(const uint8_t* p) {
    return  static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) <<  8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}
```

**Стандартный ключ СТБ 34.101.31-2020 (Приложение А):**

```text
K = E9DEE72C 8F0C0FA6 2DDB49F4 6F739647
    06075316 ED247A37 39CBA383 03A98BF6
```

**Разбиение на подключи:**

| Подключ | Значение |
|---|---|
| $K_0$ | `2CE7DEE9` |
| $K_1$ | `A60F0C8F` |
| $K_2$ | `F449DB2D` |
| $K_3$ | `4796736F` |
| $K_4$ | `16530706` |
| $K_5$ | `377A24ED` |
| $K_6$ | `83A3CB39` |
| $K_7$ | `F68BA903` |

---


**Формулы:**

- Вспомогательный ключ:

$$
H = E_K(0^{128})
$$

- Режим счётчика:

$$
C_i = P_i \oplus E_K(J_0 + i)
$$

- GHASH:

$$
Y_0 = 0^{128}, \qquad Y_i = (Y_{i-1} \oplus X_i) \cdot H \bmod f(x)
$$

- Тег:

$$
T = \text{GHASH}\bigl(AAD, C, \text{len}(AAD), \text{len}(C)\bigr) \oplus E_K(J_0)
$$

**Реализация CTR-счётчика (big-endian):**

```cpp
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
```
## 3. Анализ безопасности (Constant-time)

### 3.1. Задача варианта: алгоритм Карацубы в $\mathbb{GF}(2^8)$

**Цель задачи:** обеспечить независимость времени выполнения умножения в $\mathbb{GF}(2^8)$ от значений сомножителей. Наивный shift-and-XOR содержит неявную зависимость от веса Хэмминга множителя (число установленных битов влияет на число операций `result ^= a`). Карацуба заменяет его **фиксированной последовательностью** из трёх умножений 4×4 и одной редукции.

**Математическое условие Constant-time:**

$$
\forall K_1, K_2, P_1, P_2: \quad \mathcal{T}(K_1, P_1) = \mathcal{T}(K_2, P_2)
$$

где $\mathcal{T}$ — время выполнения.


### 3.2. Обоснование отсутствия утечек через кэш

**Угроза Cache-timing Attack:** обращение к элементу массива по индексу, зависящему от секретного байта, приводит к разному состоянию L1-кэша. Атакующий по времени отклика восстанавливает индекс.

**Проблемное место** — доступ к таблице подстановок:

```cpp
// ОПАСНО: индекс зависит от секретного x
uint8_t S = beltSbox[x];
```

**Constant-time решение** в коде — обход всей таблицы с маской:

```cpp
uint8_t gfc::sbox(uint8_t x) const {
    uint8_t result = 0;
    for (uint16_t i = 0; i < 256; i++) {
        const uint8_t d    = static_cast<uint8_t>(x ^ i);
        const uint8_t mask = static_cast<uint8_t>(
            ((static_cast<uint32_t>(d) - 1u) >> 8) & 0xFFu);
        result |= static_cast<uint8_t>(beltSbox[i] & mask);
    }
    return result;
}
```

**Логика маски:**

- При $i = x$: $d = 0$, $d - 1 = \text{0xFFFFFFFF}$, $(d-1) \gg 8 = \text{0xFFFFFF}$, маска = `0xFF` → берётся `beltSbox[x]`.
- При $i \neq x$: $d \geq 1$, $d - 1 < 256$, $(d-1) \gg 8 = 0$, маска = `0x00` → элемент обнуляется.

Цикл всегда выполняет **все 256 итераций** и обращается ко **всем 256 элементам массива** независимо от $x$. Аппаратный префетчер загружает весь массив в L1 целиком, поэтому паттерн обращений не зависит от секрета.

Аналогично для $H(w)$ в БелТ: четыре вызова `calc.sbox(...)` — каждый Constant-time.

### 3.4. Constant-time сравнение тегов (защита от атаки ранним выходом)

**Уязвимость стандартных функций:**

```cpp
// ОПАСНО: ранний выход при первом несовпадении
if (std::memcmp(expected, actual, 16) == 0) return true;
```

Функция `memcmp` завершается при первом различающемся байте. По времени её работы атакующий определяет **позицию первого несовпадения** и подбирает тег побайтово ($16 \times 256$ попыток вместо $2^{128}$).

**Constant-time решение:**

```cpp
bool GCM::verify_tag(const Block& expected, const Block& actual) {
    std::uint8_t diff = 0;
    for (unsigned i = 0; i < 16; ++i) {
        diff |= static_cast<std::uint8_t>(expected[i] ^ actual[i]);
    }
    return static_cast<std::uint8_t>(
        ((static_cast<std::uint32_t>(diff) - 1u) >> 8) & 0x01u) == 1u;
}
```

**Свойства:**

1. Цикл всегда выполняет **ровно 16 итераций**, независимо от количества совпадающих байт.
2. Накопление через `|=` (побитовое ИЛИ) не имеет раннего выхода.
3. Финализация $\bigl((\text{diff} - 1) \gg 8\bigr) \wedge 1$ даёт 1 при $\text{diff} = 0$ и 0 при $\text{diff} \neq 0$ — это проверка на равенство нулю **без ветвления**.

**Итог:** время работы функции одинаково для всех пар `(expected, actual)` длиной 16 байт.

### 3.5. Отсутствие динамических контейнеров в криптографических путях

Все структуры данных, участвующие в крипто-операциях, имеют фиксированный размер и размещаются в непрерывных блоках памяти:

| Структура | Тип | Размер |
|---|---|---|
| Блок шифрования | `std::array<uint8_t, 16>` | 16 байт (стек) |
| S-блок БелТ | `static const uint8_t beltSbox[256]` | 256 байт (статическая память) |
| Ключ | `uint32_t K[8]` | 32 байта (поле класса) |
| Тег | `Block` (`std::array<uint8_t, 16>`) | 16 байт (стек) |
| Счётчик | `Block counter` | 16 байт (стек) |

**Многомерные динамические контейнеры** (`vector<vector<...>>`, `map`, `unordered_map`) в крипто-путях **не используются**. Причина: недетерминированное размещение в куче → непредсказуемые промахи кэша → утечка по времени.

## 4. Результаты тестирования

```========== BelT / GCM test suite ==========
p(x) = 0x11D, GHASH f(x) = x^128+x^7+x^2+x+1

[1] Zero element in inverse
[2] Reduction overflow (shift-and-XOR vs Karatsuba)
[3] Byte order: CTR counter and GHASH
[4] Tag comparison: no early exit
[+] BelT encrypt/decrypt roundtrip
[+] GCM encrypt/decrypt roundtrip

-------------------------------------------
PASSED: 31
FAILED: 0
===========================================
```
```
============================================================
 BelT (STB 34.101.31) + GCM AEAD
 Field GF(2^8), p(x) = 0x11D
 GHASH modulus  f(x) = x^128 + x^7 + x^2 + x + 1
 Constant-time task: Karatsuba in GF(2^8)
============================================================

[GF(2^8) calculator, p = 0x11D]
  add(57, 83)        = D4
  multiply(57, 83)   = 31
  karatsuba(57, 83)  = 31  (same result)
  inverse(0x00)          = 00  (0 without division by zero)
  inverse(0x57)          = 61
  0x57 * inverse(0x57)   = 01  (must be 01)

[BelT single block]
Key                 E9DEE72C8F0C0FA62DDB49F46F739647 06075316ED247A3739CBA38303A98BF6
Plaintext block     B194BAC80A08F53B366D008E584A5DE4
Ciphertext block    69CCA1C93557C9E3D66BC3E0FA88FA6E
Decrypted block     B194BAC80A08F53B366D008E584A5DE4
Roundtrip: OK

[GCM AEAD]
Nonce               CAFEBABE0011223344556677
AAD                 DEADBEEF00010203
Plaintext           42656C542D47434D3A2061757468656E 7469636174656420656E637279707469 6F6E2064656D6F2E
Ciphertext          ABF1366080E918533573DEDBDDA9B07D 7C7C3878A47C53500CC87C94566293C8 C72C5D1DEC9B1CDE
Tag (16 B)          F763B9C8C71DFB5908C99CD33D1AB1EB

verify_tag (correct)        : VALID
verify_tag (1-bit tampered) : INVALID (expected)

Decrypted           42656C542D47434D3A2061757468656E 7469636174656420656E637279707469 6F6E2064656D6F2E
GCM roundtrip: OK
```
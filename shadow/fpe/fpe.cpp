// Copyright 2023 TikTok Pte. Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "shadow/fpe/fpe.h"

#include <openssl/aes.h>
#include <openssl/bn.h>
#include <stdint.h>

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <random>
#include <stdexcept>
#include <utility>

#include "shadow/common/common.h"
#include "shadow/common/config.h"
#include "shadow/fpe/fpe_internal.h"

namespace shadow {
namespace fpe {

const std::string kCharsetNumbers = "0123456789";

const std::string kCharsetLettersLowercase = "abcdefghijklmnopqrstuvwxyz";

const std::string kCharsetLettersUppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

Alphabet::Alphabet(const std::string& charset) {
    if (charset.length() == 0 || charset.length() > SHADOW_FPE_ALPHABET_SIZE_MAX) {
        throw std::invalid_argument("Invalid character set size");
    }
    map_digit_to_char_.reserve(charset.length());
    for (std::size_t i = 0; i < charset.length(); i++) {
        if (charset[i] == '\0') {
            throw std::invalid_argument("Character set contains an empty character");
        }
        map_digit_to_char_.emplace_back(charset[i]);
    }
    // This ensures that alphabets are comparable.
    std::sort(map_digit_to_char_.begin(), map_digit_to_char_.end());

    map_char_to_digit_.reserve(map_digit_to_char_.size());
    std::pair<std::unordered_map<unsigned char, std::uint32_t>::iterator, bool> result{};
    for (std::size_t i = 0; i < map_digit_to_char_.size(); i++) {
        result = map_char_to_digit_.emplace(map_digit_to_char_[i], static_cast<std::uint32_t>(i));
        if (!result.second) {
            throw std::invalid_argument("Character set has duplication");
        }
    }
}

std::size_t Alphabet::size() const {
    return map_char_to_digit_.size();
}

bool are_identical(const Alphabet& in_0, const Alphabet& in_1) {
#ifdef SHADOW_DEBUG
    if ((in_0.map_digit_to_char_ == in_1.map_digit_to_char_) != (in_0.map_char_to_digit_ == in_1.map_char_to_digit_)) {
        throw std::logic_error("Bad alphahets");
    }
#endif
    return in_0.map_digit_to_char_ == in_1.map_digit_to_char_;
}

bool are_exclusive(const Alphabet& in_0, const Alphabet& in_1) {
    for (const auto& i : in_0.map_digit_to_char_) {
        if (in_1.map_char_to_digit_.find(i) != in_1.map_char_to_digit_.end()) {
            return false;
        }
    }
    for (const auto& i : in_1.map_digit_to_char_) {
        if (in_0.map_char_to_digit_.find(i) != in_0.map_char_to_digit_.end()) {
            return false;
        }
    }
    return true;
}

AlphabetInternal::AlphabetInternal(const std::string& charset) : Alphabet(charset) {
}

AlphabetInternal::AlphabetInternal(const Alphabet& alphabet) : Alphabet(alphabet) {
}

std::uint32_t AlphabetInternal::radix() const {
    return static_cast<std::uint32_t>(size());
}

bool AlphabetInternal::validate(const unsigned char& in) const {
    return in != '\0' && map_char_to_digit_.find(in) != map_char_to_digit_.end();
}

bool AlphabetInternal::validate(const std::string& in) const {
    for (const auto& i : in) {
        if (map_char_to_digit_.find(i) == map_char_to_digit_.end()) {
            return false;
        }
    }
    return true;
}

std::uint32_t AlphabetInternal::to_digit(const unsigned char& in) const {
    try {
        return map_char_to_digit_.at(in);
    } catch (const std::out_of_range&) {
        throw std::invalid_argument("Invalid character");
    }
}

unsigned char AlphabetInternal::to_char(std::uint32_t in) const {
    if (in > map_digit_to_char_.size()) {
        throw std::invalid_argument("Invalid digit");
    }
    return map_digit_to_char_[in];
}

void AlphabetInternal::to_digit(const std::string& in, std::vector<std::uint32_t>& out) const {
    out.clear();
    out.reserve(in.length());
    for (std::size_t i = 0; i < in.length(); i++) {
        try {
            out.emplace_back(to_digit(in[i]));
        } catch (const std::invalid_argument&) {
            throw std::invalid_argument("Invalid character");
            return;
        }
    }
}

void AlphabetInternal::to_char(const std::vector<std::uint32_t>& in, std::string& out) const {
    out.clear();
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); i++) {
        try {
            out.push_back(to_char(in[i]));
        } catch (const std::invalid_argument&) {
            throw std::invalid_argument("Invalid digit");
            return;
        }
    }
}

void AlphabetInternal::to_digit(const std::string& in, std::string& schema, std::vector<std::uint32_t>& out) const {
    out.clear();
    out.reserve(in.length());
    schema.clear();
    schema.reserve(in.length());
    for (std::size_t i = 0; i < in.length(); i++) {
        try {
            out.emplace_back(to_digit(in[i]));
            schema.push_back('\0');
        } catch (const std::invalid_argument&) {
            schema.push_back(in[i]);
        }
    }
}

void AlphabetInternal::to_char(
        const std::vector<std::uint32_t>& in, const std::string& schema, std::string& out) const {
    out.clear();
    out.reserve(schema.size());

    std::size_t j = 0;
    for (std::size_t i = 0; i < schema.size(); i++) {
        if (schema[i] != '\0') {
            out.push_back(schema[i]);
        } else {
            // in is too short
            if (j == in.size()) {
                throw std::invalid_argument("Invalid schema");
                return;
            }
            try {
                out.push_back(to_char(in[j]));
            } catch (const std::invalid_argument&) {
                throw std::invalid_argument("Invalid digit");
                return;
            }
            j++;
        }
    }

    // schema is too short
    if (j != in.size()) {
        throw std::invalid_argument("Invalid schema");
        return;
    }
}

Key generate_key() {
    Key key;
    common::get_bytes_from_random_device(key.size(), key.data());
    return key;
}

Tweak::Tweak(const std::vector<unsigned char>& tweak) : std::vector<unsigned char>(tweak) {
    if (tweak.size() > SHADOW_FPE_TWEAK_BYTE_COUNT_MAX) {
        throw std::invalid_argument("Tweak is too long");
    }
}

Tweak::Tweak(const std::string& tweak) {
    if (tweak.size() > SHADOW_FPE_TWEAK_BYTE_COUNT_MAX) {
        throw std::invalid_argument("Tweak is too long");
    }
    this->reserve(tweak.size());
    for (auto i : tweak) {
        this->emplace_back(i);
    }
}

// See Algorithm 1 in https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf.
// out = in[0] * (radix^num_digits-1) + in[1] * (radix^num_digits-2) + ... + in[num_digits] * radix^0
static void digit_to_bn(
        std::uint32_t radix, BN_CTX* bn_ctx, const std::uint32_t* in, std::size_t num_digits, BIGNUM* bn_out) {
    BN_CTX_start(bn_ctx);
    std::size_t i = 1;

    std::uint32_t out_32 = in[0];
    std::uint32_t tmp_32 = out_32;
    std::uint32_t inv_radix_32 = std::numeric_limits<std::uint32_t>::max() / radix;
    for (; i < num_digits;) {
        if (tmp_32 > inv_radix_32) {
            break;
        }
        tmp_32 *= radix;
        tmp_32 += in[i];
        if (tmp_32 < in[i]) {
            break;
        }
        out_32 = tmp_32;
        i++;
    }
    if (i == num_digits) {
        BN_lebin2bn(reinterpret_cast<unsigned char*>(&out_32), sizeof(std::uint32_t), bn_out);
        BN_CTX_end(bn_ctx);
        return;
    }

    std::uint64_t out_64 = out_32;
    std::uint64_t tmp_64 = out_32;
    std::uint64_t inv_radix_64 = std::numeric_limits<std::uint64_t>::max() / radix;
    for (; i < num_digits;) {
        if (tmp_64 > inv_radix_64) {
            break;
        }
        tmp_64 *= radix;
        tmp_64 += in[i];
        if (tmp_64 < in[i]) {
            break;
        }
        out_64 = tmp_64;
        i++;
    }
    if (i == num_digits) {
        BN_lebin2bn(reinterpret_cast<unsigned char*>(&out_64), sizeof(std::uint64_t), bn_out);
        BN_CTX_end(bn_ctx);
        return;
    }

    unsigned __int128 out_128 = out_64;
    unsigned __int128 tmp_128 = out_64;
    unsigned __int128 inv_radix_128 = std::numeric_limits<unsigned __int128>::max() / radix;
    for (; i < num_digits;) {
        if (tmp_128 > inv_radix_128) {
            break;
        }
        tmp_128 *= radix;
        tmp_128 += in[i];
        if (tmp_128 < in[i]) {
            break;
        }
        out_128 = tmp_128;
        i++;
    }

    BN_lebin2bn(reinterpret_cast<unsigned char*>(&out_128), sizeof(unsigned __int128), bn_out);

    if (i == num_digits) {
        BN_CTX_end(bn_ctx);
        return;
    }

    std::size_t radix_digist_num_lt_u32 =
            static_cast<std::size_t>(std::ceil(32.0 / std::log2(static_cast<double>(radix)))) - 1;
    std::vector<std::uint32_t> radix_pow_j(radix_digist_num_lt_u32, radix);
    bool radix_filled_flag = false;

    for (; i < num_digits; i += radix_digist_num_lt_u32) {
        std::uint32_t u32_cache = in[i];
        std::size_t j = 1;
        std::size_t radix_max = radix;
        for (; (j < radix_digist_num_lt_u32) && (i + j < num_digits); j++) {
            u32_cache *= radix;
            u32_cache += in[i + j];
            if (!radix_filled_flag) {
                radix_pow_j[j] = radix_pow_j[j - 1] * radix;
            }
        }
        if (radix_pow_j[radix_digist_num_lt_u32 - 1] != radix) {
            radix_filled_flag = true;
        }
        BN_mul_word(bn_out, radix_pow_j[j - 1]);
        BN_add_word(bn_out, u32_cache);
    }
    BN_CTX_end(bn_ctx);
}

// See Algorithm 3 in https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf.
// in = out[0] * (radix^num_digits-1) + out[1] * (radix^num_digits-2) + ... + out[num_digits] * radix^0
static void bn_to_digit(
        std::uint32_t radix, BN_CTX* bn_ctx, const BIGNUM* in, std::size_t num_digits, std::uint32_t* out) {
    std::size_t in_byte_count = static_cast<std::size_t>(BN_num_bytes(in));
    std::size_t i = 0;
    BN_CTX_start(bn_ctx);
    BIGNUM* bn_q = BN_CTX_get(bn_ctx);
    BN_copy(bn_q, in);

    std::size_t radix_digist_num_lt_u128 = 0;
    std::size_t radix_digist_num_lt_u32 = 0;
    std::uint32_t radix_lt_u32 = radix;
    if (in_byte_count > sizeof(std::uint32_t)) {
        radix_digist_num_lt_u128 =
                static_cast<std::size_t>(std::ceil(128.0 / std::log2(static_cast<double>(radix)))) - 1;
        radix_digist_num_lt_u32 = radix_digist_num_lt_u128 / 4;
        for (std::size_t j = 1; j < radix_digist_num_lt_u32; ++j) {
            radix_lt_u32 *= radix;
        }
    }

    if (in_byte_count > sizeof(unsigned __int128)) {
        BIGNUM* bn_radix_lt_u128 = BN_CTX_get(bn_ctx);
        BIGNUM* bn_exponent = BN_CTX_get(bn_ctx);
        BN_set_word(bn_exponent, radix_digist_num_lt_u128);
        BN_set_word(bn_radix_lt_u128, radix);
        BN_exp(bn_radix_lt_u128, bn_radix_lt_u128, bn_exponent, bn_ctx);

        BIGNUM* bn_rem = BN_CTX_get(bn_ctx);
        for (; i < num_digits;) {
            BN_div(bn_q, bn_rem, bn_q, bn_radix_lt_u128, bn_ctx);
            unsigned __int128 q_128;
            BN_bn2lebinpad(bn_rem, (unsigned char*)&q_128, sizeof(unsigned __int128));

            std::size_t j = 0;
            for (; j < 3; ++j) {
                std::uint32_t q_32 = q_128 % radix_lt_u32;
                for (std::size_t k = 0; k < radix_digist_num_lt_u32; ++k) {
                    out[num_digits - 1 - i] = static_cast<std::uint32_t>(q_32 % radix);
                    q_32 /= radix;
                    i++;
                }
                q_128 /= radix_lt_u32;
            }

            std::uint64_t q_64 = static_cast<std::uint64_t>(q_128);
            for (std::size_t k = 0; k < radix_digist_num_lt_u128 - 3 * radix_digist_num_lt_u32; ++k) {
                out[num_digits - 1 - i] = static_cast<std::uint32_t>(q_64 % radix);
                q_64 /= radix;
                i++;
            }

            in_byte_count = static_cast<std::size_t>(BN_num_bytes(bn_q));
            if (in_byte_count <= sizeof(unsigned __int128)) {
                break;
            }
        }
    }

    if (in_byte_count <= sizeof(std::uint32_t)) {
        uint32_t q_32;
        BN_bn2lebinpad(bn_q, (unsigned char*)&q_32, sizeof(std::uint32_t));
        for (; i < num_digits; i++) {
            out[num_digits - 1 - i] = static_cast<std::uint32_t>(q_32 % radix);
            q_32 /= radix;
        }
        BN_CTX_end(bn_ctx);
        return;
    }

    if (in_byte_count <= sizeof(std::uint64_t)) {
        uint64_t q_64;
        BN_bn2lebinpad(bn_q, (unsigned char*)&q_64, sizeof(std::uint64_t));
        std::uint32_t q_32 = q_64 % radix_lt_u32;
        q_64 = q_64 / radix_lt_u32;
        for (std::size_t k = 0; k < radix_digist_num_lt_u32 && i < num_digits; ++k) {
            out[num_digits - 1 - i] = static_cast<std::uint32_t>(q_32 % radix);
            q_32 /= radix;
            i++;
        }
        for (; i < num_digits; i++) {
            out[num_digits - 1 - i] = static_cast<std::uint32_t>(q_64 % radix);
            q_64 /= radix;
        }
        BN_CTX_end(bn_ctx);
        return;
    }

    if (in_byte_count <= sizeof(unsigned __int128)) {
        unsigned __int128 q_128;
        BN_bn2lebinpad(bn_q, (unsigned char*)&q_128, sizeof(unsigned __int128));
        std::size_t j = 0;
        for (; j < 3; ++j) {
            std::uint32_t q_32 = q_128 % radix_lt_u32;
            for (std::size_t k = 0; k < radix_digist_num_lt_u32 && i < num_digits; ++k) {
                out[num_digits - 1 - i] = static_cast<std::uint32_t>(q_32 % radix);
                q_32 /= radix;
                i++;
            }
            q_128 /= radix_lt_u32;
        }
        std::uint64_t q_64 = static_cast<std::uint64_t>(q_128);
        for (std::size_t k = 0; k < radix_digist_num_lt_u128 - 3 * radix_digist_num_lt_u32 && i < num_digits; ++k) {
            out[num_digits - 1 - i] = static_cast<std::uint32_t>(q_64 % radix);
            q_64 /= radix;
            i++;
        }
        BN_CTX_end(bn_ctx);
        return;
    }
}

// See Section 3.3 in https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf.
// out[out_byte_count - 1 - i] = (bn_in / 256^i) % 256
static void bn_to_byte(const BIGNUM* bn_in, std::size_t out_byte_count, unsigned char* out) {
    std::size_t byte_count = BN_bn2bin(bn_in, out);
    for (std::size_t i = 0; i < byte_count; i++) {
        out[out_byte_count - 1 - i] = out[byte_count - 1 - i];
    }
    std::fill_n(out, out_byte_count - byte_count, 0);
}

// See Algorithm 2 in https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf.
// (bn_in / 256^i) % 256 = in[in_byte_count - 1 - i]
static void byte_to_bn(unsigned char* in, std::size_t in_byte_count, BIGNUM* bn_out) {
    BN_bin2bn(in, static_cast<int>(in_byte_count), bn_out);
}

void ff1_encrypt(std::uint32_t radix, const Key& key, const std::vector<unsigned char>& tweak, bool encrypt,
        const std::uint32_t* in, std::size_t in_len, std::uint32_t* out) {
    // 0 <= t <= 2^32-1, represted with 32 bits
    const std::uint32_t t = static_cast<std::uint32_t>(tweak.size());
    // 2 <= n <= 2^32-1, represented with 32 bits
    const std::uint32_t n = static_cast<std::uint32_t>(in_len);
    // allocate and set OpenSSL AES_KEY
    AES_KEY aes_key;
    AES_set_encrypt_key(key.data(), SHADOW_FPE_KEY_BIT_COUNT, &aes_key);

    // create cipher with the key
    auto cipher = [&](const unsigned char* pt, unsigned char* ct) { AES_ecb_encrypt(pt, ct, &aes_key, 1); };

    // Step 1-5
    // 1 <= u <= 2^31-1, represented with 32 bits
    const std::uint32_t u = n / 2;
    // 1 <= v <= 2^31, represented with 32 bits
    const std::uint32_t v = n - u;
    // 1 <= b <= 2^32, represented with 64 bits
    const std::uint64_t b =
            (static_cast<std::uint64_t>(ceil(static_cast<double>(v) * std::log2(static_cast<double>(radix)))) + 7) / 8;
    // 5 <= d <= 2^30+4, represented with 32 bits
    const std::uint32_t d = static_cast<std::uint32_t>((b + 3) / 4 * 4 + 4);
    // See Section 3.3 in https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf.
    const unsigned char p[16] = {1, 2, 1, static_cast<unsigned char>(radix >> 16),
            static_cast<unsigned char>((radix >> 8) % 256), static_cast<unsigned char>(radix % 256), 10,
            static_cast<unsigned char>(u % 256), static_cast<unsigned char>(n >> 24),
            static_cast<unsigned char>((n >> 16) % 256), static_cast<unsigned char>((n >> 8) % 256),
            static_cast<unsigned char>(n % 256), static_cast<unsigned char>(t >> 24),
            static_cast<unsigned char>((t >> 16) % 256), static_cast<unsigned char>((t >> 8) % 256),
            static_cast<unsigned char>(t % 256)};

    // Step 6.ii: the first block
    unsigned char r0[16];
    cipher(reinterpret_cast<const unsigned char*>(p), r0);

    // Pre-allocate buffers
    const std::size_t q_padding_size = (-t - b - 1) & 0xF;
    const std::size_t q_size = t + q_padding_size + 1 + b;
    std::size_t buf_uint32_count = std::max(u, v);
    std::size_t buf_size = q_size + 16 + (d + 15) / 16 * 16 + buf_uint32_count * sizeof(std::uint32_t) * 3;
    std::vector<unsigned char> buf(buf_size);
    unsigned char* q = buf.data();
    unsigned char* buf_r = q + q_size;
    unsigned char* buf_s = buf_r + 16;
    std::uint32_t* buf_a = reinterpret_cast<std::uint32_t*>(buf_s + (d + 15) / 16 * 16);
    std::copy_n(in, u, buf_a);
    std::uint32_t* buf_b = buf_a + buf_uint32_count;
    std::copy_n(in + u, v, buf_b);
    std::uint32_t* buf_c = buf_b + buf_uint32_count;

    // Step 6.i: the beginning bytes
    std::copy_n(tweak.cbegin(), t, q);
    std::fill_n(q + t, q_padding_size, 0x00);

    // Pre-allocate BIGNUM
    BN_CTX* bn_ctx = BN_CTX_new();
    BIGNUM* bn_a = BN_new();
    BIGNUM* bn_b = BN_new();
    BIGNUM* bn_y = BN_new();
    BIGNUM* bn_c = BN_new();
    BIGNUM* bn_radix = BN_new();
    BN_set_word(bn_radix, radix);
    BIGNUM* bn_u = BN_new();
    BN_set_word(bn_u, u);
    BIGNUM* bn_radix_to_u = BN_new();
    BIGNUM* bn_radix_to_v = BN_new();
    BN_exp(bn_radix_to_u, bn_radix, bn_u, bn_ctx);
    if (u == v) {
        BN_copy(bn_radix_to_v, bn_radix_to_u);
    } else if (u == v - 1) {
        BN_mul(bn_radix_to_v, bn_radix_to_u, bn_radix, bn_ctx);
    }
    BIGNUM* bn_radix_to_m = nullptr;

    for (std::uint32_t round = 0; round < SHADOW_FF1_NUM_ROUNDS; round++) {
        std::uint32_t i;
        if (encrypt) {
            i = round;
        } else {
            i = SHADOW_FF1_NUM_ROUNDS - 1 - round;
        }

        // Step 6.v: if i is even, let m = u; else let m = v
        const std::uint32_t m = i % 2 ? v : u;

        // Step 6.vii
        bn_radix_to_m = i % 2 ? bn_radix_to_v : bn_radix_to_u;

        // Step 6.i and 6.vi
        if (encrypt) {
            digit_to_bn(radix, bn_ctx, buf_a, m, bn_a);
            digit_to_bn(radix, bn_ctx, buf_b, n - m, bn_b);
        } else {
            digit_to_bn(radix, bn_ctx, buf_a, n - m, bn_a);
            digit_to_bn(radix, bn_ctx, buf_b, m, bn_b);
        }

        // Step 6.i: if encrypt, buf_b; otherwise, buf_a
        q[q_size - b - 1] = static_cast<unsigned char>(i);
        if (encrypt) {
            bn_to_byte(bn_b, b, q + q_size - b);
        } else {
            bn_to_byte(bn_a, b, q + q_size - b);
        }

        // Step 6.ii
        unsigned char temp[16];
        std::copy_n(r0, 16, buf_r);
        for (std::uint32_t j = 0; j < q_size / 16; j++) {
            reinterpret_cast<std::uint64_t*>(temp)[0] =
                    reinterpret_cast<std::uint64_t*>(q + 16 * j)[0] ^ reinterpret_cast<std::uint64_t*>(buf_r)[0];
            reinterpret_cast<std::uint64_t*>(temp)[1] =
                    reinterpret_cast<std::uint64_t*>(q + 16 * j)[1] ^ reinterpret_cast<std::uint64_t*>(buf_r)[1];
            cipher(temp, buf_r);
        }

        // Step 6.iii
        std::copy_n(buf_r, 16, buf_s);
        std::copy_n(buf_r, 16, temp);
        for (std::uint32_t j = 1; j < (d + 15) / 16; j++) {
            reinterpret_cast<std::uint32_t*>(temp)[3] = reinterpret_cast<std::uint32_t*>(buf_r)[3] ^ j;
            cipher(temp, buf_s + 16 * j);
        }

        // Step 6.iv
        byte_to_bn(buf_s, d, bn_y);

        // Step 6.vi
        if (encrypt) {
            BN_mod_add(bn_c, bn_a, bn_y, bn_radix_to_m, bn_ctx);
        } else {
            BN_mod_sub(bn_c, bn_b, bn_y, bn_radix_to_m, bn_ctx);
        }

        // Step 6.vii
        bn_to_digit(radix, bn_ctx, bn_c, m, buf_c);

        // Step 6.viii and 6.ix
        if (encrypt) {
            std::uint32_t* buf_t = buf_b;
            buf_a = buf_b;
            buf_b = buf_c;
            buf_c = buf_t;
        } else {
            uint32_t* buf_t = buf_a;
            buf_b = buf_a;
            buf_a = buf_c;
            buf_c = buf_t;
        }
    }

    // Step 7
    std::copy_n(buf_a, u, out);
    std::copy_n(buf_b, v, out + u);

    // Clean up
    std::fill(buf.begin(), buf.end(), 0);

    BN_clear_free(bn_a);
    BN_clear_free(bn_b);
    BN_clear_free(bn_y);
    BN_clear_free(bn_c);
    BN_clear_free(bn_radix);
    BN_clear_free(bn_u);
    BN_clear_free(bn_radix_to_u);
    BN_clear_free(bn_radix_to_v);
    BN_CTX_free(bn_ctx);
}

static void encrypt_internal(const AlphabetInternal& alphabet, const Key& key, const std::vector<unsigned char>& tweak,
        bool encrypt, const std::vector<std::uint32_t>& in, std::vector<std::uint32_t>& out) {
    std::size_t length = in.size();
    if (length < SHADOW_FPE_MESSAGE_LEN_MIN || length > SHADOW_FPE_MESSAGE_LEN_MAX) {
        throw std::invalid_argument("Invalid message length");
    }

    double log_domain = std::log10(static_cast<double>(alphabet.radix())) * static_cast<double>(length);
    if (log_domain < 6) {
        throw std::invalid_argument("Domain is less than 1 million");
    }

    out.resize(in.size());
    ff1_encrypt(alphabet.radix(), key, tweak, encrypt, in.data(), in.size(), out.data());
}

void encrypt_internal(const Alphabet& alphabet, const Key& key, const std::vector<unsigned char>& tweak, bool encrypt,
        const std::string& in, std::string& out) {
    AlphabetInternal alphabet_internal(alphabet);
    std::vector<std::uint32_t> in_digits;
    std::vector<std::uint32_t> out_digits;

    try {
        alphabet_internal.to_digit(in, in_digits);
    } catch (const std::invalid_argument&) {
        throw std::invalid_argument("Unsupported character");
    }

    encrypt_internal(alphabet_internal, key, tweak, encrypt, in_digits, out_digits);

    try {
        alphabet_internal.to_char(out_digits, out);
    } catch (const std::invalid_argument&) {
        throw std::logic_error("Unsupported digit from encryption");
    }
}

void encrypt(const Alphabet& alphabet, const Key& key, const std::vector<unsigned char>& tweak, const std::string& in,
        std::string& out) {
    encrypt_internal(alphabet, key, tweak, true, in, out);
}

void decrypt(const Alphabet& alphabet, const Key& key, const std::vector<unsigned char>& tweak, const std::string& in,
        std::string& out) {
    encrypt_internal(alphabet, key, tweak, false, in, out);
}

void encrypt_skip_unsupported_internal(const Alphabet& alphabet, const Key& key,
        const std::vector<unsigned char>& tweak, bool encrypt, const std::string& in, std::string& out) {
    AlphabetInternal alphabet_internal(alphabet);
    std::string schema;
    std::vector<std::uint32_t> in_digits;
    std::vector<std::uint32_t> out_digits;

    alphabet_internal.to_digit(in, schema, in_digits);

    encrypt_internal(alphabet_internal, key, tweak, encrypt, in_digits, out_digits);

    try {
        alphabet_internal.to_char(out_digits, schema, out);
    } catch (const std::invalid_argument&) {
        throw std::logic_error("Unsupported digit from encryption");
    }
}

void encrypt_skip_unsupported(const Alphabet& alphabet, const Key& key, const std::vector<unsigned char>& tweak,
        const std::string& in, std::string& out) {
    encrypt_skip_unsupported_internal(alphabet, key, tweak, true, in, out);
}

void decrypt_skip_unsupported(const Alphabet& alphabet, const Key& key, const std::vector<unsigned char>& tweak,
        const std::string& in, std::string& out) {
    encrypt_skip_unsupported_internal(alphabet, key, tweak, false, in, out);
}

void encrypt_skip_specified_internal(const Alphabet& alphabet, const Alphabet& specification, const Key& key,
        const std::vector<unsigned char>& tweak, bool encrypt, const std::string& in, std::string& out) {
    if (!are_exclusive(alphabet, specification)) {
        throw std::invalid_argument("Alphabet and specification have an overlapping character");
    }

    AlphabetInternal alphabet_internal(alphabet);
    AlphabetInternal specification_internal(specification);
    std::string schema;
    std::vector<std::uint32_t> in_digits;
    std::vector<std::uint32_t> out_digits;

    alphabet_internal.to_digit(in, schema, in_digits);

    for (auto i : schema) {
        if (i != '\0') {
            if (!specification_internal.validate(i)) {
                throw std::invalid_argument("Unsupported and unspecified character");
            }
        }
    }

    encrypt_internal(alphabet_internal, key, tweak, encrypt, in_digits, out_digits);

    try {
        alphabet_internal.to_char(out_digits, schema, out);
    } catch (const std::invalid_argument&) {
        throw std::logic_error("Unsupported digit from encryption");
    }
}

void encrypt_skip_specified(const Alphabet& alphabet, const Alphabet& specification, const Key& key,
        const std::vector<unsigned char>& tweak, const std::string& in, std::string& out) {
    encrypt_skip_specified_internal(alphabet, specification, key, tweak, true, in, out);
}

void decrypt_skip_specified(const Alphabet& alphabet, const Alphabet& specification, const Key& key,
        const std::vector<unsigned char>& tweak, const std::string& in, std::string& out) {
    encrypt_skip_specified_internal(alphabet, specification, key, tweak, false, in, out);
}

}  // namespace fpe
}  // namespace shadow

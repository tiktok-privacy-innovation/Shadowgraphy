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

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace shadow {
namespace fpe {

// @brief Alphabet should have at least two characters.
#define SHADOW_FPE_ALPHABET_SIZE_MIN 2

// @brief Restricts alphabets to 8-bit characters.
#define SHADOW_FPE_ALPHABET_SIZE_MAX 256

// @brief The minimum number of characters in an input or output message.
#define SHADOW_FPE_MESSAGE_LEN_MIN 0x2

// @brief The maximum number of characters in an input or output message.
#define SHADOW_FPE_MESSAGE_LEN_MAX 0xFFFFFFFF

// @brief The number of bytes in a key.
#define SHADOW_FPE_KEY_BYTE_COUNT 16

// @brief The number of bytes in a key.
#define SHADOW_FPE_KEY_BIT_COUNT (SHADOW_FPE_KEY_BYTE_COUNT * 8)

// @brief The maximum number of bytes in a tweak.
#define SHADOW_FPE_TWEAK_BYTE_COUNT_MAX 0xFFFFFFFF

// @brief The number of rounds in FF1.
#define SHADOW_FF1_NUM_ROUNDS 10

// @brief Arabic number characters 0-9.
extern const std::string kCharsetNumbers;

// @brief English lower-case letter characters a-z.
extern const std::string kCharsetLettersLowercase;

// @brief English upper-case letter characters A-Z.
extern const std::string kCharsetLettersUppercase;

/**
 * @brief Defines an alphabet from a set of unique and sorted characters.
 */
class Alphabet {
public:
    /**
     * @brief Constructs an alphabet from a given set of characters.
     *
     * @param[in] charset A set of characters.
     * @throws std::invalid_argument if charset's size is empty or larger than SHADOW_FPE_ALPHABET_SIZE_MAX, or if
     * character set has duplication.
     */
    explicit Alphabet(const std::string& charset);

    /**
     * @brief Returns the size of this alphabet.
     */
    std::size_t size() const;

    friend bool are_identical(const Alphabet& in_0, const Alphabet& in_1);

    friend bool are_exclusive(const Alphabet& in_0, const Alphabet& in_1);

protected:
    std::vector<unsigned char> map_digit_to_char_{};

    std::unordered_map<unsigned char, std::uint32_t> map_char_to_digit_{};
};

/**
 * @brief Returns true if two alphabets are identical.
 *
 * @param[in] in_0 An alphabet.
 * @param[in] in_1 The other alphabet.
 */
bool are_identical(const Alphabet& in_0, const Alphabet& in_1);

/**
 * @brief Returns true if two alphabets have no overlapping characters.
 *
 * @param[in] in_0 An alphabet.
 * @param[in] in_1 The other alphabet.
 */
bool are_exclusive(const Alphabet& in_0, const Alphabet& in_1);

// @brief A key has 128 bits.
class Key : public std::array<unsigned char, SHADOW_FPE_KEY_BYTE_COUNT> {
public:
    /**
     * @brief Constructs an empty key.
     */
    Key() : std::array<unsigned char, SHADOW_FPE_KEY_BYTE_COUNT>() {
    }

    /**
     * @brief Constructs a key from an array of 16 bytes.
     * @param[in] tweak A array of 16 bytes.
     */
    Key(const std::array<unsigned char, SHADOW_FPE_KEY_BYTE_COUNT>& copy)
            : std::array<unsigned char, SHADOW_FPE_KEY_BYTE_COUNT>(copy) {
    }

    /**
     * @brief Destructs and wipe data.
     */
    ~Key() {
        std::fill(this->begin(), this->end(), 0);
    }
};

/**
 * @brief Generate a random key.
 */
Key generate_key();

/**
 * @brief A tweak has 0 ~ 2^32-1 bytes.
 */
class Tweak : public std::vector<unsigned char> {
public:
    /**
     * @brief Constructs an empty tweak.
     */
    Tweak() : std::vector<unsigned char>() {
    }

    /**
     * @brief Constructs a tweak from a vector of bytes.
     * @param[in] tweak A vector of bytes.
     * @throws std::invadlid_argument if tweak is longer than SHADOW_FPE_TWEAK_BYTE_COUNT_MAX
     */
    Tweak(const std::vector<unsigned char>& tweak);

    /**
     * @brief Constructs a tweak from a string.
     * @param[in] tweak A string.
     * @throws std::invadlid_argument if tweak is longer than SHADOW_FPE_TWEAK_BYTE_COUNT_MAX
     */
    Tweak(const std::string& tweak);
};

/**
 * @brief Performs encryption and throws if any character is unsupported.
 *
 * If alphabet is '0'-'9', "37413222" --> "93947487"; "SF3741-NE32:F22" throws.
 * If alphabet is '0'-'9' and 'A'-'Z', "SF3741NE32F22" --> "KL9394TC74M87"; "SF3741-NE32:F22" throws.
 *
 * @param[in] alphabet An alphabet of supported characters.
 * @param[in] key An encryption key.
 * @param[in] tweak A tweak.
 * @param[in] in A string to be encrypted.
 * @param[out] out Encryption result.
 * @throws std::invalid_argument if input domain is less than 1 million, if message's length is less than
 * SHADOW_FPE_MESSAGE_LEN_MIN or larger than SHADOW_FPE_MESSAGE_LEN_MAX, or if message contains an unsupported
 * character.
 * @throws std::logic_error if encryption generates an unsupported digit.
 */
void encrypt(const Alphabet& alphabet, const Key& key, const std::vector<unsigned char>& tweak, const std::string& in,
        std::string& out);

/**
 * @brief Performs decryption and throws if any character is unsupported.
 *
 * If alphabet is '0'-'9', "37413222" --> "93947487"; "SF3741-NE32:F22" throws.
 * If alphabet is '0'-'9' and 'A'-'Z', "SF3741NE32F22" --> "KL9394TC74M87"; "SF3741-NE32:F22" throws.
 *
 * @param[in] alphabet An alphabet of supported characters.
 * @param[in] key A decryption key.
 * @param[in] tweak A tweak.
 * @param[in] in A string to be decrypted.
 * @param[out] out Decryption result.
 * @throws std::invalid_argument if input domain is less than 1 million, if message's length is less than
 * SHADOW_FPE_MESSAGE_LEN_MIN or larger than SHADOW_FPE_MESSAGE_LEN_MAX, or if message contains an unsupported
 * character.
 * @throws std::logic_error if decryption generates an unsupported digit.
 */
void decrypt(const Alphabet& alphabet, const Key& key, const std::vector<unsigned char>& tweak, const std::string& in,
        std::string& out);

/**
 * @brief Performs encryption and skips unsupported characters.
 *
 * @par If alphabet is '0'-'9', "SF3741-NE32:F22" --> "SF9394-NE74:F87".
 *
 * @param[in] alphabet An alphabet of supported characters.
 * @param[in] key An encryption key.
 * @param[in] tweak A tweak.
 * @param[in] in A string to be encrypted.
 * @param[out] out Encryption result.
 * @throws std::invalid_argument if input domain is less than 1 million or if message's length is less than
 * SHADOW_FPE_MESSAGE_LEN_MIN or larger than SHADOW_FPE_MESSAGE_LEN_MAX.
 * @throws std::logic_error if encryption generates an unsupported digit.
 */
void encrypt_skip_unsupported(const Alphabet& alphabet, const Key& key, const std::vector<unsigned char>& tweak,
        const std::string& in, std::string& out);

/**
 * @brief Performs decryption and skips unsupported characters.
 *
 * @par If alphabet is '0'-'9', "SF3741-NE32:F22" --> "SF9394-NE74:F87".
 *
 * @par If alphabet contains only numbers "SF3741-NE32:F22" --> "SF9394-NE74:F87".
 * @param[in] alphabet An alphabet of supported characters.
 * @param[in] key A decryption key.
 * @param[in] tweak A tweak.
 * @param[in] in A string to be decrypted.
 * @param[out] out Decryption result.
 * @throws std::invalid_argument if input domain is less than 1 million or if message's length is less than
 * SHADOW_FPE_MESSAGE_LEN_MIN or larger than SHADOW_FPE_MESSAGE_LEN_MAX.
 * @throws std::logic_error if decryption generates an unsupported digit.
 */
void decrypt_skip_unsupported(const Alphabet& alphabet, const Key& key, const std::vector<unsigned char>& tweak,
        const std::string& in, std::string& out);

/**
 * @brief Performs encryption and skips specified characters.
 *
 * If alphabet is '0'-'9' and specification is 'A'-'Z', '-', and ':', "SF3741-NE32:F22" --> "SF9394-NE74:F87".
 * If alphabet is '0'-'9' and 'A'-'Z' and specification is '-' and ':', "SF3741-NE32:F22" --> "KL9394-TC74:M87".
 * If alphabet is '0'-'9' and specification is 'A'-'Z', "SF3741-NE32:F22" throws.
 *
 * @param[in] alphabet An alphabet of supported characters.
 * @param[in] specification An alphabet of specified characters to skip.
 * @param[in] key An encryption key.
 * @param[in] tweak A tweak.
 * @param[in] in A string to be encrypted.
 * @param[out] out Encryption result.
 * @throws std::invalid_argument if input domain is less than 1 million, if message's length is less than
 * SHADOW_FPE_MESSAGE_LEN_MIN or larger than SHADOW_FPE_MESSAGE_LEN_MAX, or if message contains an unsupported and
 * unspecified character.
 * @throws std::logic_error if encryption generates an unsupported digit.
 */
void encrypt_skip_specified(const Alphabet& alphabet, const Alphabet& specification, const Key& key,
        const std::vector<unsigned char>& tweak, const std::string& in, std::string& out);

/**
 * @brief Performs decryption and skips specified characters.
 *
 * If alphabet is '0'-'9' and specification is 'A'-'Z', '-', and ':', "SF3741-NE32:F22" --> "SF9394-NE74:F87".
 * If alphabet is '0'-'9' and 'A'-'Z' and specification is '-' and ':', "SF3741-NE32:F22" --> "KL9394-TC74:M87".
 * If alphabet is '0'-'9' and specification is 'A'-'Z', "SF3741-NE32:F22" throws.
 *
 * @param[in] alphabet An alphabet of supported characters.
 * @param[in] specification An alphabet of specified characters to skip.
 * @param[in] key A decryption key.
 * @param[in] tweak A tweak.
 * @param[in] in A string to be decrypted.
 * @param[out] out Decryption result.
 * @throws std::invalid_argument if input domain is less than 1 million, if message's length is less than
 * SHADOW_FPE_MESSAGE_LEN_MIN or larger than SHADOW_FPE_MESSAGE_LEN_MAX, or if message contains an unsupported and
 * unspecified character.
 * @throws std::logic_error if decryption generates an unsupported digit.
 */
void decrypt_skip_specified(const Alphabet& alphabet, const Alphabet& specification, const Key& key,
        const std::vector<unsigned char>& tweak, const std::string& in, std::string& out);

}  // namespace fpe
}  // namespace shadow

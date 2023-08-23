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

#include <math.h>

#include "shadow/fpe/fpe.h"

namespace shadow {
namespace fpe {

class AlphabetInternal : public Alphabet {
public:
    /**
     * @brief Constructs an alphabet from a given set of characters.
     * @param[in] charset A set of characters.
     * @throws std::invalid_argument if charset's size is less than SHADOW_FPE_ALPHABET_SIZE_MIN or larger than
     * SHADOW_FPE_ALPHABET_SIZE_MAX, or if character set has duplication.
     */
    explicit AlphabetInternal(const std::string& charset);

    /**
     * @brief Constructs an alphabet from a given set of characters.
     * @param[in] charset A set of characters.
     * @throws std::invalid_argument if charset's size is less than SHADOW_FPE_ALPHABET_SIZE_MIN or larger than
     * SHADOW_FPE_ALPHABET_SIZE_MAX, or if character set has duplication.
     */
    explicit AlphabetInternal(const Alphabet& alphabet);

    /**
     * @brief Returns the size of this alphabet.
     */
    std::uint32_t radix() const;

    /**
     * @brief Returns false if the character is unsupported.
     * @param[in] in A character.
     */
    bool validate(const unsigned char& in) const;

    /**
     * @brief Returns false if any character is unsupported.
     * @param[in] in A string of characters.
     */
    bool validate(const std::string& in) const;

    /**
     * @brief Returns an integer digit that maps to the character.
     * @param[in] in A character.
     * @throws std::invalid_argument if the character is unsupported by this alphabet.
     */
    std::uint32_t to_digit(const unsigned char& in) const;

    /**
     * @brief Returns an character that maps to the integer digit.
     * @param[in] in An integer digit.
     * @throws std::invalid_argument if the integer digit is unsupported by this alphabet.
     */
    unsigned char to_char(std::uint32_t in) const;

    /**
     * @brief Maps a string of characters to a vector of integer digits.
     * @param[in] in A string of characters.
     * @param[out] out A vector of integer digits.
     * @throws std::invalid_argument if any character is unsupported by this alphabet.
     */
    void to_digit(const std::string& in, std::vector<std::uint32_t>& out) const;

    /**
     * @brief Maps a vector of integer digits to a string of characters.
     * @param[in] in A vector of integer digits.
     * @param[out] in A string of characters.
     * @throws std::invalid_argument if any integer digit is unsupported by this alphabet.
     */
    void to_char(const std::vector<std::uint32_t>& in, std::string& out) const;

    /**
     * @brief Extracts supported characters from a string to a vector of integer digits; record unsupported characters
     * and their indexes in a schema.
     * @param[in] in A string of characters.
     * @param[out] schema A string of empty and unsupported characters.
     * @param[out] out A vector of integer digits.
     */
    void to_digit(const std::string& in, std::string& schema, std::vector<std::uint32_t>& out) const;

    /**
     * @brief Maps a vector of integer digits to a string of characters formatted by the schema.
     * @param[in] in A vector of integer digits.
     * @param[in] schema A string of empty and unsupported characters.
     * @param[out] in A string of characters.
     * @throws std::invalid_argument if any integer digit is unsupported by this alphabet.
     */
    void to_char(const std::vector<std::uint32_t>& in, const std::string& schema, std::string& out) const;
};

void encrypt_internal(const Alphabet& alphabet, const Key& key, const std::vector<unsigned char>& tweak, bool encrypt,
        const std::string& in, std::string& out);

void encrypt_skip_unsupported_internal(const Alphabet& alphabet, const Key& key,
        const std::vector<unsigned char>& tweak, bool encrypt, const std::string& in, std::string& out);

void encrypt_skip_specified_internal(const Alphabet& alphabet, const Alphabet& specification, const Key& key,
        const std::vector<unsigned char>& tweak, bool encrypt, const std::string& in, std::string& out);

inline void print(const std::string& name, const unsigned char* in, std::size_t len) {
    std::cout << name << ": ";
    for (std::size_t i = 0; i < len; i++)
        std::cout << static_cast<std::uint32_t>(in[i]) << " ";
    std::cout << std::endl;
}

inline void print(const std::string& name, const std::uint32_t* in, std::size_t len) {
    std::cout << name << ": ";
    for (std::size_t i = 0; i < len; i++)
        std::cout << in[i] << " ";
    std::cout << std::endl;
}

}  // namespace fpe
}  // namespace shadow

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

#include "gtest/gtest.h"
#include "shadow/fpe/fpe_internal.h"

namespace shadowtest {

using namespace shadow::fpe;
using namespace std;

TEST(AlphabetTest, Constructor) {
    {
        Alphabet alphabet(kCharsetNumbers);
        ASSERT_EQ(alphabet.size(), 10);
        ASSERT_TRUE(are_identical(alphabet, Alphabet("9876543210")));
        ASSERT_TRUE(are_exclusive(alphabet, Alphabet(kCharsetLettersLowercase)));
        ASSERT_FALSE(are_exclusive(alphabet, Alphabet("%*&5@()")));
    }
    {
        Alphabet alphabet(kCharsetLettersLowercase);
        ASSERT_EQ(alphabet.size(), 26);
        ASSERT_TRUE(are_identical(alphabet, Alphabet("zyxwvutsrqponmlkjihgfedcba")));
        ASSERT_TRUE(are_exclusive(alphabet, Alphabet(kCharsetLettersUppercase)));
        ASSERT_FALSE(are_exclusive(alphabet, Alphabet("%*&f@()")));
    }
    {
        Alphabet alphabet(kCharsetNumbers + kCharsetLettersLowercase + kCharsetLettersUppercase);
        ASSERT_EQ(alphabet.size(), 62);
        ASSERT_TRUE(
                are_identical(alphabet, Alphabet("uZo1rXjk45lVdzeAqiBwOsHfMWPQL8TSxGapchgKCItU27m6JEYbFRnNy3v09D")));
        ASSERT_TRUE(are_exclusive(alphabet, Alphabet("%*&?[]<>@()")));
        ASSERT_FALSE(are_exclusive(alphabet, Alphabet("%*&J@()")));
    }
    {
        ASSERT_THROW(Alphabet(string(257, 'a')), invalid_argument);
        ASSERT_THROW(Alphabet("aa"), invalid_argument);
    }
}

TEST(AlphabetTest, CharDigitConversion) {
    {
        AlphabetInternal alphabet(kCharsetNumbers);
        ASSERT_EQ(alphabet.to_digit('0'), 0);
        ASSERT_EQ(alphabet.to_digit('1'), 1);
        ASSERT_EQ(alphabet.to_digit('2'), 2);
        ASSERT_EQ(alphabet.to_digit('3'), 3);
        ASSERT_EQ(alphabet.to_digit('4'), 4);
        ASSERT_EQ(alphabet.to_digit('5'), 5);
        ASSERT_EQ(alphabet.to_digit('6'), 6);
        ASSERT_EQ(alphabet.to_digit('7'), 7);
        ASSERT_EQ(alphabet.to_digit('8'), 8);
        ASSERT_EQ(alphabet.to_digit('9'), 9);
        ASSERT_FALSE(alphabet.validate('\0'));
        ASSERT_FALSE(alphabet.validate('a'));
        ASSERT_TRUE(alphabet.validate('0'));
        ASSERT_FALSE(alphabet.validate(kCharsetLettersLowercase));
        ASSERT_TRUE(alphabet.validate(kCharsetNumbers));
    }
    {
        AlphabetInternal alphabet(kCharsetLettersLowercase);
        ASSERT_EQ(alphabet.radix(), 26);
        ASSERT_EQ(alphabet.to_digit('a'), 0);
        ASSERT_EQ(alphabet.to_digit('b'), 1);
        ASSERT_EQ(alphabet.to_digit('c'), 2);
        ASSERT_EQ(alphabet.to_digit('d'), 3);
        ASSERT_EQ(alphabet.to_digit('e'), 4);
        ASSERT_EQ(alphabet.to_digit('f'), 5);
        ASSERT_EQ(alphabet.to_digit('g'), 6);
        ASSERT_EQ(alphabet.to_digit('h'), 7);
        ASSERT_EQ(alphabet.to_digit('i'), 8);
        ASSERT_EQ(alphabet.to_digit('j'), 9);
        ASSERT_EQ(alphabet.to_digit('k'), 10);
        ASSERT_EQ(alphabet.to_digit('l'), 11);
        ASSERT_EQ(alphabet.to_digit('m'), 12);
        ASSERT_EQ(alphabet.to_digit('n'), 13);
        ASSERT_EQ(alphabet.to_digit('o'), 14);
        ASSERT_EQ(alphabet.to_digit('p'), 15);
        ASSERT_EQ(alphabet.to_digit('q'), 16);
        ASSERT_EQ(alphabet.to_digit('r'), 17);
        ASSERT_EQ(alphabet.to_digit('s'), 18);
        ASSERT_EQ(alphabet.to_digit('t'), 19);
        ASSERT_EQ(alphabet.to_digit('u'), 20);
        ASSERT_EQ(alphabet.to_digit('v'), 21);
        ASSERT_EQ(alphabet.to_digit('w'), 22);
        ASSERT_EQ(alphabet.to_digit('x'), 23);
        ASSERT_EQ(alphabet.to_digit('y'), 24);
        ASSERT_EQ(alphabet.to_digit('z'), 25);
        ASSERT_FALSE(alphabet.validate('\0'));
        ASSERT_FALSE(alphabet.validate('0'));
        ASSERT_TRUE(alphabet.validate('a'));
        ASSERT_FALSE(alphabet.validate(kCharsetNumbers));
        ASSERT_TRUE(alphabet.validate(kCharsetLettersLowercase));
    }
    {
        AlphabetInternal alphabet(kCharsetLettersUppercase + kCharsetNumbers + kCharsetLettersLowercase);
        ASSERT_EQ(alphabet.to_digit('3'), 3);
        ASSERT_EQ(alphabet.to_digit('8'), 8);
        ASSERT_EQ(alphabet.to_digit('E'), 14);
        ASSERT_EQ(alphabet.to_digit('T'), 29);
        ASSERT_EQ(alphabet.to_digit('i'), 44);
        ASSERT_EQ(alphabet.to_digit('u'), 56);
        ASSERT_FALSE(alphabet.validate('\0'));
        ASSERT_FALSE(alphabet.validate('%'));
        ASSERT_TRUE(alphabet.validate('a'));
        ASSERT_FALSE(alphabet.validate("%*&"));
        ASSERT_TRUE(alphabet.validate(kCharsetLettersUppercase));
        ASSERT_TRUE(alphabet.validate(kCharsetNumbers));
        ASSERT_TRUE(alphabet.validate(kCharsetLettersLowercase));
    }
}

TEST(AlphabetTest, CharDigitSequenceConversion) {
    {
        AlphabetInternal alphabet(kCharsetLettersUppercase + kCharsetNumbers + kCharsetLettersLowercase);
        vector<uint32_t> digit_seq;
        ASSERT_THROW(alphabet.to_digit("Ei3!Tu8", digit_seq), invalid_argument);
        alphabet.to_digit("Ei3Tu8", digit_seq);
        ASSERT_EQ(digit_seq, vector<uint32_t>({14, 44, 3, 29, 56, 8}));
        string char_seq;
        ASSERT_THROW(alphabet.to_char(vector<uint32_t>({14, 44, 3, 63, 29, 56, 8}), char_seq), invalid_argument);
        alphabet.to_char(vector<uint32_t>({14, 44, 3, 29, 56, 8}), char_seq);
        ASSERT_EQ(char_seq, "Ei3Tu8");
    }
    {
        AlphabetInternal alphabet(kCharsetLettersUppercase + kCharsetNumbers + kCharsetLettersLowercase);
        vector<uint32_t> digit_seq;
        string schema;
        alphabet.to_digit("&Ei3!Tu8#", schema, digit_seq);
        ASSERT_EQ(schema[0], '&');
        ASSERT_EQ(schema[1], '\0');
        ASSERT_EQ(schema[2], '\0');
        ASSERT_EQ(schema[3], '\0');
        ASSERT_EQ(schema[4], '!');
        ASSERT_EQ(schema[5], '\0');
        ASSERT_EQ(schema[6], '\0');
        ASSERT_EQ(schema[7], '\0');
        ASSERT_EQ(schema[8], '#');
        ASSERT_EQ(digit_seq, vector<uint32_t>({14, 44, 3, 29, 56, 8}));
        string char_seq;
        ASSERT_THROW(
                alphabet.to_char(vector<uint32_t>({14, 44, 3, 29, 56, 8}), schema + '\0', char_seq), invalid_argument);
        ASSERT_THROW(
                alphabet.to_char(vector<uint32_t>({14, 44, 3, 29, 56, 8, 15}), schema, char_seq), invalid_argument);
        ASSERT_THROW(
                alphabet.to_char(vector<uint32_t>({14, 44, 3, 63, 29, 56, 8}), schema, char_seq), invalid_argument);
        alphabet.to_char(vector<uint32_t>({14, 44, 3, 29, 56, 8}), schema, char_seq);
        ASSERT_EQ(char_seq, "&Ei3!Tu8#");
    }
}

TEST(KeyTest, Constructor) {
    { Key key(); }
    { Key key = generate_key(); }
    { Key key({0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C}); }
}

TEST(TweakTest, Constructor) {
    {
        vector<unsigned char> tweak_vec = {0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30};
        Tweak tweak(tweak_vec);
    }
    {
        string tweak_str = {0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30};
        Tweak tweak(tweak_str);
    }
    { Tweak tweak(); }
}

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF1samples.pdf.
TEST(FPETest, EncryptDecrypt) {
    {
        Alphabet alphabet(kCharsetNumbers);
        string pt = "0123456789";
        string ct;
        string pt_check;
        vector<unsigned char> tweak;
        Key key({0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C});
        encrypt(alphabet, key, tweak, pt, ct);
        ASSERT_EQ(ct, "2433477484");
        decrypt(alphabet, key, tweak, ct, pt_check);
        ASSERT_EQ(pt_check, "0123456789");
    }
    {
        Alphabet alphabet(kCharsetNumbers);
        string pt = "0123456789";
        string ct;
        string pt_check;
        vector<unsigned char> tweak = {0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30};
        Key key({0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C});
        encrypt(alphabet, key, tweak, pt, ct);
        ASSERT_EQ(ct, "6124200773");
        decrypt(alphabet, key, tweak, ct, pt_check);
        ASSERT_EQ(pt_check, "0123456789");
    }
    {
        Alphabet alphabet(kCharsetNumbers + kCharsetLettersLowercase);
        string pt = "0123456789abcdefghi";
        string ct;
        string pt_check;
        vector<unsigned char> tweak = {0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37};
        Key key({0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C});
        encrypt(alphabet, key, tweak, pt, ct);
        ASSERT_EQ(ct, "a9tv40mll9kdu509eum");
        decrypt(alphabet, key, tweak, ct, pt_check);
        ASSERT_EQ(pt_check, "0123456789abcdefghi");
    }
    {
        Alphabet alphabet(kCharsetNumbers);
        string pt(128, '9');
        string ct;
        string pt_check;
        vector<unsigned char> tweak = {0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37};
        Key key({0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C});
        encrypt(alphabet, key, tweak, pt, ct);
        decrypt(alphabet, key, tweak, ct, pt_check);
        ASSERT_EQ(pt_check, pt);
    }
    {
        Alphabet alphabet(kCharsetNumbers);
        string ct;
        vector<unsigned char> tweak;
        Key key({0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C});
        ASSERT_THROW(encrypt(Alphabet("x"), key, tweak, "xxxxxx", ct), invalid_argument);
        ASSERT_THROW(encrypt(alphabet, key, tweak, "1", ct), invalid_argument);
        ASSERT_THROW(encrypt(alphabet, key, tweak, "1234", ct), invalid_argument);
        ASSERT_THROW(encrypt(alphabet, key, tweak, "1234abc", ct), invalid_argument);
        ASSERT_THROW(encrypt(alphabet, key, tweak, "SF3741-NE32:F22", ct), invalid_argument);
    }
}

TEST(FPETest, EncryptDecryptSkipUnsupported) {
    {
        Alphabet alphabet(kCharsetNumbers);
        string pt = "SF3741-NE32:F22";
        string ct;
        string pt_check;
        vector<unsigned char> tweak;
        Key key({0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C});
        encrypt_skip_unsupported(alphabet, key, tweak, pt, ct);
        ASSERT_EQ(ct, "SF2639-NE49:F99");
        decrypt_skip_unsupported(alphabet, key, tweak, ct, pt_check);
        ASSERT_EQ(pt_check, pt);
    }
    {
        Alphabet alphabet(kCharsetNumbers);
        string pt = "01234-56789";
        string ct;
        string pt_check;
        vector<unsigned char> tweak;
        Key key({0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C});
        encrypt_skip_unsupported(alphabet, key, tweak, pt, ct);
        ASSERT_EQ(ct, "24334-77484");
        decrypt_skip_unsupported(alphabet, key, tweak, ct, pt_check);
        ASSERT_EQ(pt_check, "01234-56789");
    }
    {
        Alphabet alphabet(kCharsetNumbers);
        string pt = "01234@56789";
        string ct;
        string pt_check;
        vector<unsigned char> tweak = {0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30};
        Key key({0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C});
        encrypt_skip_unsupported(alphabet, key, tweak, pt, ct);
        ASSERT_EQ(ct, "61242@00773");
        decrypt_skip_unsupported(alphabet, key, tweak, ct, pt_check);
        ASSERT_EQ(pt_check, "01234@56789");
    }
    {
        Alphabet alphabet(kCharsetNumbers + kCharsetLettersLowercase);
        string pt = "01234-56789@abcdefghi";
        string ct;
        string pt_check;
        vector<unsigned char> tweak = {0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37};
        Key key({0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C});
        encrypt_skip_unsupported(alphabet, key, tweak, pt, ct);
        ASSERT_EQ(ct, "a9tv4-0mll9@kdu509eum");
        decrypt_skip_unsupported(alphabet, key, tweak, ct, pt_check);
        ASSERT_EQ(pt_check, "01234-56789@abcdefghi");
    }
}

TEST(FPETest, EncryptDecryptSkipSpecified) {
    {
        Alphabet alphabet(kCharsetNumbers);
        Alphabet specification(kCharsetLettersUppercase + "-:");
        string pt = "SF3741-NE32:F22";
        string ct;
        string pt_check;
        vector<unsigned char> tweak;
        Key key({0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C});
        encrypt_skip_specified(alphabet, specification, key, tweak, pt, ct);
        ASSERT_EQ(ct, "SF2639-NE49:F99");
        decrypt_skip_specified(alphabet, specification, key, tweak, ct, pt_check);
        ASSERT_EQ(pt_check, pt);
    }
    {
        Alphabet alphabet(kCharsetNumbers + kCharsetLettersUppercase);
        Alphabet specification("-:");
        string pt = "SF3741-NE32:F22";
        string ct;
        string pt_check;
        vector<unsigned char> tweak;
        Key key({0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C});
        encrypt_skip_specified(alphabet, specification, key, tweak, pt, ct);
        ASSERT_EQ(ct, "5RMWCT-3E5R:2HI");
        decrypt_skip_specified(alphabet, specification, key, tweak, ct, pt_check);
        ASSERT_EQ(pt_check, pt);
    }
    {
        Alphabet alphabet(kCharsetNumbers);
        Alphabet specified("-");
        string pt = "01234-56789";
        string ct;
        string pt_check;
        vector<unsigned char> tweak;
        Key key({0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C});
        encrypt_skip_specified(alphabet, specified, key, tweak, pt, ct);
        ASSERT_EQ(ct, "24334-77484");
        decrypt_skip_specified(alphabet, specified, key, tweak, ct, pt_check);
        ASSERT_EQ(pt_check, "01234-56789");
    }
    {
        Alphabet alphabet(kCharsetNumbers);
        Alphabet specified(kCharsetLettersLowercase);
        string pt = "01234abc56789";
        string ct;
        string pt_check;
        vector<unsigned char> tweak = {0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30};
        Key key({0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C});
        encrypt_skip_specified(alphabet, specified, key, tweak, pt, ct);
        ASSERT_EQ(ct, "61242abc00773");
        decrypt_skip_specified(alphabet, specified, key, tweak, ct, pt_check);
        ASSERT_EQ(pt_check, "01234abc56789");
    }
    {
        Alphabet alphabet(kCharsetNumbers + kCharsetLettersLowercase);
        Alphabet specified("ABCD-@");
        string pt = "01234-56789@ABCabcdefghi";
        string ct;
        string pt_check;
        vector<unsigned char> tweak = {0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37};
        Key key({0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C});
        encrypt_skip_specified(alphabet, specified, key, tweak, pt, ct);
        ASSERT_EQ(ct, "a9tv4-0mll9@ABCkdu509eum");
        decrypt_skip_specified(alphabet, specified, key, tweak, ct, pt_check);
        ASSERT_EQ(pt_check, "01234-56789@ABCabcdefghi");
    }
    {
        Alphabet alphabet(kCharsetNumbers);
        Alphabet specification(kCharsetLettersUppercase);
        string pt = "SF3741-NE32:F22";
        string ct;
        string pt_check;
        vector<unsigned char> tweak;
        Key key({0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C});
        ASSERT_THROW(encrypt_skip_specified(alphabet, specification, key, tweak, pt, ct), invalid_argument);
    }
    {
        Alphabet alphabet(kCharsetNumbers);
        Alphabet specification(kCharsetLettersUppercase + kCharsetNumbers);
        string pt = "SF3741-NE32:F22";
        string ct;
        string pt_check;
        vector<unsigned char> tweak;
        Key key({0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C});
        ASSERT_THROW(encrypt_skip_specified(alphabet, specification, key, tweak, pt, ct), invalid_argument);
    }
}

}  // namespace shadowtest

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

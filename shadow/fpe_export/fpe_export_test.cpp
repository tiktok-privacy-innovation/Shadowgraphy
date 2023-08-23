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

#include "shadow/fpe_export/fpe_export.h"

#include <iostream>

#include "gtest/gtest.h"

namespace shadowtest {

TEST(FPEBytesTest, fpe_alphabet_new) {
    char str[] = "0123456789";
    FPEBytes charset;
    charset.data = str;
    charset.len = strlen(str);
    FPEStatus status = S_FALSE;

    FPEAlphabet* alphabet = fpe_alphabet_new(&charset, &status);
    EXPECT_EQ(status, S_OK);

    std::size_t size = 0;
    status = fpe_alphabet_size(alphabet, &size);
    EXPECT_EQ(charset.len, size);

    status = fpe_alphabet_free(alphabet);
    EXPECT_EQ(status, S_OK);
}

TEST(FPEBytesTest, fpe_alphabet_are_identical) {
    char str0[] = "0123456789";
    char str1[] = "9876543210";
    char str2[] = "abcd";
    FPEBytes charset0;
    charset0.data = str0;
    charset0.len = strlen(str0);
    FPEBytes charset1;
    charset1.data = str1;
    charset1.len = strlen(str1);
    FPEBytes charset2;
    charset2.data = str2;
    charset2.len = strlen(str2);

    FPEStatus status = S_FALSE;

    FPEAlphabet* alphabet0 = fpe_alphabet_new(&charset0, &status);
    EXPECT_EQ(status, S_OK);
    FPEAlphabet* alphabet1 = fpe_alphabet_new(&charset1, &status);
    EXPECT_EQ(status, S_OK);
    FPEAlphabet* alphabet2 = fpe_alphabet_new(&charset2, &status);
    EXPECT_EQ(status, S_OK);

    bool result;
    fpe_alphabet_are_identical(alphabet0, alphabet1, &result);
    EXPECT_EQ(result, true);
    fpe_alphabet_are_identical(alphabet0, alphabet2, &result);
    EXPECT_EQ(result, false);
    fpe_alphabet_are_exclusive(alphabet0, alphabet2, &result);
    EXPECT_EQ(result, true);

    status = fpe_alphabet_free(alphabet0);
    EXPECT_EQ(status, S_OK);
    status = fpe_alphabet_free(alphabet1);
    EXPECT_EQ(status, S_OK);
    status = fpe_alphabet_free(alphabet2);
    EXPECT_EQ(status, S_OK);
}

TEST(FPEBytesTest, fpe_key_new) {
    FPEStatus status = S_FALSE;

    FPEKey* key0 = fpe_key_new(&status);
    EXPECT_EQ(status, S_OK);

    FPEKey* key1 = fpe_key_new(&status);
    EXPECT_EQ(status, S_OK);

    status = fpe_key_generate(key0);
    EXPECT_EQ(status, S_OK);

    std::vector<char> buffer0(16, 0);
    std::vector<char> buffer1(16, 0);
    FPEBytes bytes0;
    bytes0.data = buffer0.data();
    bytes0.len = buffer0.size();

    status = fpe_key_to_bytes(key0, &bytes0);
    EXPECT_EQ(status, S_OK);
    EXPECT_NE(buffer0, buffer1);

    status = fpe_key_from_bytes(key1, &bytes0);
    EXPECT_EQ(status, S_OK);

    FPEBytes bytes1;
    bytes1.data = buffer1.data();
    bytes1.len = buffer1.size();

    status = fpe_key_to_bytes(key1, &bytes1);
    EXPECT_EQ(status, S_OK);
    EXPECT_EQ(buffer0, buffer1);

    status = fpe_key_free(key0);
    EXPECT_EQ(status, S_OK);

    status = fpe_key_free(key1);
    EXPECT_EQ(status, S_OK);
}

TEST(FPEBytesTest, fpe_tweak_new) {
    std::vector<char> buffer = {0, 1, 2, 3};

    FPEStatus status = S_FALSE;

    FPETweak* tweak = fpe_tweak_new(&status);
    EXPECT_EQ(status, S_OK);
    EXPECT_NE(*reinterpret_cast<std::vector<char>*>(tweak), buffer);

    FPEBytes bytes;
    bytes.data = buffer.data();
    bytes.len = buffer.size();

    status = fpe_tweak_fill(tweak, &bytes);
    EXPECT_EQ(status, S_OK);
    EXPECT_EQ(*reinterpret_cast<std::vector<char>*>(tweak), buffer);

    status = fpe_tweak_free(tweak);
    EXPECT_EQ(status, S_OK);
}

TEST(FPEBytesTest, encrypt_decrypt) {
    char charset_chr[] = "0123456789";
    FPEBytes charset;
    charset.data = charset_chr;
    charset.len = strlen(charset_chr);
    FPEStatus status = S_FALSE;

    FPEAlphabet* alphabet = fpe_alphabet_new(&charset, &status);
    EXPECT_EQ(status, S_OK);

    char pt_str[] = "0123456789";
    FPEBytes pt;
    pt.data = pt_str;
    pt.len = strlen(pt_str);

    std::vector<char> ct_buffer(strlen(pt_str), 0);
    FPEBytes ct;
    ct.data = ct_buffer.data();
    ct.len = ct_buffer.size();

    std::vector<unsigned char> test_key_buffer = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
    FPEBytes key_bytes;
    key_bytes.data = reinterpret_cast<char*>(test_key_buffer.data());
    key_bytes.len = test_key_buffer.size();

    FPEKey* key = fpe_key_new(&status);
    EXPECT_EQ(status, S_OK);
    status = fpe_key_from_bytes(key, &key_bytes);
    EXPECT_EQ(status, S_OK);

    FPETweak* tweak = fpe_tweak_new(&status);
    EXPECT_EQ(status, S_OK);

    status = fpe_encrypt(alphabet, key, tweak, &pt, &ct);
    EXPECT_EQ(status, S_OK);

    std::string ct_str(ct.data, ct.len);
    EXPECT_EQ(ct_str, "2433477484");

    std::vector<char> pt_check_buffer(strlen(pt_str), 0);
    FPEBytes pt_check;
    pt_check.data = pt_check_buffer.data();
    pt_check.len = pt_check_buffer.size();

    status = fpe_decrypt(alphabet, key, tweak, &ct, &pt_check);

    std::string pt_check_str(pt_check.data, pt_check.len);
    EXPECT_EQ(pt_check_str, "0123456789");

    status = fpe_alphabet_free(alphabet);
    EXPECT_EQ(status, S_OK);
    status = fpe_key_free(key);
    EXPECT_EQ(status, S_OK);
    status = fpe_tweak_free(tweak);
    EXPECT_EQ(status, S_OK);
}

TEST(FPEBytesTest, encrypt_decrypt_skip_unsupported) {
    char charset_chr[] = "0123456789";
    FPEBytes charset;
    charset.data = charset_chr;
    charset.len = strlen(charset_chr);
    FPEStatus status = S_FALSE;

    FPEAlphabet* alphabet = fpe_alphabet_new(&charset, &status);
    EXPECT_EQ(status, S_OK);

    char pt_str[] = "01234@56789";
    FPEBytes pt;
    pt.data = pt_str;
    pt.len = strlen(pt_str);

    std::vector<char> ct_buffer(strlen(pt_str), 0);
    FPEBytes ct;
    ct.data = ct_buffer.data();
    ct.len = ct_buffer.size();

    std::vector<unsigned char> test_key_buffer = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
    FPEBytes key_bytes;
    key_bytes.data = reinterpret_cast<char*>(test_key_buffer.data());
    key_bytes.len = test_key_buffer.size();

    FPEKey* key = fpe_key_new(&status);
    EXPECT_EQ(status, S_OK);
    status = fpe_key_from_bytes(key, &key_bytes);
    EXPECT_EQ(status, S_OK);

    FPETweak* tweak = fpe_tweak_new(&status);
    EXPECT_EQ(status, S_OK);

    status = fpe_encrypt_skip_unsupported(alphabet, key, tweak, &pt, &ct);
    EXPECT_EQ(status, S_OK);

    std::string ct_str(ct.data, ct.len);
    EXPECT_EQ(ct_str, "24334@77484");

    std::vector<char> pt_check_buffer(strlen(pt_str), 0);
    FPEBytes pt_check;
    pt_check.data = pt_check_buffer.data();
    pt_check.len = pt_check_buffer.size();

    status = fpe_decrypt_skip_unsupported(alphabet, key, tweak, &ct, &pt_check);

    std::string pt_check_str(pt_check.data, pt_check.len);
    EXPECT_EQ(pt_check_str, "01234@56789");

    status = fpe_alphabet_free(alphabet);
    EXPECT_EQ(status, S_OK);
    status = fpe_key_free(key);
    EXPECT_EQ(status, S_OK);
    status = fpe_tweak_free(tweak);
    EXPECT_EQ(status, S_OK);
}

TEST(FPEBytesTest, encrypt_decrypt_skip_specified) {
    char charset_chr[] = "0123456789";
    FPEBytes charset;
    charset.data = charset_chr;
    charset.len = strlen(charset_chr);
    FPEStatus status = S_FALSE;

    FPEAlphabet* alphabet = fpe_alphabet_new(&charset, &status);
    EXPECT_EQ(status, S_OK);

    char specified_chr[] = "-@";
    FPEBytes specified;
    specified.data = specified_chr;
    specified.len = strlen(specified_chr);

    FPEAlphabet* specification = fpe_alphabet_new(&specified, &status);
    EXPECT_EQ(status, S_OK);

    char pt_str[] = "01234-56789";
    FPEBytes pt;
    pt.data = pt_str;
    pt.len = strlen(pt_str);

    std::vector<char> ct_buffer(strlen(pt_str), 0);
    FPEBytes ct;
    ct.data = ct_buffer.data();
    ct.len = ct_buffer.size();

    std::vector<unsigned char> test_key_buffer = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
    FPEBytes key_bytes;
    key_bytes.data = reinterpret_cast<char*>(test_key_buffer.data());
    key_bytes.len = test_key_buffer.size();

    FPEKey* key = fpe_key_new(&status);
    EXPECT_EQ(status, S_OK);
    status = fpe_key_from_bytes(key, &key_bytes);
    EXPECT_EQ(status, S_OK);

    FPETweak* tweak = fpe_tweak_new(&status);
    EXPECT_EQ(status, S_OK);

    status = fpe_encrypt_skip_specified(alphabet, specification, key, tweak, &pt, &ct);
    EXPECT_EQ(status, S_OK);

    std::string ct_str(ct.data, ct.len);
    EXPECT_EQ(ct_str, "24334-77484");

    std::vector<char> pt_check_buffer(strlen(pt_str), 0);
    FPEBytes pt_check;
    pt_check.data = pt_check_buffer.data();
    pt_check.len = pt_check_buffer.size();

    status = fpe_decrypt_skip_specified(alphabet, specification, key, tweak, &ct, &pt_check);

    std::string pt_check_str(pt_check.data, pt_check.len);
    EXPECT_EQ(pt_check_str, "01234-56789");

    status = fpe_alphabet_free(alphabet);
    EXPECT_EQ(status, S_OK);
    status = fpe_alphabet_free(specification);
    EXPECT_EQ(status, S_OK);
    status = fpe_key_free(key);
    EXPECT_EQ(status, S_OK);
    status = fpe_tweak_free(tweak);
    EXPECT_EQ(status, S_OK);
}

}  // namespace shadowtest

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

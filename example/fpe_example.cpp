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

#include <iostream>
#include <string>
#include <vector>

#include "shadow/fpe/fpe.h"
#include "shadow/fpe/fpe_internal.h"

int main(int argc, char** argv) {
    // Example 1: credit card number
    shadow::fpe::Alphabet alphabet(shadow::fpe::kCharsetNumbers);
    std::string pt = "4263982640269299";
    std::string ct;
    std::string pt_check;
    shadow::fpe::Key key(
            {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C});
    shadow::fpe::encrypt(alphabet, key, shadow::fpe::Tweak(), pt, ct);
    shadow::fpe::decrypt(alphabet, key, shadow::fpe::Tweak(), ct, pt_check);
    std::cout << "Example 1: encrypt credit card numbers" << std::endl;
    std::cout << "  message    : " << pt << std::endl;
    std::cout << "  encryption : " << ct << std::endl;
    std::cout << "  decryption : " << pt_check << std::endl;
    std::cout << std::endl;

    // Example 2: credit card number with tweaks
    // use first 4 digits and last 6 digits as tweak, and encrypt middle 6 digits
    std::string pt_middle_six = pt.substr(6, 6);
    shadow::fpe::Tweak tweak_remaining_ten(pt.substr(0, 6) + pt.substr(12, 4));
    shadow::fpe::encrypt(alphabet, key, tweak_remaining_ten, pt_middle_six, ct);
    shadow::fpe::decrypt(alphabet, key, tweak_remaining_ten, ct, pt_check);
    std::cout << "Example 2: encrypt credit card numbers with tweaks" << std::endl;
    std::cout << "  message    : " << pt_middle_six << std::endl;
    std::cout << "  encryption : " << ct << std::endl;
    std::cout << "  decryption : " << pt_check << std::endl;
    std::cout << std::endl;

    // Example 3: encrypt an email address as a string.
    shadow::fpe::Alphabet alphabet_email_1(shadow::fpe::kCharsetNumbers + shadow::fpe::kCharsetLettersLowercase + "@.");
    std::string pt_email = "my.personal.email@hotmail.com";
    shadow::fpe::encrypt(alphabet_email_1, key, shadow::fpe::Tweak(), pt_email, ct);
    shadow::fpe::decrypt(alphabet_email_1, key, shadow::fpe::Tweak(), ct, pt_check);
    std::cout << "Example 3: encrypt email addresses as strings" << std::endl;
    std::cout << "  message    : " << pt_email << std::endl;
    std::cout << "  encryption : " << ct << std::endl;
    std::cout << "  decryption : " << pt_check << std::endl;
    std::cout << std::endl;

    // Example 4: encrypt email addresses
    // encrypt all numbers and characters, but leave '@' and '.' as it is.
    shadow::fpe::Alphabet alphabet_email_2(shadow::fpe::kCharsetNumbers + shadow::fpe::kCharsetLettersLowercase);
    shadow::fpe::encrypt_skip_unsupported(alphabet_email_2, key, shadow::fpe::Tweak(), pt_email, ct);
    shadow::fpe::decrypt_skip_unsupported(alphabet_email_2, key, shadow::fpe::Tweak(), ct, pt_check);
    std::cout << "Example 4: encrypt email addresses and preserve email address format" << std::endl;
    std::cout << "  message    : " << pt_email << std::endl;
    std::cout << "  encryption : " << ct << std::endl;
    std::cout << "  decryption : " << pt_check << std::endl;
    std::cout << std::endl;

    // Example 5: encrypt email addresses
    // encrypt only the parts before '@', and use the rest as tweak.
    std::string pt_email_prefix = "my.personal.email";
    shadow::fpe::Tweak tweak_email("@hotmail.com");
    shadow::fpe::encrypt_skip_unsupported(alphabet_email_2, key, tweak_email, pt_email_prefix, ct);
    shadow::fpe::decrypt_skip_unsupported(alphabet_email_2, key, tweak_email, ct, pt_check);
    std::cout << "Example 5: encrypt email addresses with tweaks" << std::endl;
    std::cout << "  message    : " << pt_email_prefix << std::endl;
    std::cout << "  encryption : " << ct << std::endl;
    std::cout << "  decryption : " << pt_check << std::endl;
    std::cout << std::endl;

    // Example 6: encrypt physical addresses
    // Leave the space and comma as it is, and encrypt the rest.
    shadow::fpe::Alphabet alphabet_address(shadow::fpe::kCharsetNumbers + shadow::fpe::kCharsetLettersLowercase);
    std::string pt_address = "6666 fpe avenue , san jose, ca, 94000";
    shadow::fpe::encrypt_skip_unsupported(alphabet_address, key, shadow::fpe::Tweak(), pt_address, ct);
    shadow::fpe::decrypt_skip_unsupported(alphabet_address, key, shadow::fpe::Tweak(), ct, pt_check);
    std::cout << "Example 6: encrypt physical addresses" << std::endl;
    std::cout << "  message    : " << pt_address << std::endl;
    std::cout << "  encryption : " << ct << std::endl;
    std::cout << "  decryption : " << pt_check << std::endl;
    std::cout << std::endl;

    // Example 7: encrypt physical addresses
    // the encryptions of digits are still digits, the encryptions of letters remain letters
    std::string ct_temp;
    shadow::fpe::encrypt_skip_unsupported(
            shadow::fpe::Alphabet(shadow::fpe::kCharsetNumbers), key, shadow::fpe::Tweak(), pt_address, ct_temp);
    shadow::fpe::encrypt_skip_unsupported(
            shadow::fpe::Alphabet(shadow::fpe::kCharsetLettersLowercase), key, shadow::fpe::Tweak(), ct_temp, ct);
    std::cout << "Example 7: encrypt physical addresses and preserve the format of street numbers and zip codes"
              << std::endl;
    std::cout << "  message    : " << pt_address << std::endl;
    std::cout << "  encryption : " << ct << std::endl;

    return 0;
}

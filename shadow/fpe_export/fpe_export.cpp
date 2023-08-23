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

#include <stdint.h>

#include <algorithm>
#include <iostream>
#include <stdexcept>

#include "shadow/fpe/fpe.h"

FPEAlphabet* fpe_alphabet_new(FPEBytes* charset, FPEStatus* status) {
    if (charset == nullptr || status == nullptr) {
        *status = E_POINTER;
        return nullptr;
    }
    try {
        std::string charset_str(charset->data, charset->len);
        shadow::fpe::Alphabet* t_alphabet = new shadow::fpe::Alphabet(charset_str);
        *status = S_OK;
        return reinterpret_cast<FPEAlphabet*>(t_alphabet);
    } catch (const std::invalid_argument&) {
        *status = E_INVALIDARG;
        return nullptr;
    }
}

FPEStatus fpe_alphabet_free(FPEAlphabet* alphabet) {
    if (alphabet == nullptr) {
        return E_POINTER;
    }
    shadow::fpe::Alphabet* t_alphabet = reinterpret_cast<shadow::fpe::Alphabet*>(alphabet);
    delete t_alphabet;
    return S_OK;
}

FPEStatus fpe_alphabet_size(FPEAlphabet* alphabet, size_t* size) {
    if (alphabet == nullptr || size == nullptr) {
        return E_POINTER;
    }
    shadow::fpe::Alphabet* t_alphabet = reinterpret_cast<shadow::fpe::Alphabet*>(alphabet);
    *size = t_alphabet->size();
    return S_OK;
}

FPEStatus fpe_alphabet_are_identical(FPEAlphabet* alphabet_0, FPEAlphabet* alphabet_1, bool* result) {
    if (alphabet_0 == nullptr || alphabet_1 == nullptr || result == nullptr) {
        return E_POINTER;
    }
    shadow::fpe::Alphabet* t_alphabet_0 = reinterpret_cast<shadow::fpe::Alphabet*>(alphabet_0);
    shadow::fpe::Alphabet* t_alphabet_1 = reinterpret_cast<shadow::fpe::Alphabet*>(alphabet_1);

    *result = shadow::fpe::are_identical(*t_alphabet_0, *t_alphabet_1);
    return S_OK;
}

FPEStatus fpe_alphabet_are_exclusive(FPEAlphabet* alphabet_0, FPEAlphabet* alphabet_1, bool* result) {
    if (alphabet_0 == nullptr || alphabet_1 == nullptr || result == nullptr) {
        return E_POINTER;
    }
    shadow::fpe::Alphabet* t_alphabet_0 = reinterpret_cast<shadow::fpe::Alphabet*>(alphabet_0);
    shadow::fpe::Alphabet* t_alphabet_1 = reinterpret_cast<shadow::fpe::Alphabet*>(alphabet_1);

    *result = shadow::fpe::are_exclusive(*t_alphabet_0, *t_alphabet_1);
    return S_OK;
}

FPEKey* fpe_key_new(FPEStatus* status) {
    if (status == nullptr) {
        *status = E_POINTER;
        return nullptr;
    }
    shadow::fpe::Key* t_key = new shadow::fpe::Key();
    *status = S_OK;
    return reinterpret_cast<FPEKey*>(t_key);
}

FPEStatus fpe_key_free(FPEKey* key) {
    if (key == nullptr) {
        return E_POINTER;
    }
    shadow::fpe::Key* t_key = reinterpret_cast<shadow::fpe::Key*>(key);
    delete t_key;
    return S_OK;
}

FPEStatus fpe_key_from_bytes(FPEKey* key, FPEBytes* bytes) {
    if (key == nullptr || bytes == nullptr) {
        return E_POINTER;
    }
    if (bytes->len != SHADOW_FPE_KEY_BYTE_COUNT) {
        return E_INVALIDARG;
    }
    shadow::fpe::Key* t_key = reinterpret_cast<shadow::fpe::Key*>(key);
    std::copy_n(bytes->data, SHADOW_FPE_KEY_BYTE_COUNT, t_key->data());
    return S_OK;
}

FPEStatus fpe_key_to_bytes(FPEKey* key, FPEBytes* bytes) {
    if (key == nullptr || bytes == nullptr) {
        return E_POINTER;
    }
    if (bytes->len != SHADOW_FPE_KEY_BYTE_COUNT) {
        return E_INVALIDARG;
    }
    shadow::fpe::Key* t_key = reinterpret_cast<shadow::fpe::Key*>(key);
    std::copy_n(t_key->data(), SHADOW_FPE_KEY_BYTE_COUNT, bytes->data);
    return S_OK;
}

FPEStatus fpe_key_generate(FPEKey* key) {
    if (key == nullptr) {
        return E_POINTER;
    }
    // todo[yindong] strange
    shadow::fpe::Key* t_key = reinterpret_cast<shadow::fpe::Key*>(key);
    shadow::fpe::Key tmp_key = shadow::fpe::generate_key();
    std::copy_n(tmp_key.data(), SHADOW_FPE_KEY_BYTE_COUNT, t_key->data());
    return S_OK;
}

FPETweak* fpe_tweak_new(FPEStatus* status) {
    if (status == nullptr) {
        *status = E_POINTER;
        return nullptr;
    }
    shadow::fpe::Tweak* t_tweak = new shadow::fpe::Tweak();
    *status = S_OK;
    return reinterpret_cast<FPETweak*>(t_tweak);
}

FPEStatus fpe_tweak_free(FPETweak* tweak) {
    if (tweak == nullptr) {
        return E_POINTER;
    }
    shadow::fpe::Tweak* t_tweak = reinterpret_cast<shadow::fpe::Tweak*>(tweak);
    delete t_tweak;
    return S_OK;
}

FPEStatus fpe_tweak_fill(FPETweak* tweak, FPEBytes* bytes) {
    if (tweak == nullptr || bytes == nullptr) {
        return E_POINTER;
    }
    shadow::fpe::Tweak* t_tweak = reinterpret_cast<shadow::fpe::Tweak*>(tweak);
    t_tweak->resize(bytes->len);
    std::copy_n(bytes->data, bytes->len, t_tweak->data());
    return S_OK;
}

FPEStatus fpe_encrypt(FPEAlphabet* alphabet, FPEKey* key, FPETweak* tweak, FPEBytes* in, FPEBytes* out) {
    if (alphabet == nullptr || key == nullptr || tweak == nullptr || in == nullptr || out == nullptr) {
        return E_POINTER;
    }
    try {
        shadow::fpe::Alphabet* t_alphabet = reinterpret_cast<shadow::fpe::Alphabet*>(alphabet);
        shadow::fpe::Key* t_key = reinterpret_cast<shadow::fpe::Key*>(key);
        shadow::fpe::Tweak* t_tweak = reinterpret_cast<shadow::fpe::Tweak*>(tweak);
        std::string in_str(in->data, in->len);
        std::string out_str;
        shadow::fpe::encrypt(*t_alphabet, *t_key, *t_tweak, in_str, out_str);
        std::copy_n(out_str.c_str(), out_str.length(), out->data);
        return S_OK;
    } catch (const std::invalid_argument&) {
        return E_INVALIDARG;
    }
}

FPEStatus fpe_decrypt(FPEAlphabet* alphabet, FPEKey* key, FPETweak* tweak, FPEBytes* in, FPEBytes* out) {
    if (alphabet == nullptr || key == nullptr || tweak == nullptr || in == nullptr || out == nullptr) {
        return E_POINTER;
    }
    try {
        shadow::fpe::Alphabet* t_alphabet = reinterpret_cast<shadow::fpe::Alphabet*>(alphabet);
        shadow::fpe::Key* t_key = reinterpret_cast<shadow::fpe::Key*>(key);
        shadow::fpe::Tweak* t_tweak = reinterpret_cast<shadow::fpe::Tweak*>(tweak);
        std::string in_str(in->data, in->len);
        std::string out_str;
        shadow::fpe::decrypt(*t_alphabet, *t_key, *t_tweak, in_str, out_str);
        std::copy_n(out_str.c_str(), out_str.length(), out->data);
        return S_OK;
    } catch (const std::invalid_argument&) {
        return E_INVALIDARG;
    }
}
FPEStatus fpe_encrypt_skip_unsupported(
        FPEAlphabet* alphabet, FPEKey* key, FPETweak* tweak, FPEBytes* in, FPEBytes* out) {
    if (alphabet == nullptr || key == nullptr || tweak == nullptr || in == nullptr || out == nullptr) {
        return E_POINTER;
    }
    try {
        shadow::fpe::Alphabet* t_alphabet = reinterpret_cast<shadow::fpe::Alphabet*>(alphabet);
        shadow::fpe::Key* t_key = reinterpret_cast<shadow::fpe::Key*>(key);
        shadow::fpe::Tweak* t_tweak = reinterpret_cast<shadow::fpe::Tweak*>(tweak);
        std::string in_str(in->data, in->len);
        std::string out_str;
        shadow::fpe::encrypt_skip_unsupported(*t_alphabet, *t_key, *t_tweak, in_str, out_str);
        std::copy_n(out_str.c_str(), out_str.length(), out->data);
        return S_OK;
    } catch (const std::invalid_argument&) {
        return E_INVALIDARG;
    }
}

FPEStatus fpe_decrypt_skip_unsupported(
        FPEAlphabet* alphabet, FPEKey* key, FPETweak* tweak, FPEBytes* in, FPEBytes* out) {
    if (alphabet == nullptr || key == nullptr || tweak == nullptr || in == nullptr || out == nullptr) {
        return E_POINTER;
    }
    try {
        shadow::fpe::Alphabet* t_alphabet = reinterpret_cast<shadow::fpe::Alphabet*>(alphabet);
        shadow::fpe::Key* t_key = reinterpret_cast<shadow::fpe::Key*>(key);
        shadow::fpe::Tweak* t_tweak = reinterpret_cast<shadow::fpe::Tweak*>(tweak);
        std::string in_str(in->data, in->len);
        std::string out_str;
        shadow::fpe::decrypt_skip_unsupported(*t_alphabet, *t_key, *t_tweak, in_str, out_str);
        std::copy_n(out_str.c_str(), out_str.length(), out->data);
        return S_OK;
    } catch (const std::invalid_argument&) {
        return E_INVALIDARG;
    }
}

FPEStatus fpe_encrypt_skip_specified(
        FPEAlphabet* alphabet, FPEAlphabet* specification, FPEKey* key, FPETweak* tweak, FPEBytes* in, FPEBytes* out) {
    if (alphabet == nullptr || specification == nullptr || key == nullptr || tweak == nullptr || in == nullptr ||
            out == nullptr) {
        return E_POINTER;
    }
    try {
        shadow::fpe::Alphabet* t_alphabet = reinterpret_cast<shadow::fpe::Alphabet*>(alphabet);
        shadow::fpe::Alphabet* t_specification = reinterpret_cast<shadow::fpe::Alphabet*>(specification);
        shadow::fpe::Key* t_key = reinterpret_cast<shadow::fpe::Key*>(key);
        shadow::fpe::Tweak* t_tweak = reinterpret_cast<shadow::fpe::Tweak*>(tweak);
        std::string in_str(in->data, in->len);
        std::string out_str;
        shadow::fpe::encrypt_skip_specified(*t_alphabet, *t_specification, *t_key, *t_tweak, in_str, out_str);
        std::copy_n(out_str.c_str(), out_str.length(), out->data);
        return S_OK;
    } catch (const std::invalid_argument&) {
        return E_INVALIDARG;
    }
}

FPEStatus fpe_decrypt_skip_specified(
        FPEAlphabet* alphabet, FPEAlphabet* specification, FPEKey* key, FPETweak* tweak, FPEBytes* in, FPEBytes* out) {
    if (alphabet == nullptr || specification == nullptr || key == nullptr || tweak == nullptr || in == nullptr ||
            out == nullptr) {
        return E_POINTER;
    }
    try {
        shadow::fpe::Alphabet* t_alphabet = reinterpret_cast<shadow::fpe::Alphabet*>(alphabet);
        shadow::fpe::Alphabet* t_specification = reinterpret_cast<shadow::fpe::Alphabet*>(specification);
        shadow::fpe::Key* t_key = reinterpret_cast<shadow::fpe::Key*>(key);
        shadow::fpe::Tweak* t_tweak = reinterpret_cast<shadow::fpe::Tweak*>(tweak);
        std::string in_str(in->data, in->len);
        std::string out_str;
        shadow::fpe::decrypt_skip_specified(*t_alphabet, *t_specification, *t_key, *t_tweak, in_str, out_str);
        std::copy_n(out_str.c_str(), out_str.length(), out->data);
        return S_OK;
    } catch (const std::invalid_argument&) {
        return E_INVALIDARG;
    }
}

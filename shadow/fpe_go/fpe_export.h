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

#ifndef SHADOW_FPE_EXPORT_HEADER_FPE_H
#define SHADOW_FPE_EXPORT_HEADER_FPE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef long FPEStatus;

#define _FPE_STATUS_TYPEDEF_(status) ((FPEStatus)status)

#define S_OK _FPE_STATUS_TYPEDEF_(0L)
#define S_FALSE _FPE_STATUS_TYPEDEF_(1L)
#define E_POINTER _FPE_STATUS_TYPEDEF_(2L)
#define E_INVALIDARG _FPE_STATUS_TYPEDEF_(3L)
#define E_OUTOFMEMORY _FPE_STATUS_TYPEDEF_(4L)
#define E_UNEXPECTED _FPE_STATUS_TYPEDEF_(5L)
#define COR_E_IO _FPE_STATUS_TYPEDEF_(6L)
#define COR_E_INVALIDOPERATION _FPE_STATUS_TYPEDEF_(7L)

typedef struct {
    char* data;
    size_t len;
} FPEBytes;

typedef struct FPEAlphabet FPEAlphabet;

typedef struct FPEKey FPEKey;

typedef struct FPETweak FPETweak;

FPEAlphabet* fpe_alphabet_new(FPEBytes* charset, FPEStatus* status);

FPEStatus fpe_alphabet_free(FPEAlphabet* alphabet);

FPEStatus fpe_alphabet_size(FPEAlphabet* alphabet, size_t* size);

FPEStatus fpe_alphabet_are_identical(FPEAlphabet* alphabet_0, FPEAlphabet* alphabet_1, bool* result);

FPEStatus fpe_alphabet_are_exclusive(FPEAlphabet* alphabet_0, FPEAlphabet* alphabet_1, bool* result);

FPEKey* fpe_key_new(FPEStatus* status);

FPEStatus fpe_key_free(FPEKey* key);

FPEStatus fpe_key_from_bytes(FPEKey* key, FPEBytes* bytes);

FPEStatus fpe_key_to_bytes(FPEKey* key, FPEBytes* bytes);

FPEStatus fpe_key_generate(FPEKey* key);

FPETweak* fpe_tweak_new(FPEStatus* status);

FPEStatus fpe_tweak_free(FPETweak* tweak);

FPEStatus fpe_tweak_fill(FPETweak* tweak, FPEBytes* bytes);

FPEStatus fpe_encrypt(FPEAlphabet* alphabet, FPEKey* key, FPETweak* tweak, FPEBytes* in, FPEBytes* out);

FPEStatus fpe_decrypt(FPEAlphabet* alphabet, FPEKey* key, FPETweak* tweak, FPEBytes* in, FPEBytes* out);

FPEStatus fpe_encrypt_skip_unsupported(
        FPEAlphabet* alphabet, FPEKey* key, FPETweak* tweak, FPEBytes* in, FPEBytes* out);

FPEStatus fpe_decrypt_skip_unsupported(
        FPEAlphabet* alphabet, FPEKey* key, FPETweak* tweak, FPEBytes* in, FPEBytes* out);

FPEStatus fpe_encrypt_skip_specified(
        FPEAlphabet* alphabet, FPEAlphabet* specification, FPEKey* key, FPETweak* tweak, FPEBytes* in, FPEBytes* out);

FPEStatus fpe_decrypt_skip_specified(
        FPEAlphabet* alphabet, FPEAlphabet* specification, FPEKey* key, FPETweak* tweak, FPEBytes* in, FPEBytes* out);

#ifdef __cplusplus
}
#endif

#endif  // SHADOW_FPE_EXPORT_HEADER_FPE_H

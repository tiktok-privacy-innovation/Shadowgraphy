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

#include <string>
#include <vector>

#include "benchmark/benchmark.h"
#include "shadow/common/common.h"
#include "shadow/fpe/fpe.h"

#define FPE_REG_BENCH(category, name0, name1, func, ...)                                                      \
    benchmark::RegisterBenchmark((std::string(#category " / " #name0 " / ") + std::to_string(name1)).c_str(), \
            [=](benchmark::State& st) { func(st, __VA_ARGS__); })                                             \
            ->Unit(benchmark::kMicrosecond);

static const std::vector<std::size_t> kFPEMessagesLength = {
        6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 32, 40, 48, 56, 64, 128, 192, 256, 320};

void generate_random_messages(const std::vector<std::size_t>& messages_length, const std::string& charset,
        std::vector<std::string>& random_messages) {
    unsigned char charset_length = static_cast<unsigned char>(charset.length());
    random_messages.clear();
    random_messages.reserve(messages_length.size());
    for (auto msg_len : messages_length) {
        std::vector<unsigned char> random_bytes(msg_len);
        shadow::common::get_bytes_from_random_device(msg_len, random_bytes.data());
        std::string cur_msg = "";
        for (std::size_t i = 0; i < msg_len; ++i) {
            cur_msg += charset[random_bytes[i] % charset_length];
        }
        random_messages.push_back(cur_msg);
    }
}

void fpe_encrypt_charset_numbers(
        benchmark::State& state, const shadow::fpe::Key& key, const shadow::fpe::Tweak& tweak, const std::string& pt) {
    shadow::fpe::Alphabet alphabet(shadow::fpe::kCharsetNumbers);
    std::string ct;
    for (auto _ : state) {
        shadow::fpe::encrypt(alphabet, key, tweak, pt, ct);
    }
}

int main(int argc, char** argv) {
    // All bench use the same key and tweaks.
    shadow::fpe::Key key = shadow::fpe::generate_key();

    // Benchmark for charset number.
    std::vector<std::string> random_numbers;
    generate_random_messages(kFPEMessagesLength, shadow::fpe::kCharsetNumbers, random_numbers);
    for (std::size_t j = 0; j < kFPEMessagesLength.size(); ++j) {
        FPE_REG_BENCH(FPENumbers, MessageLength, j, fpe_encrypt_charset_numbers, key, shadow::fpe::Tweak(),
                random_numbers[j]);
    }

    benchmark::Initialize(&argc, argv);

    benchmark::RunSpecifiedBenchmarks();
}

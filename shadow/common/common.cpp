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

#include "shadow/common/common.h"

#include <algorithm>
#include <cstddef>
#include <random>
#include <stdexcept>

namespace shadow {
namespace common {

void get_bytes_from_random_device(std::size_t byte_count, unsigned char* out) {
    if (byte_count == 0) {
        return;
    }
    if (byte_count != 0 && out == nullptr) {
        throw std::invalid_argument("out is nullptr");
    }
    std::random_device rd("/dev/urandom");
    while (byte_count >= 4) {
        *reinterpret_cast<std::uint32_t*>(out) = rd();
        out += 4;
        byte_count -= 4;
    }
    if (byte_count) {
        std::uint32_t last = rd();
        std::copy_n(reinterpret_cast<unsigned char*>(&last), byte_count, out);
    }
}

}  // namespace common
}  // namespace shadow

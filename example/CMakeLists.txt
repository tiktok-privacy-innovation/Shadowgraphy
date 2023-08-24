# Copyright 2023 TikTok Pte. Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.14)

project(SHADOWExample VERSION 0.1.0 LANGUAGES CXX)

# If not called from root CMakeLists.txt
if(NOT DEFINED SHADOW_BUILD_EXAMPLE)
    set(SHADOW_BUILD_EXAMPLE ON)

    # Import Shadow
    find_package(Shadow 0.1.0 EXACT REQUIRED)

    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
endif()

if(SHADOW_BUILD_EXAMPLE)
    set(CMAKE_CXX_LINK_EXECUTABLE "${CMAKE_CXX_LINK_EXECUTABLE} -ldl -lrt")

    # fpe
    add_executable(fpe_example ${CMAKE_CURRENT_LIST_DIR}/fpe_example.cpp)
    if(TARGET Shadow::fpe)
        target_link_libraries(fpe_example PRIVATE Shadow::fpe)
    else()
        message(FATAL_ERROR "Cannot find target Shadow::fpe")
    endif()
endif()

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

#####################################################
# Project SHADOW includes the following components: #
#   1. FPE C++ library                        #
#   2. FPE C library                          #
#####################################################

# [OPTION] CMAKE_BUILD_TYPE (DEFAULT: "Release")
# Select from Release, Debug, MiniSizeRel, or RelWithDebInfo.
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY
        STRINGS "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

project(SHADOW VERSION 0.0.0 LANGUAGES C CXX)

########################
# Global configuration #
########################

# CMake modules
include(CMakeDependentOption)
include(CMakePushCheckState)
include(CheckIncludeFiles)
include(CheckCXXSourceCompiles)
include(CheckCXXSourceRuns)

# Extra modules
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)
include(ShadowCustomMacros)

# In Debug mode, define SHADOW_DEBUG.
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(SHADOW_DEBUG ON)
else()
    set(SHADOW_DEBUG OFF)
endif()
message(STATUS "SHADOW debug mode: ${SHADOW_DEBUG}")

# In Debug mode, enable extra compiler flags.
include(EnableDebugFlags)

# Always build position-independent-code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Make the install target depend on the all target (required by vcpkg)
set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY OFF)

# Use C++14
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Required files and directories
include(GNUInstallDirs)

# Runtime path setup
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# Source Tree
set(SHADOW_INCLUDES_DIR ${CMAKE_CURRENT_LIST_DIR})
set(SHADOW_CONFIG_IN_FILENAME ${CMAKE_CURRENT_LIST_DIR}/cmake/ShadowConfig.cmake.in)
set(SHADOW_CONFIG_H_IN_FILENAME ${SHADOW_INCLUDES_DIR}/shadow/common/config.h.in)

# Build tree
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(SHADOW_TARGETS_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/cmake/ShadowTargets.cmake)
set(SHADOW_CONFIG_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/cmake/ShadowConfig.cmake)
set(SHADOW_CONFIG_VERSION_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/cmake/ShadowConfigVersion.cmake)
set(SHADOW_CONFIG_H_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/shadow/common/config.h)
set(SHADOW_THIRDPARTY_DIR ${CMAKE_CURRENT_BINARY_DIR}/thirdparty)

# Install
set(SHADOW_CONFIG_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/Shadow-${SHADOW_VERSION_MAJOR}.${SHADOW_VERSION_MINOR})
set(SHADOW_INCLUDES_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR}/Shadow-${SHADOW_VERSION_MAJOR}.${SHADOW_VERSION_MINOR})

# Supported target operating systems are Linux and macOS.
if (NOT DEFINED LINUX)
    if (UNIX AND NOT APPLE AND NOT CYGWIN AND NOT MINGW)
        set(LINUX ON)
    endif()
endif()
if (UNIX AND APPLE)
    set(MACOS ON)
endif()
if (NOT LINUX AND NOT MACOS)
    message(FATAL_ERROR "Supported target operating systems are Linux and macOS")
endif()

# Enable test coverage
set(SHADOW_ENABLE_GCOV_STR "Enable gcov")
option(SHADOW_ENABLE_GCOV ${SHADOW_ENABLE_GCOV_STR} OFF)
message(STATUS "SHADOW_ENABLE_GCOV: ${SHADOW_ENABLE_GCOV}")
if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND SHADOW_ENABLE_GCOV)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-arcs -ftest-coverage")
    set(CMAKE_CXX_LINK_EXECUTABLE "${CMAKE_CXX_LINK_EXECUTABLE} -fprofile-arcs -ftest-coverage -lgcov")
endif()

#########################
# External dependencies #
#########################

# OpenSSL
message(STATUS "OpenSSL: download ...")
shadow_fetch_thirdparty_content(ExternalOpenSSL)

# [OPTION] SHADOW_BUILD_UTILS (DEFAULT: OFF)
# Look for utilities using find_package first.
# If a utility is not found, download and build it if set to ON.
# FATAL_ERROR if set to OFF.
set(SHADOW_BUILD_UTILS_OPTION_STR "Automatically download and build utilities")
option(SHADOW_BUILD_UTILS ${SHADOW_BUILD_UTILS_OPTION_STR} OFF)
message(STATUS "SHADOW_BUILD_UTILS: ${SHADOW_BUILD_UTILS}")

if(SHADOW_BUILD_UTILS)
    include(FetchContent)
endif()

#########################
# COMMON object library #
#########################

# Create the config file
configure_file(${SHADOW_CONFIG_H_IN_FILENAME} ${SHADOW_CONFIG_H_FILENAME})

add_library(common OBJECT)
target_sources(common PRIVATE ${CMAKE_CURRENT_LIST_DIR}/shadow/common/common.cpp)
target_compile_features(common PUBLIC cxx_std_14)
target_include_directories(common PRIVATE
    $<BUILD_INTERFACE:${SHADOW_INCLUDES_DIR}>
    $<INSTALL_INTERFACE:${SHADOW_INCLUDES_INSTALL_DIR}>)
target_include_directories(common PRIVATE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>)

###################
# FPE C++ library #
###################

add_library(fpe STATIC)
target_sources(fpe PRIVATE ${CMAKE_CURRENT_LIST_DIR}/shadow/fpe/fpe.cpp)
target_compile_features(common PUBLIC cxx_std_14)
target_include_directories(fpe PUBLIC
    $<BUILD_INTERFACE:${SHADOW_INCLUDES_DIR}>
    $<INSTALL_INTERFACE:${SHADOW_INCLUDES_INSTALL_DIR}>)
target_include_directories(fpe PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>)

target_link_libraries(fpe PRIVATE common)
add_dependencies(fpe OpenSSL::crypto)
target_include_directories(fpe PRIVATE $<BUILD_INTERFACE:${OPENSSL_INCLUDE_DIR}>)
target_include_directories(fpe PRIVATE $<BUILD_INTERFACE:$<TARGET_PROPERTY:OpenSSL::crypto,BINARY_DIR>>)
shadow_combine_archives(fpe OpenSSL::crypto)
set(SHADOW_CARRY_OPENSSL TRUE)

set_target_properties(fpe PROPERTIES VERSION ${SHADOW_VERSION})
set_target_properties(fpe PROPERTIES OUTPUT_NAME fpe-${SHADOW_VERSION_MAJOR}.${SHADOW_VERSION_MINOR})
if(TARGET fpe)
    add_library(Shadow::fpe ALIAS fpe)
endif()

##############
# SHADOW C++ #
##############

# [option] SHADOW_BUILD_TEST
set(SHADOW_BUILD_TEST_OPTION_STR "Build C++ test for SHADOW")
option(SHADOW_BUILD_TEST ${SHADOW_BUILD_TEST_OPTION_STR} OFF)
message(STATUS "SHADOW_BUILD_TEST: ${SHADOW_BUILD_TEST}")

# GoogleTest
if(SHADOW_BUILD_TEST)
    find_package(GTest 1 CONFIG)
    if(GTest_FOUND)
        message(STATUS "GoogleTest: found")
    else()
        if(SHADOW_BUILD_UTILS)
            message(STATUS "GoogleTest: download ...")
            shadow_fetch_thirdparty_content(ExternalGTest)
            add_library(GTest::gtest ALIAS gtest)
        else()
            message(FATAL_ERROR "GoogleTest: not found, please download and install manually")
        endif()
    endif()
endif()

if(SHADOW_BUILD_TEST)
    add_executable(fpe_test ${CMAKE_CURRENT_LIST_DIR}/shadow/fpe/fpe_test.cpp)
    target_link_libraries(fpe_test PRIVATE fpe GTest::gtest)

    # In Debug mode, enable AddressSanitizer (and LeakSanitizer) on Unix-like platforms.
    if(SHADOW_DEBUG AND UNIX)
        # On macOS, only AddressSanitizer is enabled.
        # On Linux, LeakSanitizer is enabled by default.
        target_compile_options(fpe_test PUBLIC -fsanitize=address)
        target_link_options(fpe_test PUBLIC -fsanitize=address)
        if(NOT APPLE)
            message(STATUS "Sanitizers enabled: address, leak")
        else()
            message(STATUS "Sanitizers enabled: address")
        endif()
    endif()

    add_custom_target(test_report
        COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/fpe_test --gtest_output="xml:${CMAKE_CURRENT_BINARY_DIR}/report/fpe_test.xml"
        DEPENDS fpe_test)
    if(SHADOW_DEBUG AND SHADOW_ENABLE_GCOV)
        add_custom_target(test_coverage
            COMMAND gcovr -r ${CMAKE_CURRENT_LIST_DIR} -f \"shadow\" -e \".+\(test\\.cpp\)\" --xml-pretty -o "${CMAKE_CURRENT_BINARY_DIR}/report/coverage.xml"
            WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR})
    endif()
endif()

#################################
# Installation and CMake config #
#################################

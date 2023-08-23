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

include(ExternalProject)

set(OPENSSL_SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl-src) # default path by CMake
set(OPENSSL_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl)
set(OPENSSL_INCLUDE_DIR ${OPENSSL_INSTALL_DIR}/include)
set(OPENSSL_CONFIGURE_COMMAND ${OPENSSL_SOURCE_DIR}/config)
ExternalProject_Add(
	openssl
	SOURCE_DIR ${OPENSSL_SOURCE_DIR}
	GIT_REPOSITORY https://github.com/openssl/openssl.git
	GIT_TAG OpenSSL_1_1_1u
	USES_TERMINAL_DOWNLOAD TRUE
	CONFIGURE_COMMAND
		${OPENSSL_CONFIGURE_COMMAND}
		--prefix=${OPENSSL_INSTALL_DIR}
		--openssldir=${OPENSSL_INSTALL_DIR}
		no-afalgeng
		no-aria
		no-asan
		no-asm
		no-async
		no-autoalginit
		no-autoerrinit
		no-autoload-config
		no-bf
		no-blake2
		no-buildtest-c++
		no-camellia
		no-capieng
		no-cast
		no-chacha
		no-cmac
		no-cms
		no-comp
		no-crypto-mdebug
		no-crypto-mdebug-backtrace
		no-ct
		no-deprecated
		no-des
		no-devcryptoeng
		no-dgram
		no-dh
		no-dsa
		no-dso
		no-dtls
		no-dynamic-engine
		no-ec
		no-ec2m
		no-ecdh
		no-ecdsa
		no-ec_nistp_64_gcc_128
		no-egd
		no-engine
		no-err
		no-external-tests
		no-filenames
		no-fuzz-libfuzzer
		no-fuzz-afl
		no-gost
		no-heartbeats
		no-hw
		no-idea
		no-makedepend
		no-md2
		no-md4
		no-mdc2
		no-msan
		no-multiblock
		no-nextprotoneg
		no-pinshared
		no-ocb
		no-ocsp
		no-poly1305
		no-posix-io
		no-psk
		no-rc2
		no-rc4
		no-rc5
		no-rdrand
		no-rfc3779
		no-rmd160
		no-scrypt
		no-sctp
		no-seed
		no-shared
		no-siphash
		no-sm2
		no-sm3
		no-sm4
		no-sock
		no-srp
		no-srtp
		no-sse2
		no-ssl
		no-ssl-trace
		no-static-engine
		no-stdio
		no-tests
		no-threads
		no-tls
		no-ts
		no-ubsan
		no-ui-console
		no-unit-test
		no-whirlpool
		no-weak-ssl-ciphers
		no-zlib
		no-zlib-dynamic
	BUILD_COMMAND make -j
	TEST_COMMAND ""
	INSTALL_COMMAND make install_sw -j
	INSTALL_DIR ${OPENSSL_INSTALL_DIR}
)

file(MAKE_DIRECTORY ${OPENSSL_INCLUDE_DIR})

add_library(OpenSSL::crypto STATIC IMPORTED GLOBAL)
set_property(TARGET OpenSSL::crypto PROPERTY IMPORTED_LOCATION ${OPENSSL_INSTALL_DIR}/lib/libcrypto.a)
set_property(TARGET OpenSSL::crypto PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})
add_dependencies(OpenSSL::crypto openssl)

#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#


# shared_model_cryptography is the main target which includes ed25519 and crypto_model

add_subdirectory(model_impl)
add_subdirectory(ed25519_sha3_impl)

add_library(shared_model_cryptography INTERFACE)

if (USE_LIBURSA)
  add_subdirectory(ed25519_ursa_impl)
  set(DEFAULT_CRYPTO_PROVIDER CryptoProviderEd25519Ursa)
  set(DEFAULT_CRYPTO_INCLUDE "cryptography/ed25519_ursa_impl/crypto_provider.hpp")

  target_link_libraries(shared_model_cryptography INTERFACE
    ursa_cryptography
  )
else()
  set(DEFAULT_CRYPTO_PROVIDER CryptoProviderEd25519Sha3)
  set(DEFAULT_CRYPTO_INCLUDE "cryptography/ed25519_sha3_impl/crypto_provider.hpp")

  target_link_libraries(shared_model_cryptography INTERFACE
    sha3_cryptography
  )
endif()

# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
  "${PROJECT_SOURCE_DIR}/cryptography/crypto_provider/crypto_defaults.hpp.in"
  "${PROJECT_BINARY_DIR}/cryptography/crypto_provider/crypto_defaults.hpp"
  )

target_include_directories(shared_model_cryptography INTERFACE
  "${PROJECT_BINARY_DIR}"
  )

add_library(crypto_blob_hasher blob_hasher.cpp)
target_link_libraries(crypto_blob_hasher
    common
    )

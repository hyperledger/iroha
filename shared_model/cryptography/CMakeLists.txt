#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#


# shared_model_cryptography is the main target which includes ed25519 and crypto_model

add_subdirectory(model_impl)
add_subdirectory(ed25519_sha3_impl)
add_subdirectory(gost3410_impl)

add_library(shared_model_cryptography
  crypto_provider/crypto_verifier.cpp
  )

target_link_libraries(shared_model_cryptography
  multihash
  sha3_cryptography
)

add_library(crypto_init
  crypto_init/from_config.cpp
  crypto_init/internal.cpp
  )
target_link_libraries(crypto_init
  common
  iroha_conf_loader
  keys_manager
  logger_manager
  multihash
  shared_model_cryptography
  )

if(USE_LIBURSA)
  add_subdirectory(ed25519_ursa_impl)
  target_link_libraries(shared_model_cryptography
    ursa_cryptography
  )
endif()

if(USE_HSM_UTIMACO)
  add_subdirectory(hsm_utimaco)
  target_link_libraries(shared_model_cryptography
    hsm_utimaco
  )
endif()

add_library(crypto_blob_hasher blob_hasher.cpp)
target_link_libraries(crypto_blob_hasher
    common
    )

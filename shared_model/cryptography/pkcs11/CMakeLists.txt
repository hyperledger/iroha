#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

find_package(Botan REQUIRED)

add_library(pkcs11
  init.cpp
  signer.cpp
  verifier.cpp
  )
target_link_libraries(pkcs11
  Botan
  common
  shared_model_cryptography_model
  )

target_compile_definitions(pkcs11
  PUBLIC
    USE_PKCS11
  )

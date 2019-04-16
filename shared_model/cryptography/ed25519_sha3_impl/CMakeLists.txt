#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_subdirectory(internal)

add_library(shared_model_cryptography
    crypto_provider.cpp
    signer.cpp
    verifier.cpp
    )
target_link_libraries(shared_model_cryptography
    ed25519_crypto
    shared_model_cryptography_model
    common
    )

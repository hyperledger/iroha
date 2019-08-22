#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_subdirectory(internal)

add_library(sha3_cryptography
    crypto_provider.cpp
    signer.cpp
    verifier.cpp
    )
target_link_libraries(sha3_cryptography
    ed25519_crypto
    shared_model_cryptography_model
    common
    )

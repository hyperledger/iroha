#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(hash
        sha3_hash.cpp
        )

target_link_libraries(hash
        iroha::ed25519
        common
        )

add_library(ed25519_crypto
        ed25519_impl.cpp
        )
target_link_libraries(ed25519_crypto
        hash
        )

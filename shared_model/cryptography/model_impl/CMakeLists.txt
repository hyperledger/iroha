#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(shared_model_cryptography_model
    blob.cpp
    hash.cpp
    keypair.cpp
    private_key.cpp
    seed.cpp
    )

target_link_libraries(shared_model_cryptography_model
    shared_model_utils
    Boost::boost
    common
    )

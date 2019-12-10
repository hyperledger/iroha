#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(ursa_cryptography
    crypto_provider.cpp
    ursa_blob.cpp
    )

target_link_libraries(ursa_cryptography
    ursa
    shared_model_cryptography_model
    common
    )

#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

find_package(ursa)

add_library(ursa_cryptography
    crypto_provider.cpp
    )
target_link_libraries(ursa_cryptography
    common
    shared_model_cryptography_model
    ursa
    )

target_compile_definitions(ursa_cryptography
  INTERFACE
    -DUSE_LIBURSA=${USE_LIBURSA}
  )

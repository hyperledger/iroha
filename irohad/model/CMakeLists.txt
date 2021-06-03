#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_subdirectory(generators)
add_subdirectory(converters)

add_library(sha3_hash
    sha3_hash.cpp
    )

target_link_libraries(sha3_hash
    pb_model_converters
    )

add_library(model
    impl/model_operators.cpp
    )

target_link_libraries(model
    common
    )

add_library(model_crypto_provider
    model_crypto_provider_impl.cpp
    )
target_link_libraries(model_crypto_provider
    sha3_hash
    )

add_library(model_registrations INTERFACE)
target_include_directories(model_registrations INTERFACE
    registration
    )
target_link_libraries(model_registrations INTERFACE
    model
    )

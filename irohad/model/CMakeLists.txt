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
    model_crypto_provider_impl.cpp
    impl/model_operators.cpp
    )

target_link_libraries(model
    hash
    sha3_hash
    rxcpp
    logger
    schema
    ed25519_crypto
    rapidjson
    common
    )

add_library(model_registrations INTERFACE)
target_include_directories(model_registrations INTERFACE
    registration
    )
target_link_libraries(model_registrations INTERFACE
    model
    )

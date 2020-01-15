#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(json_model_converters
    impl/json_block_factory.cpp
    impl/json_command_factory.cpp
    impl/json_common.cpp
    impl/json_query_factory.cpp
    impl/json_transaction_factory.cpp
    )
target_link_libraries(json_model_converters
    model
    RapidJSON::rapidjson
    schema
    ed25519_crypto
    common
    logger
    )

add_library(pb_model_converters
    impl/pb_block_factory.cpp
    impl/pb_command_factory.cpp
    impl/pb_query_factory.cpp
    impl/pb_transaction_factory.cpp
    impl/pb_common.cpp
    )
target_link_libraries(pb_model_converters
    model
    schema
    ed25519_crypto
    common
    Boost::boost
    logger
    )

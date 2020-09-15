#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

add_subdirectory(interactive)

# Gflags config validators
add_library(cli-flags_validators
    validators.cpp
    )
target_link_libraries(cli-flags_validators
    gflags
    )

add_library(client
    client.cpp
    impl/query_response_handler.cpp
    impl/transaction_response_handler.cpp
    impl/grpc_response_handler.cpp
    )
target_link_libraries(client
    ed25519_crypto
    grpc_channel_factory
    logger
    RapidJSON::rapidjson
    pb_model_converters
    json_model_converters
    model_generators
    command_client
    query_client
    model_generators
    parser
    model
    )
target_include_directories(client PUBLIC
    ${PROJECT_SOURCE_DIR}/iroha-cli
    )

# IrohaCli
add_executable(iroha-cli
    main.cpp
    validators.cpp
    )
target_link_libraries(iroha-cli
    interactive_cli
    model_crypto_provider
    client
    cli-flags_validators
    keys_manager
    Boost::boost
    Boost::filesystem
    logger
    logger_manager
    )

add_install_step_for_bin(iroha-cli)


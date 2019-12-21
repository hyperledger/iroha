#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(model_crypto_provider_test model_crypto_provider_test.cpp)
target_link_libraries(model_crypto_provider_test
    model_crypto_provider
    model
    hash
    ed25519_crypto
    model_generators
    )

addtest(command_converter_test converters/pb_commands_test.cpp)
target_link_libraries(command_converter_test
    pb_model_converters
    )

addtest(transaction_converter_test converters/pb_transaction_test.cpp)
target_link_libraries(transaction_converter_test
    pb_model_converters
    )

addtest(block_converter_test converters/pb_block_test.cpp)
target_link_libraries(block_converter_test
    pb_model_converters
    sha3_hash
    )

addtest(model_operators_test operators/model_operators_test.cpp)
target_link_libraries(model_operators_test
    model
    sha3_hash
    )

addtest(json_command_converter_test converters/json_commands_test.cpp)
target_link_libraries(json_command_converter_test
    json_model_converters
    sha3_hash
    )

addtest(json_transaction_converter_test converters/json_transaction_test.cpp)
target_link_libraries(json_transaction_converter_test
    json_model_converters
    )

addtest(json_block_converter_test converters/json_block_test.cpp)
target_link_libraries(json_block_converter_test
    json_model_converters
    test_logger
    )

addtest(json_query_factory_test converters/json_query_factory_test.cpp)
target_link_libraries(json_query_factory_test
    model_generators
    json_model_converters
    test_logger
    )

addtest(pb_query_factory_test converters/pb_query_factory_test.cpp)
target_link_libraries(pb_query_factory_test
    model_generators
    pb_model_converters
    test_logger
    )

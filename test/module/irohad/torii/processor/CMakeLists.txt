#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

# Testing of transaction processor
addtest(transaction_processor_test transaction_processor_test.cpp)
target_link_libraries(transaction_processor_test
    consensus_round
    processors
    shared_model_stateless_validation
    test_logger
    test_make_default_signer
    test_tx_sequence_factory
    )

# Testing of query processor
addtest(query_processor_test query_processor_test.cpp)
target_link_libraries(query_processor_test
    common_test_constants
    processors
    shared_model_default_builders
    shared_model_cryptography
    test_logger
    )

# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

addtest(chain_validation_test chain_validation_test.cpp)
target_link_libraries(chain_validation_test
    chain_validator
    shared_model_default_builders
    test_logger
    )

addtest(stateful_validator_test stateful_validator_test.cpp)
target_link_libraries(stateful_validator_test
    stateful_validator
    shared_model_default_builders
    shared_model_proto_backend
    test_logger
    )

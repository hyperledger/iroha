#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(transaction_validator_test
    transaction_validator_test.cpp
    )
target_link_libraries(transaction_validator_test
    shared_model_proto_backend
    shared_model_stateless_validation
    )

addtest(query_validator_test
    query_validator_test.cpp
    )
target_link_libraries(query_validator_test
    shared_model_proto_backend
    shared_model_stateless_validation
    )

addtest(proto_query_validator_test
    protobuf/proto_query_validator_test.cpp
    )
target_link_libraries(proto_query_validator_test
    shared_model_proto_backend
    shared_model_stateless_validation
    )

addtest(field_validator_test
    field_validator_test.cpp
    )
target_link_libraries(field_validator_test
    shared_model_proto_backend
    shared_model_stateless_validation
    )

addtest(container_validator_test
    container_validator_test.cpp
    )
target_link_libraries(container_validator_test
    shared_model_proto_backend
    shared_model_stateless_validation
    )

addtest(block_validator_test
    block_validator_test.cpp
    )
target_link_libraries(block_validator_test
    shared_model_proto_backend
    shared_model_stateless_validation
    )

addtest(proto_transaction_validator_test
    protobuf/proto_tx_validator_test.cpp
    )
target_link_libraries(proto_transaction_validator_test
    shared_model_proto_backend
    shared_model_stateless_validation
    )

addtest(proto_block_validator_test
    protobuf/proto_block_validator_test.cpp
    )
target_link_libraries(proto_block_validator_test
    shared_model_proto_backend
    shared_model_stateless_validation
    )

addtest(proposal_validator_test
    proposal_validator_test.cpp
    )
target_link_libraries(proposal_validator_test
    shared_model_proto_backend
    shared_model_interfaces_factories
    shared_model_stateless_validation
    )

addtest(batch_validator_test
    batch_validator_test.cpp
    )
target_link_libraries(batch_validator_test
    shared_model_proto_backend
    shared_model_interfaces_factories
    shared_model_stateless_validation
    )

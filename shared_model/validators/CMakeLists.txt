# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_library(shared_model_stateless_validation
        field_validator.cpp
        validators_common.cpp
        validation_error.cpp
        validation_error_helpers.cpp
        transactions_collection/transactions_collection_validator.cpp
        transactions_collection/batch_order_validator.cpp
        protobuf/proto_block_validator.cpp
        protobuf/proto_query_validator.cpp
        protobuf/proto_command_validator.cpp
        protobuf/proto_transaction_validator.cpp
        protobuf/proto_proposal_validator.cpp
        transaction_batch_validator.cpp
        settings.cpp
        )

target_link_libraries(shared_model_stateless_validation
        fmt::fmt
        schema
        shared_model_interfaces
        )

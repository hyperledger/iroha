#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(shared_model_proto_builders
    transaction_responses/proto_transaction_status_builder.cpp
    )

target_link_libraries(
    shared_model_proto_builders
    shared_model_interfaces
    shared_model_proto_backend
    shared_model_stateless_validation
)

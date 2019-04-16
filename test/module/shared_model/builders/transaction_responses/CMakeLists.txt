#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(transaction_response_builder_test
    transaction_response_builder_test.cpp
    )

target_link_libraries(transaction_response_builder_test
    shared_model_proto_builders
    )

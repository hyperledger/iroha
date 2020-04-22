#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_subdirectory(common_objects)

add_library(test_tx_sequence_factory transaction_sequence_factory.cpp)
target_link_libraries(test_tx_sequence_factory
    shared_model_stateless_validation
    )

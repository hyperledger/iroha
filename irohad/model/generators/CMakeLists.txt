#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(model_generators
    impl/block_generator.cpp
    impl/transaction_generator.cpp
    impl/command_generator.cpp
    impl/query_generator.cpp
    )

target_link_libraries(model_generators
    model
    generator
    keys_manager
    sha3_hash
    )

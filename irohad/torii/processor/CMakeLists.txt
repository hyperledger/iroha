# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_library(processors
    impl/transaction_processor_impl.cpp
    impl/query_processor_impl.cpp
    )

target_link_libraries(processors PUBLIC
    logger
    endpoint
    common
    verified_proposal_creator_common
    )

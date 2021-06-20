# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_library(simulator
    impl/simulator.cpp
    )

target_link_libraries(simulator
    consensus_round
    shared_model_interfaces
    logger
    common
    ordering_gate_common
    verified_proposal_creator_common
    block_creator_common
    )

add_library(verified_proposal_creator_common
    verified_proposal_creator_common.cpp
    )
target_link_libraries(verified_proposal_creator_common
    Boost::boost
    )

add_library(block_creator_common
    block_creator_common.cpp
    )
target_link_libraries(block_creator_common
    Boost::boost
    )

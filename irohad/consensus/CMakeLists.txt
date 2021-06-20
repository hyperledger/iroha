# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_subdirectory(yac)

add_library(consensus_round
    impl/round.cpp
    )
target_link_libraries(consensus_round
    Boost::boost
    shared_model_utils
    )

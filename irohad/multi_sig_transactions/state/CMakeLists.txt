# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_library(mst_state
    impl/mst_state.cpp
    )

target_link_libraries(mst_state
    mst_hash
    Boost::boost
    common
    logger
    )

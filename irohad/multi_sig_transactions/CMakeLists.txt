# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_subdirectory(state)
add_subdirectory(storage)
add_subdirectory(transport)


add_library(mst_processor
    impl/gossip_propagation_strategy.cpp
    impl/mst_propagation_strategy_stub.cpp
    impl/mst_processor_impl.cpp
    impl/mst_processor.cpp
    )

target_link_libraries(mst_processor
    mst_storage
    mst_transport
    rxcpp
    logger
    common
    subscription
    )

add_library(mst_hash
    impl/hash.cpp
    )

target_link_libraries(mst_hash
    shared_model_interfaces
    )

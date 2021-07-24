#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(supermajority_checker
    impl/supermajority_checker_cft.cpp
    impl/supermajority_checker_bft.cpp
    impl/supermajority_checker_getter.cpp
    )
target_link_libraries(supermajority_checker
    shared_model_interfaces
    )

add_library(yac
    impl/yac.cpp
    impl/cluster_order.cpp
    impl/timer_impl.cpp
    impl/peer_orderer_impl.cpp
    impl/yac_gate_impl.cpp
    impl/yac_hash_provider_impl.cpp

    storage/impl/yac_common.cpp
    storage/impl/yac_block_storage.cpp
    storage/impl/yac_proposal_storage.cpp
    storage/impl/yac_vote_storage.cpp
    storage/impl/buffered_cleanup_strategy.cpp
    )
target_link_libraries(yac
    supermajority_checker
    common
    logger
    logger_manager
    hash
    consensus_round
    permutation_generator
    )
# avoid compilation error due to missing operator<< in Answer variant types
target_compile_definitions(yac
    PUBLIC BOOST_NO_IOSTREAM
    )

add_library(yac_transport
    transport/impl/network_impl.cpp
    transport/impl/consensus_service_impl.cpp
    impl/yac_crypto_provider_impl.cpp
    )
target_link_libraries(yac_transport
    grpc_generic_client_factory
    yac
    yac_grpc
    logger
    shared_model_plain_backend
    shared_model_proto_backend
    shared_model_stateless_validation # ProtoCommonObjectsFactory -> FieldValidator
    )

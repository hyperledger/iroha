# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_library(mock_yac_crypto_provider INTERFACE
    #mock_yac_crypto_provider.hpp
    )
target_link_libraries(mock_yac_crypto_provider
  INTERFACE
    shared_model_plain_backend
    )

# Testing of transaction processor
addtest(cluster_order_test cluster_order_test.cpp)
target_link_libraries(cluster_order_test
    yac
    )

addtest(yac_cold_case_test yac_simple_cold_case_test.cpp)
target_link_libraries(yac_cold_case_test
    mock_yac_crypto_provider
    yac
    test_logger
    )

addtest(yac_sunny_day_test yac_sunny_day_test.cpp)
target_link_libraries(yac_sunny_day_test
    mock_yac_crypto_provider
    yac
    test_logger
    )

addtest(yac_rainy_day_test yac_rainy_day_test.cpp)
target_link_libraries(yac_rainy_day_test
    mock_yac_crypto_provider
    yac
    test_logger
    )

addtest(yac_unknown_peer_test yac_unknown_peer_test.cpp)
target_link_libraries(yac_unknown_peer_test
    mock_yac_crypto_provider
    yac
    test_logger
    )

addtest(yac_block_storage_test yac_block_storage_test.cpp)
target_link_libraries(yac_block_storage_test
    yac
    test_logger
    )

addtest(yac_proposal_storage_test yac_proposal_storage_test.cpp)
target_link_libraries(yac_proposal_storage_test
    yac
    test_logger
    )

addtest(yac_timer_test timer_test.cpp)
target_link_libraries(yac_timer_test
    yac
    sync_subscription
    )

addtest(yac_network_test network_test.cpp)
target_link_libraries(yac_network_test
    mock_yac_crypto_provider
    yac
    yac_transport
    test_logger
    sync_subscription
    )

addtest(yac_peer_orderer_test peer_orderer_test.cpp)
target_link_libraries(yac_peer_orderer_test
    yac
    )

addtest(yac_gate_test yac_gate_test.cpp)
target_link_libraries(yac_gate_test
    mock_yac_crypto_provider
    yac
    test_logger
    )

addtest(yac_hash_provider_test yac_hash_provider_test.cpp)
target_link_libraries(yac_hash_provider_test
    yac
    )

addtest(yac_common_test yac_common_test.cpp)
target_link_libraries(yac_common_test
    yac
    test_logger
    )

addtest(yac_crypto_provider_test yac_crypto_provider_test.cpp)
target_link_libraries(yac_crypto_provider_test
    test_logger
    yac
    yac_transport
    )

addtest(supermajority_checker_test supermajority_checker_test.cpp)
target_link_libraries(supermajority_checker_test
    yac
    test_logger
    )

addtest(buffered_cleanup_strategy_test buffered_cleanup_strategy_test.cpp)
target_link_libraries(buffered_cleanup_strategy_test
    yac
    consensus_round
    )

addtest(yac_synchronization_test yac_synchronization_test.cpp)
target_link_libraries(yac_synchronization_test
    mock_yac_crypto_provider
    yac
    test_logger
    )

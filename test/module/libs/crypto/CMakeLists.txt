#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

# Hash Test
AddTest(hash_test hash_test.cpp)
target_link_libraries(hash_test
    ed25519_crypto
    )

# Key manager Test
AddTest(keys_manager_test keys_manager_test.cpp)
target_link_libraries(keys_manager_test
    keys_manager
    test_logger
    )

#Bloom filter Test
AddTest(bloom_filter_test bloom_filter_test.cpp)
target_link_libraries(bloom_filter_test
	shared_model_cryptography_model
	consensus_round
    )

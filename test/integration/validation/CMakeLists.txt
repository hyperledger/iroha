# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

addtest(chain_validator_storage_test chain_validator_storage_test.cpp)
target_link_libraries(chain_validator_storage_test
    ametsuchi
    ametsuchi_fixture
    yac
    chain_validator
    test_logger
    sync_subscription
    )

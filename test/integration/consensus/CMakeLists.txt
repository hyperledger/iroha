#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(consensus_sunny_day consensus_sunny_day.cpp)
target_link_libraries(consensus_sunny_day
    mock_yac_crypto_provider
    yac
    yac_transport
    shared_model_stateless_validation
    test_client_factory
    test_logger
    async_subscription
    )

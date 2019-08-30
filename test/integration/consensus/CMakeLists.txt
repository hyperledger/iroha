#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(consensus_sunny_day consensus_sunny_day.cpp)
target_link_libraries(consensus_sunny_day
    yac
    yac_transport
    shared_model_stateless_validation
    test_logger
    grpc_client_factory
    )

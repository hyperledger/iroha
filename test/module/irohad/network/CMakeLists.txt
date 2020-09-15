#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(block_loader_test block_loader_test.cpp)
target_link_libraries(block_loader_test
    block_loader
    block_loader_service
    shared_model_cryptography
    shared_model_default_builders
    test_client_factory
    test_logger
    )

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

addtest(client_factory_test client_factory_test.cpp)
target_link_libraries(client_factory_test
    test_client_factory
    shared_model_cryptography
    shared_model_default_builders
    server_runner
    test_keys
    test_p2p_tls_creds
    tls_credentials
    endpoint
    test_logger
    )

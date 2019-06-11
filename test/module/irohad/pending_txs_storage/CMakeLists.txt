#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#


addtest(pending_txs_storage_test
    pending_txs_storage_test.cpp
    )
target_link_libraries(pending_txs_storage_test
    rxcpp
    pending_txs_storage
    shared_model_cryptography
    shared_model_stateless_validation
    shared_model_proto_backend
    shared_model_interfaces_factories
    test_logger
    )

addtest(old_pending_txs_storage_test
    old_pending_txs_storage_test.cpp
    )
target_link_libraries(old_pending_txs_storage_test
    rxcpp
    pending_txs_storage
    shared_model_cryptography
    shared_model_stateless_validation
    shared_model_proto_backend
    shared_model_interfaces_factories
    test_logger
    )

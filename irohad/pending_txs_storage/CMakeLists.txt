#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(pending_txs_storage
    impl/pending_txs_storage_impl.cpp
    )

target_link_libraries(pending_txs_storage
    shared_model_interfaces
    rxcpp
    )

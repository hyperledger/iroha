# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_library(mst_storage
    impl/mst_storage.cpp
    impl/mst_storage_impl.cpp
    )

target_link_libraries(mst_storage
    crypto_blob_hasher
    mst_state
    logger
    )

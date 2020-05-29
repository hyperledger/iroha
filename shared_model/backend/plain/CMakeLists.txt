#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(shared_model_plain_backend
    impl/account.cpp
    impl/account_detail_record_id.cpp
    impl/domain.cpp
    impl/engine_receipt.cpp
    impl/peer.cpp
    impl/signature.cpp
    )

target_link_libraries(shared_model_plain_backend
    shared_model_cryptography
    )

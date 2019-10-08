#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(shared_model_plain_backend
    impl/account_detail_record_id.cpp
    impl/peer.cpp
    impl/signature.cpp
    impl/account.cpp
    impl/domain.cpp
    )

target_link_libraries(shared_model_plain_backend
    shared_model_cryptography
    )

#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(shared_model_plain_backend
    common_objects/impl/account_asset.cpp
    impl/account.cpp
    impl/account_detail_record_id.cpp
    impl/domain.cpp
    impl/peer.cpp
    impl/query_response_factory.cpp
    impl/signature.cpp
    query_responses/impl/account_asset_response.cpp
    query_responses/impl/account_detail_response.cpp
    query_responses/impl/error_query_response.cpp
    query_responses/impl/query_response.cpp
    query_responses/impl/signatories_response.cpp
    )

target_link_libraries(shared_model_plain_backend
    shared_model_cryptography
    )
